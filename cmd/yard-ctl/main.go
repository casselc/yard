// yard-ctl: the yard control plane (Phase 1 skeleton): the STS with
// TPM-backed RS256 keys, SPIFFE-shaped JWTs, JWKS publishing and active ->
// standby key rotation.
//
//	yard-ctl example-config                      print a config to start from
//	yard-ctl init-keys   -config C               create/adopt active+standby keys, write keyring state
//	yard-ctl serve       -config C               serve the API on the configured frontend
//	yard-ctl keys        -config C status|jwks|rotate|retire   offline key admin (serve must be stopped)
//	yard-ctl mint        -sock S -kind external|internal -aud A -user U -harness H -policy P -node N -sandbox S -run R [-ttl 300] [-apv ID]
//	yard-ctl admin       -sock S keys|rotate|retire
//	yard-ctl verify      -jwks F -iss I [-aud A] -token T|-
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"yard/internal/ctl"
	"yard/internal/issuer"
	"yard/internal/jwks"
	"yard/internal/keyring"
	"yard/internal/sts"
	"yard/internal/tpmkey"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "yard-ctl: "+f+"\n", a...)
	os.Exit(1)
}

func logf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, time.Now().UTC().Format("2006-01-02T15:04:05.000Z")+" "+f+"\n", a...)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: yard-ctl <example-config|init-keys|serve|keys|mint|admin|verify> [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "example-config":
		fmt.Print(exampleConfig)
	case "init-keys":
		cmdInitKeys(args)
	case "serve":
		cmdServe(args)
	case "keys":
		cmdKeys(args)
	case "mint":
		cmdMint(args)
	case "admin":
		cmdAdmin(args)
	case "verify":
		cmdVerify(args)
	default:
		die("unknown command %q", cmd)
	}
}

const exampleConfig = `{
  "issuer": "https://id.example.org/yard",
  "trust_domain": "home.arpa",
  "external_audiences": ["sts.amazonaws.com", "api://AzureADTokenExchange", "https://api.anthropic.com"],
  "internal_audiences": ["yard", "yard-mcp"],
  "max_ttl": "5m",
  "default_ttl": "5m",
  "rate_per_s": 5,
  "burst": 50,
  "aws_session_tags": true,
  "keystore": {"kind": "tpm", "tpm_path": "/dev/tpm0"},
  "active_handle": "0x81010010",
  "standby_handle": "0x81010011",
  "keyring_state": "/yard/data/yard/sts/keyring.json",
  "publish_delay": "24h",
  "retire_grace": "1h",
  "seq_log": "/yard/data/yard/sts/mint.log",
  "jwks_dir": "/yard/data/yard/sts/public",
  "frontend": {
    "kind": "unix",
    "path": "/var/run/yard-ctl.sock",
    "mode": "0660",
    "users": {"1001": {"name": "chuck", "roles": ["mint", "admin"]}}
  }
}
`

type env struct {
	cfg   *ctl.Config
	store keyring.KeyStore
	close func()
}

func load(path string) *env {
	cfg, err := ctl.LoadConfig(path)
	if err != nil {
		die("%v", err)
	}
	e := &env{cfg: cfg, close: func() {}}
	switch cfg.KeyStore.Kind {
	case "tpm":
		d, err := tpmkey.OpenDev(cfg.KeyStore.TPMPath)
		if err != nil {
			die("open %s: %v", cfg.KeyStore.TPMPath, err)
		}
		e.store = keyring.TPMStore{T: d}
		e.close = func() { d.Close() }
	case "dir":
		if cfg.KeyStore.Dir == "" {
			die("keystore.dir required")
		}
		logf("WARNING: software keys in %s (development only; private keys are on disk)", cfg.KeyStore.Dir)
		e.store = keyring.DirStore{Dir: cfg.KeyStore.Dir}
	default:
		die("keystore.kind %q (tpm|dir)", cfg.KeyStore.Kind)
	}
	return e
}

func cmdInitKeys(args []string) {
	fs := flag.NewFlagSet("init-keys", flag.ExitOnError)
	cp := fs.String("config", "", "config file")
	fs.Parse(args)
	e := load(*cp)
	defer e.close()
	a, s, err := e.cfg.Handles()
	if err != nil {
		die("%v", err)
	}
	r, err := keyring.Init(e.store, e.cfg.KeyringState, a, s, e.cfg.RingConfig(), nil)
	if err != nil {
		die("init: %v", err)
	}
	printJSON(r.Snapshot())
	pub := &jwks.Publisher{Dir: e.cfg.JWKSDir, Issuer: e.cfg.Issuer}
	if _, err := pub.Publish(r.JWKS()); err != nil {
		die("publish: %v", err)
	}
	logf("keyring initialised; JWKS written under %s/.well-known", e.cfg.JWKSDir)
}

func openRing(e *env) *keyring.Ring {
	r, err := keyring.Open(e.store, e.cfg.KeyringState, e.cfg.RingConfig(), nil)
	if err != nil {
		die("keyring: %v", err)
	}
	return r
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cp := fs.String("config", "", "config file")
	every := fs.Duration("housekeep", time.Minute, "housekeeping interval (auto-retire)")
	fs.Parse(args)
	e := load(*cp)
	defer e.close()
	ring := openRing(e)
	seq, f, err := sts.OpenSeqLogFile(e.cfg.SeqLog)
	if err != nil {
		die("seq log: %v", err)
	}
	defer f.Close()
	iss, err := issuer.New(e.cfg.IssuerConfig(), ring, seq, nil)
	if err != nil {
		die("%v", err)
	}
	fe, err := e.cfg.BuildFrontend()
	if err != nil {
		die("%v", err)
	}
	s := &ctl.Server{FE: fe, Iss: iss, Ring: ring, Pub: &jwks.Publisher{Dir: e.cfg.JWKSDir, Issuer: e.cfg.Issuer}, Log: logf}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, kid := ring.Active()
	logf("yard-ctl serve: iss=%s active kid=%s last seq=%d", e.cfg.Issuer, kid, seq.Last())
	if err := s.Run(ctx, *every); err != nil {
		die("serve: %v", err)
	}
}

func cmdKeys(args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	cp := fs.String("config", "", "config file")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die("keys: want one of status|jwks|rotate|retire")
	}
	e := load(*cp)
	defer e.close()
	if e.cfg.Frontend.Kind == "unix" || e.cfg.Frontend.Kind == "" {
		if c, err := net.Dial("unix", e.cfg.Frontend.Path); err == nil {
			c.Close()
			die("yard-ctl serve is running on %s: use `yard-ctl admin` instead (one TPM client at a time)", e.cfg.Frontend.Path)
		}
	}
	r := openRing(e)
	pub := &jwks.Publisher{Dir: e.cfg.JWKSDir, Issuer: e.cfg.Issuer}
	switch fs.Arg(0) {
	case "status":
		printJSON(r.Snapshot())
	case "jwks":
		printJSON(r.JWKS())
	case "rotate", "retire":
		var err error
		if fs.Arg(0) == "rotate" {
			err = r.Rotate()
		} else {
			err = r.Retire()
		}
		if err != nil {
			die("%s: %v", fs.Arg(0), err)
		}
		if _, err := pub.Publish(r.JWKS()); err != nil {
			die("publish: %v", err)
		}
		printJSON(r.Snapshot())
	default:
		die("keys: unknown action %q", fs.Arg(0))
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func unixClient(sock string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
}

func call(sock, method, path string, body any) []byte {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://yard-ctl"+path, rd)
	resp, err := unixClient(sock).Do(req)
	if err != nil {
		die("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		die("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return b
}

func cmdMint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	sock := fs.String("sock", "/var/run/yard-ctl.sock", "yard-ctl socket")
	var r issuer.Request
	kind := fs.String("kind", "external", "external|internal")
	fs.StringVar(&r.Audience, "aud", "", "audience")
	fs.StringVar(&r.User, "user", "", "user (tailnet login)")
	fs.StringVar(&r.Workload.Harness, "harness", "", "harness")
	fs.StringVar(&r.Workload.Policy, "policy", "", "policy class")
	fs.StringVar(&r.Workload.Node, "node", "", "node")
	fs.StringVar(&r.Workload.Sandbox, "sandbox", "", "sandbox id")
	fs.StringVar(&r.Workload.Run, "run", "", "run id")
	fs.StringVar(&r.Approval, "apv", "", "approval id")
	fs.IntVar(&r.TTL, "ttl", 0, "ttl seconds (0 = default)")
	full := fs.Bool("json", false, "print the whole response, not just the token")
	fs.Parse(args)
	r.Kind = issuer.Kind(*kind)
	b := call(*sock, "POST", "/v1/mint", &r)
	if *full {
		fmt.Print(string(b))
		return
	}
	var t issuer.Token
	if err := json.Unmarshal(b, &t); err != nil {
		die("%v", err)
	}
	fmt.Println(t.Token)
}

func cmdAdmin(args []string) {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	sock := fs.String("sock", "/var/run/yard-ctl.sock", "yard-ctl socket")
	fs.Parse(args)
	switch fs.Arg(0) {
	case "keys":
		fmt.Print(string(call(*sock, "GET", "/v1/keys", nil)))
	case "rotate":
		fmt.Print(string(call(*sock, "POST", "/v1/admin/rotate", nil)))
	case "retire":
		fmt.Print(string(call(*sock, "POST", "/v1/admin/retire", nil)))
	default:
		die("admin: want keys|rotate|retire")
	}
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	jf := fs.String("jwks", "", "JWKS file")
	iss := fs.String("iss", "", "required issuer")
	aud := fs.String("aud", "", "required audience")
	tok := fs.String("token", "-", "token, or - for stdin")
	fs.Parse(args)
	b, err := os.ReadFile(*jf)
	if err != nil {
		die("%v", err)
	}
	var set sts.JWKS
	if err := json.Unmarshal(b, &set); err != nil {
		die("jwks: %v", err)
	}
	t := *tok
	if t == "-" {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		if !sc.Scan() {
			die("no token on stdin")
		}
		t = strings.TrimSpace(sc.Text())
	}
	claims, err := sts.Verify(t, set, sts.VerifyOptions{Issuer: *iss, Audience: *aud, MaxTTL: sts.HardMaxTTL, Now: time.Now()})
	if err != nil {
		die("verify: %v", err)
	}
	printJSON(claims)
}
