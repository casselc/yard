//go:build linux

// yard-agentd is yard-ctl's agent executor (internal/agentexec) as a process: the operation envelope for api
// "agent" on -listen, the attempts' durable stages over -state, VMs through yard-node's socket, model calls through
// in-process broker routes to halo. (It folds into yard-ctl later; the broker's routes into yard-broker.)
//
//	yard-agentd -state DIR -node-sock SOCK -alloc-root DIR -repo fixture=/path/to/repo -valuation val.json
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"yard/internal/agentexec"
	"yard/internal/haloop"
	"yard/internal/ledger"
	"yard/internal/yardtime"
)

type repoFlags map[string]string

func (r repoFlags) String() string { return "" }
func (r repoFlags) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	if !ok {
		return flag.ErrHelp
	}
	r[name] = path
	return nil
}

func main() {
	P := "/work/platform"
	state := flag.String("state", P+"/agentd", "the executor's store, ledger, artifacts and images")
	listen := flag.String("listen", "127.0.0.1:18200", "the envelope's address")
	keyFile := flag.String("api-key-file", "", "bearer key callers must present (empty: none, loopback only)")
	nodeSock := flag.String("node-sock", P+"/agent-node/node.sock", "yard-node's socket")
	allocRoot := flag.String("alloc-root", P+"/agent-node/allocs", "yard-node's allocation directory")
	halo := flag.String("halo", "http://127.0.0.1:18080", "halo base URL")
	haloKey := flag.String("halo-key-file", P+"/configs/halo-api-key", "halo API key file")
	valFile := flag.String("valuation", "", "the operator's valuation (JSON: {routes: {...}}); its digest is computed")
	kernel := flag.String("kernel", P+"/firecracker/guest/vmlinux-6.1.155", "guest kernel")
	rootfs := flag.String("rootfs", P+"/firecracker/images/review-agent.ext4", "harness image")
	model := flag.String("model", "claude-sonnet-5-5", "model name the harness asks for")
	vcpu := flag.Int64("vcpu", 2, "VM vCPUs")
	mem := flag.Int64("mem", 2048, "VM memory (MiB)")
	maxOut := flag.Int64("max-out", 16384, "per-call output cap")
	maxRunning := flag.Int("max-running", 3, "attempts running at once")
	ceilTokens := flag.Int64("ceiling-tokens", 2_000_000, "token ceiling")
	ceilCharge := flag.Int64("ceiling-charge", 10_000_000, "charge ceiling (valuation units)")
	ceilMoney := flag.Int64("ceiling-money", 0, "money ceiling (µUSD); the local route spends none")
	ceilSeconds := flag.Int64("ceiling-seconds", 3600, "wall-time ceiling")
	startBound := flag.Duration("start-bound", 30*time.Second, "a start still absent after this is tombstoned (F3)")
	unreachable := flag.Duration("unreachable-bound", 30*time.Second, "a node unreachable this long fences its worker (F4)")
	leaseMs := flag.Int64("lease-ms", 60000, "allocation lease yard-node's watchdog enforces (F8)")
	retention := flag.Duration("retention", 7*24*time.Hour, "artifacts' retention floor")
	repos := repoFlags{}
	flag.Var(repos, "repo", "a registered repository, name=path (repeatable)")
	flag.Parse()
	logger := log.New(os.Stderr, "yard-agentd ", log.LstdFlags|log.Lmicroseconds)
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/sbin:/sbin")

	if err := os.MkdirAll(*state, 0o700); err != nil {
		logger.Fatal(err)
	}
	st, err := agentexec.OpenStore(filepath.Join(*state, "exec.db"))
	if err != nil {
		logger.Fatal(err)
	}
	l, err := ledger.Open(filepath.Join(*state, "ledger.db"))
	if err != nil {
		logger.Fatal(err)
	}
	clock, err := yardtime.Open(st.DB())
	if err != nil {
		logger.Fatal(err)
	}
	vraw, err := os.ReadFile(*valFile)
	if err != nil {
		logger.Fatalf("valuation: %v", err)
	}
	var val ledger.Valuation
	if err := json.Unmarshal(vraw, &val); err != nil {
		logger.Fatalf("valuation: %v", err)
	}
	canon, _ := json.Marshal(val.Routes) // the digest is over the price table itself
	sum := sha256.Sum256(canon)
	val.Digest = "sha256:" + hex.EncodeToString(sum[:16])
	hk, err := os.ReadFile(*haloKey)
	if err != nil {
		logger.Fatal(err)
	}
	apiKey := ""
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			logger.Fatal(err)
		}
		apiKey = strings.TrimSpace(string(b))
	}
	hc := haloop.Client{Base: *halo, Key: strings.TrimSpace(string(hk))}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	k, err := hc.Contract(ctx)
	mode := "relaxed"
	if err == nil {
		mode = k.Inference.Mode
	} else {
		logger.Printf("halo contract: %v (assuming relaxed)", err)
	}
	ex := agentexec.New(ctx, agentexec.Config{Store: st, Clock: clock, Ledger: l, Halo: hc, HaloMode: mode,
		Node: agentexec.NewNodeClient(*nodeSock), AllocRoot: *allocRoot,
		ArtifactDir: filepath.Join(*state, "artifacts"), ImageDir: filepath.Join(*state, "images"), Repos: repos,
		Valuations: map[string]ledger.Valuation{val.Digest: val}, Current: val.Digest,
		Ceilings: agentexec.Limits{Tokens: *ceilTokens, Charge: *ceilCharge, Money: *ceilMoney, Seconds: *ceilSeconds},
		Kernel:   *kernel, Rootfs: *rootfs, VCPU: *vcpu, MemMiB: *mem, Model: *model, MaxOut: *maxOut, MinOut: 256,
		OutputCap: 64 << 20, StartBound: *startBound, UnreachableBound: *unreachable, Tick: 500 * time.Millisecond,
		LeaseMs: *leaseMs, MaxRunning: *maxRunning, MaxSubmitAgeMs: 600_000, RetentionMs: retention.Milliseconds(),
		Logf: logger.Printf})
	if err := ex.Start(); err != nil {
		logger.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: ex.Handler(apiKey), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	logger.Printf("serving %s; incarnation %s; valuation %s; repos %v", *listen, st.Inc, val.Digest, repos)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal(err)
	}
	ex.Wait()
}
