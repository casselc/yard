package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"yard/internal/frontend"
	"yard/internal/issuer"
	"yard/internal/jwks"
	"yard/internal/keyring"
	"yard/internal/sts"
)

type harness struct {
	sock, dir string
	ring      *keyring.Ring
	cancel    context.CancelFunc
	done      chan error
	logs      *lockedBuf
}

func start(t *testing.T, roles []string) *harness {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes: keep it short.
	dir, err := os.MkdirTemp("", "yc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	st := keyring.NewMemStore()
	st.Bits = 1024
	ring, err := keyring.Init(st, filepath.Join(dir, "k.json"), 0x81010010, 0x81010011, keyring.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, f, err := sts.OpenSeqLogFile(filepath.Join(dir, "mint.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	iss, err := issuer.New(issuer.Config{Issuer: "https://id.example.org/yard", TrustDomain: "home.arpa",
		ExternalAudiences: []string{"sts.amazonaws.com"}, InternalAudiences: []string{"yard"}}, ring, seq, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{sock: filepath.Join(dir, "s"), dir: dir, ring: ring, logs: &lockedBuf{}, done: make(chan error, 1)}
	fe := &frontend.Unix{Path: h.sock, Users: map[uint32]frontend.Caller{uint32(os.Getuid()): {Name: "me", Roles: roles}}}
	s := &Server{FE: fe, Iss: iss, Ring: ring, Pub: &jwks.Publisher{Dir: filepath.Join(dir, "pub"), Issuer: "https://id.example.org/yard"},
		Log: func(f string, a ...any) { h.logs.add(fmt.Sprintf(f, a...) + "\n") }}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- s.Run(ctx, 20*time.Millisecond) }()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", h.sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *harness) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", h.sock)
	}}}
	req, _ := http.NewRequest(method, "http://x"+path, rd)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

var mintReq = issuer.Request{Kind: issuer.External, Audience: "sts.amazonaws.com", User: "chuck",
	Workload: issuer.WorkloadID{Harness: "h", Policy: "p", Node: "n", Sandbox: "s", Run: "r"}}

func TestServeMintVerifyAgainstPublishedFile(t *testing.T) {
	h := start(t, []string{"mint", "admin"})
	code, b := h.do(t, "POST", "/v1/mint", mintReq)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var tok issuer.Token
	json.Unmarshal(b, &tok)
	// verify against the JWKS file the server published (what a static host would serve)
	jb, err := os.ReadFile(filepath.Join(h.dir, "pub/.well-known/jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set sts.JWKS
	json.Unmarshal(jb, &set)
	if _, err := sts.Verify(tok.Token, set, sts.VerifyOptions{Issuer: "https://id.example.org/yard", Audience: "sts.amazonaws.com", Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// discovery doc over HTTP
	code, b = h.do(t, "GET", "/.well-known/openid-configuration", nil)
	var d jwks.Discovery
	json.Unmarshal(b, &d)
	if code != 200 || d.JWKSURI != "https://id.example.org/yard/.well-known/jwks.json" || d.Issuer != "https://id.example.org/yard" {
		t.Fatalf("%d %+v", code, d)
	}
	if bytes.Contains(h.logs.get(), []byte(tok.Token[:20])) {
		t.Fatal("token logged")
	}
}

func TestRotateRepublishesAndAutoRetires(t *testing.T) {
	h := start(t, []string{"mint", "admin"})
	before := h.ring.JWKS()
	code, b := h.do(t, "POST", "/v1/admin/rotate", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	// RetireGrace is 0 in this test, so the housekeeping ticker retires within a few ticks
	deadline := time.Now().Add(3 * time.Second)
	for {
		jb, _ := os.ReadFile(filepath.Join(h.dir, "pub/.well-known/jwks.json"))
		var set sts.JWKS
		json.Unmarshal(jb, &set)
		if len(set.Keys) == 2 && set.Keys[0].Kid == before.Keys[1].Kid && set.Keys[1].Kid != before.Keys[0].Kid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("published jwks never reached [B, A'] : %s", jb)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRolesEnforced(t *testing.T) {
	h := start(t, []string{"mint"})
	if code, _ := h.do(t, "POST", "/v1/admin/rotate", nil); code != http.StatusForbidden {
		t.Fatalf("rotate without admin: %d", code)
	}
	if code, _ := h.do(t, "POST", "/v1/mint", mintReq); code != 200 {
		t.Fatalf("mint: %d", code)
	}
	bad := mintReq
	bad.TTL = 3600
	if code, _ := h.do(t, "POST", "/v1/mint", bad); code != http.StatusForbidden {
		t.Fatalf("ttl 3600: %d", code)
	}
	if code, _ := h.do(t, "POST", "/v1/mint", map[string]any{"kind": "external", "bogus": 1}); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
}

func TestNoPeerCredsRejected(t *testing.T) {
	fe := &frontend.Unix{Users: map[uint32]frontend.Caller{1: {Name: "other"}}}
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), struct{}{}, 0))
	if _, err := fe.Identify(req); err == nil {
		t.Fatal("request without peer creds identified")
	}
}

func TestConfigExampleParses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(`{"issuer":"https://i","trust_domain":"home.arpa","external_audiences":["a"],
	 "max_ttl":"5m","keystore":{"kind":"dir","dir":"/x"},"active_handle":"0x81010010","standby_handle":"0x81010011",
	 "publish_delay":"2h","frontend":{"kind":"unix","path":"/s","mode":"0600","users":{"1001":{"name":"c","roles":["mint"]}}}}`), 0o600)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	a, s, err := c.Handles()
	if err != nil || a != 0x81010010 || s != 0x81010011 {
		t.Fatal(a, s, err)
	}
	if c.RingConfig().PublishDelay != 2*time.Hour || c.RingConfig().RetireGrace != keyring.DefaultConfig.RetireGrace {
		t.Fatal(c.RingConfig())
	}
	fe, err := c.BuildFrontend()
	if err != nil {
		t.Fatal(err)
	}
	if u := fe.(*frontend.Unix); u.Mode != 0o600 || u.Users[1001].Name != "c" {
		t.Fatalf("%+v", u)
	}
	os.WriteFile(p, []byte(`{"issuer":"x","typo_field":1}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown field accepted")
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) add(s string) { l.mu.Lock(); l.b.WriteString(s); l.mu.Unlock() }
func (l *lockedBuf) get() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}

func TestUnmappedUidGets401(t *testing.T) {
	h := start(t, []string{"mint"})
	_ = h
	// a second server whose map does not contain our uid
	dir, _ := os.MkdirTemp("", "yc")
	defer os.RemoveAll(dir)
	fe := &frontend.Unix{Path: filepath.Join(dir, "s"), Users: map[uint32]frontend.Caller{uint32(os.Getuid()) + 1: {Name: "other", Roles: []string{"mint"}}}}
	s := &Server{FE: fe, Ring: h.ring, Pub: &jwks.Publisher{Issuer: "i"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, time.Hour) }()
	defer func() { cancel(); <-done }()
	h2 := &harness{sock: fe.Path}
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", h2.sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _ := h2.do(t, "POST", "/v1/mint", mintReq); code != http.StatusUnauthorized {
		t.Fatalf("unmapped uid: %d", code)
	}
}
