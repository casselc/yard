package broker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- F1 identity over time --------------------------------------------

// A keep-alive connection accepted for sandbox A must not carry requests
// once the address is reallocated to sandbox B.
func TestKeepAliveAcrossReplacement(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	send := func() (*http.Response, error) {
		io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nContent-Length: 2\r\n\r\n{}")
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		return http.ReadResponse(br, nil)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// the address now belongs to another sandbox
	if err := e.update(func(ls []Link) []Link {
		ls[0].Incarnation, ls[0].Workload = incOf("sx-0001"), workload("sx")
		return ls
	}); err != nil {
		t.Fatal(err)
	}
	if resp, err := send(); err == nil {
		resp.Body.Close()
		t.Fatalf("the old connection was still open after the replacement (status %d)", resp.StatusCode)
	}
	hs := halo.headers()
	if len(hs) != 1 || hs[0].Get("X-Halo-Principal") != e.principal("sa") {
		t.Fatalf("halo saw %d requests", len(hs))
	}
	// a new connection is the new allocation's
	resp2 := e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	resp2.Body.Close()
	if got := halo.headers()[1].Get("X-Halo-Principal"); got != e.principal("sx") {
		t.Fatalf("new connection served as %q", got)
	}
}

// A request on a connection tagged with an older incarnation is refused
// even if the connection survived (the second fence behind the close).
func TestStaleConnectionRefused(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	l := e.reg.S.Links[0]
	e.b.mu.Lock()
	oldLs := e.b.servers[l.Addr]
	e.b.mu.Unlock()
	if err := e.update(func(ls []Link) []Link { ls[0].Incarnation = incOf("sa-2"); return ls }); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://inference.yard/v1/responses", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:5555"
	ctx := context.WithValue(r.Context(), keyListener, l.Addr)
	ctx = context.WithValue(ctx, keyConn, &trackedConn{ls: oldLs, b: e.b})
	w := httptest.NewRecorder()
	e.b.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != 403 || len(halo.headers()) != 0 {
		t.Fatalf("stale connection: %d, halo %d", w.Code, len(halo.headers()))
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "stale_connection" })
}

func TestIMDSTokenDiesWithAllocation(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	tok := e.imdsToken("sa")
	if err := e.update(func(ls []Link) []Link { ls[0].Incarnation = incOf("sa-0002"); return ls }); err != nil {
		t.Fatal(err)
	}
	r := e.req("sa", "GET", "169.254.169.254", credPrefix+"/yard-task", "")
	r.Header.Set("X-aws-ec2-metadata-token", tok)
	if st := e.status(r); st != 401 {
		t.Fatalf("a token of the previous allocation was accepted: %d", st)
	}
}

// --- F2 control-state freshness ---------------------------------------

func TestRegistryRefusesRegressions(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	good := e.reg.S
	expect := func(reason string, sn Snapshot) {
		t.Helper()
		e.reg.S = sn
		if err := e.b.Sync(context.Background(), true); err == nil || !strings.Contains(err.Error(), reason) {
			t.Fatalf("%s: %v", reason, err)
		}
		e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "registry" && ev.Reason == reason })
	}
	// move to epoch 3, serial 2
	if err := e.update(func(ls []Link) []Link { ls[0].Epoch = 3; return ls }); err != nil {
		t.Fatal(err)
	}
	cur := e.reg.S
	older := good
	older.Issued = time.Now()
	expect("regression", older) // serial 1 < 2
	same := cur
	same.Links = append([]Link(nil), cur.Links...)
	same.Links[0].Session = "other"
	expect("unverified_replay", same) // serial 2 with other content
	low := cur
	low.Serial, low.Issued = 9, time.Now()
	low.Links = append([]Link(nil), cur.Links...)
	low.Links[0].Epoch = 2
	expect("epoch_regression", low)
	stale := cur
	stale.Serial, stale.Issued = 10, time.Now().Add(-time.Hour)
	expect("stale", stale)
	future := cur
	future.Serial, future.Issued = 11, time.Now().Add(time.Hour)
	expect("future", future)
	// removing the link retires its incarnation; it can never come back
	e.reg.S = Snapshot{Serial: 12, Issued: time.Now()}
	if err := e.b.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	back := cur
	back.Serial, back.Issued = 13, time.Now()
	expect("resurrected", back)
	// nothing above reached halo through a refused snapshot
	if st := e.tryStatus(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st == 200 {
		t.Fatal("served after the link was removed")
	}
}

// The floors survive a restart: a new broker on the same floor store
// refuses the snapshot an old writer replays.
func TestFloorsPersistAcrossRestart(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	if err := e.update(func(ls []Link) []Link { ls[0].Epoch = 5; return ls }); err != nil {
		t.Fatal(err)
	}
	_ = e.b.Close()
	reg := &StaticRegistry{S: Snapshot{Serial: 1, Issued: time.Now(), Links: e.reg.S.Links}}
	reg.S.Links[0].Epoch = 1
	d := testDeps()
	d.Registry, d.Floors = reg, e.floors
	b2, err := New(Config{TrustDomain: "home.arpa", AllowLoopback: true}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if err := b2.Sync(context.Background(), true); err == nil {
		t.Fatal("a restarted broker applied a replayed older snapshot")
	}
	reg.S.Serial = 7
	if err := b2.Sync(context.Background(), true); err == nil || !strings.Contains(err.Error(), "epoch_regression") {
		t.Fatalf("a restarted broker accepted a lower epoch: %v", err)
	}
	// a floor store that cannot save blocks the apply
	e.floors.Err = errors.New("disk full")
	reg.S.Links[0].Epoch, reg.S.Serial = 6, 8
	if err := b2.Sync(context.Background(), true); err == nil || !strings.Contains(err.Error(), "floors_unsaved") {
		t.Fatalf("applied without persisting floors: %v", err)
	}
	// a corrupt floor file stops the start
	if _, err := (FileFloors{Path: writeTemp(t, "{not json")}).Load(); err == nil {
		t.Fatal("corrupt floors loaded")
	}
}

func writeTemp(t *testing.T, s string) string {
	p := t.TempDir() + "/f.json"
	if err := osWriteFile(p, s); err != nil {
		t.Fatal(err)
	}
	return p
}

// Without a fresh snapshot within the lease, every link stops being served
// and credentials are fenced; a fresh snapshot restores service.
func TestRegistryLeaseExpires(t *testing.T) {
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	cfg.RegistryLease = 300 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"})
	if _, m := e.ecs("sa"); m["AccessKeyId"] == "" {
		t.Fatal("no credential")
	}
	e.reg.Err = errors.New("unreadable")
	_ = e.b.Sync(context.Background(), true)
	time.Sleep(350 * time.Millisecond)
	_ = e.b.Sync(context.Background(), true)
	if st := e.tryStatus(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st == 200 {
		t.Fatalf("served past the registry lease: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "registry" && ev.Reason == "lease_expired" })
	e.reg.Err = nil
	e.reg.Set(e.reg.S.Links)
	if err := e.b.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if st := e.status(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st != 200 {
		t.Fatalf("not restored: %d", st)
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("%d mints", n)
	}
	if _, m := e.ecs("sa"); m["AccessKeyId"] == "" || e.minter.n.Load() != 2 {
		t.Fatal("the credential held before the lease expired was served again")
	}
}

// Every entry in a conflict is invalid: the first one listed does not win.
func TestConflictingEntriesAllInvalid(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa", "sb"})
	err := e.update(func(ls []Link) []Link {
		ls[1].Workload = ls[0].Workload // the same principal on two links
		ls[1].Incarnation = incOf("dup-0001")
		return ls
	})
	if err == nil {
		t.Fatal("conflict not reported")
	}
	for _, s := range []string{"sa", "sb"} {
		c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
		if resp, err := c.Do(e.req(s, "POST", "inference.yard", "/v1/responses", `{}`)); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				t.Fatalf("%s served while its principal was listed twice", s)
			}
		}
	}
}

func TestSyncAfterCloseDoesNothing(t *testing.T) {
	reg := &StaticRegistry{}
	d := testDeps()
	d.Registry = reg
	opened := 0
	d.Listen = func(a netip.AddrPort) (net.Listener, error) { opened++; return net.Listen("tcp", "127.0.0.1:0") }
	b, err := New(Config{TrustDomain: "home.arpa", AllowLoopback: true}, d)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	reg.Set([]Link{{Addr: netip.MustParseAddrPort("127.0.0.2:8099"), Incarnation: incOf("sa-0001"),
		Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Workload: workload("sa"), Epoch: 1, Class: ClassOwnCode}})
	if err := b.Sync(context.Background(), true); !errors.Is(err, ErrClosed) || opened != 0 {
		t.Fatalf("Sync after Close: %v, %d listeners", err, opened)
	}
}

// Concurrent Syncs are serialized (run under -race).
func TestConcurrentSyncs(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	var mu sync.Mutex
	reg := &countingRegistry{base: e.reg.S}
	e.b.deps.Registry = reg
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			mu.Unlock()
			_ = e.b.Sync(context.Background(), true)
		}()
	}
	wg.Wait()
	if e.b.floors.Serial < 2 {
		t.Fatalf("serial %d", e.b.floors.Serial)
	}
}

type countingRegistry struct {
	mu   sync.Mutex
	base Snapshot
	n    uint64
}

func (c *countingRegistry) Snapshot(context.Context) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	s := c.base
	s.Serial, s.Issued = c.base.Serial+c.n, time.Now()
	s.Links = append([]Link(nil), c.base.Links...)
	return s, nil
}

// --- F3 credential atomicity ------------------------------------------

func TestRevokeBetweenSelectionAndCommit(t *testing.T) {
	e := mdEnv(t, MetadataConfig{})
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatal(st)
	}
	var once sync.Once
	testHookBeforeCommit.Store(ptr(func() { once.Do(func() { e.b.Revoke(e.principal("sa")) }) }))
	defer func() { testHookBeforeCommit.Store(nil) }()
	if st, m := e.ecs("sa"); st != 503 {
		t.Fatalf("a credential selected before the revoke was committed after it: %d %v", st, m["AccessKeyId"])
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "credential_fenced" })
}

// A request that still carries the old epoch fails without touching the
// credential of the new epoch.
func TestStaleRequestDoesNotTouchNewerCredential(t *testing.T) {
	e := mdEnv(t, MetadataConfig{})
	old := e.reg.S.Links[0]
	if err := e.update(func(ls []Link) []Link { ls[0].Epoch = 2; return ls }); err != nil {
		t.Fatal(err)
	}
	_, m := e.ecs("sa")
	if m["AccessKeyId"] == "" {
		t.Fatal("no epoch-2 credential")
	}
	_, err := e.b.creds.get(context.Background(), old, e.principal("sa"))
	if !errors.Is(err, errStale) {
		t.Fatalf("stale request: %v", err)
	}
	_, m2 := e.ecs("sa")
	if m2["AccessKeyId"] != m["AccessKeyId"] || e.minter.n.Load() != 1 {
		t.Fatal("the stale request disturbed the current credential")
	}
}

// --- F4 mint settlement -----------------------------------------------

// A minter that ignores cancellation is settled by the store at the fence
// (JWT exp + skew); its late answer is never adopted; the next mint starts
// after the fence.
func TestMinterIgnoringCancellationIsFenced(t *testing.T) {
	e := mdEnv(t, MetadataConfig{Skew: 50 * time.Millisecond, MintWait: 50 * time.Millisecond})
	release := make(chan struct{})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if !req.Begin(time.Now().Add(200 * time.Millisecond)) {
			return Credential{}, ErrNotSent
		}
		<-release // ignores ctx
		return validCred(req), nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatal(st)
	}
	if st, _ := e.ecs("sa"); st != 503 || e.minter.n.Load() != 1 {
		t.Fatalf("second mint before the fence")
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Detail == "no_answer_by_fence" })
	close(release) // the late answer arrives
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "late_answer_discarded" })
	e.minter.set(nil)
	if st, _ := e.ecs("sa"); st != 200 || e.minter.n.Load() != 2 {
		t.Fatalf("after the fence: %d, %d mints", st, e.minter.n.Load())
	}
}

func TestBeginRules(t *testing.T) {
	e := mdEnv(t, MetadataConfig{PrepareTimeout: 100 * time.Millisecond, MintWait: 300 * time.Millisecond})
	refused := make(chan bool, 1)
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		time.Sleep(150 * time.Millisecond) // the STS JWT took too long
		ok := req.Begin(time.Now().Add(time.Minute))
		refused <- !ok
		return Credential{}, ErrNotSent
	})
	e.ecs("sa")
	if !<-refused {
		t.Fatal("Begin accepted after the prepare timeout")
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Detail == "prepare_timeout" && ev.Outcome == "not_done" })
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		ok := req.Begin(time.Now().Add(time.Hour)) // a JWT that lives an hour
		refused <- !ok
		return Credential{}, ErrNotSent
	})
	e.ecs("sa")
	if !<-refused {
		t.Fatal("Begin accepted a JWT exp beyond the lifetime bound")
	}
}

func TestCloseJoinsMintWorkers(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: 20 * time.Millisecond})
	stuck := make(chan struct{})
	defer close(stuck)
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		<-ctx.Done() // honours cancellation
		return Credential{}, ctx.Err()
	})
	e.ecs("sa")
	if err := e.b.creds.close(2 * time.Second); err != nil {
		t.Fatalf("close with a cooperative minter: %v", err)
	}
	e2 := mdEnv(t, MetadataConfig{MintWait: 20 * time.Millisecond})
	e2.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		<-stuck // ignores cancellation
		return Credential{}, errors.New("late")
	})
	e2.ecs("sa")
	if err := e2.b.creds.close(100 * time.Millisecond); err == nil {
		t.Fatal("close did not report a minter ignoring cancellation")
	}
}

// After a restart the broker has no record of a mint whose answer was
// lost; the control plane's slot ownership (one JWT per grant and slot)
// refuses the new attempt, and the broker holds until the slot turns.
func TestSlotSpentAfterRestartHolds(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: 50 * time.Millisecond})
	at := time.Now().Add(400 * time.Millisecond)
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		return Credential{}, &RetryLaterError{At: at}
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatal(st)
	}
	e.ecs("sa")
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("%d mints before the slot turned", n)
	}
	time.Sleep(time.Until(at) + 20*time.Millisecond)
	e.minter.set(nil)
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatal(st)
	}
}

func TestMintFencedWhenLinkRemoved(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: 50 * time.Millisecond})
	release := make(chan struct{})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		<-release
		return validCred(req), nil
	})
	e.ecs("sa")
	if err := e.update(func([]Link) []Link { return nil }); err != nil {
		t.Fatal(err)
	}
	close(release)
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "mint" && ev.AccessKey != "" })
	if ev.Decision == "allow" || (ev.Reason != "fenced" && ev.Reason != "link_gone") {
		t.Fatalf("a mint for a removed link was adopted: %+v", ev)
	}
}
