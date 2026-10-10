package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	nip "net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- R1: listener generations -----------------------------------------

// pauseAccept blocks the accept loop on its first accepted connection
// until release is closed.
func pauseAccept(t *testing.T) (paused chan struct{}, release chan struct{}) {
	paused, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	testHookAccepted.Store(ptr(func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(paused)
			<-release
		}
	}))
	t.Cleanup(func() { testHookAccepted.Store(nil) })
	return paused, release
}

// A connection accepted for allocation A whose tagging is paused while the
// address is reallocated to B is closed, never tagged with B; so is a
// connection waiting in the old listener's backlog. A new connection is B's.
func TestAcceptPausedAcrossReallocation(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	paused, release := pauseAccept(t)
	addr := strings.TrimPrefix(e.urls["sa"], "http://")
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	<-paused
	c2, err := net.Dial("tcp", addr) // completes the handshake into the backlog
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	e.b.mu.Lock()
	oldLs := e.b.servers[e.reg.S.Links[0].Addr]
	e.b.mu.Unlock()
	synced := make(chan error, 1)
	go func() {
		synced <- e.update(func(ls []Link) []Link {
			ls[0].Incarnation, ls[0].Workload = incOf("sx-1"), workload("sx")
			return ls
		})
	}()
	// Sync has detached the old generation (and now waits for its accept
	// loop); only then does the paused accept resume
	for deadline := time.Now().Add(3 * time.Second); ; {
		e.b.mu.Lock()
		dead := oldLs.dead
		e.b.mu.Unlock()
		if dead {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Sync did not detach the old listener")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	for i, c := range []net.Conn{c1, c2} {
		io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nContent-Length: 2\r\n\r\n{}")
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
			resp.Body.Close()
			t.Fatalf("connection %d of the old allocation got an answer (%d)", i+1, resp.StatusCode)
		}
	}
	if n := len(halo.headers()); n != 0 {
		t.Fatalf("halo saw %d requests from old-allocation connections", n)
	}
	testHookAccepted.Store(nil)
	if st := e.status(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st != 200 {
		t.Fatalf("the new allocation is not served on its new listener: %d", st)
	}
	if got := halo.headers()[0].Get("X-Halo-Principal"); got != e.principal("sx") {
		t.Fatalf("served as %q", got)
	}
}

// Replacing an attached server with live connections does not deadlock.
func TestReplaceAttachedServerNoDeadlock(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nContent-Length: 2\r\n\r\n{}")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() // the connection stays open (keep-alive) and tracked
	l := e.reg.S.Links[0]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := e.b.attach(ln, l.Addr, l.Incarnation); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attach deadlocked closing the old server's connections")
	}
}

// --- R2/R4/R12: floors ------------------------------------------------

type failAt string

func opsFailing(step failAt) *floorOps {
	o := defaultFloorOps
	boom := errors.New("injected " + string(step) + " failure")
	switch step {
	case "create":
		o.createTemp = func(string) (*os.File, error) { return nil, boom }
	case "write":
		o.write = func(*os.File, []byte) error { return boom }
	case "fsync":
		o.syncFile = func(*os.File) error { return boom }
	case "rename":
		o.rename = func(string, string) error { return boom }
	case "dirsync":
		o.syncDir = func(string) error { return boom }
	}
	return &o
}

// Every crash boundary of a save: before the rename the old floors stay
// and the error is plain; after it the new file is there but the save is
// uncertain.
func TestFloorsCrashBoundaries(t *testing.T) {
	for _, step := range []failAt{"create", "write", "fsync", "rename", "dirsync"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "floors.json")
		if err := InitFileFloors(path); err != nil {
			t.Fatal(err)
		}
		nf := NewFloors()
		nf.Serial, nf.Digest = 7, strings.Repeat("a", 64)
		err := FileFloors{Path: path, ops: opsFailing(step)}.Save(nf)
		if err == nil {
			t.Fatalf("%s: save reported success", step)
		}
		got, lerr := FileFloors{Path: path}.Load()
		if lerr != nil {
			t.Fatalf("%s: reload: %v", step, lerr)
		}
		if step == "dirsync" {
			if !errors.Is(err, ErrFloorsUncertain) || got.Serial != 7 {
				t.Fatalf("dirsync: %v, serial %d (want uncertain and the renamed file)", err, got.Serial)
			}
		} else if errors.Is(err, ErrFloorsUncertain) || got.Serial != 0 {
			t.Fatalf("%s: %v, serial %d (want a plain error and the old file)", step, err, got.Serial)
		}
		ents, _ := os.ReadDir(dir)
		if len(ents) != 1 {
			t.Fatalf("%s: temp files left: %v", step, ents)
		}
	}
}

// An uncertain save stops authorization changes until floors are durable.
func TestUncertainFloorsBlockChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "floors.json")
	if err := InitFileFloors(path); err != nil {
		t.Fatal(err)
	}
	halo := newFakeHalo(t)
	ff := FileFloors{Path: path}
	e := newEnv(t, haloCfg(halo), []string{"sa"}, func(c *Config, d *Deps) { d.Floors = &ff; d.FirstBoot = false })
	ff.ops = opsFailing("dirsync")
	err := e.update(func(ls []Link) []Link { ls[0].Epoch = 2; return ls })
	if err == nil || !strings.Contains(err.Error(), "floors_unsaved") {
		t.Fatalf("an uncertain save was applied: %v", err)
	}
	// the previous authorization continues; no change is applied
	if st := e.status(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st != 200 {
		t.Fatal(st)
	}
	e.reg.Set(e.reg.S.Links)
	if err := e.b.Sync(context.Background(), true); err == nil || !strings.Contains(err.Error(), "floors_uncertain") {
		t.Fatalf("applied while floors are uncertain: %v", err)
	}
	ff.ops = nil // the disk recovers
	e.reg.Set(e.reg.S.Links)
	if err := e.b.Sync(context.Background(), true); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if fl, _ := ff.Load(); fl.Epochs[e.principal("sa")] != 2 || fl.Serial != e.reg.S.Serial {
		t.Fatalf("recovered floors %+v", fl)
	}
}

func TestFloorsStructure(t *testing.T) {
	for _, doc := range []string{`{}`, `{"version":1}`, `{"version":2,"epochs":{},"active":{},"retired":{}}`,
		`{"version":1,"serial":3,"epochs":{},"active":{},"retired":{}}`,
		`{"version":1,"epochs":{},"active":{"short":{"addr":"10.0.0.1:1","principal":"p"}},"retired":{}}`} {
		if _, err := (FileFloors{Path: writeTemp(t, doc)}).Load(); err == nil {
			t.Errorf("floors %s accepted", doc)
		}
	}
	// a missing floors file is recovery, not first boot
	d := testDeps()
	d.FirstBoot = false
	if _, err := New(Config{TrustDomain: "home.arpa"}, d); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("missing floors: %v", err)
	}
}

func TestIncarnationFormat(t *testing.T) {
	l := Link{Addr: nip.MustParseAddrPort("10.77.0.1:8099"), Incarnation: "alloc-000001",
		Peers: []nip.Prefix{nip.MustParsePrefix("10.77.0.2/32")}}
	l.Workload, l.Class = workload("sa"), ClassOwnCode
	if err := l.validate(false); err == nil {
		t.Fatal("a sequential incarnation id accepted")
	}
	l.Incarnation = incOf("x")
	if err := l.validate(false); err != nil {
		t.Fatal(err)
	}
}

// Across a restart: an active incarnation cannot move to another sandbox,
// one removed while the broker was down is retired, and the unchanged
// snapshot is accepted again (same digest); a reused serial is not.
func TestIncarnationsAcrossRestart(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	snap := e.reg.S
	_ = e.b.Close()
	restart := func(sn Snapshot) error {
		reg := &StaticRegistry{S: sn}
		d := testDeps()
		d.Registry, d.Floors, d.FirstBoot = reg, e.floors, false
		b, err := New(Config{TrustDomain: "home.arpa", AllowLoopback: true}, d)
		if err != nil {
			return err
		}
		defer b.Close()
		return b.Sync(context.Background(), false)
	}
	if err := restart(snap); err != nil {
		t.Fatalf("the unchanged snapshot after a restart: %v", err)
	}
	other := snap
	other.Links = append([]Link(nil), snap.Links...)
	other.Links[0].Session = "changed"
	if err := restart(other); err == nil || !strings.Contains(err.Error(), "unverified_replay") {
		t.Fatalf("a reused serial with other content: %v", err)
	}
	moved := Snapshot{Serial: snap.Serial + 1, Issued: time.Now(), Links: append([]Link(nil), snap.Links...)}
	moved.Links[0].Workload = workload("sb")
	if err := restart(moved); err == nil || !strings.Contains(err.Error(), "incarnation_reused") {
		t.Fatalf("an incarnation moved to another sandbox across a restart: %v", err)
	}
	if err := restart(Snapshot{Serial: snap.Serial + 2, Issued: time.Now()}); err != nil {
		t.Fatal(err)
	}
	back := Snapshot{Serial: snap.Serial + 3, Issued: time.Now(), Links: snap.Links}
	if err := restart(back); err == nil || !strings.Contains(err.Error(), "resurrected") {
		t.Fatalf("an incarnation removed across a restart came back: %v", err)
	}
}

// --- R3: one authorization generation, monotonic deadline -------------

// The lease runs on the monotonic clock: a wall clock stepped back does not
// extend it, and an expired generation never comes back.
func TestLeaseMonotonicAndIrreversible(t *testing.T) {
	halo := newFakeHalo(t)
	clk := &fakeClock{}
	cfg := haloCfg(halo)
	cfg.RegistryLease = 400 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"}, withClock(clk))
	clk.Add(-time.Hour) // NTP steps the wall clock back
	time.Sleep(450 * time.Millisecond)
	if st := e.tryStatus(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st == 200 {
		t.Fatal("served past the lease after a backward wall-clock step")
	}
	gen := e.b.currentGen()
	if e.b.authOK(gen) {
		t.Fatal("an expired generation became valid again")
	}
}

// Lease expiry while Sync is applying: the freshness recheck right before
// publication refuses the snapshot.
func TestLeaseRecheckedBeforePublish(t *testing.T) {
	halo := newFakeHalo(t)
	clk := &fakeClock{}
	cfg := haloCfg(halo)
	cfg.RegistryLease = time.Minute
	e := newEnv(t, cfg, []string{"sa"}, withClock(clk))
	testHookBeforePublish.Store(ptr(func() { clk.Add(2 * time.Minute) })) // slow persistence/fencing
	defer func() { testHookBeforePublish.Store(nil) }()
	e.reg.Set(e.reg.S.Links)
	if err := e.b.Sync(context.Background(), true); err == nil || !strings.Contains(err.Error(), "stale_at_publish") {
		t.Fatalf("published a snapshot whose lease ran out while applying: %v", err)
	}
}

// Expiry fences only the generation it observed.
func TestExpiryFencesOnlyItsGeneration(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	old := e.b.currentGen()
	e.reg.Set(e.reg.S.Links)
	if err := e.b.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	_, m := e.ecs("sa")
	if m["AccessKeyId"] == "" {
		t.Fatal("no credential")
	}
	e.b.creds.expireGen(old) // a late expiry of the previous generation
	_, m2 := e.ecs("sa")
	if m2["AccessKeyId"] != m["AccessKeyId"] || e.minter.n.Load() != 1 {
		t.Fatal("a late expiry of an old generation fenced the current one")
	}
}

// A metadata request that waits for a mint across the lease expiry does not
// commit its credential.
func TestCommitAcrossLeaseExpiry(t *testing.T) {
	cfg := Config{RegistryLease: 300 * time.Millisecond}
	cfg.Metadata.MintWait = 2 * time.Second
	e := newEnv(t, cfg, []string{"sa"})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		time.Sleep(400 * time.Millisecond)
		return validCred(req), nil
	})
	if st, _ := e.ecs("sa"); st == 200 {
		t.Fatal("a credential was committed after the lease expired")
	}
}

// --- R5: bytes metered as they flow ------------------------------------

func TestStreamsStopAtByteBudget(t *testing.T) {
	halo := newFakeHalo(t)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := []byte("data: " + strings.Repeat("b", 8<<10) + "\n\n")
		for i := 0; i < 256; i++ { // 2 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}
	cfg := haloCfg(halo)
	cfg.Limits.BytesPerMin = 300 << 10
	e := newEnv(t, cfg, []string{"sa"})
	var wg sync.WaitGroup
	var total atomic.Int64
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}
			resp, err := c.Do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
			if err != nil {
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			total.Add(n)
		}()
	}
	wg.Wait()
	if got := total.Load(); got > 300<<10+3<<10 { // the bucket refills a little while it runs
		t.Fatalf("two concurrent streams moved %d bytes on a 300 KiB budget", got)
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Detail == "quota_exhausted" })
	if ev.Outcome != "unknown" {
		t.Fatal(ev.Outcome)
	}
}

func TestChunkedUploadStopsAtByteBudget(t *testing.T) {
	halo := newFakeHalo(t)
	var got atomic.Int64
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
	}
	cfg := haloCfg(halo)
	cfg.Limits.BytesPerMin = 200 << 10
	e := newEnv(t, cfg, []string{"sa"})
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", "")
	r.Body = io.NopCloser(strings.NewReader(strings.Repeat("u", 1<<20)))
	r.ContentLength = -1
	e.tryStatus(r)
	if got.Load() > 200<<10+2<<10 {
		t.Fatalf("halo received %d upload bytes on a 200 KiB budget", got.Load())
	}
}

// Bytes are charged when they move, so a stream the client abandons, or an
// early reply before the upload finished, is still paid for exactly.
func TestBytesChargedOnAbortAndEarlyReply(t *testing.T) {
	halo := newFakeHalo(t)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		// reply without reading the declared body
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.Repeat("r", 100<<10))
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", strings.Repeat("q", 512<<10))
	e.tryStatus(r)
	time.Sleep(100 * time.Millisecond)
	e.b.quota.mu.Lock()
	pq := e.b.quota.m[e.principal("sa")]
	in, out := pq.bytesIn, pq.bytesOut
	e.b.quota.mu.Unlock()
	if out < 100<<10 || in > 512<<10 {
		t.Fatalf("charged in=%d out=%d (want out >= 100 KiB, accounted apart from in)", in, out)
	}
}

func TestDailyCeilingsRobust(t *testing.T) {
	clk := &fakeClock{}
	q := newQuotas(Limits{RequestsPerMin: 1000, BytesPerMin: 1 << 30, CloudDailyRequests: 1, CloudDailyBytes: 1 << 30,
		CloudDailyRequestsGlobal: 1000, CloudDailyBytesGlobal: 1000}, clk.Now)
	if ok, _, _ := q.admit("p", true); !ok {
		t.Fatal("first")
	}
	clk.Add(-48 * time.Hour) // the clock steps back across midnight
	if ok, _, why := q.admit("p", true); ok {
		t.Fatalf("a clock stepped back reopened a spent day (%s)", why)
	}
	gq := newQuotas(Limits{RequestsPerMin: 1000, BytesPerMin: 1 << 30, CloudDailyRequests: 10, CloudDailyBytes: 1 << 30,
		CloudDailyRequestsGlobal: 1, CloudDailyBytesGlobal: 1 << 30}, clk.Now)
	gq.admit("a", true)
	clk.Add(-48 * time.Hour)
	if ok, _, _ := gq.admit("b", true); ok {
		t.Fatal("a clock stepped back reopened the node-wide daily ceiling")
	}
	// the node-wide daily byte ceiling binds across principals
	if n := q.take("a", true, true, 800); n != 800 {
		t.Fatal(n)
	}
	if n := q.take("b", true, true, 800); n != 200 {
		t.Fatalf("second principal got %d bytes past a 1000-byte global ceiling", n)
	}
}

// --- R6: methods, per-link admission, unread bodies --------------------

func TestRejectedMethodsAndRates(t *testing.T) {
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	cfg.Limits.LinkRequestBurst, cfg.Limits.LinkRequestsPerSec = 5, 0.001
	e := newEnv(t, cfg, []string{"sa"})
	r := e.req("sa", "SK-SECRET-METHOD-XYZ", "inference.yard", "/v1/responses", "")
	e.tryStatus(r)
	statuses := []int{}
	for i := 0; i < 6; i++ {
		statuses = append(statuses, e.tryStatus(e.req("sa", "GET", "evil.example", "/", "")))
	}
	if statuses[len(statuses)-1] != 429 {
		t.Fatalf("no per-link admission before routing: %v", statuses)
	}
	out := e.audit.String() + e.spans.String()
	if strings.Contains(out, "SK-SECRET-METHOD") || !strings.Contains(out, `"method":"OTHER"`) {
		t.Fatalf("raw method recorded:\n%s", out)
	}
}

func TestRejectedBodyClosesConnection(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// a large declared body, only a little of it sent, to a denied host
	// (small enough that net/http would otherwise wait to drain it)
	io.WriteString(c, "POST / HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 10000\r\n\r\nxx")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || !resp.Close {
		t.Fatalf("%d close=%v: a refused request's unread body must not be drained", resp.StatusCode, resp.Close)
	}
}

// --- R7: credential render bound ---------------------------------------

func TestOversizeCredentialRefused(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.SessionToken = NewSecret(strings.Repeat("t", 20<<10))
		return c, nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("a %d KiB credential response was written: %d", 20, st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "credential_oversize" })
}

// --- R8: authoritative attempt deadlines --------------------------------

// The fence passed before the answer took the lock; the timer has not run
// (it is minutes away in real time): the answer is discarded all the same.
func TestLateAnswerBeatsTimer(t *testing.T) {
	clk := &fakeClock{}
	cfg := Config{}
	cfg.Metadata.MintWait = 100 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"}, withClock(clk))
	e.reg.S.Issued = clk.Now()
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if !req.Begin(clk.Now().Add(time.Minute)) {
			return Credential{}, ErrNotSent
		}
		clk.Add(2 * time.Minute) // the answer arrives after the fence
		return validCred(req), nil
	})
	e.ecs("sa")
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "late_answer_discarded" })
}

func TestBeginAtPrepareBoundaryAndWorkerBound(t *testing.T) {
	clk := &fakeClock{}
	cfg := Config{}
	cfg.Metadata.MintWait, cfg.Metadata.MaxWorkers, cfg.Metadata.PrepareTimeout = 20*time.Millisecond, 2, 50*time.Millisecond
	e := newEnv(t, cfg, []string{"sa"}, withClock(clk))
	refused := make(chan bool, 1)
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		clk.Add(50 * time.Millisecond) // exactly at the prepare deadline
		refused <- !req.Begin(clk.Now().Add(time.Minute))
		return Credential{}, ErrNotSent
	})
	e.ecs("sa")
	if !<-refused {
		t.Fatal("Begin accepted at the prepare deadline")
	}
	// minters that ignore cancellation: at most MaxWorkers goroutines
	stuck := make(chan struct{})
	defer close(stuck)
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		<-stuck
		return Credential{}, ErrNotSent
	})
	for i := 0; i < 6; i++ {
		e.ecs("sa")
		clk.Add(time.Second)               // each attempt is past its prepare deadline
		time.Sleep(100 * time.Millisecond) // and its timer settles it
	}
	if n := e.minter.n.Load(); n > 3 { // 1 from the first part + at most 2 stuck workers
		t.Fatalf("%d mint calls with %d workers allowed", n, 2)
	}
}

// --- R9: SSE parsing and delivery ----------------------------------------

func TestSSEParser(t *testing.T) {
	cases := []struct {
		kind sseKind
		in   string
		want int32
	}{
		{sseResponses, "event: response.completed\ndata: {}\n\n", termDone},
		{sseResponses, "event: response.completed\ndata: {}\n", termNone},       // no blank line: not dispatched
		{sseResponses, "event: response.completed\n\n", termNone},               // no data: not dispatched
		{sseResponses, "event:response.completed\r\ndata:{}\r\n\r\n", termDone}, // no space, CRLF
		{sseResponses, "event: response.completed" + strings.Repeat(" ", 5000) + "x\ndata: {}\n\n", termNone},
		{sseResponses, "event: response.created\ndata: " + strings.Repeat("d", 5000) + "\nevent: response.completed\n\n", termNone},
		{sseResponses, "event: response.failed\ndata: {}\n\n", termError},
		{sseResponses, ": keepalive\n\nevent: response.cancelled\ndata: {}\n\n", termCancelled},
		{sseMessages, "event: message_stop\ndata: {}\n\n", termDone},
		{sseMessages, "event: response.completed\ndata: {}\n\n", termNone}, // another API's terminal
		{sseChat, "data: [DONE]\n\n", termDone},
		{sseChat, "data: [DONE]xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\n", termNone},
		{sseChat, "data: [DONE]\ndata: more\n\n", termNone},
	}
	for i, c := range cases {
		p := &sseParser{kind: c.kind}
		for j := 0; j < len(c.in); j += 7 { // arbitrary chunking
			p.feed([]byte(c.in[j:min(j+7, len(c.in))]))
		}
		if p.result != c.want {
			t.Errorf("case %d: %d, want %d", i, p.result, c.want)
		}
	}
}

// The upstream finished but the sandbox did not receive it all: not done.
func TestDeliveryFailureAfterUpstreamEOF(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	st := &reqState{ev: AuditEvent{Kind: "request", Decision: "allow", Route: "halo POST /v1/responses"}, in: &countReader{}}
	st.svc = &service{kind: "halo"}
	st.gotResp.Store(true)
	st.upStatus = 200
	st.bodyDone.Store(true)
	st.parser = &sseParser{kind: sseResponses, result: termDone}
	rec := httptest.NewRecorder()
	cw := &countWriter{ResponseWriter: rec, werr: true}
	e.b.finish(st, cw, httptest.NewRequest("POST", "/v1/responses", nil), time.Now())
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Route == "halo POST /v1/responses" })
	if ev.Outcome != "unknown" || ev.Detail != "delivery_failed" {
		t.Fatalf("%+v", ev)
	}
}

// --- R10: sinks -----------------------------------------------------------

type flakyWriter struct {
	mu    sync.Mutex
	fails int // the next n writes fail
	short int // the next n writes are short
	buf   strings.Builder
}

func (f *flakyWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return 0, errors.New("EIO")
	}
	if f.short > 0 {
		f.short--
		f.buf.Write(p[:len(p)/2])
		return len(p) / 2, nil
	}
	f.buf.Write(p)
	return len(p), nil
}

func (f *flakyWriter) String() string { f.mu.Lock(); defer f.mu.Unlock(); return f.buf.String() }

func TestSinkLossAndFraming(t *testing.T) {
	// a loss record that fails to write keeps the count pending
	fw := &flakyWriter{}
	s := NewLineSink("audit", fw, 8, nil)
	s.pending.Store(3)
	fw.mu.Lock()
	fw.fails = 1 // the loss record's write fails
	fw.mu.Unlock()
	s.Write([]byte(`{"n":1}`))
	s.Flush()
	s.Write([]byte(`{"n":2}`))
	s.Flush()
	if !strings.Contains(fw.String(), `"dropped":3`) {
		t.Fatalf("a failed loss record was forgotten:\n%s", fw.String())
	}
	s.Close(time.Second)
	// a short write is followed by a newline: every complete line parses
	fw2 := &flakyWriter{short: 1}
	s2 := NewLineSink("audit", fw2, 8, nil)
	s2.Write([]byte(`{"a":1}`))
	s2.Write([]byte(`{"b":2}`))
	s2.Flush()
	s2.Close(time.Second)
	lines := strings.Split(strings.TrimSpace(fw2.String()), "\n")
	last := lines[len(lines)-1]
	var v map[string]any
	if err := json.Unmarshal([]byte(last), &v); err != nil {
		t.Fatalf("record after a partial write is corrupt: %q", fw2.String())
	}
}

func TestSinkCloseBoundedAndRaces(t *testing.T) {
	bw := &blockWriter{gate: make(chan struct{})}
	defer close(bw.gate)
	s := NewLineSink("audit", bw, 8, nil)
	for i := 0; i < 5; i++ {
		s.Write([]byte(`{"x":1}`))
	}
	done := make(chan bool, 1)
	go func() { done <- s.Close(100 * time.Millisecond) }()
	select {
	case ok := <-done:
		if ok || s.Abandoned.Load() == 0 {
			t.Fatalf("close drained=%v abandoned=%d with a blocked writer", ok, s.Abandoned.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on a stuck writer")
	}
	before := s.Dropped.Load()
	s.Write([]byte(`{"after":1}`))
	if s.Dropped.Load() != before+1 {
		t.Fatal("a write after Close was not counted")
	}
	fl := make(chan struct{})
	go func() { s.Flush(); close(fl) }()
	select {
	case <-fl:
	case <-time.After(time.Second):
		t.Fatal("Flush after Close hung")
	}
	// enqueue racing close (under -race)
	s3 := NewLineSink("audit", io.Discard, 64, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s3.Write([]byte(`{"r":1}`))
			}
		}()
	}
	s3.Close(time.Second)
	wg.Wait()
	// the byte bound
	s4 := NewLineSink("audit", &blockWriter{gate: bw.gate}, 1000, nil)
	s4.maxBytes = 100
	for i := 0; i < 10; i++ {
		s4.Write([]byte(strings.Repeat("m", 60)))
	}
	if s4.Dropped.Load() < 8 {
		t.Fatalf("queue byte bound not enforced: %d dropped", s4.Dropped.Load())
	}
}

// --- R13 ---------------------------------------------------------------------

func TestRetryAfterFromHold(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: 50 * time.Millisecond})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		return Credential{}, &RetryLaterError{At: time.Now().Add(30 * time.Second)}
	})
	e.ecs("sa")
	resp := e.do(e.req("sa", "GET", "169.254.170.2", "/creds", ""))
	resp.Body.Close()
	if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra < 25 || ra > 30 {
		t.Fatalf("Retry-After %q during a 30 s hold", resp.Header.Get("Retry-After"))
	}
}
