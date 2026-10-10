package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"yard/internal/issuer"
)

// syncBuf is a goroutine-safe buffer for audit, span and log output. When
// flush is set (a LineSink's Flush), reads flush the sink first.
type syncBuf struct {
	mu    sync.Mutex
	b     bytes.Buffer
	flush func()
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	if s.flush != nil {
		s.flush()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) events(t *testing.T) []AuditEvent {
	t.Helper()
	var out []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(s.String()), "\n") {
		if line == "" {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// waitEvent polls the audit log for an event matching f.
func (s *syncBuf) waitEvent(t *testing.T, f func(AuditEvent) bool) AuditEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range s.events(t) {
			if f(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no matching audit event in:\n%s", s.String())
	return AuditEvent{}
}

// waitFor polls until the buffer contains every string.
func (s *syncBuf) waitFor(t *testing.T, subs ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		all := true
		cur := s.String()
		for _, x := range subs {
			if !strings.Contains(cur, x) {
				all = false
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing %q in:\n%s", subs, cur)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeMinter is a controllable Minter. By default it calls Begin with a
// JWT exp of now + 5 min and answers a valid 15-minute credential.
type fakeMinter struct {
	mu    sync.Mutex
	calls []MintRequest
	n     atomic.Int64
	fn    func(ctx context.Context, req MintRequest) (Credential, error)
}

func validCred(req MintRequest) Credential {
	return Credential{AccessKeyID: "ASIAFAKE" + strings.ToUpper(req.MintID[2:10]),
		SecretAccessKey: NewSecret("fake-secret-access-key-" + req.MintID),
		SessionToken:    NewSecret("fake-session-token-" + req.MintID),
		Expiration:      time.Now().Add(15 * time.Minute), Epoch: req.Epoch, MintID: req.MintID,
		RoleARN: "arn:aws:iam::000000000000:role/yard-task"}
}

// begin is what a well-behaved minter does before the exchange.
func begin(req MintRequest) error {
	if !req.Begin(time.Now().Add(5 * time.Minute)) {
		return ErrNotSent
	}
	return nil
}

func (f *fakeMinter) Mint(ctx context.Context, req MintRequest) (Credential, error) {
	f.n.Add(1)
	f.mu.Lock()
	f.calls = append(f.calls, req)
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	if err := begin(req); err != nil {
		return Credential{}, err
	}
	return validCred(req), nil
}

func (f *fakeMinter) set(fn func(ctx context.Context, req MintRequest) (Credential, error)) {
	f.mu.Lock()
	f.fn = fn
	f.mu.Unlock()
}

type fakeChains map[string]string // sandbox -> root

func (f fakeChains) ChainRoot(_ context.Context, l Link) (string, bool) {
	r, ok := f[l.Workload.Sandbox]
	return r, ok
}

type testEnv struct {
	t      *testing.T
	b      *Broker
	reg    *StaticRegistry
	floors *MemFloors
	audit  *syncBuf
	spans  *syncBuf
	logs   *syncBuf
	minter *fakeMinter
	urls   map[string]string // sandbox -> http://listener
	lns    map[string]net.Listener
}

func workload(sbx string) issuer.WorkloadID {
	return issuer.WorkloadID{Harness: "opencode", Policy: "aws-ro", Node: "nuc", Sandbox: sbx, Run: "r1"}
}

type envOpt func(*Config, *Deps)

const testHaloKey = "halo-test-key-0000"

// newEnv starts a broker with one loopback listener per sandbox name.
// Identity is the listener: every client connects from 127.0.0.1.
func newEnv(t *testing.T, cfg Config, sandboxes []string, opts ...envOpt) *testEnv {
	t.Helper()
	e := &testEnv{t: t, reg: &StaticRegistry{}, floors: &MemFloors{}, audit: &syncBuf{}, spans: &syncBuf{}, logs: &syncBuf{},
		minter: &fakeMinter{}, urls: map[string]string{}, lns: map[string]net.Listener{}}
	var ls []Link
	for _, s := range sandboxes {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(ln.Addr().String())
		ls = append(ls, Link{Addr: ap, Incarnation: incOf(s + "-0001"), Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			Workload: workload(s), Epoch: 1, Class: ClassOwnCode})
		e.urls[s] = "http://" + ln.Addr().String()
		e.lns[s] = ln
	}
	e.reg.Set(ls)
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "home.arpa"
	}
	cfg.AllowLoopback = true
	logf := func(f string, a ...any) { _, _ = e.logs.Write([]byte(strings.TrimSpace(fmt.Sprintf(f, a...)) + "\n")) }
	audit := NewJSONLAudit(e.audit, 0, logf)
	spans := NewJSONLExporter(e.spans, 0, logf)
	e.audit.flush, e.spans.flush = audit.Sink.Flush, spans.Sink.Flush
	t.Cleanup(func() { audit.Sink.Close(time.Second); spans.Sink.Close(time.Second) })
	pre := e.lns
	var lmu sync.Mutex
	d := Deps{Registry: e.reg, Floors: e.floors, Minter: e.minter, Spans: spans, Audit: audit, Logf: logf, FirstBoot: true,
		Secrets: MapSource{"halo-key": testHaloKey},
		// the first listener per address is the one reserved above; later
		// ones (after a reallocation closed it) bind the same port again
		Listen: func(a netip.AddrPort) (net.Listener, error) {
			lmu.Lock()
			defer lmu.Unlock()
			for s, ln := range pre {
				if ln != nil && ln.Addr().String() == a.String() {
					pre[s] = nil
					return ln, nil
				}
			}
			return net.Listen("tcp", a.String())
		}}
	for _, o := range opts {
		o(&cfg, &d)
	}
	b, err := New(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	e.b = b
	if err := b.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return e
}

// update edits the link table and syncs a new snapshot.
func (e *testEnv) update(f func(ls []Link) []Link) error {
	ls := append([]Link(nil), e.reg.S.Links...)
	e.reg.Set(f(ls))
	return e.b.Sync(context.Background(), true)
}

func (e *testEnv) principal(sbx string) string { return workload(sbx).SPIFFE("home.arpa") }

// req builds a request to the sandbox's listener with the given Host.
func (e *testEnv) req(sbx, method, host, path string, body string) *http.Request {
	e.t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, e.urls[sbx]+path, nil)
	} else {
		r, err = http.NewRequest(method, e.urls[sbx]+path, strings.NewReader(body))
	}
	if err != nil {
		e.t.Fatal(err)
	}
	r.Host = host
	return r
}

func (e *testEnv) do(r *http.Request) *http.Response {
	e.t.Helper()
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}
	resp, err := c.Do(r)
	if err != nil {
		e.t.Fatalf("%s %s: %v", r.Method, r.URL, err)
	}
	return resp
}

// status sends a request and returns its status (body discarded).
func (e *testEnv) status(r *http.Request) int {
	e.t.Helper()
	resp := e.do(r)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testDeps builds minimal deps for New-only tests.
func testDeps() Deps {
	return Deps{Registry: &StaticRegistry{}, Floors: &MemFloors{}, FirstBoot: true, Audit: NewJSONLAudit(io.Discard, 0, nil)}
}

func osWriteFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

// tryStatus is status, but a refused or dropped connection is -1.
func (e *testEnv) tryStatus(r *http.Request) int {
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := c.Do(r)
	if err != nil {
		return -1
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// incOf is a deterministic 128-bit incarnation for a test name.
func incOf(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:16])
}

// fakeClock is a wall clock the test can step (forward or back); the
// broker's lease deadlines use the monotonic clock and ignore it.
type fakeClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// withClock drives the broker's and the registry's wall clock.
func withClock(c *fakeClock) envOpt {
	return func(cfg *Config, d *Deps) {
		cfg.Now = c.Now
		if r, ok := d.Registry.(*StaticRegistry); ok {
			r.Now = c.Now
			r.S.Issued = c.Now()
		}
	}
}

func ptr[T any](v T) *T { return &v }
