package broker

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- F5 resource and spend isolation ----------------------------------

func TestBodyLimits(t *testing.T) {
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	cfg.Limits.MaxBody = 1024
	e := newEnv(t, cfg, []string{"sa"})
	if st := e.status(e.req("sa", "POST", "inference.yard", "/v1/responses", strings.Repeat("x", 2048))); st != 413 {
		t.Fatalf("declared oversize body: %d", st)
	}
	if len(halo.headers()) != 0 {
		t.Fatal("an oversize body reached halo")
	}
	// chunked (no Content-Length): cut at the limit
	var got atomic.Int64
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		got.Store(n)
		if err != nil {
			<-r.Context().Done() // do not race the proxy's upload error with a 200 response
		}
	}
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", "")
	r.Body = io.NopCloser(strings.NewReader(strings.Repeat("y", 4096)))
	r.ContentLength = -1
	tid := strings.Repeat("b", 32)
	r.Header.Set("Traceparent", "00-"+tid+"-00f067aa0ba902b7-01")
	resp := e.do(r)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 413 || resp.Header.Get("X-Yard-Outcome") != "unknown" {
		t.Fatalf("chunked oversize: status=%d outcome=%q", resp.StatusCode, resp.Header.Get("X-Yard-Outcome"))
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.TraceID == tid && ev.Kind == "request" })
	// MaxBytesReader reads one extra byte to detect overflow; that byte is
	// charged as client input even though it is not forwarded upstream.
	if ev.Outcome != "unknown" || ev.Reason != "body_too_large" || ev.BytesIn > 1025 {
		t.Fatalf("chunked oversize audit: %+v", ev)
	}
}

// A body that stops making progress is aborted after UploadIdle.
func TestSlowUploadAborted(t *testing.T) {
	halo := newFakeHalo(t)
	aborted := make(chan struct{})
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			close(aborted)
		}
	}
	cfg := haloCfg(halo)
	cfg.Limits.UploadIdle = 200 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nContent-Length: 100\r\n\r\n0123456789")
	select {
	case <-aborted:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("a stalled upload was not aborted")
	}
}

// A sandbox that stops reading its response cannot hold the upstream.
func TestStalledReaderAborted(t *testing.T) {
	halo := newFakeHalo(t)
	gone := make(chan struct{})
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := []byte("data: " + strings.Repeat("z", 64<<10) + "\n\n")
		for {
			if _, err := w.Write(chunk); err != nil {
				close(gone)
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				close(gone)
				return
			default:
			}
		}
	}
	cfg := haloCfg(halo)
	cfg.Limits.WriteIdle = 200 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nContent-Length: 2\r\n\r\n{}")
	// never read
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream still streaming into a sandbox that stopped reading")
	}
}

func TestConnectionCapPerLink(t *testing.T) {
	e := newEnv(t, Config{Limits: Limits{MaxConnsPerLink: 3}}, []string{"sa"})
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	addr := strings.TrimPrefix(e.urls["sa"], "http://")
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	if st := e.tryStatus(e.req("sa", "GET", "169.254.170.2", "/creds", "")); st != -1 {
		t.Fatalf("a fourth connection was served: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "conn" && ev.Reason == "conn_limit" })
}

// Proxy slots per link; metadata keeps its own pool.
func TestConcurrencyLimitsReserveMetadata(t *testing.T) {
	halo := newFakeHalo(t)
	hold := make(chan struct{})
	started := make(chan struct{}, 4)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		<-hold
	}
	cfg := haloCfg(halo)
	cfg.Limits.PerLinkProxy = 1
	e := newEnv(t, cfg, []string{"sa"})
	done := make(chan int)
	go func() { done <- e.tryStatus(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)) }()
	<-started
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 2 * time.Second}
	resp, err := c.Do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	if err != nil {
		close(hold)
		t.Fatalf("second concurrent request was admitted and held: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second concurrent request: %d", resp.StatusCode)
	}
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatalf("metadata starved by proxy traffic: %d", st)
	}
	close(hold)
	<-done
}

func TestQuotas(t *testing.T) {
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	cfg.Limits.RequestsPerMin = 2
	e := newEnv(t, cfg, []string{"sa", "sb"})
	for i := 0; i < 2; i++ {
		if st := e.status(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); st != 200 {
			t.Fatal(st)
		}
	}
	resp := e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over the request rate: %d", resp.StatusCode)
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Reason == "quota_rate_requests" })
	if ev.Outcome != "not_done" {
		t.Fatal(ev.Outcome)
	}
	if st := e.status(e.req("sb", "POST", "inference.yard", "/v1/responses", `{}`)); st != 200 {
		t.Fatalf("another principal paid for sa's quota: %d", st)
	}
	// the daily ceiling on key-injected cloud egress
	q := newQuotas(Limits{RequestsPerMin: 100, BytesPerMin: 1 << 30, CloudDailyRequests: 1, CloudDailyBytes: 1 << 30,
		CloudDailyRequestsGlobal: 100, CloudDailyBytesGlobal: 1 << 30}, time.Now)
	if ok, _, _ := q.admit("p", true); !ok {
		t.Fatal("first cloud request refused")
	}
	if ok, after, why := q.admit("p", true); ok || why != "daily_cloud" || after <= 0 || after > 24*time.Hour {
		t.Fatalf("daily ceiling: %v %v %s", ok, after, why)
	}
	if ok, _, _ := q.admit("p", false); !ok {
		t.Fatal("halo traffic counted against the cloud ceiling")
	}
	// bytes: a stream that used the budget blocks the next admission
	q2 := newQuotas(Limits{RequestsPerMin: 100, BytesPerMin: 1000, CloudDailyRequests: 10, CloudDailyBytes: 1 << 30,
		CloudDailyRequestsGlobal: 100, CloudDailyBytesGlobal: 1 << 30}, time.Now)
	q2.admit("p", false)
	for q2.take("p", false, true, 400) > 0 {
	}
	if ok, _, why := q2.admit("p", false); ok || why != "rate_bytes" {
		t.Fatalf("byte rate: %v %s", ok, why)
	}
}

func TestHaloHeaderTimeout(t *testing.T) {
	halo := newFakeHalo(t)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}
	cfg := haloCfg(halo)
	cfg.HaloHeaderTimeout = 200 * time.Millisecond
	e := newEnv(t, cfg, []string{"sa"})
	resp := e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 504 || resp.Header.Get("X-Yard-Outcome") != "unknown" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("X-Yard-Outcome"))
	}
}

func TestMetricsText(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	e.ecs("sa")
	var b bytes.Buffer
	if err := WritePrometheus(&b, e.b.Metrics()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `yard_broker_events_total{event="mint_done"} 1`) ||
		!strings.Contains(b.String(), `{event="registry_applied"}`) {
		t.Fatal(b.String())
	}
}

// --- F6 halo trust channel --------------------------------------------

func TestHaloURLRules(t *testing.T) {
	cases := []struct {
		url, secret string
		ok          bool
	}{
		{"http://127.0.0.1:8080", "halo-key", true},
		{"http://[::1]:8080", "halo-key", true},
		{"https://halo.example.ts.net:8443", "halo-key", true},
		{"http://127.0.0.1:8080", "", false},
		{"http://100.82.193.10:8443", "halo-key", false},
		{"http://localhost:8080", "halo-key", false},
		{"http://user:pw@127.0.0.1:8080", "halo-key", false},
		{"https://user@halo.example:8443", "halo-key", false},
		{"http://127.0.0.1:8080/v1", "halo-key", false},
	}
	for _, c := range cases {
		_, err := New(Config{TrustDomain: "home.arpa", HaloURL: c.url, HaloSecret: c.secret}, testDeps())
		if (err == nil) != c.ok {
			t.Errorf("%s secret=%q: err %v, want ok=%v", c.url, c.secret, err, c.ok)
		}
	}
}

// --- F7 honest outcomes -----------------------------------------------

func TestOutcomeClasses(t *testing.T) {
	halo := newFakeHalo(t)
	var mode atomic.Value
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch mode.Load().(string) {
		case "sse-truncated":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: response.created\ndata: {}\n\n")
		case "sse-cancelled":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: response.cancelled\ndata: {}\n\n")
		case "sse-failed":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: response.failed\ndata: {}\n\n")
		case "429":
			w.WriteHeader(429)
		case "500":
			w.WriteHeader(500)
		case "302":
			w.Header().Set("Location", "http://evil.example/")
			w.WriteHeader(302)
		}
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, x := range []struct{ mode, outcome, detail, hdr string }{
		{"sse-truncated", "unknown", "no_terminal_event", ""},
		{"sse-cancelled", "unknown", "cancelled", ""}, // cancellation does not prove nothing ran
		{"sse-failed", "unknown", "terminal_error", ""},
		{"429", "not_done", "", "not_done"},
		{"500", "unknown", "", "unknown"},
		{"302", "unknown", "", "unknown"},
	} {
		mode.Store(x.mode)
		n0 := len(halo.headers())
		r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)
		r.Header.Set("Traceparent", "00-"+strings.Repeat("a", 31)+strconv.Itoa(len(x.mode)%10)+"-00f067aa0ba902b7-01")
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.Header.Get("X-Yard-Outcome") != x.hdr {
			t.Errorf("%s: X-Yard-Outcome %q", x.mode, resp.Header.Get("X-Yard-Outcome"))
		}
		if len(halo.headers()) != n0+1 {
			t.Errorf("%s: %d upstream requests (a redirect must not be followed)", x.mode, len(halo.headers())-n0)
		}
		tid := strings.Repeat("a", 31) + strconv.Itoa(len(x.mode)%10)
		ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.TraceID == tid && ev.Kind == "request" })
		if ev.Outcome != x.outcome || ev.Detail != x.detail {
			t.Errorf("%s: outcome %s/%s, want %s/%s", x.mode, ev.Outcome, ev.Detail, x.outcome, x.detail)
		}
		e.audit.b.Reset()
	}
	// cloud statuses: only 401/403/429 settle as not done
	for code, want := range map[int]string{400: "unknown", 404: "unknown", 401: "not_done", 429: "not_done", 503: "unknown", 200: ""} {
		if got := statusOutcome("cloud", code); got != want {
			t.Errorf("cloud %d: %q want %q", code, got, want)
		}
	}
	if statusOutcome("halo", 400) != "not_done" || statusOutcome("halo", 502) != "unknown" {
		t.Error("halo statuses")
	}
	if !strings.Contains(retryAdvice("cloud"), "billed twice") || !strings.Contains(retryAdvice("halo"), "same Idempotency-Key") {
		t.Error("retry advice")
	}
}

// TLS hostname verification stays on: a certificate that does not name
// the upstream fails before any byte of the request is sent (not done).
func TestCloudTLSHostnameVerified(t *testing.T) {
	cl := newFakeCloud(t)
	pool := x509.NewCertPool()
	pool.AddCert(cl.srv.Certificate())
	port := cl.srv.Listener.Addr().(*net.TCPAddr).Port
	hp := "localhost:" + strconv.Itoa(port) // the test certificate names 127.0.0.1 and example.com only
	cfg := Config{UpstreamAllow: []string{hp}, AllowPrivateUpstream: true, CloudRootCAs: pool,
		Providers: []Provider{{Name: "openai", Hosts: []string{"openai.yard"}, Upstream: "https://" + hp, Secret: "openai", Inject: "bearer", Routes: OpenAIRoutes}}}
	e := newEnv(t, cfg, []string{"sa"}, func(c *Config, d *Deps) { d.Secrets = MapSource{"openai": fakeOpenAIKey} })
	resp := e.do(e.req("sa", "POST", "openai.yard", "/v1/responses", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 502 || resp.Header.Get("X-Yard-Outcome") != "not_done" || len(cl.requests()) != 0 {
		t.Fatalf("%d %q %d", resp.StatusCode, resp.Header.Get("X-Yard-Outcome"), len(cl.requests()))
	}
}

func TestShutdownMidStreamIsNotDone(t *testing.T) {
	halo := newFakeHalo(t)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: response.created\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	resp := e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	buf := make([]byte, 10)
	resp.Body.Read(buf)
	go e.b.Close()
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "request" && ev.Route != "" })
	if ev.Outcome != "unknown" {
		t.Fatalf("a stream cut by shutdown classified %q", ev.Outcome)
	}
}

// --- F8 no content in audit -------------------------------------------

func TestRejectedContentNotRecorded(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	e.status(e.req("sa", "GET", "sk-hostsecret-1.example", "/x", ""))
	e.status(e.req("sa", "GET", "inference.yard", "/sk-pathsecret-2", ""))
	e.status(e.req("sa", "GET", "169.254.169.254", "/latest/sk-mdsecret-3", ""))
	e.status(e.req("sa", "GET", "inference.yard", "/v1/responses/resp_idsecret4", ""))
	e.audit.waitFor(t, `"path":"/v1/responses/*"`)
	e.spans.waitFor(t, `"/v1/responses/*"`)
	out := e.audit.String() + e.spans.String()
	for _, s := range []string{"sk-hostsecret-1", "sk-pathsecret-2", "sk-mdsecret-3", "idsecret4"} {
		if strings.Contains(out, s) {
			t.Errorf("request content %q recorded", s)
		}
	}
	if !strings.Contains(out, `"path":"/v1/responses/*"`) {
		t.Errorf("route template not recorded:\n%s", out)
	}
}

// --- F9 audit robustness ----------------------------------------------

type failWriter struct{ short bool }

func (f failWriter) Write(p []byte) (int, error) {
	if f.short {
		return len(p) / 2, nil
	}
	return 0, errors.New("no space left on device")
}

type blockWriter struct {
	gate chan struct{}
	buf  syncBuf
}

func (b *blockWriter) Write(p []byte) (int, error) { <-b.gate; return b.buf.Write(p) }

func TestLineSinkFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		var logs syncBuf
		s := NewLineSink("audit", failWriter{short: short}, 8, func(f string, a ...any) { logs.Write([]byte(f)) })
		s.Write([]byte("a"))
		s.Write([]byte("b"))
		s.Flush()
		if s.WriteErrors.Load() != 2 || !strings.Contains(logs.String(), "write failed") {
			t.Fatalf("short=%v: %d errors, log %q", short, s.WriteErrors.Load(), logs.String())
		}
		s.Close(time.Second)
	}
	bw := &blockWriter{gate: make(chan struct{})}
	s := NewLineSink("audit", bw, 2, nil)
	wrote := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			s.Write([]byte(`{"n":` + strconv.Itoa(i) + `}`))
		}
		close(wrote)
	}()
	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		close(bw.gate)
		t.Fatal("a blocked disk blocked the writer")
	}
	if s.Dropped.Load() == 0 {
		t.Fatal("no drops counted")
	}
	close(bw.gate)
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(bw.buf.String(), `"kind":"loss"`) && time.Now().Before(deadline) {
		s.Write([]byte(`{"n":"after"}`))
		s.Flush()
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(bw.buf.String(), `"kind":"loss"`) {
		t.Fatalf("no loss line:\n%s", bw.buf.String())
	}
	s.Close(time.Second)
}

func TestConnDenyAuditRateLimited(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	if err := e.update(func(ls []Link) []Link {
		ls[0].Peers = []netip.Prefix{netip.MustParsePrefix("10.9.9.9/32")}
		ls[0].Incarnation = incOf("sa-0002")
		return ls
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://")); err == nil {
			c.Read(make([]byte, 1))
			c.Close()
		}
	}
	n := 0
	for _, ev := range e.audit.events(t) {
		if ev.Kind == "conn" {
			n++
		}
	}
	if n == 0 || n > denyPerWindow {
		t.Fatalf("%d conn-deny lines for 30 refused connections", n)
	}
	if e.b.Metrics()["audit_conn_deny_suppressed"] == 0 {
		t.Fatal("suppressed denies not counted")
	}
}

// --- F12 destination policy -------------------------------------------

func TestDestinationPolicy(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "192.168.1.72", "100.64.0.10", "169.254.169.254", "127.0.0.1", "0.0.0.1",
		"192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255", "224.0.0.1",
		"::1", "::", "::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:a00:1::1", "2001::1", "2001:db8::1",
		"fd7a:115c:a1e0::1", "fc00::1", "fe80::1", "ff02::1", "100::1"} {
		if isPublic(mustAddr(a)) {
			t.Errorf("%s treated as public", a)
		}
	}
	for _, a := range []string{"160.79.104.10", "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"} {
		if !isPublic(mustAddr(a)) {
			t.Errorf("%s treated as non-public", a)
		}
	}
	b, err := New(Config{TrustDomain: "home.arpa"}, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	got := b.candidates([]netip.Addr{mustAddr("10.0.0.5"), mustAddr("160.79.104.10"), mustAddr("64:ff9b::a00:5")})
	if len(got) != 1 || got[0] != mustAddr("160.79.104.10") {
		t.Fatalf("mixed answers: %v", got)
	}
	b2, _ := New(Config{TrustDomain: "home.arpa", UpstreamAllow: []string{"api.example:443"},
		Resolver: staticResolver{mustAddr("10.0.0.5"), mustAddr("192.168.1.1")}}, testDeps())
	if _, err := b2.dialAllowed(context.Background(), "tcp", "api.example:443"); !errors.Is(err, ErrNotAllowlisted) {
		t.Fatalf("a name resolving only to private addresses: %v", err)
	}
}

type staticResolver []netip.Addr

func (s staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s, nil
}

// --- F13 lows ---------------------------------------------------------

func TestIdleSlotEviction(t *testing.T) {
	var c Counters
	s := newCredStore(MetadataConfig{MaxIdleSlots: 2}, nil, time.Now, func(AuditEvent) {}, &c)
	s.mu.Lock()
	s.slot("idle-1")
	held := s.slot("held")
	held.holdUntil = time.Now().Add(time.Hour) // an unknown mint's fence
	s.slot("idle-2")                           // triggers a sweep
	_, heldThere := s.slots["held"]
	_, idleThere := s.slots["idle-1"]
	s.mu.Unlock()
	if !heldThere {
		t.Fatal("a slot holding a mint fence was evicted")
	}
	if idleThere {
		t.Fatal("a quiescent slot was not evicted")
	}
}

func TestMetadataStrictness(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"})
	r := e.req("sa", "PUT", "169.254.169.254", "/latest/api/%74oken", "")
	r.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	if st := e.status(r); st != 404 {
		t.Errorf("escaped IMDS path: %d", st)
	}
	if st := e.status(e.req("sa", "GET", "169.254.170.2", "/%63reds", "")); st != 404 {
		t.Errorf("escaped ECS path: %d", st)
	}
	for _, ttl := range [][]string{{"9223372036854775807"}, {"60", "60"}, {"-1"}, {"1e3"}} {
		r := e.req("sa", "PUT", "169.254.169.254", "/latest/api/token", "")
		for _, v := range ttl {
			r.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", v)
		}
		if st := e.status(r); st != 400 {
			t.Errorf("ttl %v: %d", ttl, st)
		}
	}
	tok := e.imdsToken("sa")
	r = e.req("sa", "GET", "169.254.169.254", credPrefix+"/yard-task", "")
	r.Header.Add("X-aws-ec2-metadata-token", tok)
	r.Header.Add("X-aws-ec2-metadata-token", tok)
	if st := e.status(r); st != 401 {
		t.Errorf("two token headers: %d", st)
	}
	// no-store on token and credential answers
	r = e.req("sa", "PUT", "169.254.169.254", "/latest/api/token", "")
	r.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp := e.do(r)
	resp.Body.Close()
	resp2 := e.do(e.req("sa", "GET", "169.254.170.2", "/creds", ""))
	resp2.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp2.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q %q", resp.Header.Get("Cache-Control"), resp2.Header.Get("Cache-Control"))
	}
}

func TestTokenCapAndExpiry(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	tk := &imdsTokens{m: map[string]imdsToken{}, now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	var first []string
	for i := 0; i < maxTokensPerLink+6; i++ {
		tok := tk.issue(incOf("a"), time.Duration(i+1)*time.Second) // later tokens live longer
		if i < 6 {
			first = append(first, tok)
		}
	}
	for _, tok := range first {
		if tk.valid(incOf("a"), tok) {
			t.Fatal("the oldest tokens survived the per-link cap")
		}
	}
	last := tk.issue(incOf("a"), time.Second)
	mu.Lock()
	now = now.Add(2 * time.Second)
	mu.Unlock()
	if tk.valid(incOf("a"), last) {
		t.Fatal("an expired token is valid")
	}
}

func TestAddressNormalization(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	if err := e.update(func(ls []Link) []Link {
		ls[0].Addr = netip.AddrPortFrom(netip.AddrFrom16(ls[0].Addr.Addr().As16()), ls[0].Addr.Port()) // ::ffff:127.0.0.1
		ls[0].Peers = []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16(mustAddr("127.0.0.1").As16()), 128)}
		return ls
	}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"INFERENCE.YARD", "inference.yard.", "inference.yard:80"} {
		if st := e.status(e.req("sa", "POST", h, "/v1/responses", `{}`)); st != 200 {
			t.Errorf("host %q: %d", h, st)
		}
	}
}

// Trailers and Connection-nominated headers cannot smuggle identity.
func TestTrailersAndHopByHop(t *testing.T) {
	halo := newFakeHalo(t)
	var trailer http.Header
	var mu sync.Mutex
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		trailer = r.Trailer.Clone()
		mu.Unlock()
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\nConnection: X-Halo-Principal, keep-alive\r\n"+
		"X-Halo-Principal: spoof\r\nTransfer-Encoding: chunked\r\nTrailer: X-Halo-Principal\r\n\r\n2\r\n{}\r\n0\r\nX-Halo-Principal: spoof-trailer\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	c.Read(buf)
	h := halo.headers()
	if len(h) != 1 || h[0].Get("X-Halo-Principal") != e.principal("sa") {
		t.Fatalf("principal %v", h)
	}
	mu.Lock()
	defer mu.Unlock()
	for k, v := range trailer {
		if len(v) > 0 && v[0] != "" {
			t.Fatalf("client trailer %s=%v reached halo", k, v)
		}
	}
}

// Halo authorizes object access (GET/cancel of a response id) by the
// principal header the broker sets: the broker must always send it.
func TestHaloObjectRoutesCarryPrincipal(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	e.status(e.req("sa", "GET", "inference.yard", "/v1/responses/resp_of_another_sandbox", ""))
	e.status(e.req("sa", "POST", "inference.yard", "/v1/responses/resp_of_another_sandbox/cancel", ""))
	for _, h := range halo.headers() {
		if h.Get("X-Halo-Principal") != e.principal("sa") {
			t.Fatal("object route without the caller's principal")
		}
	}
}
