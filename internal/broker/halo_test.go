package broker

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHalo records the headers of every request it receives.
type fakeHalo struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []http.Header
	// handle, when set, answers; default: 200 {"ok":true}.
	handle func(w http.ResponseWriter, r *http.Request)
}

func newFakeHalo(t *testing.T) *fakeHalo {
	f := &fakeHalo{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Header.Clone())
		h := f.handle
		f.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHalo) headers() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.seen...)
}

func haloCfg(f *fakeHalo) Config {
	return Config{HaloURL: f.srv.URL, HaloHosts: []string{"inference.yard"}, HaloSecret: "halo-key"}
}

func TestHaloHeadersAreTheBrokers(t *testing.T) {
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	e := newEnv(t, cfg, []string{"sa"}, func(c *Config, d *Deps) { d.Secrets = MapSource{"halo-key": "halo-real-key-123"} })

	r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{"input":"hi"}`)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Halo-Principal", "spiffe://home.arpa/harness/x/policy/y/node/z/sandbox/victim/run/r1")
	r.Header.Set("X-Halo-Chain-Id", "victim-chain")
	r.Header.Set("X-Halo-Session-Id", "victim-session")
	r.Header.Set("X-Halo-Variant-Id", "evil")
	r.Header.Set("Authorization", "Bearer sk-sandbox-placeholder")
	r.Header.Set("X-Api-Key", "placeholder")
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("Idempotency-Key", "turn-1")
	r.Header.Set("Forwarded", "for=10.0.0.1")
	r.Header.Set("Tracestate", "evil=1")
	parent := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	r.Header.Set("Traceparent", parent)
	resp := e.do(r)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	hs := halo.headers()
	if len(hs) != 1 {
		t.Fatalf("halo saw %d requests", len(hs))
	}
	h := hs[0]
	if got := h.Get("X-Halo-Principal"); got != e.principal("sa") {
		t.Errorf("X-Halo-Principal = %q, want the link's %q", got, e.principal("sa"))
	}
	if got := h.Get("X-Halo-Chain-Id"); got != e.principal("sa") {
		t.Errorf("X-Halo-Chain-Id = %q, want the principal (no relay context)", got)
	}
	if got := h.Get("Authorization"); got != "Bearer halo-real-key-123" {
		t.Errorf("Authorization = %q, want the broker's halo key", got)
	}
	if got := h.Get("Idempotency-Key"); got == "turn-1" || !strings.HasPrefix(got, "yb1-") {
		t.Errorf("Idempotency-Key = %q, want the namespaced key", got)
	}
	for k, v := range h {
		lk := strings.ToLower(k)
		switch {
		case strings.HasPrefix(lk, "x-halo-") && lk != "x-halo-principal" && lk != "x-halo-chain-id" && lk != "x-halo-trace-id":
			t.Errorf("client header %s: %v reached halo", k, v)
		case lk == "cookie" || lk == "x-api-key" || lk == "forwarded" || lk == "tracestate":
			t.Errorf("client header %s reached halo", k)
		}
		for _, x := range v {
			if strings.Contains(x, "victim") || strings.Contains(x, "placeholder") || strings.Contains(x, "evil") {
				t.Errorf("spoofed value in %s: %q", k, x)
			}
		}
	}
	if got := len(h.Values("X-Halo-Principal")); got != 1 {
		t.Errorf("%d X-Halo-Principal values", got)
	}
	tp, ok := ParseTraceparent(h.Get("Traceparent"))
	if !ok || hex.EncodeToString(tp.TraceID[:]) != "0af7651916cd43dd8448eb211c80319c" || hex.EncodeToString(tp.SpanID[:]) == "b7ad6b7169203331" {
		t.Errorf("traceparent %q: want the client's trace with the broker's span", h.Get("Traceparent"))
	}
	if h.Get("X-Halo-Trace-Id") != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("X-Halo-Trace-Id %q", h.Get("X-Halo-Trace-Id"))
	}
	// the span names the claimed parent
	e.spans.waitFor(t, `"parentSpanId":"b7ad6b7169203331"`, "yard.trace.parent_claimed", `"traceId":"0af7651916cd43dd8448eb211c80319c"`)
}

// A raw request with lower-case and repeated identity headers.
func TestHaloRawWireSpoof(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := `{"input":"x"}`
	io.WriteString(c, "POST /v1/responses HTTP/1.1\r\nHost: inference.yard\r\n"+
		"x-halo-principal: spoof-a\r\nX-HALO-PRINCIPAL: spoof-b\r\nx-halo-chain-id: spoof-c\r\nidempotency-key: k\r\n"+
		"Content-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n"+body)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := halo.headers()[0]
	if v := h.Values("X-Halo-Principal"); len(v) != 1 || v[0] != e.principal("sa") {
		t.Fatalf("X-Halo-Principal %v", v)
	}
	if v := h.Get("X-Halo-Chain-Id"); v != e.principal("sa") {
		t.Fatalf("X-Halo-Chain-Id %q", v)
	}
}

func TestChainRootFromRelayContext(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa", "sb"}, func(c *Config, d *Deps) {
		d.Chains = fakeChains{"sa": "spiffe://home.arpa/harness/h/policy/p/node/n/sandbox/root/run/r1", "sb": "bad value with spaces"}
	})
	for _, s := range []string{"sa", "sb"} {
		r := e.req(s, "POST", "inference.yard", "/v1/messages", `{}`)
		r.Header.Set("X-Halo-Chain-Id", "client-chosen")
		resp := e.do(r)
		resp.Body.Close()
	}
	hs := halo.headers()
	if got := hs[0].Get("X-Halo-Chain-Id"); got != "spiffe://home.arpa/harness/h/policy/p/node/n/sandbox/root/run/r1" {
		t.Errorf("sa chain %q: want the relay's root", got)
	}
	if got := hs[1].Get("X-Halo-Chain-Id"); got != e.principal("sb") {
		t.Errorf("sb chain %q: an invalid relay root falls back to the principal", got)
	}
}

func TestIdempotencyKeyNamespacedByPrincipal(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa", "sb"})
	send := func(sbx, key string) int {
		r := e.req(sbx, "POST", "inference.yard", "/v1/responses", `{"input":"same"}`)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		resp := e.do(r)
		resp.Body.Close()
		return resp.StatusCode
	}
	send("sa", "turn-1")
	send("sb", "turn-1")
	send("sa", "turn-1") // the same sandbox's retry
	send("sa", "")       // no key: halo derives its D5 default
	hs := halo.headers()
	ka, kb, ka2 := hs[0].Get("Idempotency-Key"), hs[1].Get("Idempotency-Key"), hs[2].Get("Idempotency-Key")
	if ka == kb {
		t.Errorf("two principals' key turn-1 collide at halo: %q", ka)
	}
	if ka != ka2 {
		t.Errorf("a sandbox's retry with the same key changed it: %q vs %q", ka, ka2)
	}
	if v := hs[3].Values("Idempotency-Key"); len(v) != 0 {
		t.Errorf("broker invented a key %v (SCHEDULER.md D5: halo derives the default)", v)
	}
	// two keys on one request is ambiguous: refused before anything is sent
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)
	r.Header.Add("Idempotency-Key", "a")
	r.Header.Add("Idempotency-Key", "b")
	resp := e.do(r)
	resp.Body.Close()
	if resp.StatusCode != 400 || len(halo.headers()) != 4 {
		t.Errorf("two keys: status %d, halo requests %d", resp.StatusCode, len(halo.headers()))
	}
}

func TestSSEStreamsWithoutBuffering(t *testing.T) {
	halo := newFakeHalo(t)
	release := make(chan struct{})
	var once sync.Once
	rel := func() { once.Do(func() { close(release) }) }
	t.Cleanup(rel)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: response.created\ndata: {\"n\":1}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		io.WriteString(w, "event: response.completed\ndata: {\"n\":2}\n\n")
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	// headers and the first event must both arrive while the upstream is
	// still holding its second event
	first := make(chan string, 1)
	var br *bufio.Reader
	var resp *http.Response
	go func() {
		resp = e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{"stream":true}`))
		br = bufio.NewReader(resp.Body)
		l, _ := br.ReadString('\n')
		first <- l
	}()
	select {
	case l := <-first:
		if !strings.Contains(l, "response.created") {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(2 * time.Second):
		rel()
		<-first
		resp.Body.Close()
		t.Fatal("first SSE event not delivered before the upstream finished: the broker buffers")
	}
	defer resp.Body.Close()
	rel()
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "response.completed") {
		t.Fatalf("rest %q", rest)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "request" && ev.Outcome == "done" })
}

func TestClientDepartureClosesUpstream(t *testing.T) {
	halo := newFakeHalo(t)
	gone := make(chan struct{})
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-r.Context().Done():
				close(gone)
				return
			case <-tk.C:
				if _, err := io.WriteString(w, "data: {\"delta\":\"x\"}\n\n"); err != nil {
					close(gone)
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	ctx, cancel := context.WithCancel(context.Background())
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{"stream":true}`).WithContext(ctx)
	resp := e.do(r)
	br := bufio.NewReader(resp.Body)
	if l, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(l, "data:") {
		t.Fatalf("first line %q %v", l, err)
	}
	cancel()
	resp.Body.Close()
	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream still streaming after the client left")
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "request" && ev.Route != "" })
	if ev.Outcome != "unknown" || ev.Detail != "client_gone" {
		t.Errorf("audit %+v: want unknown/client_gone", ev)
	}
}

// A client that leaves while halo holds its request (queued or prefilling:
// no response headers yet) must release the upstream request at once.
func TestClientDepartureBeforeHeaders(t *testing.T) {
	halo := newFakeHalo(t)
	gone := make(chan struct{})
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // as halo_serve: the request is read, then queued
		select {
		case <-r.Context().Done():
			close(gone)
		case <-time.After(5 * time.Second):
		}
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	if resp, err := c.Do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`).WithContext(ctx)); err == nil {
		resp.Body.Close()
		t.Fatal("got an answer")
	}
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request still open after the client left")
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "request" && ev.Route != "" })
	if ev.Outcome != "unknown" || ev.Detail != "client_gone" || ev.Status != 499 {
		t.Errorf("audit %+v: want unknown/client_gone/499", ev)
	}
}

func TestUpstreamFailureAfterSendIsUnknownAndNotRetried(t *testing.T) {
	halo := newFakeHalo(t)
	halo.handle = func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			c.Close() // read the request, answer nothing
		}
	}
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{"input":"x"}`)
	r.Header.Set("Idempotency-Key", "k1")
	resp := e.do(r)
	resp.Body.Close()
	if resp.StatusCode != 502 || resp.Header.Get("X-Yard-Outcome") != "unknown" {
		t.Fatalf("status %d outcome %q", resp.StatusCode, resp.Header.Get("X-Yard-Outcome"))
	}
	if n := len(halo.headers()); n != 1 {
		t.Fatalf("halo saw %d attempts: the broker must not retry", n)
	}
	ev := e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "request" })
	if ev.Outcome != "unknown" || ev.Detail != "upstream_error" {
		t.Errorf("audit %+v", ev)
	}

	// halo down: nothing sent, so the outcome is "not done"
	halo.srv.Close()
	resp = e.do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 502 || resp.Header.Get("X-Yard-Outcome") != "not_done" {
		t.Fatalf("down: status %d outcome %q", resp.StatusCode, resp.Header.Get("X-Yard-Outcome"))
	}
}

func TestDefaultDeny(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	cases := []struct {
		method, host, path string
		status             int
		reason             string
	}{
		{"GET", "evil.example", "/", 403, "host"},
		{"POST", "evil.example", "/v1/responses", 403, "host"},
		{"POST", "api.anthropic.com", "/v1/messages", 403, "host"},
		{"POST", "10.77.0.1", "/v1/responses", 403, "host"},
		{"POST", "inference.yard", "/admin/keys", 403, "route"},
		{"DELETE", "inference.yard", "/v1/responses", 403, "route"},
		{"GET", "inference.yard", "/v1/responses/..", 403, "route"},
		{"GET", "inference.yard", "/v1/responses/a%2Fb", 403, "route"},
		{"GET", "inference.yard", "/v1/models/extra", 403, "route"},
		{"GET", "169.254.169.254", "/latest/user-data", 404, "route"},
		{"GET", "169.254.169.254", "/latest/meta-data/placement/region", 404, "route"},
		{"POST", "169.254.170.2", "/creds", 404, "route"},
		{"GET", "169.254.170.2", "/v2/credentials/x", 404, "route"},
	}
	for _, c := range cases {
		resp := e.do(e.req("sa", c.method, c.host, c.path, ""))
		resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s %s%s: status %d, want %d", c.method, c.host, c.path, resp.StatusCode, c.status)
		}
	}
	if n := len(halo.headers()); n != 0 {
		t.Fatalf("halo saw %d denied requests", n)
	}
	// an absolute-form request (a forward proxy request) and CONNECT
	for _, raw := range []string{
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n",
	} {
		c, err := net.Dial("tcp", strings.TrimPrefix(e.urls["sa"], "http://"))
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, raw)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != 403 {
			t.Errorf("%q: status %d", raw[:20], resp.StatusCode)
		}
	}
	denies := 0
	for _, ev := range e.audit.events(t) {
		if ev.Decision == "deny" {
			denies++
			if ev.Reason == "" || ev.Principal != e.principal("sa") {
				t.Errorf("deny event without a reason or principal: %+v", ev)
			}
		}
	}
	if denies != len(cases)+2 {
		t.Errorf("%d deny events, want %d", denies, len(cases)+2)
	}
}
