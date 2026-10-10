package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// service is one upstream: halo_serve or a cloud provider.
type service struct {
	kind     string // halo | cloud
	name     string
	routes   []Route
	upstream *url.URL
	secret   string
	inject   string
	proxy    *httputil.ReverseProxy
}

var segRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$`)

// match finds the route for a request. Escaped paths are refused (the
// upstream must see exactly the path that was matched).
func (s *service) match(method string, u *url.URL) (Route, bool) {
	if u.RawPath != "" || !strings.HasPrefix(u.Path, "/") {
		return Route{}, false
	}
	got := strings.Split(u.Path[1:], "/")
	for _, r := range s.routes {
		if r.Method != method {
			continue
		}
		want := strings.Split(strings.TrimPrefix(r.Path, "/"), "/")
		if len(want) != len(got) {
			continue
		}
		ok := true
		for i := range want {
			if want[i] == "*" {
				ok = segRe.MatchString(got[i])
			} else {
				ok = want[i] == got[i]
			}
			if !ok {
				break
			}
		}
		if ok {
			return r, true
		}
	}
	return Route{}, false
}

// lookupService maps a Host to its service; nil is the default deny.
func (b *Broker) lookupService(host string) *service {
	return b.hosts[host] // MUTANT:defaultAllow
}

// reqState is one request's record, shared with the proxy hooks.
type reqState struct {
	ev        AuditEvent
	link      Link
	key       netip.AddrPort
	principal string
	chain     string
	idem      string // namespaced Idempotency-Key ("" = none: halo derives its D5 default)
	secret    Secret
	svc       *service
	tc        TraceContext // this span
	parent    string       // client-supplied parent span id (claimed)
	in        *countReader
	gotConn   atomic.Bool // a connection to the upstream existed: from here on bytes may have left
	gotResp   atomic.Bool
	sse       bool
	bodyDone  atomic.Bool // upstream body read to EOF
	sseKind   sseKind
	parser    *sseParser  // the response's SSE parser (handler goroutine only)
	quotaStop atomic.Bool // a byte budget ran out mid-transfer
	hasBody   bool        // the request carries a body (deny closes the connection instead of draining it)
	ls        *linkServer
	proxyErr  error
	timedOut  bool
	upStatus  int
	ctlr      *http.ResponseController
	writeIdle time.Duration
}

type countReader struct {
	r    io.ReadCloser
	n    atomic.Int64
	ctlr *http.ResponseController
	idle time.Duration
}

// Read extends the connection's read deadline on every read: a body that
// stops making progress for idle is aborted. The deadline is cleared at
// EOF (the server's background read must not time out while halo works).
func (c *countReader) Read(p []byte) (int, error) {
	if c.ctlr != nil && c.idle > 0 {
		_ = c.ctlr.SetReadDeadline(time.Now().Add(c.idle)) // MUTANT:uploadUnbounded
	}
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	if err != nil && c.ctlr != nil {
		_ = c.ctlr.SetReadDeadline(time.Time{})
	}
	return n, err
}
func (c *countReader) Close() error { return c.r.Close() }

type countWriter struct {
	http.ResponseWriter
	status int
	n      int64
	werr   bool
	ctlr   *http.ResponseController
	idle   time.Duration
}

func (c *countWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

// Write sets a write deadline per write: a sandbox that stops reading
// cannot hold a response (and its upstream) forever; a live SSE stream
// with heartbeats is unaffected.
func (c *countWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.armWrite()
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	if err != nil {
		c.werr = true
	}
	return n, err
}

// armWrite gives the next write (or flush) WriteIdle to complete.
func (c *countWriter) armWrite() {
	if c.ctlr != nil && c.idle > 0 {
		_ = c.ctlr.SetWriteDeadline(time.Now().Add(c.idle)) // MUTANT:writeUnbounded
	}
}

func (c *countWriter) Flush() {
	c.armWrite()
	if err := http.NewResponseController(c.ResponseWriter).Flush(); err != nil {
		c.werr = true
	}
}

func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// bodyWatch follows the upstream body: EOF, and (for event streams) the
// bounded SSE parser. Upstream completion only; delivery is judged
// separately from the downstream writes.
type bodyWatch struct {
	rc io.ReadCloser
	r  io.Reader // metered
	st *reqState
}

func (w *bodyWatch) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if w.st.parser != nil && n > 0 {
		w.st.parser.feed(p[:n])
	}
	if err == io.EOF {
		w.st.bodyDone.Store(true)
	}
	return n, err
}
func (w *bodyWatch) Close() error { return w.rc.Close() }

// meteredBody is a request body that takes its bytes from the quota.
type meteredBody struct {
	meteredReader
	c io.Closer
}

func (m *meteredBody) Close() error { return m.c.Close() }

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// ServeHTTP handles one request on a link listener.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := b.cfg.Now()
	key, _ := r.Context().Value(keyListener).(netip.AddrPort)
	tconn, _ := r.Context().Value(keyConn).(*trackedConn)
	ra, _ := netip.ParseAddrPort(r.RemoteAddr)
	// Path and Host are request content: they are recorded only as a route
	// template and a configured service name, once matched.
	st := &reqState{key: key, ev: AuditEvent{Time: start, Kind: "request", Link: key.String(), Remote: ra.String(), Method: normMethod(r.Method)}}
	st.hasBody = r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody
	ctlr := http.NewResponseController(w)
	st.ctlr = ctlr
	st.in = &countReader{r: r.Body}
	r.Body = st.in
	// W3C trace context: continue a valid client trace (claimed), else start one.
	randBytes(st.tc.SpanID[:])
	st.tc.Flags = 1
	if tps := r.Header.Values("Traceparent"); len(tps) == 1 {
		if p, ok := ParseTraceparent(tps[0]); ok {
			st.tc.TraceID, st.tc.Flags = p.TraceID, p.Flags
			st.parent = hex.EncodeToString(p.SpanID[:])
		}
	}
	if isZero(st.tc.TraceID[:]) {
		randBytes(st.tc.TraceID[:])
	}
	st.ev.TraceID = hex.EncodeToString(st.tc.TraceID[:])
	cw := &countWriter{ResponseWriter: w, ctlr: ctlr, idle: b.cfg.Limits.WriteIdle}
	defer b.finish(st, cw, r, start)

	if tconn != nil {
		st.ls = tconn.ls
	}
	if st.ls == nil {
		b.deny(cw, st, http.StatusForbidden, "unknown_link")
		return
	}
	// cheap per-link admission before any routing (denied requests count too)
	if !st.ls.rate.allow() {
		w.Header().Set("Retry-After", "1")
		b.deny(cw, st, http.StatusTooManyRequests, "rate_link")
		return
	}
	l, ok := b.serving(st.ls)
	switch {
	case !ok:
		b.deny(cw, st, http.StatusForbidden, "stale_connection") // another allocation, a removed link, or an expired lease
		return
	case !l.peerOK(ra.Addr()):
		b.deny(cw, st, http.StatusForbidden, "peer")
		return
	}
	st.link = l
	st.principal = b.Principal(l)
	st.ev.Sandbox, st.ev.Principal, st.ev.Epoch = l.Workload.Sandbox, st.principal, l.Epoch
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		b.deny(cw, st, http.StatusForbidden, "forward_proxy") // B0 has no forward proxy
		return
	}
	psem, msem := st.ls.psem, st.ls.msem
	switch host := hostOnly(r.Host); host {
	case imdsHost, ecsHost:
		if !acquire(msem) {
			w.Header().Set("Retry-After", "1")
			b.deny(cw, st, http.StatusTooManyRequests, "busy_metadata")
			return
		}
		defer release(msem)
		if host == imdsHost {
			st.ev.Host = "imds"
			b.serveIMDS(cw, r, st)
		} else {
			st.ev.Host = "ecs"
			b.serveECS(cw, r, st)
		}
	default:
		svc := b.lookupService(host)
		if svc == nil {
			b.deny(cw, st, http.StatusForbidden, "host")
			return
		}
		st.ev.Host = svc.name
		if !acquire(psem) { // MUTANT:concurrencyUnlimited
			w.Header().Set("Retry-After", "1")
			b.deny(cw, st, http.StatusTooManyRequests, "busy_link")
			return
		}
		defer release(psem)
		if !acquire(b.gsem) {
			w.Header().Set("Retry-After", "1")
			b.deny(cw, st, http.StatusTooManyRequests, "busy_node")
			return
		}
		defer release(b.gsem)
		b.serveProxy(cw, r, st, svc)
	}
}

func acquire(sem chan struct{}) bool {
	if sem == nil {
		return false
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(sem chan struct{}) { <-sem }

func (b *Broker) deny(w http.ResponseWriter, st *reqState, status int, reason string) {
	st.ev.Decision, st.ev.Reason, st.ev.Status, st.ev.Outcome = "deny", reason, status, "not_done"
	if st.hasBody {
		// never drain an unread body after a refusal: close the connection
		w.Header().Set("Connection", "close") // MUTANT:drainRejectedBody
	}
	writeJSONError(w, status, "denied by yard-broker: "+reason)
}

// namespaceKey binds a client Idempotency-Key to its principal, so two
// sandboxes choosing the same key never share a turn's replay at halo.
func namespaceKey(principal, key string) string {
	h := sha256.New()
	io.WriteString(h, strconv.Itoa(len(principal)))
	io.WriteString(h, ":")
	io.WriteString(h, principal)
	io.WriteString(h, key)
	return "yb1-" + hex.EncodeToString(h.Sum(nil))
}

func validIdemKey(k string) bool {
	if k == "" || len(k) > 255 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x21 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// secretErrCategory maps any SecretSource error to a fixed word: the
// source's own message is never logged (it might quote content).
func secretErrCategory(err error) string {
	switch {
	case errors.Is(err, ErrNoSecret):
		return "missing"
	case errors.Is(err, ErrSecretPolicy):
		return "policy"
	default:
		return "unavailable"
	}
}

func (b *Broker) serveProxy(w *countWriter, r *http.Request, st *reqState, svc *service) {
	st.ev.Upstream = svc.name
	st.svc = svc
	route, ok := svc.match(r.Method, r.URL)
	if !ok {
		b.deny(w, st, http.StatusForbidden, "route")
		return
	}
	st.ev.Route = svc.kind + " " + route.Method + " " + route.Path
	st.ev.Path = route.Path
	limit := route.MaxBody
	if limit <= 0 {
		limit = b.cfg.Limits.MaxBody
	}
	if r.ContentLength > limit { // MUTANT:bodyUnbounded
		b.deny(w, st, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if ik := r.Header.Values("Idempotency-Key"); len(ik) > 1 || len(ik) == 1 && !validIdemKey(ik[0]) {
		b.deny(w, st, http.StatusBadRequest, "idempotency_key")
		return
	} else if len(ik) == 1 {
		st.idem = namespaceKey(st.principal, ik[0]) // MUTANT:rawIdemKey
	}
	cloud := svc.kind == "cloud"
	st.sseKind = sseKindFor(route.Path)
	// Admission charges the request even if it then fails (secret
	// unavailable, upstream down): self-harm only, stated in B12.
	if ok, after, why := b.quota.admit(st.principal, cloud); !ok {
		secs := int(after.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		b.deny(w, st, http.StatusTooManyRequests, "quota_"+why)
		return
	}
	if svc.secret != "" {
		if b.deps.Secrets == nil {
			b.deny(w, st, http.StatusServiceUnavailable, "no_secret_source")
			return
		}
		key, err := b.deps.Secrets.Secret(r.Context(), svc.secret)
		if err != nil {
			b.deps.Logf("secret %s: %s", svc.secret, secretErrCategory(err))
			b.deny(w, st, http.StatusServiceUnavailable, "secret_unavailable")
			return
		}
		st.secret = key
		st.ev.Credential = svc.secret // MUTANT:logSecretValue
	}
	st.chain = st.principal
	if root, ok := b.deps.Chains.ChainRoot(r.Context(), st.link); ok && chainRe.MatchString(root) {
		st.chain = root
	}
	if svc.kind == "halo" {
		st.ev.Chain = st.chain
	}
	st.ev.Decision = "allow"
	if r.Body != nil && r.Body != http.NoBody {
		st.in.ctlr, st.in.idle = st.ctlr, b.cfg.Limits.UploadIdle
		mb := &meteredBody{meteredReader{r: st.in, q: b.quota, principal: st.principal, cloud: cloud, stopped: &st.quotaStop}, st.in}
		r.Body = http.MaxBytesReader(w, mb, limit)
	}
	ctx := context.WithValue(r.Context(), keyState, st)
	svc.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// passHeaders are the only client request headers forwarded upstream; every
// identity, credential, idempotency and tracing header is set by the broker.
var passHeaders = []string{"Accept", "Content-Type", "User-Agent", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

func outHeaders(in http.Header) http.Header {
	out := http.Header{}
	for _, k := range passHeaders {
		if v := in.Values(k); len(v) > 0 {
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}

func injectKey(h http.Header, mode string, key Secret) {
	switch mode {
	case "x-api-key":
		h.Set("X-Api-Key", key.value())
	case "bearer":
		h.Set("Authorization", "Bearer "+key.value())
	}
}

func stateOf(r *http.Request) *reqState { st, _ := r.Context().Value(keyState).(*reqState); return st }

func (b *Broker) newProxy(svc *service, rt http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			st := stateOf(pr.In)
			pr.SetURL(svc.upstream)
			pr.Out.Header = outHeaders(pr.In.Header)
			pr.Out.Trailer = nil // client trailers never travel upstream
			h := pr.Out.Header
			h.Set("Accept-Encoding", "identity") // stream as sent; no transparent gzip
			if st.idem != "" {
				h.Set("Idempotency-Key", st.idem)
			}
			switch svc.kind {
			case "halo":
				principal := st.principal // MUTANT:trustClientPrincipal
				h.Set("X-Halo-Principal", principal)
				h.Set("X-Halo-Chain-Id", st.chain)
				h.Set("X-Halo-Trace-Id", hex.EncodeToString(st.tc.TraceID[:]))
				if st.link.Session != "" {
					h.Set("X-Halo-Session-Id", st.link.Session)
				}
				h.Set("Traceparent", st.tc.Traceparent())
				injectKey(h, "bearer", st.secret)
			case "cloud":
				injectKey(h, svc.inject, st.secret) // MUTANT:forwardClientAuth
			}
			trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { st.gotConn.Store(true) }}
			ctx := httptrace.WithClientTrace(pr.Out.Context(), trace)
			pr.Out = pr.Out.WithContext(ctx) // MUTANT:detachUpstream
		},
		Transport:     rt,
		FlushInterval: -1,
		ErrorLog:      b.errorLog("proxy " + svc.name + ": "),
		ModifyResponse: func(resp *http.Response) error {
			st := stateOf(resp.Request)
			st.gotResp.Store(true)
			st.upStatus = resp.StatusCode
			ct := resp.Header.Get("Content-Type")
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/event-stream") {
				st.parser = &sseParser{kind: st.sseKind}
			}
			resp.Header.Del("Set-Cookie")
			resp.Header.Del("X-Yard-Outcome")
			// a status that already settles the outcome is said before the body
			switch o := statusOutcome(svc.kind, resp.StatusCode); o {
			case "not_done", "unknown":
				resp.Header.Set("X-Yard-Outcome", o)
			}
			resp.Body = &bodyWatch{rc: resp.Body, st: st, r: &meteredReader{r: resp.Body, q: b.quota, principal: st.principal,
				cloud: svc.kind == "cloud", out: true, stopped: &st.quotaStop}}
			return nil // MUTANT:bufferSSE
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st := stateOf(r)
			st.proxyErr = err
			var ne net.Error
			st.timedOut = errors.As(err, &ne) && ne.Timeout()
			if r.Context().Err() != nil {
				return // the client is gone; finish() records it
			}
			status := http.StatusBadGateway
			if st.timedOut {
				status = http.StatusGatewayTimeout
			}
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) { // MUTANT:chunkedBodyStatusIgnored
				status = http.StatusRequestEntityTooLarge // a chunked body over the cap
				st.ev.Reason = "body_too_large"
			}
			if !st.gotConn.Load() {
				// no connection to the upstream was ever made: nothing left
				w.Header().Set("X-Yard-Outcome", "not_done")
				writeJSONError(w, status, "upstream not reached")
				return
			}
			w.Header().Set("X-Yard-Outcome", "unknown")
			writeJSONError(w, status, retryAdvice(svc.kind))
		},
	}
}

// retryAdvice is what a client is told after an unknown outcome.
func retryAdvice(kind string) string {
	if kind == "halo" {
		return "upstream failed after the request may have been sent; outcome unknown: retry only with the same Idempotency-Key (halo replays or adopts it)"
	}
	return "upstream failed after the request may have been sent; outcome unknown: a retry may run and be billed twice (the provider's idempotency is not guaranteed)"
}

// statusOutcome is the outcome a complete upstream status implies.
// halo: 429 and 4xx are refusals before anything ran (SCHEDULER.md §7: a
// refused turn is removed atomically). Cloud providers: only 401, 403 and
// 429 are taken as "not run" ([D], unverified); everything else non-2xx is
// unknown. 2xx is decided by the body (see finish).
func statusOutcome(kind string, code int) string {
	switch {
	case code >= 200 && code < 300:
		return ""
	case kind == "halo" && code >= 400 && code < 500:
		return "not_done"
	case kind == "cloud" && (code == 401 || code == 403 || code == 429): // MUTANT:cloud4xxNotDone
		return "not_done"
	default:
		return "unknown"
	}
}

// finish classifies the outcome and writes the audit event and the span.
// It runs on every path, including http.ErrAbortHandler panics. Default:
// unknown unless a pre-send refusal or a complete answer establishes more.
func (b *Broker) finish(st *reqState, cw *countWriter, r *http.Request, start time.Time) {
	end := b.cfg.Now()
	ev := &st.ev
	if ev.Status == 0 {
		ev.Status = cw.status
	}
	ev.BytesIn, ev.BytesOut = st.in.n.Load(), cw.n
	ev.Millis = end.Sub(start).Milliseconds()
	clientGone := r.Context().Err() != nil || cw.werr
	kind := ""
	if st.svc != nil {
		kind = st.svc.kind
	}
	if ev.Outcome == "" {
		ev.Outcome = "unknown" // MUTANT:optimisticOutcome
		switch {
		case st.gotResp.Load():
			ev.Status = st.upStatus
			if o := statusOutcome(kind, st.upStatus); o != "" {
				ev.Outcome = o
				break
			}
			// upstream completion first, then delivery to the sandbox
			upstreamDone := false
			switch {
			case st.quotaStop.Load():
				ev.Detail = "quota_exhausted"
			case !st.bodyDone.Load() && clientGone:
				ev.Detail = "client_gone"
			case !st.bodyDone.Load():
				ev.Detail = "upstream_broken"
			case st.parser == nil:
				upstreamDone = true // a complete non-streamed 2xx answer
			default:
				switch st.parser.result {
				case termDone:
					upstreamDone = true
				case termCancelled:
					ev.Detail = "cancelled" // cancellation does not prove nothing ran
				case termError:
					ev.Detail = "terminal_error" // MUTANT:terminalErrorUnreported
				default:
					ev.Detail = "no_terminal_event"
				}
			}
			if upstreamDone {
				if clientGone { // MUTANT:deliveryIgnored
					ev.Detail = "delivery_failed" // the upstream finished; the sandbox did not get it all
				} else {
					ev.Outcome = "done"
				}
			}
		case st.proxyErr != nil || clientGone:
			switch {
			case !st.gotConn.Load():
				ev.Outcome, ev.Detail = "not_done", "upstream_unreachable"
				if errors.Is(st.proxyErr, ErrNotAllowlisted) {
					ev.Detail = "not_allowlisted"
				}
				if clientGone && st.proxyErr == nil {
					ev.Detail = "client_gone"
				}
			case st.quotaStop.Load():
				ev.Detail = "quota_exhausted"
			case clientGone:
				ev.Detail = "client_gone"
			case st.timedOut:
				ev.Detail = "upstream_timeout"
			default:
				ev.Detail = "upstream_error"
			}
			if clientGone && ev.Status == 0 {
				ev.Status = 499
			}
		case ev.Decision == "allow" && st.svc == nil:
			ev.Outcome = "done" // a metadata answer the broker produced itself
		}
	}
	if ev.Decision == "" {
		ev.Decision = "allow"
	}
	b.deps.Audit.Audit(*ev)
	b.Count.Add(ev.Decision + "_" + ev.Outcome)
	if b.deps.Spans == nil {
		return
	}
	attrs := map[string]any{
		"http.request.method": ev.Method, "http.response.status_code": int64(ev.Status),
		"yard.decision": ev.Decision, "yard.outcome": ev.Outcome,
		"yard.link": ev.Link, "yard.capture": "off", "yard.observed": "host",
		"yard.bytes_in": ev.BytesIn, "yard.bytes_out": ev.BytesOut,
	}
	opt := map[string]string{"url.template": ev.Path, "yard.service": ev.Host, "yard.reason": ev.Reason,
		"yard.detail": ev.Detail, "yard.route": ev.Route, "yard.credential.name": ev.Credential, "yard.mint.id": ev.MintID,
		"yard.principal": ev.Principal, "yard.sandbox.id": ev.Sandbox, "yard.chain.root": st.chain,
		"yard.run.id": st.link.Workload.Run, "yard.harness.name": st.link.Workload.Harness,
		"yard.run.class": string(st.link.Class)}
	for k, v := range opt {
		if v != "" {
			attrs[k] = v
		}
	}
	if st.parent != "" {
		attrs["yard.trace.parent_claimed"] = true // the parent came from inside the VM
	}
	b.deps.Spans.ExportSpan(Span{TraceID: ev.TraceID, SpanID: hex.EncodeToString(st.tc.SpanID[:]), ParentSpanID: st.parent,
		Name: "broker " + firstNonEmpty(ev.Route, ev.Method), Start: start, End: end,
		Error: ev.Decision != "allow" || ev.Outcome != "done", Attrs: attrs})
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// --- credential endpoints ---------------------------------------------

const credPrefix = "/latest/meta-data/iam/security-credentials"

func (b *Broker) serveIMDS(w *countWriter, r *http.Request, st *reqState) {
	st.ev.Route = "imds"
	md := b.cfg.Metadata
	if r.URL.RawPath != "" { // MUTANT:metadataEscaped
		b.deny(w, st, http.StatusNotFound, "route")
		return
	}
	switch p := r.URL.Path; {
	case p == "/latest/api/token" && r.Method == http.MethodPut:
		st.ev.Route, st.ev.Path = "imds token", "/latest/api/token"
		if len(r.Header.Values("X-Forwarded-For")) > 0 {
			b.deny(w, st, http.StatusForbidden, "forwarded") // as EC2: a proxied token PUT is refused
			return
		}
		ttls := r.Header.Values("X-Aws-Ec2-Metadata-Token-Ttl-Seconds")
		if len(ttls) != 1 || len(ttls[0]) > 6 {
			b.deny(w, st, http.StatusBadRequest, "token_ttl")
			return
		}
		secs, err := strconv.Atoi(ttls[0])
		if err != nil || secs < 1 || int64(secs) > int64(md.TokenMaxTTL/time.Second) {
			b.deny(w, st, http.StatusBadRequest, "token_ttl")
			return
		}
		tok := b.toks.issue(st.link.Incarnation, time.Duration(secs)*time.Second)
		st.ev.Decision = "allow"
		w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", strconv.Itoa(secs))
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, tok)
	case r.Method == http.MethodGet && (p == credPrefix || p == credPrefix+"/" || p == credPrefix+"/"+md.RoleName):
		toks := r.Header.Values("X-Aws-Ec2-Metadata-Token")
		if len(toks) != 1 || !b.toks.valid(st.link.Incarnation, toks[0]) {
			b.deny(w, st, http.StatusUnauthorized, "imds_token") // IMDSv1 is off
			return
		}
		if p != credPrefix+"/"+md.RoleName {
			st.ev.Route, st.ev.Path, st.ev.Decision = "imds role", credPrefix+"/", "allow"
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, md.RoleName)
			return
		}
		st.ev.Route, st.ev.Path = "imds credentials", credPrefix+"/<role>"
		b.credential(w, r, st, func(c Credential) map[string]any {
			return map[string]any{"Code": "Success", "LastUpdated": b.cfg.Now().UTC().Format(time.RFC3339),
				"Type": "AWS-HMAC", "AccessKeyId": c.AccessKeyID, "SecretAccessKey": c.SecretAccessKey.value(),
				"Token": c.SessionToken.value(), "Expiration": b.creds.advertised(c).Format(time.RFC3339)}
		})
	default:
		b.deny(w, st, http.StatusNotFound, "route")
	}
}

func (b *Broker) serveECS(w *countWriter, r *http.Request, st *reqState) {
	st.ev.Route = "ecs"
	if r.URL.RawPath != "" || r.Method != http.MethodGet || r.URL.Path != b.cfg.Metadata.ECSPath {
		b.deny(w, st, http.StatusNotFound, "route")
		return
	}
	st.ev.Route, st.ev.Path = "ecs credentials", b.cfg.Metadata.ECSPath
	b.credential(w, r, st, func(c Credential) map[string]any {
		m := map[string]any{"AccessKeyId": c.AccessKeyID, "SecretAccessKey": c.SecretAccessKey.value(),
			"Token": c.SessionToken.value(), "Expiration": b.creds.advertised(c).Format(time.RFC3339)}
		if c.RoleARN != "" {
			m["RoleArn"] = c.RoleARN
		}
		return m
	})
}

// credential selects a credential and commits the response at the store's
// linearization point: a revoke or rebind after selection makes the commit
// fail (503) instead of serving a fenced credential.
func (b *Broker) credential(w *countWriter, r *http.Request, st *reqState, render func(Credential) map[string]any) {
	if b.deps.Minter == nil {
		b.deny(w, st, http.StatusServiceUnavailable, "no_minter")
		return
	}
	t, err := b.creds.get(r.Context(), st.link, st.principal)
	if errors.Is(err, errStale) {
		b.deny(w, st, http.StatusForbidden, "stale_request")
		return
	}
	if err != nil {
		w.Header().Set("Retry-After", strconv.Itoa(retrySecs(t.retryAt, b.cfg.Now()))) // MUTANT:retryAfterIgnoresHold
		b.deny(w, st, http.StatusServiceUnavailable, "credential_unavailable")
		return
	}
	var c Credential
	body, why := b.creds.commit(st.link, st.principal, t, func(cr Credential) ([]byte, error) {
		c = cr
		return json.Marshal(render(cr))
	})
	if why != "" {
		w.Header().Set("Retry-After", "1")
		b.deny(w, st, http.StatusServiceUnavailable, why)
		return
	}
	// committed: written after the store lock is released
	st.ev.Decision, st.ev.MintID, st.ev.AccessKey = "allow", c.MintID, c.AccessKeyID
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// retrySecs is Retry-After for a hold until at: at least 1 s, at most 60 s.
func retrySecs(at, now time.Time) int {
	d := int(at.Sub(now).Seconds() + 0.999)
	return max(1, min(60, d))
}
