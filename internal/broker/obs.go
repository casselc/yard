package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TraceContext is a W3C trace context (traceparent version 00).
type TraceContext struct {
	TraceID [16]byte
	SpanID  [8]byte
	Flags   byte
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ParseTraceparent parses "00-<32 hex>-<16 hex>-<2 hex>"; ok is false for
// anything else (an invalid header is ignored and a new trace started).
func ParseTraceparent(v string) (TraceContext, bool) {
	var tc TraceContext
	v = strings.TrimSpace(v)
	if len(v) != 55 || v[2] != '-' || v[35] != '-' || v[52] != '-' || v[:2] != "00" {
		return tc, false
	}
	for _, c := range v {
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return tc, false
		}
	}
	if _, err := hex.Decode(tc.TraceID[:], []byte(v[3:35])); err != nil {
		return tc, false
	}
	if _, err := hex.Decode(tc.SpanID[:], []byte(v[36:52])); err != nil {
		return tc, false
	}
	f, err := hex.DecodeString(v[53:55])
	if err != nil || isZero(tc.TraceID[:]) || isZero(tc.SpanID[:]) {
		return tc, false
	}
	tc.Flags = f[0]
	return tc, true
}

// Traceparent renders the header.
func (tc TraceContext) Traceparent() string {
	return "00-" + hex.EncodeToString(tc.TraceID[:]) + "-" + hex.EncodeToString(tc.SpanID[:]) + "-" + hex.EncodeToString([]byte{tc.Flags})
}

func randBytes(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

// Span is one broker request (OTLP SERVER span).
type Span struct {
	TraceID, SpanID, ParentSpanID string
	Name                          string
	Start, End                    time.Time
	Error                         bool
	Attrs                         map[string]any // string, int64, bool only
}

// Exporter receives finished spans.
type Exporter interface{ ExportSpan(Span) }

// JSONLExporter writes one OTLP/JSON ExportTraceServiceRequest per line
// through a bounded LineSink.
type JSONLExporter struct{ Sink *LineSink }

// NewJSONLExporter wraps w in a LineSink of the given depth.
func NewJSONLExporter(w io.Writer, depth int, logf func(string, ...any)) *JSONLExporter {
	return &JSONLExporter{Sink: NewLineSink("spans", w, depth, logf)}
}

type otlpAttr struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

func otlpAttrs(m map[string]any) []otlpAttr {
	out := make([]otlpAttr, 0, len(m))
	for k, v := range m {
		var val map[string]any
		switch x := v.(type) {
		case string:
			val = map[string]any{"stringValue": x}
		case int:
			val = map[string]any{"intValue": strconv.Itoa(x)}
		case int64:
			val = map[string]any{"intValue": strconv.FormatInt(x, 10)}
		case bool:
			val = map[string]any{"boolValue": x}
		default:
			continue // only plain values are exported
		}
		out = append(out, otlpAttr{k, val})
	}
	sortAttrs(out)
	return out
}

func sortAttrs(a []otlpAttr) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Key < a[j-1].Key; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (e *JSONLExporter) ExportSpan(s Span) {
	status := map[string]any{"code": 1}
	if s.Error {
		status = map[string]any{"code": 2}
	}
	sp := map[string]any{
		"traceId": s.TraceID, "spanId": s.SpanID, "name": s.Name, "kind": 2,
		"startTimeUnixNano": strconv.FormatInt(s.Start.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(s.End.UnixNano(), 10),
		"attributes":        otlpAttrs(s.Attrs), "status": status,
	}
	if s.ParentSpanID != "" {
		sp["parentSpanId"] = s.ParentSpanID
	}
	req := map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": otlpAttrs(map[string]any{"service.name": "yard-broker"})},
		"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "yard/internal/broker"}, "spans": []any{sp}}},
	}}}
	b, err := json.Marshal(req)
	if err != nil {
		return
	}
	e.Sink.Write(b)
}

// AuditEvent is one broker decision (REPORT 5.4 "Audit": every decision with
// byte counts and the credential's name, never its value). Paths carry no
// query string; no header values and no bodies are recorded.
type AuditEvent struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"` // request | conn | mint
	Link       string    `json:"link,omitempty"`
	Remote     string    `json:"remote,omitempty"`
	Sandbox    string    `json:"sandbox,omitempty"`
	Principal  string    `json:"principal,omitempty"`
	Chain      string    `json:"chain,omitempty"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path,omitempty"`
	Route      string    `json:"route,omitempty"`
	Decision   string    `json:"decision"` // allow | deny
	Reason     string    `json:"reason,omitempty"`
	Status     int       `json:"status,omitempty"`
	Outcome    string    `json:"outcome,omitempty"` // done | not_done | unknown (AMBIGUITY.md)
	Detail     string    `json:"detail,omitempty"`  // e.g. client_gone, upstream_timeout
	Upstream   string    `json:"upstream,omitempty"`
	Credential string    `json:"credential,omitempty"` // a secret's NAME
	MintID     string    `json:"mint_id,omitempty"`    // the per-mint tag (yard-mint), not secret
	AccessKey  string    `json:"access_key_id,omitempty"`
	Epoch      uint64    `json:"epoch,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	TraceID    string    `json:"trace_id,omitempty"`
	Millis     int64     `json:"ms,omitempty"`
	Suppressed int64     `json:"suppressed,omitempty"` // conn denies not logged since the previous line
}

// AuditSink receives audit events.
type AuditSink interface{ Audit(AuditEvent) }

// JSONLAudit writes one event per line through a bounded LineSink.
type JSONLAudit struct{ Sink *LineSink }

// NewJSONLAudit wraps w in a LineSink of the given depth.
func NewJSONLAudit(w io.Writer, depth int, logf func(string, ...any)) *JSONLAudit {
	return &JSONLAudit{Sink: NewLineSink("audit", w, depth, logf)}
}

func (a *JSONLAudit) Audit(e AuditEvent) {
	e.Time = e.Time.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.Sink.Write(b)
}

// LineSink writes lines from a bounded queue on its own goroutine, so a
// slow or failing disk never blocks a request or a lock holder.
//
// Bounds: at most depth lines and maxBytes bytes queued. Loss policy: a
// line that does not fit is dropped and counted; the count stays pending
// until a {"kind":"loss"} record carrying it has been written successfully.
// A failed or short write is counted, and the next write starts with a
// newline so a partial fragment cannot merge with the following record.
// Close drains for at most its timeout; lines still queued then are counted
// as abandoned. Write and Flush after Close never block (Write counts a drop).
type LineSink struct {
	name        string
	w           io.Writer
	logf        func(string, ...any)
	maxBytes    int64
	Dropped     atomic.Int64 // lines lost to a full queue or a closed sink (total)
	WriteErrors atomic.Int64 // failed or short writes (total)
	Abandoned   atomic.Int64 // lines still queued when Close gave up
	pending     atomic.Int64 // drops not yet reported in the stream
	queued      atomic.Int64 // bytes queued

	mu     sync.Mutex // guards closed and sends on ch
	closed bool
	ch     chan sinkItem
	done   chan struct{}

	broken  bool // the last write was partial or failed (writer goroutine only)
	lastLog time.Time
}

type sinkItem struct {
	line  []byte
	flush chan struct{}
}

// NewLineSink starts the writer goroutine (depth lines, 4 MiB).
func NewLineSink(name string, w io.Writer, depth int, logf func(string, ...any)) *LineSink {
	if depth <= 0 {
		depth = 4096
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &LineSink{name: name, w: w, ch: make(chan sinkItem, depth), logf: logf, done: make(chan struct{}), maxBytes: 4 << 20}
	go s.run()
	return s
}

// Write queues one line (a newline is added); it never blocks.
func (s *LineSink) Write(line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.queued.Load()+int64(len(line)) > s.maxBytes { // MUTANT:sinkUnboundedBytes
		s.Dropped.Add(1)
		s.pending.Add(1)
		return
	}
	select {
	case s.ch <- sinkItem{line: line}:
		s.queued.Add(int64(len(line)))
	default:
		s.Dropped.Add(1) // MUTANT:sinkBlocks
		s.pending.Add(1)
	}
}

func (s *LineSink) run() {
	defer close(s.done)
	for it := range s.ch {
		if it.flush != nil {
			close(it.flush)
			continue
		}
		s.queued.Add(-int64(len(it.line)))
		if n := s.pending.Load(); n > 0 {
			loss := []byte(`{"kind":"loss","sink":"` + s.name + `","dropped":` + strconv.FormatInt(n, 10) + `}`)
			ok := s.write(loss)
			if ok { // MUTANT:lossForgotten
				s.pending.Add(-n)
			}
		}
		s.write(it.line)
	}
}

// write writes one record; false if it failed or was short.
func (s *LineSink) write(line []byte) bool {
	b := make([]byte, 0, len(line)+2)
	if s.broken { // MUTANT:noFramingRecovery
		b = append(b, '\n') // terminate a partial record left by a failed write
	}
	b = append(append(b, line...), '\n')
	n, err := s.w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.broken = true
		s.WriteErrors.Add(1)
		if now := time.Now(); now.Sub(s.lastLog) > 10*time.Second {
			s.lastLog = now
			s.logf("%s sink: write failed (%d failures so far): %v", s.name, s.WriteErrors.Load(), err)
		}
		return false
	}
	s.broken = false
	return true
}

// Flush waits until every line queued before it has been written; after
// Close it returns at once.
func (s *LineSink) Flush() {
	f := make(chan struct{})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	select {
	case s.ch <- sinkItem{flush: f}:
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		return // queue full: nothing to wait for that a flush could promise
	}
	select {
	case <-f:
	case <-s.done:
	}
}

// Close stops accepting lines and drains the queue for at most timeout.
// It reports whether the drain completed; otherwise the lines left are
// counted as abandoned (the writer goroutine is left to its blocked write).
func (s *LineSink) Close(timeout time.Duration) bool {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return true
	case <-time.After(timeout): // MUTANT:closeUnbounded
		s.Abandoned.Store(int64(len(s.ch)))
		return false
	}
}

// Counters: per-outcome production counts (AMBIGUITY.md rule 5).
type Counters struct {
	mu sync.Mutex
	m  map[string]int64
}

func (c *Counters) Add(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[k]++
}

// Snapshot copies the counters.
func (c *Counters) Snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// denyLimiter rate-limits audit lines for refused connections per link
// (a flood of spoofed or non-peer connections must not fill the disk).
type denyLimiter struct {
	mu sync.Mutex
	m  map[string]*denyBucket
}

type denyBucket struct {
	windowStart time.Time
	n           int
	suppressed  int64
}

const (
	denyWindow    = 10 * time.Second
	denyPerWindow = 5
)

// allow reports whether to log this deny now and how many were suppressed
// since the last logged one.
func (d *denyLimiter) allow(key string, now time.Time) (bool, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]*denyBucket{}
	}
	b := d.m[key]
	if b == nil {
		if len(d.m) > 4096 {
			d.m = map[string]*denyBucket{}
		}
		b = &denyBucket{windowStart: now}
		d.m[key] = b
	}
	if now.Sub(b.windowStart) >= denyWindow {
		b.windowStart, b.n = now, 0
	}
	if b.n >= denyPerWindow { // MUTANT:denyUnlimited
		b.suppressed++
		return false, 0
	}
	b.n++
	s := b.suppressed
	b.suppressed = 0
	return true, s
}

// normMethod maps a request method to a closed set; anything else is OTHER
// (the raw token is request content and never recorded).
func normMethod(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE":
		return m
	}
	return "OTHER" // MUTANT:rawMethodLogged
}
