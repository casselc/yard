// Package fakehalo is a fake halo-flash for tests: the slice of its API the broker route uses (contract,
// count_tokens, the operation verbs for api "messages"), with faults a test switches on. Operations finish at
// submit (the generation is instant), so every accepted operation ran; what it really cost is kept in Real, a ghost
// that survives a Restart (a restart loses halo's records, not the work done).
package fakehalo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"yard/internal/haloop"
)

// Halo is the fake server: an http.Handler.
type Halo struct {
	Mu   sync.Mutex
	inc  string
	t0   time.Time
	ops  map[string]*op
	Real map[string]haloop.Usage
	// one-shot faults
	DropSubmitAnswer, RefuseNext, RestartAfterSubmit, FullLength bool
	BreakStreamAfter                                             int
}

type op struct {
	digest   string
	notAfter int64
	status   string
	usage    haloop.Usage
	frames   []string
	body     []byte
}

func NewInc() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func New() *Halo {
	return &Halo{inc: NewInc(), t0: time.Now(), ops: map[string]*op{}, Real: map[string]haloop.Usage{}}
}

func (f *Halo) now() int64 { return time.Since(f.t0).Milliseconds() }

func (f *Halo) Restart() { f.inc, f.ops, f.t0 = NewInc(), map[string]*op{}, time.Now() }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Halo) view(id string, att uint64, o *op) map[string]any {
	v := map[string]any{"operation_id": id, "attempt": att, "status": o.status, "digest": o.digest}
	if o.status == "done" || o.status == "released" {
		v["finish"] = "stop"
		v["usage"] = o.usage
	}
	return v
}

func (f *Halo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.URL.Path == "/v1/halo/contract":
		writeJSON(w, 200, map[string]any{"incarnation": f.inc, "time_ms": f.now(), "inference": map[string]string{"mode": "relaxed"}})
	case r.URL.Path == "/v1/messages/count_tokens":
		writeJSON(w, 200, map[string]int64{"input_tokens": int64(len(body))/10 + 1})
	case r.URL.Path == "/v1/operations" && r.Method == "POST":
		f.submit(w, r, body)
	case strings.HasPrefix(r.URL.Path, "/v1/operations/"):
		f.verb(w, r)
	default:
		writeJSON(w, 404, map[string]string{"error": "no"})
	}
}

func (f *Halo) submit(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Header.Get("Halo-Incarnation") != f.inc {
		writeJSON(w, 409, map[string]string{"error": "stale incarnation"})
		return
	}
	if f.RefuseNext {
		f.RefuseNext = false
		w.Header().Set("Retry-After", "1")
		writeJSON(w, 429, map[string]string{"error": "principal limit"})
		return
	}
	var b struct {
		OperationID string `json:"operation_id"`
		Attempt     uint64 `json:"attempt"`
		NotAfter    int64  `json:"not_after"`
		Request     struct {
			MaxTokens int64 `json:"max_tokens"`
		} `json:"request"`
	}
	_ = json.Unmarshal(body, &b)
	key := fmt.Sprintf("%s/%d", b.OperationID, b.Attempt)
	if o, ok := f.ops[key]; ok {
		writeJSON(w, 200, f.view(b.OperationID, b.Attempt, o))
		return
	}
	prompt := int64(len(body)) / 20
	u := haloop.Usage{Prompt: prompt, Cached: prompt / 2, Completion: min(b.Request.MaxTokens, 3+prompt%5)}
	if f.FullLength { // the model uses every token it was allowed
		f.FullLength = false
		u.Completion = b.Request.MaxTokens
	}
	o := &op{digest: r.Header.Get("Halo-Digest"), notAfter: b.NotAfter, status: "done", usage: u}
	o.frames = []string{"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"}
	for i := int64(0); i < u.Completion; i++ {
		o.frames = append(o.frames, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n")
	}
	o.frames = append(o.frames, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	o.body = []byte(`{"type":"message","content":[]}`)
	f.ops[key] = o
	f.Real[key] = u
	if f.RestartAfterSubmit {
		f.RestartAfterSubmit = false
		f.Restart()
	}
	if f.DropSubmitAnswer {
		f.DropSubmitAnswer = false
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
		return
	}
	writeJSON(w, 202, map[string]any{"operation_id": b.OperationID, "attempt": b.Attempt, "status": "running"})
}

func (f *Halo) verb(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/operations/"), "/")
	id := parts[0]
	att, _ := strconv.ParseUint(parts[1], 10, 64)
	what := ""
	if len(parts) == 3 {
		what = parts[2]
	}
	key := fmt.Sprintf("%s/%d", id, att)
	if r.Header.Get("Halo-Incarnation") != f.inc {
		writeJSON(w, 200, map[string]any{"operation_id": id, "attempt": att, "status": "unknown"})
		return
	}
	notAfter, _ := strconv.ParseInt(r.Header.Get("Halo-Not-After"), 10, 64)
	o, ok := f.ops[key]
	if !ok {
		st := "never_accepted"
		if what == "cancel" {
			f.ops[key] = &op{digest: r.Header.Get("Halo-Digest"), notAfter: notAfter, status: "cancelled_before_accept"}
			st = "cancelled_before_accept"
		} else if f.now() > notAfter {
			st = "closed"
		}
		writeJSON(w, 200, map[string]any{"operation_id": id, "attempt": att, "status": st})
		return
	}
	switch what {
	case "":
		writeJSON(w, 200, f.view(id, att, o))
	case "result":
		if o.status != "done" {
			writeJSON(w, 409, f.view(id, att, o))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(o.body)
	case "stream":
		if o.status != "done" {
			writeJSON(w, 410, f.view(id, att, o))
			return
		}
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		for i := from; i < len(o.frames); i++ {
			if f.BreakStreamAfter > 0 && i-from >= f.BreakStreamAfter {
				f.BreakStreamAfter = 0
				w.(http.Flusher).Flush()
				hj, _ := w.(http.Hijacker)
				c, _, _ := hj.Hijack()
				c.Close()
				return
			}
			io.WriteString(w, o.frames[i])
		}
	case "cancel":
		writeJSON(w, 200, f.view(id, att, o))
	case "ack":
		if o.status == "done" {
			o.status = "released"
		}
		writeJSON(w, 200, f.view(id, att, o))
	}
}
