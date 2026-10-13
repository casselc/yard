// Package agentroute is the broker's route for one allocation (design/AGENT-OPERATIONS.md sections 5 and 6): an
// Anthropic Messages endpoint served on that allocation's own host socket, so whatever connects to it is that
// allocation's worker and nothing else (the guest CID identifies nothing). Each model call is:
//
//  1. bounded: its input counted exactly by halo's count_tokens, its output clamped to what the attempt's limits
//     leave (and to the operator's per-call cap);
//  2. reserved at that maximum in the ledger, durably, before it is sent;
//  3. sent as one halo operation (api "messages"), whose observation stream is relayed to the harness;
//  4. settled at the usage halo reports, then acknowledged to halo (commit before ack).
//
// A call whose answer is lost is unresolved, charged at its maximum, and resolved later from halo's record while
// halo still holds it (Resolve). The route never resends a call; the harness's own retry is a new call.
package agentroute

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"yard/internal/haloop"
	"yard/internal/ledger"
)

type Config struct {
	Attempt string // the attempt this allocation serves
	Alloc   string // the allocation id (hex): every call id is derived from it
	Ledger  *ledger.Ledger
	Halo    *haloop.Client // its Principal names the attempt
	Route   string         // "local"
	Mode    string         // halo's inference mode, as its contract says
	// MaxOut caps a call's output (the operator's per-call cap); MinOut is the smallest output worth sending.
	MaxOut, MinOut int64
	NotAfter       time.Duration // a submit's acceptance window in halo's clock
	MaxBody        int64         // request body cap
	Logf           func(format string, args ...any)
	// OnCall, if set, observes each call: when it arrived, its input bound, the output granted (0: refused).
	OnCall func(id string, at time.Time, in, out int64)
}

type Server struct {
	cfg       Config
	mu        sync.Mutex
	active    bool
	n         int
	exhausted string               // the limit that refused a call, if any
	epoch     string               // this route instance's part of its call ids
	inflight  map[string]*inflight // call id -> its op, for Revoke
	wg        sync.WaitGroup
	srv       *http.Server
}

type inflight struct {
	op     *haloop.Op
	cancel context.CancelFunc
}

func New(cfg Config) *Server {
	if cfg.MinOut <= 0 {
		cfg.MinOut = 1
	}
	if cfg.NotAfter <= 0 {
		cfg.NotAfter = 60 * time.Second
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 32 << 20
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	// a call id is unique across every route this allocation ever has: a route restarted after a broker crash
	// starts its count again, so each route instance has its own epoch (the ledger's call ids are its keys)
	eb := make([]byte, 4)
	rand.Read(eb)
	s := &Server{cfg: cfg, active: true, inflight: map[string]*inflight{}, epoch: hex.EncodeToString(eb)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/messages", s.messages)
	mux.HandleFunc("POST /v1/messages/count_tokens", s.countTokens)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, 404, "not_found_error", "yard: no such route")
	})
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	return s
}

// Serve serves the allocation's socket until Revoke.
func (s *Server) Serve(ln net.Listener) error {
	err := s.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Exhausted names the limit that refused a call ("" if none): the driver ends the task budget_exhausted.
func (s *Server) Exhausted() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exhausted
}

// Revoke ends the scope: no new call is accepted, every call in flight is cancelled at halo (it finishes at the next
// unit boundary with its usage), the socket is closed, and Revoke returns once every handler has settled or
// unresolved its call. Then the ledger refuses further reservations for the attempt.
func (s *Server) Revoke(ctx context.Context) error {
	s.mu.Lock()
	s.active = false
	calls := make([]*inflight, 0, len(s.inflight))
	for _, f := range s.inflight {
		calls = append(calls, f)
	}
	s.mu.Unlock()
	for _, f := range calls {
		s.cancelOp(ctx, f.op)
	}
	_ = s.srv.Close()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		// handlers still running: cut their halo streams; each one unresolves its own call on the way out
		for _, f := range calls {
			f.cancel()
		}
		<-done
	}
	return s.cfg.Ledger.End(context.Background(), s.cfg.Attempt)
}

// Close cuts the route's socket and connections without ending the ledger's attempt: what a crash of the broker
// does. (Revoke is the orderly end.)
func (s *Server) Close() error {
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
	return s.srv.Close()
}

func apiError(w http.ResponseWriter, code int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}})
}

func (s *Server) countTokens(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBody+1))
	if err != nil || int64(len(body)) > s.cfg.MaxBody {
		apiError(w, 413, "request_too_large", "yard: request body too large")
		return
	}
	n, err := s.count(r.Context(), body)
	if err != nil {
		apiError(w, 502, "api_error", "yard: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"input_tokens": n})
}

// count asks halo for the request's exact input tokens (its rendered prompt).
func (s *Server) count(ctx context.Context, body []byte) (int64, error) {
	c := s.cfg.Halo
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.Base, "/")+"/v1/messages/count_tokens", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var v struct {
		InputTokens *int64 `json:"input_tokens"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 || json.Unmarshal(raw, &v) != nil || v.InputTokens == nil {
		return 0, fmt.Errorf("count_tokens: HTTP %d %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return *v.InputTokens, nil
}

// ext is what the ledger keeps with a sent call so it can be resolved after a crash.
type ext struct {
	OperationID string `json:"operation_id"`
	Attempt     uint64 `json:"attempt"`
	Incarnation string `json:"incarnation"`
	NotAfter    int64  `json:"not_after"`
	Digest      string `json:"digest"`
}

func toUsage(u *haloop.Usage) ledger.Usage {
	cached := min(u.Cached, u.Prompt) // halo: prompt_tokens is the whole prompt, cached_tokens a part of it
	return ledger.Usage{Input: u.Prompt - cached, CacheRead: cached, Output: u.Completion}
}

func (s *Server) messages(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		apiError(w, 403, "permission_error", "yard: this allocation's scope is revoked")
		return
	}
	s.n++
	id := fmt.Sprintf("%s.%s.%d", s.cfg.Alloc, s.epoch, s.n)
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBody+1))
	if err != nil || int64(len(body)) > s.cfg.MaxBody {
		apiError(w, 413, "request_too_large", "yard: request body too large")
		return
	}
	var req map[string]json.RawMessage
	var want int64
	if json.Unmarshal(body, &req) != nil || json.Unmarshal(req["max_tokens"], &want) != nil || want < 1 {
		apiError(w, 400, "invalid_request_error", "yard: a JSON Messages request with max_tokens")
		return
	}
	ctx := r.Context()
	in, err := s.count(ctx, body)
	if err != nil {
		apiError(w, 502, "api_error", "yard: "+err.Error())
		return
	}
	if s.cfg.MaxOut > 0 {
		want = min(want, s.cfg.MaxOut)
	}
	arrived := time.Now()
	out, err := s.cfg.Ledger.Reserve(ctx, s.cfg.Attempt, id, s.cfg.Route, in, want, min(want, s.cfg.MinOut))
	if s.cfg.OnCall != nil {
		s.cfg.OnCall(id, arrived, in, out)
	}
	var lim *ledger.LimitError
	if errors.As(err, &lim) {
		s.mu.Lock()
		s.exhausted = lim.Limit
		s.mu.Unlock()
		// not 429: the harness must stop, not retry
		apiError(w, 400, "invalid_request_error", "yard: the task's "+lim.Limit+" budget is exhausted")
		return
	} else if errors.Is(err, ledger.ErrEnded) {
		apiError(w, 403, "permission_error", "yard: this attempt's scope has ended")
		return
	} else if err != nil {
		// yard's own failure: retryable, never an authentication error (a harness stops on 401/403)
		apiError(w, 529, "overloaded_error", "yard: "+err.Error())
		return
	}
	req["max_tokens"] = json.RawMessage(fmt.Sprint(out))
	reqBytes, _ := json.Marshal(req)

	k, err := s.cfg.Halo.Contract(ctx)
	if err != nil {
		// reserved and never sent: settle it at zero (it was never sent, so nothing ran)
		s.settleNeverSent(id)
		apiError(w, 529, "overloaded_error", "yard: halo unavailable")
		return
	}
	op, err := haloop.NewOp(id, 0, k.Incarnation, k.TimeMs+s.cfg.NotAfter.Milliseconds(), "messages", s.cfg.Mode, reqBytes)
	if err != nil {
		s.settleNeverSent(id)
		apiError(w, 500, "api_error", "yard: "+err.Error())
		return
	}
	ej, _ := json.Marshal(ext{op.ID, op.Attempt, op.Incarnation, op.NotAfter, op.Digest})
	if err := s.cfg.Ledger.MarkSent(context.Background(), id, string(ej)); err != nil {
		apiError(w, 500, "api_error", "yard: "+err.Error())
		return
	}
	opCtx, cancel := context.WithCancel(context.Background()) // the op outlives the harness's request
	defer cancel()
	s.mu.Lock()
	s.inflight[id] = &inflight{op: op, cancel: cancel}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.inflight, id); s.mu.Unlock() }()

	ans, err := s.cfg.Halo.Submit(opCtx, op)
	switch {
	case err != nil:
		s.lost(id, op, "submit: "+err.Error())
		apiError(w, 529, "overloaded_error", "yard: halo did not answer")
		return
	case ans.Code == 429 || ans.Code == 503:
		// a refusal of this copy: cancel to make it final (cancelled_before_accept), then settle at zero
		s.lost(id, op, fmt.Sprintf("submit refused %d", ans.Code))
		if ans.RetryAfter != "" {
			w.Header().Set("Retry-After", ans.RetryAfter)
		}
		apiError(w, 529, "overloaded_error", "yard: halo is busy")
		return
	case ans.Code != 202 && ans.Code != 200:
		s.lost(id, op, fmt.Sprintf("submit answered %d %s", ans.Code, ans.Raw))
		apiError(w, 502, "api_error", fmt.Sprintf("yard: halo answered %d", ans.Code))
		return
	}

	var stream bool
	_ = json.Unmarshal(req["stream"], &stream)
	if !stream { // a whole Message: wait for the result, fetch it before the ack
		body, err := s.finish(opCtx, id, op, true)
		if err != nil || body == nil {
			s.cfg.Logf("call %s: %v", id, err)
			apiError(w, 502, "api_error", "yard: the call did not finish")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}
	relayed, clientGone := s.relay(opCtx, ctx, w, op)
	if clientGone {
		// the harness left: halo would finish the call regardless (a departure never cancels), so cancel it
		s.cancelOp(opCtx, op)
	}
	if _, err := s.finish(opCtx, id, op, false); err != nil {
		s.cfg.Logf("call %s: %v (unresolved after %d events)", id, err, relayed)
	}
}

// relay copies the operation's observation stream (Anthropic SSE frames) to the harness, resuming from the last
// event if halo's stream breaks. It returns the events relayed and whether the harness left.
func (s *Server) relay(opCtx, clientCtx context.Context, w http.ResponseWriter, op *haloop.Op) (int, bool) {
	flusher, _ := w.(http.Flusher)
	events, started := 0, false
	for tries := 0; tries < 5; tries++ {
		resp, err := s.cfg.Halo.Stream(opCtx, op, events)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if resp.StatusCode != 200 { // 410: the body is no longer held (done and acked, or expired)
			resp.Body.Close()
			return events, false
		}
		if !started {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(200)
			started = true
		}
		br := bufio.NewReader(resp.Body)
		var frame bytes.Buffer
		for {
			line, err := br.ReadBytes('\n')
			frame.Write(line)
			if err == nil && (len(line) == 1 || bytes.Equal(line, []byte("\r\n"))) && frame.Len() > len(line) {
				if _, werr := w.Write(frame.Bytes()); werr != nil || clientCtx.Err() != nil {
					resp.Body.Close()
					return events, true
				}
				if flusher != nil {
					flusher.Flush()
				}
				events++
				frame.Reset()
				continue
			}
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		if clientCtx.Err() != nil {
			return events, true
		}
		// the stream ended: normally the operation finished; check before resuming
		if st, err := s.cfg.Halo.Status(opCtx, op); err == nil && st.View.Status != "running" {
			return events, false
		}
	}
	return events, false
}

// finish waits for the call's terminal status, settles it at halo's usage, then acknowledges it to halo. With
// wantBody it fetches the result body first (before the ack releases it).
func (s *Server) finish(ctx context.Context, id string, op *haloop.Op, wantBody bool) ([]byte, error) {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		ans, err := s.cfg.Halo.Status(ctx, op)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		v := ans.View
		switch {
		case v.HasUsage():
			var body []byte
			if wantBody && v.Status == "done" {
				if res, err := s.cfg.Halo.Result(ctx, op); err == nil && res.Code == 200 {
					body = res.Raw
				}
			}
			if err := s.cfg.Ledger.Settle(context.Background(), id, toUsage(v.Usage)); err != nil {
				return nil, err
			}
			_, _ = s.cfg.Halo.Ack(ctx, op) // after the commit; a lost ack only keeps halo's body longer
			return body, nil
		case v.NeverRan():
			return nil, s.cfg.Ledger.Settle(context.Background(), id, ledger.Usage{})
		case v.Status == "running" || v.Status == "never_accepted":
			time.Sleep(300 * time.Millisecond)
		default: // unknown: halo lost the record
			_ = s.cfg.Ledger.Unresolve(context.Background(), id)
			return nil, fmt.Errorf("halo answered %q", v.Status)
		}
	}
	_ = s.cfg.Ledger.Unresolve(context.Background(), id)
	return nil, errors.New("no terminal status")
}

// settleNeverSent settles a reserved call that never left the broker.
func (s *Server) settleNeverSent(id string) {
	if err := s.cfg.Ledger.MarkSent(context.Background(), id, ""); err == nil {
		_ = s.cfg.Ledger.Settle(context.Background(), id, ledger.Usage{})
	}
}

// lost handles a submit whose outcome is not known or was refused: it cancels the attempt at halo (which makes
// "not accepted yet" final) and settles from what halo then says; failing that, the call stays unresolved.
func (s *Server) lost(id string, op *haloop.Op, why string) {
	s.cfg.Logf("call %s: %s", id, why)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.cancelOp(ctx, op)
	if _, err := s.finish(ctx, id, op, false); err != nil {
		s.cfg.Logf("call %s: %v", id, err)
	}
}

// cancelOp repeats the cancel until halo answers it (RFC 0007 rule 5).
func (s *Server) cancelOp(ctx context.Context, op *haloop.Op) {
	for i := 0; i < 10 && ctx.Err() == nil; i++ {
		if ans, err := s.cfg.Halo.Cancel(ctx, op); err == nil && ans.Code < 500 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Resolve settles the attempt's unresolved calls from halo's records while halo still holds them: a call halo ran
// at its usage (then acknowledged), one it never ran at zero; a call halo no longer knows (another incarnation, or
// a record without the identity to ask by) stays at its maximum. It returns how many remain unresolved.
func Resolve(ctx context.Context, l *ledger.Ledger, halo *haloop.Client, attempt string) (int, error) {
	calls, err := l.Unresolved(ctx, attempt)
	if err != nil {
		return 0, err
	}
	left := 0
	for _, c := range calls {
		var e ext
		if c.Ext == "" || json.Unmarshal([]byte(c.Ext), &e) != nil {
			left++
			continue
		}
		op := &haloop.Op{ID: e.OperationID, Attempt: e.Attempt, Incarnation: e.Incarnation, NotAfter: e.NotAfter, Digest: e.Digest}
		ans, err := halo.Status(ctx, op)
		if err != nil {
			left++
			continue
		}
		v := ans.View
		if v.Status == "never_accepted" || v.Status == "running" {
			_, _ = halo.Cancel(ctx, op) // final: cancelled_before_accept, or done at the next unit boundary
			for i := 0; i < 50 && (v.Status == "never_accepted" || v.Status == "running"); i++ {
				time.Sleep(200 * time.Millisecond)
				if ans, err = halo.Status(ctx, op); err != nil {
					break
				}
				v = ans.View
			}
		}
		switch {
		case v.HasUsage():
			if err := l.Settle(ctx, c.Call, toUsage(v.Usage)); err != nil {
				return left, err
			}
			_, _ = halo.Ack(ctx, op)
		case v.NeverRan():
			if err := l.Settle(ctx, c.Call, ledger.Usage{}); err != nil {
				return left, err
			}
		default:
			left++
		}
	}
	return left, nil
}
