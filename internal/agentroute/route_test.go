package agentroute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"yard/internal/fakehalo"
	"yard/internal/haloop"
	"yard/internal/ledger"
)

var val = ledger.Valuation{Digest: "v1", Routes: map[string]ledger.Route{
	"local": {Units: ledger.Prices{Input: 1_000_000, CacheRead: 250_000, CacheWrite: 1_000_000, Output: 2_000_000}}}}

type rig struct {
	fake   *fakehalo.Halo
	hs     *httptest.Server
	l      *ledger.Ledger
	dbPath string
	srv    *Server
	client *http.Client
	halo   *haloop.Client
	served chan error
	sock   string
}

func newRig(t *testing.T, lim ledger.Limits) *rig { return newRigWindow(t, lim, 2*time.Second) }

func newRigWindow(t *testing.T, lim ledger.Limits, window time.Duration) *rig {
	dir := t.TempDir()
	r := &rig{fake: fakehalo.New(), dbPath: filepath.Join(dir, "ledger.db"), served: make(chan error, 1)}
	r.hs = httptest.NewServer(r.fake)
	var err error
	if r.l, err = ledger.Open(r.dbPath); err != nil {
		t.Fatal(err)
	}
	if err := r.l.Begin("att", lim, val); err != nil {
		t.Fatal(err)
	}
	r.halo = &haloop.Client{Base: r.hs.URL, Key: "k", Principal: "yard:att"}
	r.srv = New(Config{Attempt: "att", Alloc: "a1b2", Ledger: r.l, Halo: r.halo, Route: "local", Mode: "relaxed",
		MaxOut: 64, MinOut: 1, NotAfter: window, Logf: t.Logf})
	sock := filepath.Join(dir, "v.sock_4000")
	r.sock = sock
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { r.served <- r.srv.Serve(ln) }()
	r.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	return r
}

func (r *rig) close() {
	r.hs.Close()
	r.l.Close()
}

// call makes one harness call; it reports the HTTP status and how many SSE frames arrived.
func (r *rig) call(stream bool, text string, leave bool) (int, int) {
	body := fmt.Sprintf(`{"model":"claude-x","max_tokens":128000,"stream":%v,"messages":[{"role":"user","content":%q}]}`, stream, text)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://yard/v1/messages", strings.NewReader(body))
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	frames := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: ") {
			frames++
			if leave && frames == 2 {
				cancel()
				break
			}
		}
	}
	return resp.StatusCode, frames
}

// TestRouteAccounting: whatever faults hit the calls, after the scope is revoked and the attempt resolved the
// report is available (never stuck), everything halo really ran is charged (accounted), an exact report is exact,
// and without a halo restart every call is resolved exactly.
func TestRouteAccounting(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		r := newRig(t, ledger.Limits{Tokens: 100000, Charge: 100000, Money: 0})
		defer r.close()
		n := hegel.Draw(ht, hegel.Integers(1, 6))
		restarted := false
		for i := 0; i < n; i++ {
			fault := hegel.Draw(ht, hegel.Integers(0, 6))
			stream := hegel.Draw(ht, hegel.Booleans())
			r.fake.Mu.Lock()
			switch fault {
			case 1:
				r.fake.DropSubmitAnswer = true
			case 2:
				r.fake.RefuseNext = true
			case 3:
				r.fake.BreakStreamAfter = 1
			case 4:
				r.fake.RestartAfterSubmit = true
				restarted = true
			case 6:
				r.fake.FullLength = true
			}
			r.fake.Mu.Unlock()
			code, frames := r.call(stream, strings.Repeat("x", 20+40*i), fault == 5)
			ht.Note(fmt.Sprintf("call %d fault %d stream %v -> %d, %d frames", i, fault, stream, code, frames))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := r.srv.Revoke(ctx); err != nil {
			ht.Fatalf("revoke: %v", err)
		}
		if hegel.Draw(ht, hegel.Booleans()) { // the broker crashes before resolving: the ledger recovers
			r.l.Close()
			var err error
			if r.l, err = ledger.Open(r.dbPath); err != nil {
				ht.Fatalf("reopen: %v", err)
			}
		}
		left, err := Resolve(ctx, r.l, r.halo, "att")
		if err != nil {
			ht.Fatalf("resolve: %v", err)
		}
		s, err := r.l.Report(ctx, "att")
		if err != nil {
			ht.Fatalf("report after revoke: %v", err)
		}
		var real int64
		r.fake.Mu.Lock()
		for _, u := range r.fake.Real {
			real += u.Prompt + u.Completion
		}
		r.fake.Mu.Unlock()
		charged := s.Tokens.Input.Total() + s.Tokens.CacheRead.Total() + s.Tokens.CacheWrite.Total() + s.Tokens.Output.Total()
		if real > charged {
			ht.Fatalf("halo ran %d tokens, the ledger holds %d (%+v)", real, charged, s)
		}
		if real > 100000 { // withinTokens: what halo ran stays inside the attempt's token limit
			ht.Fatalf("halo ran %d tokens past the limit of 100000", real)
		}
		if s.Certainty == "exact" && real != charged {
			ht.Fatalf("exact report holds %d, halo ran %d", charged, real)
		}
		if !restarted && (left != 0 || s.Certainty != "exact") {
			ht.Fatalf("without a halo restart every call resolves: left %d, %s", left, s.Certainty)
		}
	})
}

// A call the limits cannot fit is refused with a non-retryable error, and the route says which limit.
func TestBudgetExhausted(t *testing.T) {
	r := newRig(t, ledger.Limits{Tokens: 40, Charge: 100000, Money: 0})
	defer r.close()
	if code, _ := r.call(true, strings.Repeat("y", 400), false); code != 400 {
		t.Fatalf("over the token limit: HTTP %d", code)
	}
	if r.srv.Exhausted() != "tokens" {
		t.Fatalf("exhausted %q", r.srv.Exhausted())
	}
}

// After Revoke the socket is gone and nothing more is charged.
func TestRevokedRefuses(t *testing.T) {
	r := newRig(t, ledger.Limits{Tokens: 100000, Charge: 100000})
	defer r.close()
	if code, frames := r.call(true, "hello", false); code != 200 || frames == 0 {
		t.Fatalf("first call: %d %d", code, frames)
	}
	if err := r.srv.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.call(true, "again", false); code != 0 && code != 403 {
		t.Fatalf("after revoke: HTTP %d", code)
	}
	if _, err := r.l.Reserve(context.Background(), "att", "late", "local", 1, 1, 1); err == nil {
		t.Fatal("ledger reserved after the attempt ended")
	}
}

// A refused copy is cancelled, so "not accepted yet" becomes final at once (cancelled_before_accept) and the call
// settles at zero, without waiting out the acceptance window.
func TestRefusalSettlesAtZero(t *testing.T) {
	r := newRigWindow(t, ledger.Limits{Tokens: 100000, Charge: 100000}, 60*time.Second)
	defer r.close()
	r.fake.Mu.Lock()
	r.fake.RefuseNext = true
	r.fake.Mu.Unlock()
	if code, _ := r.call(true, "hello", false); code != 529 {
		t.Fatalf("refused copy: HTTP %d", code)
	}
	if err := r.srv.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := r.l.Report(context.Background(), "att")
	if err != nil || s.Certainty != "exact" || s.Charge.Total() != 0 {
		t.Fatalf("a refused copy is free and exact: %+v %v", s, err)
	}
}

// Regression (AG2 live probe, agentd_crash): a route restarted for the same allocation after a broker crash started
// its call count again, its call ids collided with the ledger's rows, and the harness got a 403 and stopped. Call ids
// carry a per-route epoch, and yard's own errors are retryable, never 401/403.
func TestRouteRestartKeepsCallIDsUnique(t *testing.T) {
	r := newRig(t, ledger.Limits{Tokens: 100000, Charge: 100000})
	defer r.close()
	if code, _ := r.call(true, "first", false); code != 200 {
		t.Fatalf("first route: %d", code)
	}
	r.srv.Close() // the broker crashes; a new route serves the same allocation on the same ledger
	second := New(Config{Attempt: "att", Alloc: "a1b2", Ledger: r.l, Halo: r.halo, Route: "local", Mode: "relaxed",
		MaxOut: 64, MinOut: 1, NotAfter: 2 * time.Second, Logf: t.Logf})
	os.Remove(r.sock)
	ln, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	go second.Serve(ln)
	defer second.Close()
	for i := 0; i < 3; i++ {
		if code, _ := r.call(true, fmt.Sprintf("after the restart %d", i), false); code != 200 {
			t.Fatalf("call %d after the restart: HTTP %d", i, code)
		}
	}
}

// Yard's own failure (here the ledger is gone) is retryable for the harness, never 401/403, which a harness reads as
// an authentication failure and stops on.
func TestInternalErrorIsRetryable(t *testing.T) {
	r := newRig(t, ledger.Limits{Tokens: 100000, Charge: 100000})
	defer r.close()
	r.l.Close()
	if code, _ := r.call(true, "the ledger is closed", false); code == 401 || code == 403 || code < 500 {
		t.Fatalf("an internal error answered HTTP %d", code)
	}
}
