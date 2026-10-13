package agentexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"yard/internal/fakehalo"
	"yard/internal/haloop"
	"yard/internal/ledger"
	"yard/internal/node"
	"yard/internal/yardtime"
)

// Workers the fake node runs for a task.
const (
	wOK      = iota // calls the model, then returns a valid review
	wInvalid        // calls the model, then returns output that fails the schema
	wCrash          // calls the model, then dies without a result
	wHang           // calls the model, then keeps running (and calling) until stopped
	nKinds
)

var kindName = []string{"ok", "invalid", "crash", "hang"}

// fakeNode is yard-node in-process: VMs are goroutines that call the model through their allocation's socket. It
// can be unreachable (every call errors) while its VMs keep running, and it can lose a start's answer.
type fakeNode struct {
	mu          sync.Mutex
	root        string
	reachable   bool
	loseStart   bool // the next start is applied and its answer lost
	lateStart   bool // the next start is delayed: absent now, applied later (unless tombstoned by then)
	pending     map[string]bool
	kinds       map[string]int // attempt label -> worker kind
	vms         map[string]*fvm
	tomb        map[string]bool
	alive       map[string]int      // attempt -> VMs alive now
	maxAlive    map[string]int      // attempt -> the most alive at once (ghost: oneLive)
	lateCalls   int                 // model calls that succeeded after their attempt's record was done (ghost)
	requested   map[string][]string // attempt -> allocation ids in the order their starts were asked (ghost)
	staleRuns   int                 // VMs launched for an allocation its attempt had already replaced (ghost)
	doneAttempt func(attempt string) bool
}

type fvm struct {
	id, attempt string
	state       string // running | exited | tombstoned
	finished    bool
	result      []byte
	kill        chan struct{}
	killed      bool
}

var errUnreachable = errors.New("fake node unreachable")

// up: an unreachable node does not refuse, it hangs (a stopped process): the call blocks, with the node's lock
// released, until the node is back or the caller's context ends.
func (n *fakeNode) up(ctx context.Context) error {
	for !n.reachable {
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			n.mu.Lock()
			return errUnreachable
		case <-time.After(5 * time.Millisecond):
		}
		n.mu.Lock()
	}
	return nil
}

func (n *fakeNode) Start(ctx context.Context, id string, s node.Spec) (node.State, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.up(ctx); err != nil {
		return node.State{}, err
	}
	if n.tomb[id] {
		return node.State{ID: id, State: "tombstoned"}, ErrTombstoned
	}
	if v, ok := n.vms[id]; ok {
		return node.State{ID: id, State: v.state, Finished: v.finished}, nil
	}
	if att := s.Labels["attempt"]; len(n.requested[att]) == 0 || n.requested[att][len(n.requested[att])-1] != id {
		n.requested[att] = append(n.requested[att], id)
	}
	if n.lateStart { // the request is still in flight: absent now, applied later unless tombstoned first
		n.lateStart = false
		n.pending = map[string]bool{id: true}
		go func() {
			time.Sleep(400 * time.Millisecond)
			n.mu.Lock()
			defer n.mu.Unlock()
			if !n.tomb[id] {
				n.launchLocked(id, s)
			}
		}()
		return node.State{ID: id, State: "absent"}, nil
	}
	if n.pending[id] {
		return node.State{ID: id, State: "absent"}, nil
	}
	n.launchLocked(id, s)
	if n.loseStart {
		n.loseStart = false
		return node.State{}, errors.New("start answer lost")
	}
	return node.State{ID: id, State: "running"}, nil
}

func (n *fakeNode) launchLocked(id string, s node.Spec) {
	if _, ok := n.vms[id]; ok {
		return
	}
	att := s.Labels["attempt"]
	if rq := n.requested[att]; len(rq) > 0 && rq[len(rq)-1] != id {
		n.staleRuns++ // a later allocation of this attempt was already asked for: this one must never run (F3)
	}
	v := &fvm{id: id, attempt: att, state: "running", kill: make(chan struct{})}
	n.vms[id] = v
	n.alive[att]++
	if n.alive[att] > n.maxAlive[att] {
		n.maxAlive[att] = n.alive[att]
	}
	go n.work(v, n.kinds[att])
}

// call makes one model call through the allocation's socket, as the harness would.
func (n *fakeNode) call(v *fvm) bool {
	sock := filepath.Join(n.root, v.id, "v.sock_4000")
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := hc.Post("http://yard/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-x","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"review"}]}`))
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ok := resp.StatusCode == 200
	if ok && n.doneAttempt(v.attempt) {
		n.mu.Lock()
		n.lateCalls++
		n.mu.Unlock()
	}
	return ok
}

func (n *fakeNode) exit(v *fvm, result []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if v.state != "running" {
		return
	}
	v.state = "exited"
	if result != nil {
		v.result, v.finished = result, true
	}
	n.alive[v.attempt]--
}

func transcript(value string) []byte {
	return []byte(`{"type":"system","subtype":"init","tools":["Read","Grep","Glob"]}` + "\n" +
		`{"type":"result","subtype":"success","structured_output":` + value + "}\n")
}

func (n *fakeNode) work(v *fvm, kind int) {
	for i := 0; i < 2; i++ {
		select {
		case <-v.kill:
			n.exit(v, nil)
			return
		default:
		}
		n.call(v)
	}
	switch kind {
	case wOK:
		r, _ := json.Marshal(map[string]any{"type": "result", "exit": 0,
			"stdout": transcript(`{"verdict":"pass","findings":[]}`)})
		n.exit(v, r)
	case wInvalid:
		r, _ := json.Marshal(map[string]any{"type": "result", "exit": 0, "stdout": transcript(`{"verdict":"maybe"}`)})
		n.exit(v, r)
	case wCrash:
		n.exit(v, nil)
	case wHang:
		for {
			select {
			case <-v.kill:
				n.exit(v, nil)
				return
			case <-time.After(30 * time.Millisecond):
				n.call(v) // a worker that outlives its scope keeps trying
			}
		}
	}
}

func (n *fakeNode) state(id string) node.State {
	if n.tomb[id] {
		return node.State{ID: id, State: "tombstoned"}
	}
	v, ok := n.vms[id]
	if !ok {
		return node.State{ID: id, State: "absent"}
	}
	return node.State{ID: id, State: v.state, Finished: v.finished}
}

func (n *fakeNode) Get(ctx context.Context, id string) (node.State, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.up(ctx); err != nil {
		return node.State{}, err
	}
	return n.state(id), nil
}

func (n *fakeNode) stopLocked(id string) {
	if v, ok := n.vms[id]; ok && v.state == "running" && !v.killed {
		v.killed = true
		close(v.kill)
	}
}

func (n *fakeNode) waitExit(id string) {
	for i := 0; i < 500; i++ {
		n.mu.Lock()
		v, ok := n.vms[id]
		running := ok && v.state == "running"
		n.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (n *fakeNode) Stop(ctx context.Context, id string) (node.State, error) {
	n.mu.Lock()
	if err := n.up(ctx); err != nil {
		n.mu.Unlock()
		return node.State{}, err
	}
	n.stopLocked(id)
	n.mu.Unlock()
	n.waitExit(id)
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state(id), nil
}

func (n *fakeNode) Tombstone(ctx context.Context, id string) (node.State, error) {
	n.mu.Lock()
	if err := n.up(ctx); err != nil {
		n.mu.Unlock()
		return node.State{}, err
	}
	n.stopLocked(id)
	n.mu.Unlock()
	n.waitExit(id)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tomb[id] = true
	return n.state(id), nil
}

func (n *fakeNode) Lease(ctx context.Context, id string, ms int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up(ctx)
}

func (n *fakeNode) Result(ctx context.Context, id string) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.up(ctx); err != nil {
		return nil, err
	}
	if v, ok := n.vms[id]; ok && v.finished {
		return v.result, nil
	}
	return nil, errors.New("no result")
}

func (n *fakeNode) List(ctx context.Context) ([]node.State, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.up(ctx); err != nil {
		return nil, err
	}
	var out []node.State
	for id := range n.vms {
		out = append(out, n.state(id))
	}
	return out, nil
}

func (n *fakeNode) Forget(ctx context.Context, id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up(ctx)
}

func (n *fakeNode) setReachable(r bool) {
	n.mu.Lock()
	n.reachable = r
	n.mu.Unlock()
}

const reviewSchema = `{"type":"object","additionalProperties":false,"required":["verdict","findings"],"properties":{
"verdict":{"type":"string","enum":["pass","fail","insufficient_information"]},
"findings":{"type":"array","items":{"type":"object"}}}}`

var val = ledger.Valuation{Digest: "val-1", Routes: map[string]ledger.Route{
	"local": {Units: ledger.Prices{Input: 1_000_000, CacheRead: 100_000, CacheWrite: 1_000_000, Output: 4_000_000}}}}

// rig: a fake halo, a fake node, a store, a ledger, and an executor that can be crashed and restarted.
type rig struct {
	t       *testing.T
	dir     string
	halo    *fakehalo.Halo
	hs      *httptest.Server
	node    *fakeNode
	st      *Store
	l       *ledger.Ledger
	clock   *yardtime.Clock
	ex      *Exec
	cancel  context.CancelFunc
	api     *httptest.Server
	repo    string
	mu      sync.Mutex
	handler http.Handler
}

func gitRepo(t *testing.T, dir string) string {
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "calc.py"), []byte("def clamp(x, lo, hi):\n    return max(lo, min(x, hi))\n"), 0o644)
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return repo
}

func newRig(t *testing.T) *rig {
	dir := t.TempDir()
	r := &rig{t: t, dir: dir, halo: fakehalo.New()}
	r.hs = httptest.NewServer(r.halo)
	allocs, err := os.MkdirTemp("/tmp", "ya") // short: allocation sockets must fit sun_path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(allocs) })
	r.node = &fakeNode{root: allocs, reachable: true, kinds: map[string]int{}, vms: map[string]*fvm{},
		tomb: map[string]bool{}, alive: map[string]int{}, maxAlive: map[string]int{}, requested: map[string][]string{}}
	r.repo = gitRepo(t, dir)
	r.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		h := r.handler
		r.mu.Unlock()
		if h == nil {
			http.Error(w, "down", 503)
			return
		}
		h.ServeHTTP(w, req)
	}))
	r.node.doneAttempt = func(attempt string) bool {
		parts := strings.SplitN(attempt, "/", 3)
		if len(parts) != 3 || r.st == nil {
			return false
		}
		a, _ := strconv.ParseUint(parts[2], 10, 64)
		rec, err := r.st.Get(context.Background(), Key{parts[0], parts[1], a})
		return err == nil && rec.Status != StRunning
	}
	r.start()
	return r
}

func (r *rig) start() {
	var err error
	if r.st, err = OpenStore(filepath.Join(r.dir, "exec.db")); err != nil {
		r.t.Fatal(err)
	}
	if r.l, err = ledger.Open(filepath.Join(r.dir, "ledger.db")); err != nil {
		r.t.Fatal(err)
	}
	if r.clock, err = yardtime.Open(r.st.DB()); err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.ex = New(ctx, Config{Store: r.st, Clock: r.clock, Ledger: r.l, Halo: haloop.Client{Base: r.hs.URL, Key: "k"},
		HaloMode: "relaxed", Node: r.node, AllocRoot: r.node.root, ArtifactDir: filepath.Join(r.dir, "artifacts"),
		ImageDir: filepath.Join(r.dir, "images"), Repos: map[string]string{"fixture": r.repo},
		Valuations: map[string]ledger.Valuation{val.Digest: val}, Current: val.Digest,
		Ceilings: Limits{Tokens: 1 << 30, Charge: 1 << 30, Money: 0, Seconds: 3600}, Model: "m", MaxOut: 64, MinOut: 1,
		StartBound: 150 * time.Millisecond, UnreachableBound: 300 * time.Millisecond, Tick: 10 * time.Millisecond,
		LeaseMs: 5000, MaxRunning: 10, MaxSubmitAgeMs: 600000, RetentionMs: 3600000})
	if err := r.ex.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	r.handler = r.ex.Handler("")
	r.mu.Unlock()
}

// crash: the executor process dies (routes cut, nothing revoked) and comes back over the same store and ledger.
func (r *rig) crash() {
	r.mu.Lock()
	r.handler = nil
	r.mu.Unlock()
	r.cancel()
	r.ex.Crash()
	r.l.Close()
	r.st.Close()
	r.start()
}

func (r *rig) close() {
	r.cancel()
	r.ex.Crash()
	r.node.setReachable(true)
	r.node.mu.Lock()
	for id := range r.node.vms {
		r.node.stopLocked(id)
	}
	r.node.mu.Unlock()
	r.l.Close()
	r.st.Close()
	r.api.Close()
	r.hs.Close()
}

type sub struct {
	op       string
	body     []byte
	digest   string
	notAfter int64
}

func (r *rig) do(method, path string, body []byte, h map[string]string) (int, map[string]any) {
	req, _ := http.NewRequest(method, r.api.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Yard-Principal", "cordis")
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (r *rig) contract() (string, int64) {
	_, m := r.do("GET", "/v1/yard/contract", nil, nil)
	if m == nil {
		return "", 0
	}
	inc, _ := m["incarnation"].(string)
	t, _ := m["time_ms"].(float64)
	return inc, int64(t)
}

func (r *rig) submit(op string, seconds int64) (sub, int) {
	inc, now := r.contract()
	task := map[string]any{"agent": "claude", "route": "local", "input": map[string]string{"repo": "fixture", "commit": "HEAD"},
		"change": "", "instructions": []string{"review"}, "output": json.RawMessage(reviewSchema),
		"limits": map[string]int64{"tokens": 100000, "charge": 100000, "money_micro_usd": 0, "seconds": seconds}, "valuation": val.Digest}
	s := sub{op: op, notAfter: now + 120000}
	s.body, _ = json.Marshal(map[string]any{"operation_id": op, "attempt": 0, "not_after": s.notAfter, "api": "agent", "request": task})
	sum := sha256.Sum256(s.body)
	s.digest = hex.EncodeToString(sum[:])
	code, _ := r.do("POST", "/v1/operations", s.body, map[string]string{"Yard-Incarnation": inc, "Yard-Digest": s.digest})
	return s, code
}

func (r *rig) verb(s sub, method, what string) (int, map[string]any) {
	inc, _ := r.contract()
	p := "/v1/operations/" + s.op + "/0"
	if what != "" {
		p += "/" + what
	}
	return r.do(method, p, []byte{}, map[string]string{"Yard-Incarnation": inc, "Yard-Not-After": fmt.Sprint(s.notAfter), "Yard-Digest": s.digest})
}

// TestExecutorFaults: attempts with drawn workers run through an executor crash, a node outage, a lost start answer
// and cancels. Every attempt ends; at most one worker per attempt ever runs at once (oneLive); no model call succeeds
// after an attempt's record is done (noSpendAfterFinal); "stopped" means stopped (stoppedIsStopped); each outcome
// matches its worker; what halo really ran is charged (accounted), and exactly when the report says exact; a
// fenced worker gets an execution_stopped correction once the node is back.
func TestExecutorFaults(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		r := newRig(t)
		defer r.close()
		n := hegel.Draw(ht, hegel.Integers(1, 3))
		type att struct {
			s      sub
			kind   int
			cancel bool
		}
		atts := make([]att, n)
		for i := range atts {
			atts[i].kind = hegel.Draw(ht, hegel.Integers(0, nKinds-1))
			atts[i].cancel = atts[i].kind == wHang && hegel.Draw(ht, hegel.Booleans())
			key := Key{"cordis", fmt.Sprintf("op%d", i), 0}
			r.node.mu.Lock()
			r.node.kinds[key.String()] = atts[i].kind
			r.node.mu.Unlock()
		}
		r.node.mu.Lock()
		r.node.loseStart = hegel.Draw(ht, hegel.Booleans())
		r.node.lateStart = hegel.Draw(ht, hegel.Booleans())
		r.node.mu.Unlock()
		for i := range atts {
			var code int
			atts[i].s, code = r.submit(fmt.Sprintf("op%d", i), 2)
			if code != 202 {
				ht.Fatalf("submit %d: HTTP %d", i, code)
			}
		}
		fault := hegel.Draw(ht, hegel.Integers(0, 2)) // 0 none, 1 executor crash, 2 node outage
		time.Sleep(time.Duration(hegel.Draw(ht, hegel.Integers(0, 200))) * time.Millisecond)
		switch fault {
		case 1:
			r.crash()
		case 2:
			r.node.setReachable(false)
			time.Sleep(time.Duration(hegel.Draw(ht, hegel.Integers(100, 700))) * time.Millisecond)
			r.node.setReachable(true)
		}
		for i := range atts {
			if atts[i].cancel {
				r.verb(atts[i].s, "POST", "cancel")
			}
		}
		// every attempt ends (the node is reachable from here on)
		deadline := time.Now().Add(20 * time.Second)
		outs := make([]map[string]any, n)
		for i := range atts {
			for time.Now().Before(deadline) {
				_, v := r.verb(atts[i].s, "GET", "")
				if v != nil && v["status"] == "done" {
					outs[i], _ = v["outcome"].(map[string]any)
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if outs[i] == nil {
				ht.Fatalf("attempt %d (%s) did not end", i, kindName[atts[i].kind])
			}
		}
		time.Sleep(500 * time.Millisecond) // let any late start land
		r.node.mu.Lock()
		if r.node.staleRuns > 0 {
			r.node.mu.Unlock()
			ht.Fatalf("a replaced allocation ran (%d): its late start was not refused", r.node.staleRuns)
		}
		for a, m := range r.node.maxAlive {
			if m > 1 {
				r.node.mu.Unlock()
				ht.Fatalf("oneLive: %s had %d workers alive at once", a, m)
			}
		}
		r.node.mu.Unlock()
		for i, o := range outs {
			outcome, _ := o["outcome"].(string)
			execution, _ := o["execution"].(string)
			ht.Note(fmt.Sprintf("attempt %d %s cancel=%v fault=%d -> %s %s %v", i, kindName[atts[i].kind], atts[i].cancel, fault, outcome, execution, o["why"]))
			key := Key{"cordis", fmt.Sprintf("op%d", i), 0}
			// stoppedIsStopped
			if execution == "stopped" {
				alloc, _ := o["allocation"].(string)
				r.node.mu.Lock()
				v := r.node.vms[alloc]
				running := v != nil && v.state == "running"
				r.node.mu.Unlock()
				if running {
					ht.Fatalf("attempt %d reported stopped while its worker runs", i)
				}
			}
			// the outcome matches the worker, unless a fault or the executor fenced it
			want := map[int]string{wOK: "completed", wInvalid: "invalid_output", wCrash: "worker_failed", wHang: "timeout"}[atts[i].kind]
			if atts[i].cancel {
				want = "cancelled"
			}
			if outcome != want && !(execution == "unconfirmed" && outcome == "worker_failed") &&
				!(atts[i].kind == wHang && (outcome == "cancelled" || outcome == "timeout")) {
				ht.Fatalf("attempt %d (%s): outcome %s, want %s", i, kindName[atts[i].kind], outcome, want)
			}
			// accounted, exact: what halo ran for this attempt's allocations vs. the spend
			spend, _ := o["spend"].(map[string]any)
			var charged int64
			if tk, ok := spend["tokens"].(map[string]any); ok {
				for _, c := range tk {
					p, _ := c.(map[string]any)
					cf, _ := p["confirmed"].(float64)
					um, _ := p["unresolved_max"].(float64)
					charged += int64(cf + um)
				}
			}
			var real int64
			r.halo.Mu.Lock()
			for op, u := range r.halo.Real {
				r.node.mu.Lock()
				for id, v := range r.node.vms {
					if v.attempt == key.String() && strings.HasPrefix(op, id[:16]+".") {
						real += u.Prompt + u.Completion
					}
				}
				r.node.mu.Unlock()
			}
			r.halo.Mu.Unlock()
			if real > charged {
				ht.Fatalf("attempt %d: halo ran %d tokens, charged %d", i, real, charged)
			}
			if spend["certainty"] == "exact" && real != charged {
				ht.Fatalf("attempt %d: exact report charged %d, halo ran %d", i, charged, real)
			}
			// a fenced worker's execution is confirmed later, by a correction
			if execution == "unconfirmed" {
				found := false
				for j := 0; j < 200 && !found; j++ {
					_, c := r.do("GET", "/v1/yard/corrections?after=0", nil, nil)
					cs, _ := c["corrections"].([]any)
					for _, x := range cs {
						m, _ := x.(map[string]any)
						if m["operation_id"] == key.Op && m["kind"] == "execution_stopped" {
							found = true
						}
					}
					time.Sleep(20 * time.Millisecond)
				}
				if !found {
					ht.Fatalf("attempt %d: no execution_stopped correction after the node came back", i)
				}
			}
		}
		// noSpendAfterFinal: give any surviving worker a moment, then count
		time.Sleep(100 * time.Millisecond)
		r.node.mu.Lock()
		late := r.node.lateCalls
		r.node.mu.Unlock()
		if late > 0 {
			ht.Fatalf("noSpendAfterFinal: %d model calls succeeded after their attempt was done", late)
		}
	}, hegel.WithTestCases(25))
}

// The envelope: duplicates, conflicts, never_accepted vs closed, cancel tombstones, ack releasing only the record.
func TestEnvelope(t *testing.T) {
	r := newRig(t)
	defer r.close()
	r.node.kinds["cordis/a/0"] = wOK
	s, code := r.submit("a", 30)
	if code != 202 {
		t.Fatalf("submit: %d", code)
	}
	inc, _ := r.contract()
	if code, v := r.do("POST", "/v1/operations", s.body, map[string]string{"Yard-Incarnation": inc}); code != 200 || v["status"] == nil {
		t.Fatalf("duplicate: %d %v", code, v)
	}
	other := bytes.Replace(s.body, []byte(`"review"`), []byte(`"review again"`), 1)
	if code, _ := r.do("POST", "/v1/operations", other, map[string]string{"Yard-Incarnation": inc}); code != 409 {
		t.Fatalf("conflict: %d", code)
	}
	if code, _ := r.do("POST", "/v1/operations", s.body, map[string]string{"Yard-Incarnation": "stale"}); code != 409 {
		t.Fatalf("stale incarnation: %d", code)
	}
	if code, v := r.do("GET", "/v1/operations/a/0", nil, map[string]string{"Yard-Incarnation": "another",
		"Yard-Not-After": fmt.Sprint(s.notAfter), "Yard-Digest": s.digest}); code != 200 || v["status"] != "unknown" {
		t.Fatalf("another incarnation: %d %v", code, v)
	}
	ghost := sub{op: "never", digest: "d", notAfter: s.notAfter}
	if _, v := r.verb(ghost, "GET", ""); v["status"] != "never_accepted" {
		t.Fatalf("no record before the deadline: %v", v)
	}
	gone := sub{op: "gone", digest: "d", notAfter: 1}
	if _, v := r.verb(gone, "GET", ""); v["status"] != "closed" {
		t.Fatalf("no record after the deadline: %v", v)
	}
	tomb := sub{op: "tomb", digest: "dt", notAfter: s.notAfter}
	if _, v := r.verb(tomb, "POST", "cancel"); v["status"] != "cancelled_before_accept" {
		t.Fatalf("cancel without a record: %v", v)
	}
	var out map[string]any
	for i := 0; i < 500; i++ {
		if _, v := r.verb(s, "GET", ""); v["status"] == "done" {
			out = v
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if out == nil {
		t.Fatal("did not end")
	}
	o := out["outcome"].(map[string]any)
	arts, _ := o["artifacts"].([]any)
	if o["outcome"] != "completed" || len(arts) == 0 {
		t.Fatalf("outcome %v", o)
	}
	id := arts[0].(map[string]any)["id"].(string)
	// a workflow lease, then the ack: the artifact outlives the ack, and goes once the workflow lets go
	if code, _ := r.do("POST", "/v1/artifacts/"+id+"/leases", []byte(`{"holder":"wf:1","until":9223372036854775807}`), nil); code != 200 {
		t.Fatalf("lease: %d", code)
	}
	if _, v := r.verb(s, "POST", "ack"); v["status"] != "released" {
		t.Fatalf("ack: %v", v)
	}
	r.st.db.Exec(`UPDATE artifacts SET floor = 0`) // the retention floor has passed
	r.st.GC(context.Background(), r.clock.Now())
	if code, _ := r.do("GET", "/v1/artifacts/"+id, nil, nil); code != 200 {
		t.Fatalf("leased artifact after the ack: %d", code)
	}
	r.do("DELETE", "/v1/artifacts/"+id+"/leases/wf:1", nil, nil)
	r.st.GC(context.Background(), r.clock.Now())
	if code, v := r.do("GET", "/v1/artifacts/"+id, nil, nil); code != 410 || v["error"] != "artifact_unavailable" {
		t.Fatalf("released artifact: %d %v", code, v)
	}
}

// Regression (AG2 live probe, node_outage): a frozen yard-node hangs calls instead of refusing them, and with a
// node-call timeout longer than the unreachable bound the executor never noticed the outage. Every node call has its
// own deadline inside the bound, so a worker behind a node frozen past the bound is fenced (worker_failed,
// unconfirmed) and corrected (execution_stopped) once the node is back.
func TestNodeOutageFences(t *testing.T) {
	r := newRig(t)
	defer r.close()
	r.node.kinds["cordis/hang/0"] = wHang
	s, code := r.submit("hang", 60)
	if code != 202 {
		t.Fatalf("submit: %d", code)
	}
	for i := 0; i < 200; i++ {
		if _, v := r.verb(s, "GET", ""); v["stage"] == "started" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.node.setReachable(false)
	var out map[string]any
	for i := 0; i < 300 && out == nil; i++ { // 3 s: ten times the 300 ms bound
		if _, v := r.verb(s, "GET", ""); v["status"] == "done" {
			out, _ = v["outcome"].(map[string]any)
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.node.setReachable(true)
	if out == nil || out["outcome"] != "worker_failed" || out["execution"] != "unconfirmed" {
		t.Fatalf("a worker behind a frozen node: %v", out)
	}
	for i := 0; i < 200; i++ {
		_, c := r.do("GET", "/v1/yard/corrections?after=0", nil, nil)
		if cs, _ := c["corrections"].([]any); len(cs) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no execution_stopped correction after the node came back")
}
