package agentexec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"yard/internal/agentroute"
	"yard/internal/driver"
	"yard/internal/haloop"
	"yard/internal/jsonshape"
	"yard/internal/ledger"
	"yard/internal/node"
	"yard/internal/yardtime"
)

// Limits of a task (section 6): each required, each enforced on its own.
type Limits struct {
	Tokens  int64 `json:"tokens"`
	Charge  int64 `json:"charge"`
	Money   int64 `json:"money_micro_usd"`
	Seconds int64 `json:"seconds"`
}

// Task is the request of an agent operation (the AgentTask of RFC 0008).
type Task struct {
	Agent        string                        `json:"agent"`
	Route        string                        `json:"route"`
	Input        struct{ Repo, Commit string } `json:"input"`
	Change       string                        `json:"change"`
	Instructions []string                      `json:"instructions"`
	Output       json.RawMessage               `json:"output"`
	Limits       Limits                        `json:"limits"`
	Valuation    string                        `json:"valuation"`
}

type Config struct {
	Store                              *Store
	Clock                              *yardtime.Clock
	Ledger                             *ledger.Ledger
	Halo                               haloop.Client // copied per attempt, with the attempt's principal
	HaloMode                           string
	Node                               NodeAPI
	AllocRoot                          string // yard-node's allocation directory (same host): each allocation's route socket lives there
	ArtifactDir, ImageDir              string
	Repos                              map[string]string           // registered repositories: name -> path
	Valuations                         map[string]ledger.Valuation // offered valuations by digest
	Current                            string                      // the valuation the contract offers now
	Ceilings                           Limits
	Kernel, Rootfs                     string
	VCPU, MemMiB                       int64
	Model                              string
	MaxOut, MinOut, OutputCap          int64
	StartBound, UnreachableBound, Tick time.Duration
	LeaseMs                            int64
	MaxRunning                         int
	MaxSubmitAgeMs                     int64
	RetentionMs                        int64 // the artifacts' retention floor
	Logf                               func(string, ...any)
}

type Exec struct {
	cfg  Config
	ctx  context.Context
	mu   sync.Mutex
	runs map[Key]*run
	wg   sync.WaitGroup
}

type run struct {
	alloc     string
	route     *agentroute.Server
	exhausted string
}

func New(ctx context.Context, cfg Config) *Exec {
	if cfg.Tick <= 0 {
		cfg.Tick = 500 * time.Millisecond
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Exec{cfg: cfg, ctx: ctx, runs: map[Key]*run{}}
}

func newAllocID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *Exec) now() int64 { return e.cfg.Clock.Now() }

// nodeAPI is yard-node with a deadline on every call. A frozen node hangs calls rather than refusing them, so each
// call has its own deadline inside the unreachable bound, and a call that runs out counts as unreachable (F4): quick
// calls (observe, lease, start, list, forget) get a third of the bound; stop, tombstone and result, which wait for a
// reap or a file, get the bound. (The AG2 live probe found the executor blind to a frozen node whose calls outlasted
// the bound.)
func (e *Exec) nodeAPI() NodeAPI { return bounded{e.cfg.Node, e.cfg.UnreachableBound} }

type bounded struct {
	n     NodeAPI
	bound time.Duration
}

func (b bounded) ctx(parent context.Context, long bool) (context.Context, context.CancelFunc) {
	d := b.bound / 3
	if long {
		d = b.bound
	}
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	return context.WithTimeout(parent, d)
}

func (b bounded) Start(ctx context.Context, id string, s node.Spec) (node.State, error) {
	c, cancel := b.ctx(ctx, false)
	defer cancel()
	return b.n.Start(c, id, s)
}
func (b bounded) Get(ctx context.Context, id string) (node.State, error) {
	c, cancel := b.ctx(ctx, false)
	defer cancel()
	return b.n.Get(c, id)
}
func (b bounded) Stop(ctx context.Context, id string) (node.State, error) {
	c, cancel := b.ctx(ctx, true)
	defer cancel()
	return b.n.Stop(c, id)
}
func (b bounded) Tombstone(ctx context.Context, id string) (node.State, error) {
	c, cancel := b.ctx(ctx, true)
	defer cancel()
	return b.n.Tombstone(c, id)
}
func (b bounded) Lease(ctx context.Context, id string, ms int64) error {
	c, cancel := b.ctx(ctx, false)
	defer cancel()
	return b.n.Lease(c, id, ms)
}
func (b bounded) Result(ctx context.Context, id string) ([]byte, error) {
	c, cancel := b.ctx(ctx, true)
	defer cancel()
	return b.n.Result(c, id)
}
func (b bounded) List(ctx context.Context) ([]node.State, error) {
	c, cancel := b.ctx(ctx, false)
	defer cancel()
	return b.n.List(c)
}
func (b bounded) Forget(ctx context.Context, id string) error {
	c, cancel := b.ctx(ctx, false)
	defer cancel()
	return b.n.Forget(c, id)
}

// Start resumes every running attempt from its durable stage, and runs the background loops (fences, node
// reconciliation, retention).
func (e *Exec) Start() error {
	recs, err := e.cfg.Store.Running(e.ctx)
	if err != nil {
		return err
	}
	for _, r := range recs {
		e.launch(r.Key)
	}
	e.wg.Add(1)
	go e.background()
	return nil
}

// Wait waits for every attempt's driver and the background loops to stop (after the context ends).
func (e *Exec) Wait() { e.wg.Wait() }

// Crash stops the executor as a process death would (tests): after the context is cancelled and the drivers have
// stopped, every route's socket is cut, with nothing revoked or ended in the ledger.
func (e *Exec) Crash() {
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ru := range e.runs {
		if ru.route != nil {
			ru.route.Close()
		}
	}
}

func (e *Exec) launch(k Key) {
	e.mu.Lock()
	if _, ok := e.runs[k]; ok {
		e.mu.Unlock()
		return
	}
	e.runs[k] = &run{}
	e.mu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.drive(k)
		e.mu.Lock()
		if e.ctx.Err() == nil { // stopping: keep it, so Crash can cut its route
			delete(e.runs, k)
		}
		e.mu.Unlock()
	}()
}

func (e *Exec) runOf(k Key) *run {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs[k]
}

func (e *Exec) sleep() bool {
	select {
	case <-e.ctx.Done():
		return false
	case <-time.After(e.cfg.Tick):
		return true
	}
}

// drive moves one attempt through its stages. Every stage reads its durable record and writes the next stage
// before or after its external step as section 5 says; a restart resumes from whatever the record says.
func (e *Exec) drive(k Key) {
	for e.ctx.Err() == nil {
		rec, err := e.cfg.Store.Get(e.ctx, k)
		if err != nil {
			e.cfg.Logf("%s: %v", k, err)
			if !e.sleep() {
				return
			}
			continue
		}
		if rec.Status != StRunning {
			return
		}
		var step error
		switch rec.Stage {
		case StageAccepted:
			step = e.accept(&rec)
		case StageAllocating:
			step = e.allocating(&rec)
		case StageStarted:
			step = e.started(&rec)
		case StageCapturing:
			step = e.capture(&rec)
		case StageEnding:
			step = e.end(&rec)
		default:
			step = fmt.Errorf("unknown stage %q", rec.Stage)
		}
		if step != nil && e.ctx.Err() == nil {
			e.cfg.Logf("%s (%s): %v", k, rec.Stage, step)
			if !e.sleep() {
				return
			}
		}
	}
}

func parseTask(body []byte) (Task, error) {
	var b struct {
		Request Task `json:"request"`
	}
	err := json.Unmarshal(body, &b)
	return b.Request, err
}

// partial is the outcome being assembled before the spend is known.
type partial struct {
	Outcome    string          `json:"outcome"`
	Execution  string          `json:"execution"`
	Why        string          `json:"why,omitempty"`
	Exhausted  string          `json:"exhausted,omitempty"`
	Value      json.RawMessage `json:"value,omitempty"`
	Errors     []string        `json:"validation_errors,omitempty"`
	Artifacts  []Artifact      `json:"artifacts,omitempty"`
	Allocation string          `json:"allocation,omitempty"`
	Reallocs   int             `json:"reallocs"`
	Spend      json.RawMessage `json:"spend,omitempty"`
	Unresolved int             `json:"unresolved_left,omitempty"`
}

func readPartial(r Rec) partial {
	var p partial
	if r.Outcome != nil {
		json.Unmarshal(r.Outcome, &p)
	}
	return p
}

func (r *Rec) setPartial(p partial) { r.Outcome, _ = json.Marshal(p) }

// accept: the ledger's attempt (limits, pinned valuation) and the first allocation id, written before anything
// external happens.
func (e *Exec) accept(r *Rec) error {
	t, err := parseTask(r.Body)
	if err != nil {
		return err
	}
	lim := ledger.Limits{Tokens: t.Limits.Tokens, Charge: t.Limits.Charge, Money: t.Limits.Money}
	if err := e.cfg.Ledger.Begin(r.Key.String(), lim, e.cfg.Valuations[t.Valuation]); err != nil {
		return err
	}
	r.Stage, r.Alloc = StageAllocating, newAllocID()
	return e.cfg.Store.Update(e.ctx, *r)
}

func (e *Exec) allocDir(alloc string) string { return filepath.Join(e.cfg.AllocRoot, alloc) }

// bindRoute activates the allocation's scope: the broker route on its own socket (F2). Idempotent per allocation.
func (e *Exec) bindRoute(r *Rec) error {
	ru := e.runOf(r.Key)
	if ru == nil {
		return errors.New("no run")
	}
	e.mu.Lock()
	bound := ru.route != nil && ru.alloc == r.Alloc
	e.mu.Unlock()
	if bound {
		return nil
	}
	if err := os.MkdirAll(e.allocDir(r.Alloc), 0o700); err != nil {
		return err
	}
	sock := filepath.Join(e.allocDir(r.Alloc), "v.sock_4000")
	if len(sock) > 107 { // sun_path: the allocation root must be short enough for every allocation's sockets
		return fmt.Errorf("socket path %q is %d bytes, over the 107 a Unix socket allows", sock, len(sock))
	}
	os.Remove(sock) // a stale socket from before a restart: nobody serves it
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	halo := e.cfg.Halo
	halo.Principal = "yard:" + r.Key.String()
	k := r.Key
	route := agentroute.New(agentroute.Config{Attempt: k.String(), Alloc: r.Alloc[:16], Ledger: e.cfg.Ledger, Halo: &halo,
		Route: "local", Mode: e.cfg.HaloMode, MaxOut: e.cfg.MaxOut, MinOut: e.cfg.MinOut, NotAfter: 60 * time.Second,
		Logf: func(f string, a ...any) { e.cfg.Logf("%s route: "+f, append([]any{k}, a...)...) },
		OnCall: func(id string, at time.Time, in, out int64) {
			if out == 0 {
				e.mu.Lock()
				if ru := e.runs[k]; ru != nil {
					ru.exhausted = "limit"
				}
				e.mu.Unlock()
			}
		}})
	go route.Serve(ln)
	e.mu.Lock()
	ru.alloc, ru.route = r.Alloc, route
	e.mu.Unlock()
	return nil
}

// revokeRoute ends the scope (F6): in this process the revocation is synchronous, so it is confirmed when it
// returns. After a restart nothing serves an old allocation's socket: that scope is revoked by construction.
func (e *Exec) revokeRoute(r *Rec) string {
	ru := e.runOf(r.Key)
	if ru == nil {
		return ""
	}
	e.mu.Lock()
	route, ex := ru.route, ru.exhausted
	ru.route = nil
	e.mu.Unlock()
	if route != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		route.Revoke(ctx)
		if x := route.Exhausted(); x != "" {
			ex = x
		}
	}
	return ex
}

func (e *Exec) spec(r *Rec, t Task) node.Spec {
	repo := e.cfg.Repos[t.Input.Repo]
	img, _, _ := BuildInput(repo, t.Input.Commit, t.Change, e.cfg.ImageDir) // built at submit; cached
	prompt := ""
	for i, s := range t.Instructions {
		if i > 0 {
			prompt += "\n\n"
		}
		prompt += s
	}
	task := driver.Claude(prompt, string(t.Output), e.cfg.Model, e.cfg.OutputCap)
	tj, _ := json.Marshal(task)
	return node.Spec{VCPU: e.cfg.VCPU, MemMiB: e.cfg.MemMiB, Kernel: e.cfg.Kernel, Rootfs: e.cfg.Rootfs, Input: img,
		Task: tj, LeaseMs: e.cfg.LeaseMs, Labels: map[string]string{"attempt": r.Key.String()}}
}

// fence makes an unreachable worker harmless (F4): its scope revoked, a tombstone owed to yard-node, the attempt
// ended worker_failed with execution unconfirmed. Its result is never captured (F5).
func (e *Exec) fence(r *Rec, why string) error {
	ex := e.revokeRoute(r)
	p := readPartial(*r)
	p.Outcome, p.Execution, p.Why, p.Allocation, p.Reallocs = "worker_failed", "unconfirmed", why, r.Alloc, r.Reallocs
	if ex != "" {
		p.Exhausted = ex
	}
	r.setPartial(p)
	r.Fence, r.Stage = r.Alloc, StageEnding
	return e.cfg.Store.Update(e.ctx, *r)
}

// toCapture records why the run is ending (if it is not the worker finishing) and moves to capturing.
func (e *Exec) toCapture(r *Rec, outcome, why string) error {
	p := readPartial(*r)
	if outcome != "" && p.Outcome == "" {
		p.Outcome, p.Why = outcome, why
	}
	r.setPartial(p)
	r.Stage = StageCapturing
	return e.cfg.Store.Update(e.ctx, *r)
}

// allocating: the scope is active before the start request (F2); the start is resolved by yard-node's table, never
// assumed. A start still absent past the bound is tombstoned before the attempt allocates again, at most once (F3).
func (e *Exec) allocating(r *Rec) error {
	t, err := parseTask(r.Body)
	if err != nil {
		return err
	}
	if err := e.bindRoute(r); err != nil {
		return err
	}
	if r.Cancel { // cancelled before the worker ran: tombstone the allocation, end cancelled
		if _, err := e.nodeAPI().Tombstone(e.ctx, r.Alloc); err != nil {
			return e.fence(r, "cancel: node unreachable")
		}
		return e.toCapture(r, "cancelled", "cancelled before the worker started")
	}
	spec := e.spec(r, t)
	t0 := time.Now()
	var lastReach = time.Now()
	for e.ctx.Err() == nil {
		st, err := e.nodeAPI().Start(e.ctx, r.Alloc, spec) // idempotent: a lost answer is asked again
		if errors.Is(err, ErrTombstoned) {
			st.State, err = "tombstoned", nil
		}
		if err == nil {
			lastReach = time.Now()
			switch st.State {
			case "running":
				r.Stage = StageStarted
				return e.cfg.Store.Update(e.ctx, *r)
			case "exited":
				return e.toCapture(r, "", "")
			}
		} else if time.Since(lastReach) > e.cfg.UnreachableBound {
			return e.fence(r, "start: node unreachable")
		}
		if time.Since(t0) > e.cfg.StartBound && err == nil {
			// absent (or refused) past the bound: tombstone it there, so a late start is refused, then allocate again
			if _, terr := e.nodeAPI().Tombstone(e.ctx, r.Alloc); terr != nil {
				continue
			}
			e.revokeRoute(r)
			if r.Reallocs >= 1 {
				return e.toCapture(r, "worker_failed", "the worker did not start")
			}
			r.Reallocs++
			r.Alloc = newAllocID()
			return e.cfg.Store.Update(e.ctx, *r)
		}
		if !e.sleep() {
			return nil
		}
	}
	return nil
}

// started: renew the lease, watch the worker, apply cancel and the time limit (in Yard-Time, from acceptance).
func (e *Exec) started(r *Rec) error {
	t, err := parseTask(r.Body)
	if err != nil {
		return err
	}
	if err := e.bindRoute(r); err != nil { // after a restart: the scope again, on the same socket
		return err
	}
	deadline := r.Created + t.Limits.Seconds*1000
	lastReach := time.Now()
	for e.ctx.Err() == nil {
		cur, err := e.cfg.Store.Get(e.ctx, r.Key)
		if err == nil {
			r.Cancel = cur.Cancel
		}
		_ = e.nodeAPI().Lease(e.ctx, r.Alloc, e.cfg.LeaseMs)
		st, err := e.nodeAPI().Get(e.ctx, r.Alloc)
		if err != nil {
			if time.Since(lastReach) > e.cfg.UnreachableBound {
				return e.fence(r, "node unreachable")
			}
		} else {
			lastReach = time.Now()
			switch {
			case st.State != "running":
				return e.toCapture(r, "", "")
			case r.Cancel:
				return e.toCapture(r, "cancelled", "the cancel verb")
			case e.now() > deadline:
				return e.toCapture(r, "timeout", "the task's wall-time limit")
			}
		}
		if !e.sleep() {
			return nil
		}
	}
	return nil
}

type guestResult struct {
	Type      string `json:"type"`
	Exit      int    `json:"exit"`
	Signal    string `json:"signal"`
	Stdout    []byte `json:"stdout"`
	Stderr    []byte `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error"`
}

// capture: the worker is stopped and reaped first (F5); then its result, the artifacts and the structural
// validation. Every step is idempotent, so a restart repeats it.
func (e *Exec) capture(r *Rec) error {
	t, err := parseTask(r.Body)
	if err != nil {
		return err
	}
	st, err := e.nodeAPI().Stop(e.ctx, r.Alloc)
	if err != nil {
		return e.fence(r, "stop: node unreachable")
	}
	if st.State == "running" {
		return errors.New("stop did not reap the worker")
	}
	p := readPartial(*r)
	p.Execution, p.Allocation, p.Reallocs = "stopped", r.Alloc, r.Reallocs
	holder := "op:" + r.Key.String()
	floor := e.now() + e.cfg.RetentionMs
	put := func(kind string, b []byte) {
		if len(b) == 0 {
			return
		}
		if a, err := e.cfg.Store.PutArtifact(e.ctx, e.cfg.ArtifactDir, r.Key, kind, b, floor, holder, Forever); err == nil {
			p.Artifacts = append(p.Artifacts, a)
		} else {
			e.cfg.Logf("%s: artifact %s: %v", r.Key, kind, err)
		}
	}
	p.Artifacts = nil
	if con, err := os.ReadFile(filepath.Join(e.allocDir(r.Alloc), "console.log")); err == nil {
		put("console", con)
	}
	var g guestResult
	raw, rerr := e.nodeAPI().Result(e.ctx, r.Alloc)
	if rerr == nil && json.Unmarshal(raw, &g) == nil && g.Type == "result" {
		put("transcript", g.Stdout)
		put("stderr", g.Stderr)
	}
	if p.Outcome == "" { // the worker ended on its own: what did it leave?
		ru := e.runOf(r.Key)
		if ru != nil && ru.route != nil && ru.route.Exhausted() != "" {
			p.Exhausted = ru.route.Exhausted()
		}
		switch {
		case rerr != nil || g.Type != "result":
			p.Outcome, p.Why = "worker_failed", "no result from the worker"
		case p.Exhausted != "":
			p.Outcome = "budget_exhausted"
		default:
			value, why := driver.ClaudeResult(g.Stdout)
			if value == nil {
				p.Outcome, p.Errors = "invalid_output", []string{why}
				break
			}
			schema, err := jsonshape.Parse(t.Output)
			if err != nil {
				p.Outcome, p.Errors = "invalid_output", []string{"schema: " + err.Error()}
				break
			}
			if errs := schema.Validate(value); len(errs) > 0 {
				p.Outcome, p.Errors = "invalid_output", errs
			} else {
				p.Outcome = "completed"
				var v struct {
					Verdict string `json:"verdict"`
				}
				if json.Unmarshal(value, &v) == nil && v.Verdict == "insufficient_information" {
					p.Outcome = "insufficient"
				}
			}
			p.Value = value
		}
	}
	r.setPartial(p)
	r.Stage = StageEnding
	return e.cfg.Store.Update(e.ctx, *r)
}

// end: the scope revoked and confirmed (F6), unresolved calls resolved from halo's records while it has them, the
// spend reported (never waiting for exactness), then done.
func (e *Exec) end(r *Rec) error {
	if ex := e.revokeRoute(r); ex != "" {
		p := readPartial(*r)
		p.Exhausted = ex
		r.setPartial(p)
	}
	_ = e.cfg.Ledger.End(e.ctx, r.Key.String())
	halo := e.cfg.Halo
	halo.Principal = "yard:" + r.Key.String()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	left, err := agentroute.Resolve(ctx, e.cfg.Ledger, &halo, r.Key.String())
	if err != nil {
		return err
	}
	spend, err := e.cfg.Ledger.Report(ctx, r.Key.String())
	if err != nil {
		return err
	}
	sw, _ := json.Marshal(spend)
	var sm map[string]any
	json.Unmarshal(sw, &sm)
	sm["wall_s"] = (e.now() - r.Created) / 1000
	p := readPartial(*r)
	p.Spend, _ = json.Marshal(sm)
	p.Unresolved = left
	r.setPartial(p)
	r.Status, r.Stage, r.Ended = StDone, StageEnded, e.now()
	if err := e.cfg.Store.Update(e.ctx, *r); err != nil {
		return err
	}
	if r.Fence == "" {
		_ = e.nodeAPI().Forget(e.ctx, r.Alloc)
	}
	return nil
}

// background: owed tombstones (F4, appending execution_stopped corrections), node reconciliation (F7: any VM that is
// not an attempt's current allocation is tombstoned), retention (artifacts' GC, old records' prune).
func (e *Exec) background() {
	defer e.wg.Done()
	t := time.NewTicker(2 * e.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		if fenced, err := e.cfg.Store.Fenced(e.ctx); err == nil {
			for _, r := range fenced {
				st, err := e.nodeAPI().Tombstone(e.ctx, r.Fence)
				if err != nil || st.State == "running" {
					continue
				}
				e.cfg.Store.AppendCorrection(e.ctx, r.Key, "execution_stopped",
					map[string]any{"allocation": r.Fence, "node_state": st.State, "exit": st.Exit}, e.now())
				gone := r.Fence
				r.Fence = ""
				e.cfg.Store.Update(e.ctx, r)
				e.nodeAPI().Forget(e.ctx, gone)
			}
		}
		if list, err := e.nodeAPI().List(e.ctx); err == nil {
			current := map[string]bool{}
			if recs, err := e.cfg.Store.Running(e.ctx); err == nil {
				for _, r := range recs {
					current[r.Alloc] = true
				}
				for _, st := range list {
					if st.State == "running" && !current[st.ID] {
						e.cfg.Logf("reconcile: %s is not current; tombstoning", st.ID)
						e.nodeAPI().Tombstone(e.ctx, st.ID)
					}
				}
			}
		}
		e.cfg.Store.GC(e.ctx, e.now())
		e.cfg.Store.Prune(e.ctx, e.now())
	}
}
