package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"yard/internal/issuer"
)

func testCfg() Config {
	return Config{OpTimeout: 200, MaxAttempts: 5, Clients: []string{"msg", "timer", "approval"},
		Policies: map[string]Policy{
			"own-code": {IdleAfter: 1000, MaxAge: 60_000},
			"warm":     {KeepWarm: true, IdleAfter: 1000, MaxAge: 60_000},
		}}
}

type rig struct {
	t     *testing.T
	path  string
	st    *Store
	w     *fakeWorld
	clk   *clock
	facts *factLog
	m     *Machine
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, path: filepath.Join(t.TempDir(), "yard.db"), w: newFakeWorld(), clk: &clock{t: 1}, facts: &factLog{}}
	r.start()
	return r
}

func (r *rig) start() {
	r.t.Helper()
	st, err := OpenOwned(r.path)
	if err != nil {
		r.t.Fatal(err)
	}
	r.st = st
	m, err := Start(context.Background(), st, testCfg(), r.w, r.facts, r.clk.now)
	if err != nil {
		r.t.Fatal(err)
	}
	r.m = m
}

func (r *rig) add(s, class, kind string) {
	r.t.Helper()
	r.w.addSession(s)
	if err := r.m.AddSession(s, class, kind); err != nil {
		r.t.Fatal(err)
	}
}

// settle waits until every copy in flight is one the test holds.
func (r *rig) settle() {
	for {
		r.m.mu.Lock()
		busy := false
		for id, n := range r.m.sending {
			if n > 0 {
				r.w.mu.Lock()
				ch := r.w.hold[r.m.ctl.Ops[id].Kind]
				r.w.mu.Unlock()
				busy = busy || ch == nil || closed(ch)
			}
		}
		r.m.mu.Unlock()
		if !busy {
			return
		}
		runtime.Gosched()
	}
}

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// pollUntil polls (advancing the clock by step ms) until cond or n polls.
func (r *rig) pollUntil(step int64, n int, cond func(c *Ctl) bool) bool {
	for i := 0; i < n; i++ {
		r.settle()
		if cond(r.m.State()) {
			return true
		}
		r.clk.add(step)
		_ = r.m.Poll(context.Background())
	}
	r.settle()
	return cond(r.m.State())
}

func state(s string, st State) func(c *Ctl) bool {
	return func(c *Ctl) bool { return c.Rows[s].State == st }
}

func (r *rig) suspend(s string) {
	r.t.Helper()
	if !r.pollUntil(300, 50, state(s, Suspended)) {
		r.t.Fatalf("not suspended: %+v", r.m.State().Rows[s])
	}
}

func TestMachineSuspendResume(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindFC)
	r.suspend("s1")
	c := r.m.State()
	row := c.Rows["s1"]
	if row.Token == 0 || row.CredEpoch != 2 || row.Inst != 0 {
		t.Fatalf("suspended row %+v", row)
	}
	if e, ok := r.m.Epoch("s1"); !ok || e != 2 {
		t.Fatalf("Epoch after suspend: %d %v", e, ok)
	}
	if len(r.w.insts["s1"]) != 0 || !r.w.artifacts["s1"][row.Ckpt] {
		t.Fatalf("world after suspend: insts %v artifacts %v", r.w.insts["s1"], r.w.artifacts["s1"])
	}
	if f := r.facts.named("suspend"); len(f) != 1 || f[0].Bytes != 4096 || f[0].DurationMs <= 0 {
		t.Fatalf("suspend fact %+v", f)
	}
	if err := r.m.Resume("s1", "msg", row.Token); err != nil {
		t.Fatal(err)
	}
	if !r.pollUntil(10, 50, state("s1", Active)) {
		t.Fatalf("not resumed: %+v", r.m.State().Rows["s1"])
	}
	r.pollUntil(10, 10, func(c *Ctl) bool { return len(r.w.artifacts["s1"]) == 0 })
	if len(r.w.artifacts["s1"]) != 0 {
		t.Fatalf("artifacts not deleted after resume: %v", r.w.artifacts["s1"])
	}
	if !r.w.creds["s1"][2] || r.w.starts[row.Ckpt] != 1 {
		t.Fatalf("creds %v starts %v", r.w.creds["s1"], r.w.starts)
	}
	if f := r.facts.named("resume"); len(f) != 1 || f[0].Resumes != 1 {
		t.Fatalf("resume fact %+v", f)
	}
}

func TestMachineKeepWarmNeverSuspends(t *testing.T) {
	r := newRig(t)
	r.add("w1", "warm", KindService)
	if r.pollUntil(500, 20, func(c *Ctl) bool { return c.Rows["w1"].State == Suspending }) {
		t.Fatal("keep-warm session began suspending")
	}
}

// The double-resume race through the Machine: one winner.
func TestMachineDoubleResumeRace(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindFC)
	r.suspend("s1")
	tok := r.m.Token("s1")
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, rejected := 0, 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := r.m.Resume("s1", testCfg().Clients[i%3], tok)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrTokenRejected):
				rejected++
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if won != 1 || rejected != 31 {
		t.Fatalf("won %d rejected %d", won, rejected)
	}
	r.pollUntil(10, 50, state("s1", Active))
	for ck, n := range r.w.starts {
		if n > 1 {
			t.Fatalf("checkpoint %d started %d times", ck, n)
		}
	}
}

// The race across independent store handles (two processes): exactly one
// conditional UPDATE wins.
func TestStoreConsumeRaceAcrossHandles(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindFC)
	r.suspend("s1")
	c := r.m.State()
	tok := c.Rows["s1"].Token
	next := c.Clone()
	if _, err := next.ResumeConsume("s1", "msg", tok); err != nil {
		t.Fatal(err)
	}
	row := next.Rows["s1"]
	op := next.Ops[row.Op]
	const n = 16
	var wg sync.WaitGroup
	results := make(chan bool, n+1)
	for i := 0; i < n; i++ {
		st, err := OpenStore(r.path)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o := op
			o.ID = op.ID + int64(i) // distinct op ids: only the UPDATE decides
			ok, err := st.ConsumeToken("s1", tok, row, o)
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}(i)
	}
	// and an expiry racing them (the TTL is long, so force the CAS directly)
	wg.Add(1)
	go func() {
		defer wg.Done()
		st, err := OpenStore(r.path)
		if err != nil {
			t.Error(err)
			return
		}
		defer st.Close()
		er := c.Rows["s1"]
		er.State, er.Token, er.Ckpt = Expired, 0, 0
		ok, err := st.Expire("s1", tok, er, nil)
		if err != nil {
			t.Error(err)
		}
		results <- ok
	}()
	wg.Wait()
	close(results)
	wins := 0
	for ok := range results {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d winners of one token", wins)
	}
}

// yard-ctl restarts while a restore is in flight: the new incarnation
// waits for it to settle, observes the instance, and completes; the
// checkpoint is started once.
func TestMachineRestartMidResume(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindFC)
	r.suspend("s1")
	release := r.w.holdKind(ORestore)
	if err := r.m.Resume("s1", "msg", r.m.Token("s1")); err != nil {
		t.Fatal(err)
	}
	// crash: abandon the Machine (its copy keeps running), start another
	r.st.Close()
	old := r.m
	r.start()
	if r.facts.count(ORestore, "restart_unknown") != 1 {
		t.Fatalf("outcome counts %v", r.facts.counts)
	}
	c := r.m.State()
	if c.Inc != 2 || c.DriverSet("s1")[0] != Recovery || c.Ops[c.Rows["s1"].Op].St != Unknown {
		t.Fatalf("after restart: inc %d drivers %v op %+v", c.Inc, c.DriverSet("s1"), c.Ops[c.Rows["s1"].Op])
	}
	// while the copy is in flight nothing resolves it
	r.clk.add(1000)
	_ = r.m.Poll(context.Background())
	if st := r.m.State().Ops[c.Rows["s1"].Op].St; st != Unknown {
		t.Fatalf("resolved while in flight: %s", st)
	}
	close(release) // the late effect lands
	old.Wait()
	if !r.pollUntil(10, 50, state("s1", Active)) {
		t.Fatalf("not resumed after restart: %+v", r.m.State().Rows["s1"])
	}
	for ck, n := range r.w.starts {
		if n != 1 {
			t.Fatalf("checkpoint %d started %d times", ck, n)
		}
	}
}

// A checkpoint that times out and completes late is waited for, then
// taken as done: no orphan, no second checkpoint.
func TestMachineCheckpointTimeoutLands(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindBhyve)
	release := r.w.holdKind(OCheckpoint)
	r.pollUntil(300, 50, func(c *Ctl) bool {
		return c.Rows["s1"].Phase == PCheckpoint && c.Ops[c.Rows["s1"].Op].St == Unknown
	})
	c := r.m.State()
	ck := c.Rows["s1"].Ckpt
	if c.Ops[ck].St != Unknown {
		t.Fatalf("checkpoint op %+v", c.Ops[ck])
	}
	r.pollUntil(300, 3, func(*Ctl) bool { return false })
	if r.m.State().Rows["s1"].Phase != PCheckpoint {
		t.Fatal("moved on while the checkpoint was in flight")
	}
	close(release)
	r.suspend("s1")
	c = r.m.State()
	if c.Rows["s1"].Ckpt != ck || len(r.w.artifacts["s1"]) != 1 {
		t.Fatalf("ckpt %d artifacts %v", c.Rows["s1"].Ckpt, r.w.artifacts["s1"])
	}
	if r.facts.count(OCheckpoint, "timeout") != 1 || r.facts.count(OCheckpoint, "resolved_done") != 1 ||
		r.facts.count(OCheckpoint, "answer_ignored") != 1 || r.facts.count(OQuiesce, "answer_done") != 1 {
		t.Fatalf("outcome counts %v", r.facts.counts)
	}
}

// Activity between the decision and the quiesce aborts the suspend.
func TestMachineActivityAbortsSuspend(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindJail)
	release := r.w.holdKind(OQuiesce)
	r.pollUntil(300, 50, state("s1", Suspending))
	r.w.mu.Lock()
	r.w.act["s1"]++
	r.w.mu.Unlock()
	close(release)
	if !r.pollUntil(10, 50, func(c *Ctl) bool { return c.Rows["s1"].State == Idle || c.Rows["s1"].State == Active }) {
		t.Fatalf("not aborted: %+v", r.m.State().Rows["s1"])
	}
	if len(r.facts.named("suspend_abort")) != 1 || !r.w.insts["s1"][0] {
		t.Fatalf("abort fact %v, instance %v", r.facts.facts, r.w.insts["s1"])
	}
}

// A message for a suspended session wakes it; expiry never drops it.
func TestMachineMessageWakes(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindFC)
	r.suspend("s1")
	if err := r.m.Message("s1"); err != nil {
		t.Fatal(err)
	}
	if !r.pollUntil(10, 50, func(c *Ctl) bool { return c.Rows["s1"].Resumes == 1 && c.Rows["s1"].Inbox == 0 }) {
		t.Fatalf("message not delivered: %+v", r.m.State().Rows["s1"])
	}
}

// TTL expiry deletes the artifacts.
func TestMachineExpiry(t *testing.T) {
	r := newRig(t)
	r.add("s1", "own-code", KindKV)
	r.suspend("s1")
	if !r.pollUntil(30_000, 10, state("s1", Expired)) {
		t.Fatal("not expired")
	}
	r.pollUntil(10, 10, func(*Ctl) bool { return len(r.w.artifacts["s1"]) == 0 })
	if len(r.w.artifacts["s1"]) != 0 || len(r.facts.named("expire")) != 1 {
		t.Fatalf("artifacts %v facts %v", r.w.artifacts["s1"], r.facts.facts)
	}
}

func TestMachineRefusesPlainArtifacts(t *testing.T) {
	w := newFakeWorld()
	w.encrypted = false
	st, err := OpenStore(filepath.Join(t.TempDir(), "yard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Start(context.Background(), st, testCfg(), w, nil, func() int64 { return 1 }); err == nil {
		t.Fatal("started on an unencrypted artifact dataset")
	}
}

// One yard-ctl per database: a second owner fails fast; after Close the
// lock is free again; plain handles are unaffected.
func TestOpenOwnedExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yard.db")
	a, err := OpenOwned(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenOwned(path)
	if !errors.Is(err, ErrOwned) || b != nil {
		t.Fatalf("second owner: %v", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("pid %d", os.Getpid())) || !strings.Contains(err.Error(), path+".lock") {
		t.Fatalf("message lacks the holder or the lock path: %v", err)
	}
	h, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	a.Close()
	c, err := OpenOwned(path)
	if err != nil {
		t.Fatalf("lock not released by Close: %v", err)
	}
	c.Close()
}

var _ issuer.EpochSource = (*Machine)(nil)
