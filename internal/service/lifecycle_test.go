package service

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"yard/internal/lifecycle"
)

// The service backend driven by the SR0 lifecycle (lifecycle.Machine over
// a lifecycle.Router): SR1 is a client of the lifecycle, not a parallel one.

type memMinter struct {
	mu sync.Mutex
	e  map[string]int64
}

func (m *memMinter) Mint(_ context.Context, s string, e int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.e[s] = max(m.e[s], e)
	return nil
}
func (m *memMinter) Holds(_ context.Context, s string, e int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.e[s] == e, nil
}
func (m *memMinter) InFlight(context.Context, lifecycle.Op) (bool, error) { return false, nil }

type noActivity struct{}

func (noActivity) Activity(context.Context, string) (int64, error) { return 0, nil }

type facts struct {
	mu sync.Mutex
	f  []lifecycle.Fact
}

func (x *facts) Emit(f lifecycle.Fact) { x.mu.Lock(); x.f = append(x.f, f); x.mu.Unlock() }

func (x *facts) named(n string) []lifecycle.Fact {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []lifecycle.Fact
	for _, f := range x.f {
		if f.Name == n {
			out = append(out, f)
		}
	}
	return out
}

func machine(t *testing.T, r *rig, pol lifecycle.Policy) (*lifecycle.Machine, *facts) {
	t.Helper()
	return machineWith(t, r, pol, 0)
}

// machineWith: probeEvery > 0 turns on the liveness probe; a backend with
// a workspace tree (r.b.WS) is also the Router's key service.
func machineWith(t *testing.T, r *rig, pol lifecycle.Policy, probeEvery int64) (*lifecycle.Machine, *facts) {
	t.Helper()
	st, err := lifecycle.OpenOwned(filepath.Join(t.TempDir(), "yard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rt := &lifecycle.Router{Backends: map[string]lifecycle.Backend{lifecycle.KindService: r.b},
		Mint: &memMinter{e: map[string]int64{}}, Artifacts: r.b, Act: noActivity{}}
	if r.b.WS != nil {
		rt.Keys = r.b
	}
	cfg := lifecycle.Config{OpTimeout: 5000, MaxAttempts: 3, Clients: []string{"msg"},
		Policies: map[string]lifecycle.Policy{"svc": pol}, ProbeEvery: probeEvery}
	fx := &facts{}
	t0 := time.Now()
	m, err := lifecycle.Start(context.Background(), st, cfg, rt, fx, func() int64 { return time.Since(t0).Milliseconds() + 1 })
	if err != nil {
		t.Fatal(err)
	}
	return m, fx
}

func pollUntil(t *testing.T, m *lifecycle.Machine, cond func(r lifecycle.Row, c *lifecycle.Ctl) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c := m.State()
		if cond(c.Rows["web"], c) {
			return
		}
		m.Poll(context.Background())
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out: %+v", m.State().Rows["web"])
}

func settledOps(c *lifecycle.Ctl) bool {
	for _, o := range c.Ops {
		if o.St == lifecycle.Pending || o.St == lifecycle.Unknown {
			return false
		}
	}
	return true
}

func TestLifecycleSuspendResumeCycles(t *testing.T) {
	r := newRig(t, behavior{listens: true, readyAfter: 1})
	r.up()
	m, fx := machine(t, r, lifecycle.Policy{IdleAfter: 0, MaxAge: 3_600_000})
	if err := m.AddSession("web", "svc", lifecycle.KindService, ""); err != nil {
		t.Fatal(err)
	}
	for cycle := int64(1); cycle <= 3; cycle++ {
		pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool {
			return row.State == lifecycle.Suspended && settledOps(c)
		})
		row := m.State().Rows["web"]
		if r.f.jailCount() != 0 || len(r.f.snapList()) != 1 || row.Gen != cycle || row.CredEpoch != cycle+1 {
			t.Fatalf("cycle %d suspended: jails %d snaps %v row %+v", cycle, r.f.jailCount(), r.f.snapList(), row)
		}
		if err := m.Resume("web", "msg", row.Token); err != nil {
			t.Fatal(err)
		}
		pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool {
			return row.State == lifecycle.Active && settledOps(c)
		})
		if n := r.f.live(r.name(cycle)); n != 1 || r.f.jailCount() != 1 || len(r.f.snapList()) != 0 {
			t.Fatalf("cycle %d resumed: processes %d jails %d snaps %v", cycle, n, r.f.jailCount(), r.f.snapList())
		}
	}
	n := map[string]int{}
	for _, f := range fx.f {
		n[f.Name]++
	}
	if n["suspend"] != 3 || n["resume"] != 3 {
		t.Fatalf("facts %v", n)
	}
}

// A restore whose readiness times out is observed not done: the resume
// aborts back to Suspended with a fresh token, nothing is left running, and
// a later resume (the service fixed) succeeds.
func TestLifecycleResumeReadinessTimeoutAborts(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	m, _ := machine(t, r, lifecycle.Policy{IdleAfter: 0, MaxAge: 3_600_000})
	if err := m.AddSession("web", "svc", lifecycle.KindService, ""); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool { return row.State == lifecycle.Suspended })
	r.f.behave["/workspace/devsrv"] = behavior{listens: false}
	tok := m.State().Rows["web"].Token
	if err := m.Resume("web", "msg", tok); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool {
		return row.State == lifecycle.Suspended && row.Token != tok && settledOps(c)
	})
	// aborted, not resumed and suspended again (the policy suspends at once)
	if row := m.State().Rows["web"]; row.Resumes != 0 || row.Gen != 1 {
		t.Fatalf("not a resume abort: %+v", row)
	}
	if r.f.jailCount() != 0 || len(r.f.snapList()) != 1 {
		t.Fatalf("after abort: jails %d snaps %v", r.f.jailCount(), r.f.snapList())
	}
	r.f.behave["/workspace/devsrv"] = behavior{listens: true}
	if err := m.Resume("web", "msg", m.State().Rows["web"].Token); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool {
		return row.State == lifecycle.Active && settledOps(c)
	})
}

// The pause tier through the Machine: idle -> SIGSTOPped; a message wakes
// it (SIGCONT before delivery); idle again -> paused; after the hold it is
// suspended straight from Paused, gracefully.
func TestLifecyclePauseTier(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	m, _ := machine(t, r, lifecycle.Policy{IdleAfter: 0, MaxAge: 3_600_000, Pause: true, SuspendHold: 150})
	if err := m.AddSession("web", "svc", lifecycle.KindService, ""); err != nil {
		t.Fatal(err)
	}
	paused := func(row lifecycle.Row, c *lifecycle.Ctl) bool {
		return row.State == lifecycle.Paused && row.Phase == lifecycle.PNone
	}
	pollUntil(t, m, paused)
	if _, fr, _ := r.b.Frozen(context.Background(), "web", 0); !fr {
		t.Fatal("paused row, instance not frozen")
	}
	if err := m.Message("web"); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool { return row.Inbox == 0 })
	if _, fr, _ := r.b.Frozen(context.Background(), "web", 0); fr {
		t.Fatal("message delivered to a frozen instance")
	}
	pollUntil(t, m, func(row lifecycle.Row, c *lifecycle.Ctl) bool {
		return row.State == lifecycle.Suspended && settledOps(c)
	})
	if tm := r.lastTiming("quiesce"); tm.Info["escalated"] != false {
		t.Fatalf("the paused service needed SIGKILL: %+v", tm)
	}
}
