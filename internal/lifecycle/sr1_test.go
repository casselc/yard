package lifecycle

import (
	"path/filepath"
	"testing"
)

// SR1 decisions of 2026-10-07 on the pure controller: workspace keys
// (layout D), the drift refusal (decision 2) and liveness (decision 3).
// Quint: spec/sr0/lifecycle.qnt keyUnderActive, noSilentDrift, noLiveFailed.

// keyCtl: two sessions a, b of project "p" (and c without one), both
// suspended (a: ops 1-3 token 1; b: ops 4-6 token 2).
func keyCtl(t *testing.T) *Ctl {
	t.Helper()
	cfg := unitCfg()
	c := NewCtl(cfg)
	for _, s := range []string{"a", "b"} {
		c.AddSession(s, "c", KindService, "p")
	}
	c.AddSession("c", "c", KindFC, "")
	for _, s := range []string{"a", "b"} {
		ok(t, c.ObsReq(s))
		ok(t, c.ObsAnswer(s, 0))
	}
	c.Tick()
	c.Tick()
	for _, s := range []string{"a", "b"} {
		ok(t, c.GoIdle(s))
		must(t)(c.SuspendBegin(s))
		answer(c, c.Rows[s].Op)
		must(t)(c.SuspendCheckpoint(s))
		answer(c, c.Rows[s].Op)
		must(t)(c.SuspendDestroy(s))
		answer(c, c.Rows[s].Op)
		ok(t, c.ObsReq(s))
		ok(t, c.ObsAnswer(s, 0))
		must(t)(c.SuspendCommit(s))
	}
	return c
}

func TestKeyUnloadOnlyWhenNoSessionActive(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("a", "c", KindService, "p")
	c.AddSession("b", "c", KindService, "p")
	if !c.Projects["p"].Loaded || c.Projects["p"].Phase != KNone {
		t.Fatalf("new project %+v", c.Projects["p"])
	}
	blocked2(t)(c.KeyUnloadBegin("p")) // both active
	c = keyCtl(t)
	// one session resuming: not yet
	must(t)(c.ResumeConsume("a", "msg", c.Rows["a"].Token, false))
	blocked2(t)(c.KeyUnloadBegin("p"))
	c = keyCtl(t)
	effs := must(t)(c.KeyUnloadBegin("p"))
	if len(effs) != 1 || c.Ops[effs[0].Op].Kind != OUnmount || c.Ops[effs[0].Op].Sess != "p" {
		t.Fatalf("unload begins with an unmount of the project: %+v", effs)
	}
	blocked2(t)(c.KeyUnmountDone("p")) // not answered
	answer(c, effs[0].Op)
	e2 := must(t)(c.KeyUnmountDone("p"))
	if c.Ops[e2[0].Op].Kind != OUnloadKey {
		t.Fatal("no unload-key after the unmount")
	}
	answer(c, e2[0].Op)
	must(t)(c.KeyUnloadDone("p"))
	if p := c.Projects["p"]; p.Loaded || p.Phase != KNone || p.Op != 0 {
		t.Fatalf("after unload %+v", p)
	}
	blocked2(t)(c.KeyUnloadBegin("p")) // nothing loaded
}

// KEY_FENCE: a resume does not send its load while the project's unload
// can still land; it does once the unload is resolved.
func TestResumeLoadWaitsForUnload(t *testing.T) {
	c := keyCtl(t)
	un := must(t)(c.KeyUnloadBegin("p"))[0].Op
	effs := must(t)(c.ResumeConsume("a", "msg", c.Rows["a"].Token, false))
	if len(effs) != 0 || c.Rows["a"].Phase != PKey || c.Rows["a"].Op != 0 {
		t.Fatalf("consume with a project: %+v %+v", effs, c.Rows["a"])
	}
	blocked2(t)(c.ResumeLoadKey("a", "msg"))
	answer(c, un)
	unl := must(t)(c.KeyUnmountDone("p"))[0].Op
	blocked2(t)(c.ResumeLoadKey("a", "msg"))
	answer(c, unl)
	must(t)(c.KeyUnloadDone("p"))
	load := must(t)(c.ResumeLoadKey("a", "msg"))[0].Op
	if c.Ops[load].Kind != OLoadKey {
		t.Fatal("no load op")
	}
	blocked2(t)(c.ResumeKeyDone("a", "msg"))
	answer(c, load)
	rest := must(t)(c.ResumeKeyDone("a", "msg"))[0].Op
	if c.Ops[rest].Kind != ORestore || c.Rows["a"].Phase != PRestore || !c.Projects["p"].Loaded {
		t.Fatalf("after the load: %+v %+v", c.Rows["a"], c.Projects["p"])
	}
}

// A session without a project restores at once (no PKey).
func TestResumeWithoutProject(t *testing.T) {
	c := suspendedCtl(t)
	effs := must(t)(c.ResumeConsume("s", "msg", 1, false))
	if c.Rows["s"].Phase != PRestore || len(effs) != 1 || c.Ops[effs[0].Op].Kind != ORestore {
		t.Fatalf("%+v", c.Rows["s"])
	}
}

// Decision 2: a refused restore aborts the resume with the outcome
// recorded; the override travels on the restore op.
func TestResumeRefusedDrift(t *testing.T) {
	c := suspendedCtl(t)
	must(t)(c.ResumeConsume("s", "msg", 1, false))
	c.OpAnswer(4, c.Ops[4].Inc, AnsRefused, 0)
	if c.Ops[4].St != Refused {
		t.Fatalf("op %+v", c.Ops[4])
	}
	blocked2(t)(c.ResumeMint("s", "msg", false))
	effs := must(t)(c.ResumeAbort("s", "msg"))
	r := c.Rows["s"]
	if r.State != Suspended || !r.Drift || r.Token == 0 || effs[0].Fact.Name != "resume_refused_drift" {
		t.Fatalf("after refusal %+v %+v", r, effs)
	}
	e := must(t)(c.ResumeConsume("s", "msg", r.Token, true))
	if o := c.Ops[e[0].Op]; !o.Force || !c.Rows["s"].Force {
		t.Fatalf("override not carried: %+v", o)
	}
	answer(c, e[0].Op)
	answer(c, must(t)(c.ResumeMint("s", "msg", true))[0].Op)
	must(t)(c.ResumeComplete("s", "msg", true))
	if r := c.Rows["s"]; r.Drift || r.Force {
		t.Fatalf("outcome not cleared after the resume: %+v", r)
	}
}

// Decision 3: dead only on a definite answer for the current instance and
// generation; a timeout is unknown.
func TestLostDetect(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindService, "")
	ok(t, c.ProbeReq("s"))
	blocked(t, c.ProbeReq("s")) // one at a time
	for i := int64(0); i < c.Cfg.OpTimeout; i++ {
		c.Tick()
	}
	ok(t, c.ProbeTimeout("s"))
	blocked2(t)(c.LostDetect("s"))
	ok(t, c.ProbeReq("s"))
	ok(t, c.ProbeAnswer("s", true))
	blocked2(t)(c.LostDetect("s"))
	ok(t, c.ProbeReq("s"))
	ok(t, c.ProbeAnswer("s", false))
	effs := must(t)(c.LostDetect("s"))
	if c.Rows["s"].State != Failed || effs[0].Fact.Name != "lost" {
		t.Fatalf("%+v", c.Rows["s"])
	}
}

// A "dead" answer to a probe asked before a suspend attempt (the quiesce
// had stopped the instance) does not fail the session after the abort.
func TestLostDetectStale(t *testing.T) {
	c := idleCtl(t)
	ok(t, c.ProbeReq("s"))
	must(t)(c.SuspendBegin("s")) // gen 1
	answer(c, 1)
	ok(t, c.ProbeAnswer("s", false))
	must(t)(c.SuspendAbort("s"))
	answer(c, 2)
	must(t)(c.SuspendAbortDone("s"))
	blocked2(t)(c.LostDetect("s"))
}

// The Store keeps the project records, Force/Drift/Project and Op.Force,
// and a consume into PKey writes no op.
func TestStoreSR1Fields(t *testing.T) {
	c := keyCtl(t)
	st, err := OpenStore(filepath.Join(t.TempDir(), "yard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Commit(NewCtl(c.Cfg), c); err != nil {
		t.Fatal(err)
	}
	prev := c.Clone()
	must(t)(c.KeyUnloadBegin("p"))
	if err := st.Commit(prev, c); err != nil {
		t.Fatal(err)
	}
	next := c.Clone()
	must(t)(next.ResumeConsume("a", "msg", next.Rows["a"].Token, true))
	won, err := st.ConsumeToken("a", c.Rows["a"].Token, next.Rows["a"], next.Ops[next.Rows["a"].Op])
	if err != nil || !won {
		t.Fatalf("consume: %v %v", won, err)
	}
	c2, err := st.Restore(c.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r := c2.Rows["a"]; r.Phase != PKey || r.Op != 0 || !r.Force || r.Project != "p" {
		t.Fatalf("stored row %+v", r)
	}
	if p := c2.Projects["p"]; p.Phase != KUnmount || !p.Loaded {
		t.Fatalf("stored project %+v", p)
	}
	if !durableEqual(c, c2) && c2.Rows["a"].State == Resuming {
		// c is the pre-consume state; compare the rest
		c3 := c2.Clone()
		c3.Rows["a"] = c.Rows["a"]
		if !durableEqual(c, c3) {
			t.Fatal("store lost durable state")
		}
	}
}
