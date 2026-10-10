package lifecycle

import (
	"errors"
	"testing"
)

// Unit tests per transition (Quint action), on the pure Ctl.

func unitCfg() Config {
	return Config{OpTimeout: 2, MaxAttempts: 2, Clients: []string{"msg", "timer"},
		Policies: map[string]Policy{"c": {IdleAfter: 2, MaxAge: 3}, "warm": {KeepWarm: true, IdleAfter: 2, MaxAge: 3}}}
}

// must(t)(x()) and blocked2(t)(x()) take a transition's two results.
func must(t *testing.T) func([]Effect, error) []Effect {
	return func(e []Effect, err error) []Effect {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func blocked(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrGuard) {
		t.Fatalf("want ErrGuard, got %v", err)
	}
}

func blocked2(t *testing.T) func([]Effect, error) {
	return func(_ []Effect, err error) { t.Helper(); blocked(t, err) }
}

// answer delivers a successful answer to op id.
func answer(c *Ctl, id int64) { c.OpAnswer(id, c.Ops[id].Inc, AnsDone, 100) }

func idleCtl(t *testing.T) *Ctl {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindFC, "")
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 0))
	c.Tick()
	c.Tick()
	ok(t, c.GoIdle("s"))
	return c
}

// suspendedCtl: ops 1 quiesce, 2 checkpoint, 3 destroy; token 1.
func suspendedCtl(t *testing.T) *Ctl {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	answer(c, 1)
	must(t)(c.SuspendCheckpoint("s"))
	answer(c, 2)
	must(t)(c.SuspendDestroy("s"))
	answer(c, 3)
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 0))
	must(t)(c.SuspendCommit("s"))
	return c
}

func TestObsAnswerDatesNewActivityAtAnswer(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindFC, "")
	c.Tick()
	ok(t, c.ObsReq("s"))
	c.Tick()
	ok(t, c.ObsAnswer("s", 3))
	if o := c.Obs["s"]; o.SeenAt != 2 || o.Seq != 3 || o.AnsReqAt != 1 || o.Pending {
		t.Fatalf("obs %+v", o)
	}
	blocked(t, c.ObsAnswer("s", 4)) // nothing pending
	c.Tick()
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 3)) // unchanged: keeps its date
	if c.Obs["s"].SeenAt != 2 {
		t.Fatal("unchanged activity re-dated")
	}
}

func TestGoIdleTouch(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindFC, "")
	blocked(t, c.GoIdle("s")) // nothing observed yet
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 0))
	c.Tick()
	blocked(t, c.GoIdle("s"))
	c.Tick()
	ok(t, c.GoIdle("s"))
	blocked(t, c.Touch("s")) // still idle
	ok(t, c.MessageArrive("s"))
	ok(t, c.Touch("s"))
	blocked(t, c.GoIdle("s")) // a held message
	blocked(t, c.Deliver("s", false))
	ok(t, c.Deliver("s", true))
	if r := c.Rows["s"]; r.Inbox != 0 || r.State != Active {
		t.Fatalf("%+v", r)
	}
}

func TestCredRefreshOncePerEpoch(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindFC, "")
	effs := must(t)(c.CredRefresh("s"))
	if len(effs) != 1 || c.Ops[1].Kind != OMint || c.Ops[1].Arg != 1 {
		t.Fatalf("%+v %+v", effs, c.Ops)
	}
	blocked2(t)(c.CredRefresh("s"))
}

func TestSuspendBegin(t *testing.T) {
	c := NewCtl(unitCfg())
	c.AddSession("s", "c", KindFC, "")
	blocked2(t)(c.SuspendBegin("s")) // Active
	c = idleCtl(t)
	ok(t, c.MessageArrive("s"))
	blocked2(t)(c.SuspendBegin("s")) // held message
	c = idleCtl(t)
	c.AddSession("w", "warm", KindService, "")
	c.Rows["w"] = func() Row { r := c.Rows["w"]; r.State = Idle; return r }()
	c.Obs["w"] = c.Obs["s"]
	blocked2(t)(c.SuspendBegin("w")) // keep-warm
	effs := must(t)(c.SuspendBegin("s"))
	r := c.Rows["s"]
	if r.State != Suspending || r.Phase != PQuiesce || r.Gen != 1 || r.Op != 1 || r.DecidedAt != 2 ||
		c.Ops[1].Kind != OQuiesce || c.Ops[1].Arg != 0 || len(effs) != 1 || c.DriverSet("s")[0] != Idler {
		t.Fatalf("%+v %+v %v", r, c.Ops[1], effs)
	}
}

func TestSuspendCheckpointWaitsForQuiesce(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	blocked2(t)(c.SuspendCheckpoint("s")) // pending
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	blocked2(t)(c.SuspendCheckpoint("s")) // unknown
	ok(t, c.OpResolve(1, true, true))
	must(t)(c.SuspendCheckpoint("s"))
	if r := c.Rows["s"]; r.Phase != PCheckpoint || r.Ckpt != 2 || r.Op != 2 || r.QuiescedAt != 4 {
		t.Fatalf("%+v", r)
	}
}

func TestSuspendCheckpointRetry(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	answer(c, 1)
	must(t)(c.SuspendCheckpoint("s"))
	blocked2(t)(c.SuspendCheckpointRetry("s"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(2))
	blocked(t, c.OpResolve(2, false, false)) // a copy may still land
	ok(t, c.OpResolve(2, true, false))       // partial or missing
	effs := must(t)(c.SuspendCheckpointRetry("s"))
	if len(effs) != 2 || c.Ops[3].Kind != ODelete || c.Ops[3].Arg != 2 || c.Rows["s"].Ckpt != 4 || c.Ops[4].Kind != OCheckpoint {
		t.Fatalf("%v %+v", effs, c.Ops)
	}
}

func TestSuspendCommitGuards(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	answer(c, 1)
	must(t)(c.SuspendCheckpoint("s"))
	blocked2(t)(c.SuspendDestroy("s"))
	answer(c, 2)
	must(t)(c.SuspendDestroy("s"))
	blocked2(t)(c.SuspendCommit("s")) // destroy pending
	answer(c, 3)
	blocked2(t)(c.SuspendCommit("s")) // activity not re-read since quiesce
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 1)) // new activity
	blocked2(t)(c.SuspendCommit("s"))
	c2 := idleCtl(t)
	must(t)(c2.SuspendBegin("s"))
	answer(c2, 1)
	must(t)(c2.SuspendCheckpoint("s"))
	answer(c2, 2)
	must(t)(c2.SuspendDestroy("s"))
	answer(c2, 3)
	ok(t, c2.ObsReq("s"))
	ok(t, c2.ObsAnswer("s", 0))
	ok(t, c2.MessageArrive("s"))
	blocked2(t)(c2.SuspendCommit("s")) // held message
	c = suspendedCtl(t)
	r := c.Rows["s"]
	if r.State != Suspended || r.Token != 1 || r.CredEpoch != 2 || r.Inst != 0 || r.Ckpt != 2 || len(c.Drivers["s"]) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSuspendCommitFact(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	answer(c, 1)
	must(t)(c.SuspendCheckpoint("s"))
	answer(c, 2)
	must(t)(c.SuspendDestroy("s"))
	answer(c, 3)
	c.Tick()
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 0))
	effs := must(t)(c.SuspendCommit("s"))
	if len(effs) != 1 || effs[0].Fact.Name != "suspend" || effs[0].Fact.Bytes != 100 || effs[0].Fact.DurationMs != 1 {
		t.Fatalf("%+v", effs)
	}
}

func TestSuspendAbortWaitsForResolution(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	answer(c, 1)
	must(t)(c.SuspendCheckpoint("s"))
	blocked2(t)(c.SuspendAbort("s")) // checkpoint in flight
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(2))
	blocked2(t)(c.SuspendAbort("s")) // unknown
	ok(t, c.OpResolve(2, true, true))
	effs := must(t)(c.SuspendAbort("s"))
	if len(effs) != 2 || c.Ops[3].Kind != ODelete || c.Ops[4].Kind != OUnquiesce || c.Rows["s"].Phase != PAbort {
		t.Fatalf("%v %+v", effs, c.Ops)
	}
	blocked2(t)(c.SuspendAbortDone("s"))
	answer(c, 4)
	must(t)(c.SuspendAbortDone("s"))
	if r := c.Rows["s"]; r.State != Idle || r.Ckpt != 0 || len(c.Drivers["s"]) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSuspendFail(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	ok(t, c.OpResolve(1, true, true))
	must(t)(c.SuspendAbort("s"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(2))
	ok(t, c.OpResolve(2, true, false))
	blocked2(t)(c.SuspendFail("s", true)) // instance still there: retry the unquiesce
	must(t)(c.SuspendFail("s", false))
	if c.Rows["s"].State != Failed {
		t.Fatal(c.Rows["s"])
	}
}

func TestResumeConsume(t *testing.T) {
	c := suspendedCtl(t)
	before := c.Clone()
	if _, err := c.ResumeConsume("s", "msg", 2, false); err != ErrTokenRejected {
		t.Fatal(err)
	}
	if _, err := c.ResumeConsume("s", "msg", 0, false); err != ErrTokenRejected {
		t.Fatal(err)
	}
	blocked2(t)(c.ResumeConsume("s", "stranger", 1, false))
	if !durableEqual(before, c) {
		t.Fatal("a rejected consume changed the state")
	}
	effs := must(t)(c.ResumeConsume("s", "msg", 1, false))
	r := c.Rows["s"]
	if r.State != Resuming || r.Token != 0 || c.Ops[r.Op].Kind != ORestore || c.Ops[r.Op].Arg != 2 || len(effs) != 1 {
		t.Fatalf("%+v", r)
	}
	if _, err := c.ResumeConsume("s", "timer", 1, false); err != ErrTokenRejected {
		t.Fatal("token consumed twice")
	}
}

func TestResumeMintComplete(t *testing.T) {
	c := suspendedCtl(t)
	must(t)(c.ResumeConsume("s", "msg", 1, false))
	blocked2(t)(c.ResumeMint("s", "msg", true)) // restore pending
	answer(c, 4)
	blocked2(t)(c.ResumeMint("s", "timer", true)) // not its driver
	blocked2(t)(c.ResumeMint("s", "msg", false))  // no instance
	must(t)(c.ResumeMint("s", "msg", true))
	if c.Ops[5].Kind != OMint || c.Ops[5].Arg != 2 {
		t.Fatalf("mint %+v", c.Ops[5])
	}
	blocked2(t)(c.ResumeComplete("s", "msg", true))
	answer(c, 5)
	effs := must(t)(c.ResumeComplete("s", "msg", true))
	r := c.Rows["s"]
	if r.State != Active || r.Inst != 1 || r.Resumes != 1 || r.Ckpt != 0 || c.Ops[6].Kind != ODelete || c.Ops[6].Arg != 2 {
		t.Fatalf("%+v %v", r, effs)
	}
}

func TestResumeAbortAndFail(t *testing.T) {
	c := suspendedCtl(t)
	must(t)(c.ResumeConsume("s", "msg", 1, false))
	blocked2(t)(c.ResumeAbort("s", "msg"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(4))
	blocked2(t)(c.ResumeAbort("s", "msg")) // unknown: wait to settle
	ok(t, c.OpResolve(4, true, false))
	must(t)(c.ResumeAbort("s", "msg"))
	if r := c.Rows["s"]; r.State != Suspended || r.Token != 2 {
		t.Fatalf("%+v", r)
	}
	must(t)(c.ResumeConsume("s", "timer", 2, false))
	answer(c, 5)
	blocked2(t)(c.ResumeFail("s", "timer", true))
	must(t)(c.ResumeFail("s", "timer", false))
	if r := c.Rows["s"]; r.State != Failed || c.Ops[6].Kind != ODelete {
		t.Fatalf("%+v", r)
	}
}

func TestOpAnswerOnlyToSender(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	c.OpAnswer(1, 7, AnsDone, 0) // another incarnation's copy
	if c.Ops[1].St != Pending {
		t.Fatal("answer from another incarnation taken")
	}
	c.OpAnswer(1, 1, AnsError, 0) // an error: unknown
	if c.Ops[1].St != Unknown {
		t.Fatal(c.Ops[1])
	}
	c.OpAnswer(1, 1, AnsDone, 0) // no longer pending
	if c.Ops[1].St != Unknown {
		t.Fatal("late answer to a non-pending op taken")
	}
}

func TestOpTimeoutRetry(t *testing.T) {
	c := idleCtl(t)
	must(t)(c.SuspendBegin("s"))
	c.Tick()
	blocked(t, c.OpTimeout(1))
	c.Tick()
	ok(t, c.OpTimeout(1))
	blocked2(t)(c.OpRetry(1)) // unknown, not not-done
	ok(t, c.OpResolve(1, true, false))
	effs := must(t)(c.OpRetry(1))
	if o := c.Ops[1]; o.St != Pending || o.Attempts != 2 || len(effs) != 1 {
		t.Fatalf("%+v", o)
	}
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	ok(t, c.OpResolve(1, true, false))
	blocked2(t)(c.OpRetry(1)) // MaxAttempts
	// a checkpoint is never blindly retried
	c2 := idleCtl(t)
	must(t)(c2.SuspendBegin("s"))
	answer(c2, 1)
	must(t)(c2.SuspendCheckpoint("s"))
	c2.Tick()
	c2.Tick()
	ok(t, c2.OpTimeout(2))
	ok(t, c2.OpResolve(2, true, false))
	blocked2(t)(c2.OpRetry(2))
}

func TestCrashRecoverAdopt(t *testing.T) {
	c := suspendedCtl(t)
	must(t)(c.ResumeConsume("s", "msg", 1, false))
	ok(t, c.CtlCrash())
	blocked(t, c.CtlCrash())
	if len(c.Drivers["s"]) != 0 || c.Obs["s"].Seq != -1 {
		t.Fatal("memory survived the crash")
	}
	blocked(t, c.RecoverOps("s"))
	ok(t, c.CtlRestart())
	if c.Inc != 2 {
		t.Fatal(c.Inc)
	}
	blocked(t, c.Adopt("s")) // pending ops of the old incarnation first
	blocked(t, c.OpTimeout(4))
	ok(t, c.RecoverOps("s"))
	if c.Ops[4].St != Unknown {
		t.Fatal(c.Ops[4])
	}
	ok(t, c.Adopt("s"))
	if c.DriverSet("s")[0] != Recovery {
		t.Fatal(c.Drivers)
	}
	ok(t, c.OpResolve(4, true, true))
	must(t)(c.ResumeMint("s", Recovery, true))
}

func TestExpire(t *testing.T) {
	c := suspendedCtl(t)
	c.Tick()
	c.Tick()
	blocked2(t)(c.Expire("s"))
	c.Tick()
	ok(t, c.MessageArrive("s"))
	blocked2(t)(c.Expire("s")) // held message
	c = suspendedCtl(t)
	for i := 0; i < 3; i++ {
		c.Tick()
	}
	effs := must(t)(c.Expire("s"))
	if r := c.Rows["s"]; r.State != Expired || r.Token != 0 || c.Ops[4].Kind != ODelete || c.Ops[4].Arg != 2 || len(effs) != 2 {
		t.Fatalf("%+v %v", r, effs)
	}
	if _, err := c.ResumeConsume("s", "msg", 1, false); err != ErrTokenRejected {
		t.Fatal("resumed an expired session")
	}
}

func TestMessageArriveRefusedWhenTerminal(t *testing.T) {
	c := suspendedCtl(t)
	for i := 0; i < 3; i++ {
		c.Tick()
	}
	must(t)(c.Expire("s"))
	blocked(t, c.MessageArrive("s"))
}

// ---------------------------------------------------- SR1 pause tier

func pauseCfg() Config {
	cfg := unitCfg()
	cfg.Policies["p"] = Policy{IdleAfter: 2, MaxAge: 3, Pause: true, SuspendHold: 1}
	return cfg
}

func idlePauseCtl(t *testing.T) *Ctl {
	c := NewCtl(pauseCfg())
	c.AddSession("s", "p", KindService, "")
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 0))
	c.Tick()
	c.Tick()
	ok(t, c.GoIdle("s"))
	return c
}

func TestPauseBeginNeedsPolicyAndIdle(t *testing.T) {
	c := idleCtl(t) // class "c": no pause tier
	blocked2(t)(c.PauseBegin("s"))
	c = idlePauseCtl(t)
	effs := must(t)(c.PauseBegin("s"))
	r := c.Rows["s"]
	if r.State != Paused || r.Phase != PPause || r.Op != 1 || len(effs) != 1 || c.Ops[1].Kind != OPause || c.Ops[1].Arg != 0 {
		t.Fatalf("%+v %+v", r, c.Ops[1])
	}
	blocked(t, c.PauseDone("s")) // pending
	answer(c, 1)
	ok(t, c.PauseDone("s"))
	if r := c.Rows["s"]; r.Phase != PNone || r.Op != 0 || len(c.Drivers["s"]) != 0 {
		t.Fatalf("%+v", r)
	}
}

// The fence (Quint unpauseBeforePauseSettles): no SIGCONT while the SIGSTOP
// can still land.
func TestUnpauseWaitsForPauseResolution(t *testing.T) {
	c := idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	ok(t, c.MessageArrive("s"))
	blocked2(t)(c.UnpauseBegin("s")) // pending
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	blocked2(t)(c.UnpauseBegin("s")) // unknown
	ok(t, c.OpResolve(1, true, true))
	effs := must(t)(c.UnpauseBegin("s"))
	if r := c.Rows["s"]; r.Phase != PUnpause || r.Op != 2 || len(effs) != 1 || c.Ops[2].Kind != OUnpause {
		t.Fatalf("%+v", r)
	}
	answer(c, 2)
	ok(t, c.UnpauseDone("s"))
	ok(t, c.Touch("s"))
	ok(t, c.Deliver("s", true))
	if r := c.Rows["s"]; r.State != Active || r.Inbox != 0 {
		t.Fatalf("%+v", r)
	}
}

// Paused with nothing to wake it stays paused; a pause known not done wakes it.
func TestUnpauseTriggers(t *testing.T) {
	c := idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	answer(c, 1)
	ok(t, c.PauseDone("s"))
	blocked2(t)(c.UnpauseBegin("s")) // no message, no activity
	ok(t, c.ObsReq("s"))
	ok(t, c.ObsAnswer("s", 1)) // new activity
	must(t)(c.UnpauseBegin("s"))

	c = idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	ok(t, c.OpResolve(1, true, false))
	must(t)(c.UnpauseBegin("s"))
}

// RETRY_CURRENT (Quint retrySupersededOp): a lost SIGSTOP is not resent
// once the row waits on the SIGCONT; it is while the row waits on it.
func TestOpRetryOnlyCurrent(t *testing.T) {
	c := idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	c.Tick()
	c.Tick()
	ok(t, c.OpTimeout(1))
	ok(t, c.OpResolve(1, true, false))
	c2 := c.Clone()
	must(t)(c2.OpRetry(1)) // the row still waits on the pause
	must(t)(c.UnpauseBegin("s"))
	blocked2(t)(c.OpRetry(1)) // superseded
	// a delete is owed whatever the row does
	c3 := suspendedCtl(t)
	must(t)(c3.ResumeConsume("s", "msg", 1, false))
	answer(c3, 4)
	must(t)(c3.ResumeMint("s", "msg", true))
	answer(c3, 5)
	must(t)(c3.ResumeComplete("s", "msg", true))
	c3.Tick()
	c3.Tick()
	ok(t, c3.OpTimeout(6))
	ok(t, c3.OpResolve(6, true, false))
	must(t)(c3.OpRetry(6))
}

func TestSuspendFromPausedAfterHold(t *testing.T) {
	c := idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	answer(c, 1)
	ok(t, c.PauseDone("s"))
	blocked2(t)(c.SuspendBegin("s")) // seenAt 0 + 2 + 1 > 2
	c.Tick()
	effs := must(t)(c.SuspendBegin("s"))
	if r := c.Rows["s"]; r.State != Suspending || r.Phase != PQuiesce || len(effs) != 1 {
		t.Fatalf("%+v", r)
	}
	// not while the pause itself is in flight
	c = idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	c.Tick()
	blocked2(t)(c.SuspendBegin("s"))
}

func TestPauseCrashAdoptAndUnpauseFail(t *testing.T) {
	c := idlePauseCtl(t)
	must(t)(c.PauseBegin("s"))
	ok(t, c.CtlCrash())
	ok(t, c.CtlRestart())
	blocked(t, c.Adopt("s")) // recover first
	ok(t, c.RecoverOps("s"))
	ok(t, c.Adopt("s"))
	ok(t, c.OpResolve(1, true, true))
	ok(t, c.PauseDone("s"))
	ok(t, c.MessageArrive("s"))
	must(t)(c.UnpauseBegin("s"))
	c.OpAnswer(2, c.Inc, AnsError, 0) // error answer: unknown
	ok(t, c.OpResolve(2, true, false))
	blocked2(t)(c.UnpauseFail("s", true)) // the instance is there: retry instead
	must(t)(c.UnpauseFail("s", false))
	if c.Rows["s"].State != Failed {
		t.Fatal(c.Rows["s"])
	}
}
