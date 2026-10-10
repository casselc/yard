package lifecycle

import (
	"errors"
	"fmt"
	"slices"
)

// Each method below is one Quint action of spec/sr0/lifecycle.qnt: the guard
// is the action's can<Name>, the update its apply<Name>. A method checks the
// guard first and returns ErrGuard (wrapped with the action name) without
// touching c when it is false. Arguments the model reads from the
// environment (whether an instance exists, whether an op has settled, what
// the observation shows) are parameters here: the Machine gets them from the
// backends, the replay from its simulated world.

// ErrGuard means the action is not enabled in this state.
var ErrGuard = errors.New("lifecycle: action not enabled")

// ErrTokenRejected is ResumeReject: the token does not open this session now.
var ErrTokenRejected = errors.New("lifecycle: resume token rejected")

func guard(name string, ok bool) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%s: %w", name, ErrGuard)
}

// EffectKind says what the Machine must do after a transition is persisted.
type EffectKind int

const (
	EffSend EffectKind = iota + 1 // start a copy of op Op (backend, STS, artifact store)
	EffFact                       // emit Fact
)

// Effect is an output of a pure transition.
type Effect struct {
	Kind EffectKind
	Op   int64
	Fact Fact
}

// Fact is a yard.fact/v1 record for the suspend/resume lifecycle
// (TRAINING-DATA.md): type tool_outcome, gen_ai.evaluation.name
// yard.lifecycle.<Name>@v1, source EXECUTOR.
type Fact struct {
	Name        string // suspend | resume | suspend_abort | resume_abort | fail | expire
	Session     string
	Class       string
	Kind        string
	Gen         int64
	DurationMs  int64 // decision to commit (suspend), token consume to complete (resume), suspended age (expire)
	SuspendedMs int64 // resume: how long the session was suspended
	Bytes       int64 // checkpoint bytes reported by the backend
	Resumes     int64
}

func (c *Ctl) fact(name, s string, dur int64, bytes int64) Effect {
	r := c.Rows[s]
	return Effect{Kind: EffFact, Fact: Fact{Name: name, Session: s, Class: r.Class, Kind: r.Kind,
		Gen: r.Gen, DurationMs: dur, Bytes: bytes, Resumes: r.Resumes}}
}

// ---------------------------------------------------------------- helpers

func (c *Ctl) opSt(id int64) OpSt {
	if o, ok := c.Ops[id]; ok {
		return o.St
	}
	return NotDone
}

func (c *Ctl) resolved(id int64) bool {
	st := c.opSt(id)
	return id == 0 || st == Done || st == NotDone || st == Refused
}

func (c *Ctl) opsLeft(n int64) bool { return c.Cfg.MaxOps == 0 || c.NextOp+n-1 <= c.Cfg.MaxOps }

func (c *Ctl) tokensLeft() bool { return c.Cfg.MaxTokens == 0 || c.NextToken <= c.Cfg.MaxTokens }

func (c *Ctl) hasDriver(s string) bool { return c.Up && len(c.Drivers[s]) > 0 }

func (c *Ctl) drives(s, d string) bool { return c.Up && c.Drivers[s][d] }

func (c *Ctl) inPhase(s string, st State, p Phase) bool {
	r, ok := c.Rows[s]
	return ok && r.State == st && r.Phase == p
}

func (c *Ctl) idleSeen(s string) bool {
	o := c.Obs[s]
	return o.Seq >= 0 && o.SeenAt+c.policy(s).IdleAfter <= c.Clock
}

// newOp is Quint newOp: an op row (Pending) and its first copy (EffSend).
func (c *Ctl) newOp(k OpKind, s string, gen, arg int64) (int64, Effect) {
	return c.newOpF(k, s, gen, arg, false)
}

func (c *Ctl) newOpF(k OpKind, s string, gen, arg int64, force bool) (int64, Effect) {
	id := c.NextOp
	c.Ops[id] = Op{ID: id, Kind: k, Sess: s, Gen: gen, Arg: arg, St: Pending, SentAt: c.Clock, Attempts: 1, Inc: c.Inc,
		Force: force}
	c.NextOp++
	return id, Effect{Kind: EffSend, Op: id}
}

// issueDelete is Quint issueDelete (DELETE_OWED): an owed delete op.
func (c *Ctl) issueDelete(s string, ckpt int64) []Effect {
	if ckpt == 0 {
		return nil
	}
	_, e := c.newOp(ODelete, s, c.Rows[s].Gen, ckpt)
	return []Effect{e}
}

func (c *Ctl) setDrivers(s string, ds ...string) {
	m := map[string]bool{}
	for _, d := range ds {
		m[d] = true
	}
	c.Drivers[s] = m
}

func (c *Ctl) recoverable(s string) bool {
	for _, o := range c.Ops {
		if o.Sess == s && o.St == Pending && o.Inc < c.Inc {
			return true
		}
	}
	return false
}

var retryable = []OpKind{OQuiesce, ODestroy, OUnquiesce, OMint, ODelete, OPause, OUnpause, OLoadKey, OUnmount, OUnloadKey}

// opCurrent is Quint opCurrent (RETRY_CURRENT): a delete or a mint is owed
// whatever the row does next; a stop, start, pause or key op only while
// the row (or the project) still waits on it.
func (c *Ctl) opCurrent(o Op) bool {
	if projOp(o.Kind) {
		return c.Projects[o.Sess].Op == o.ID
	}
	return o.Kind == ODelete || o.Kind == OMint || c.Rows[o.Sess].Op == o.ID
}

// ===================================================== environment inputs

// Tick advances the clock (Quint Tick; production: SetClock).
func (c *Ctl) Tick() { c.Clock++ }

// SetClock moves the clock forward to now (never back).
func (c *Ctl) SetClock(now int64) {
	if now > c.Clock {
		c.Clock = now
	}
}

// OpAnswer is the answer part of Quint OpLand: delivered only to the
// incarnation that sent the copy, and only while the op is Pending.
// AnsDone: the process exited 0 (the effect holds); AnsRefused: a definite
// refusal before anything was done (a restore of a changed workspace);
// any other answer is Unknown.
func (c *Ctl) OpAnswer(id, inc int64, out Outcome, bytes int64) {
	o, has := c.Ops[id]
	if !has || !c.Up || inc != c.Inc || o.St != Pending {
		return
	}
	switch out {
	case AnsDone:
		o.St = Done
		o.Bytes = bytes
	case AnsRefused:
		o.St = Refused
	default:
		o.St = Unknown
	}
	c.Ops[id] = o
}

// ObsAnswer: the answer to an activity observation shows activity
// sequence seq; new activity is dated at the answer (OBS_AT_ANSWER).
func (c *Ctl) ObsAnswer(s string, seq int64) error {
	o := c.Obs[s]
	if err := guard("ObsAnswer", c.Up && o.Pending); err != nil {
		return err
	}
	seen := o.SeenAt
	if seq != o.Seq {
		seen = c.Clock
	}
	c.Obs[s] = Obs{Pending: false, ReqAt: o.ReqAt, Seq: seq, SeenAt: seen, AnsReqAt: o.ReqAt}
	return nil
}

// MessageArrive: a message or approval for the session, held durably.
func (c *Ctl) MessageArrive(s string) error {
	r, ok := c.Rows[s]
	if err := guard("MessageArrive", ok && c.Up && r.State != Expired && r.State != Failed && r.State != Removed); err != nil {
		return err
	}
	r.Inbox++
	c.Rows[s] = r
	return nil
}

// CtlCrash: yard-ctl dies. Rows and ops survive (SQLite); drivers and
// observations do not. (Production: process death; Machine reloads.)
func (c *Ctl) CtlCrash() error {
	if err := guard("CtlCrash", c.Up); err != nil {
		return err
	}
	c.Up = false
	for s := range c.Rows {
		c.Drivers[s] = map[string]bool{}
		c.Obs[s] = freshObs()
		c.Probes[s] = Probe{}
	}
	return nil
}

// CtlRestart: a new incarnation; answers to earlier copies are lost.
func (c *Ctl) CtlRestart() error {
	if err := guard("CtlRestart", !c.Up); err != nil {
		return err
	}
	c.Up = true
	c.Inc++
	return nil
}

// =========================================================== op handling

// OpTimeout: an op of this incarnation unanswered past OpTimeout is Unknown.
func (c *Ctl) OpTimeout(id int64) error {
	o, ok := c.Ops[id]
	if err := guard("OpTimeout", c.Up && ok && o.St == Pending && o.Inc == c.Inc &&
		c.Clock >= o.SentAt+c.Cfg.OpTimeout); err != nil {
		return err
	}
	o.St = Unknown
	c.Ops[id] = o
	return nil
}

// OpResolve: once settled (no copy can still land), the observation decides.
func (c *Ctl) OpResolve(id int64, settled, observedDone bool) error {
	o, ok := c.Ops[id]
	if err := guard("OpResolve", c.Up && ok && o.St == Unknown && settled); err != nil {
		return err
	}
	if observedDone {
		o.St = Done
	} else {
		o.St = NotDone
	}
	c.Ops[id] = o
	return nil
}

// OpRetry: idempotent retry of a retryable op known not done.
func (c *Ctl) OpRetry(id int64) ([]Effect, error) {
	o, ok := c.Ops[id]
	if err := guard("OpRetry", c.Up && ok && o.St == NotDone && slices.Contains(retryable, o.Kind) &&
		(c.Cfg.MaxAttempts == 0 || o.Attempts < c.Cfg.MaxAttempts) && c.opCurrent(o)); err != nil {
		return nil, err
	}
	o.St, o.Attempts, o.SentAt, o.Inc = Pending, o.Attempts+1, c.Clock, c.Inc
	c.Ops[id] = o
	return []Effect{{Kind: EffSend, Op: id}}, nil
}

// RecoverOps: after a restart, a Pending op of an earlier incarnation has
// an unknown outcome (RECOVER_UNKNOWN).
func (c *Ctl) RecoverOps(s string) error {
	if err := guard("RecoverOps", c.Up && c.recoverable(s)); err != nil {
		return err
	}
	for id, o := range c.Ops {
		if o.Sess == s && o.St == Pending && o.Inc < c.Inc {
			o.St = Unknown
			c.Ops[id] = o
		}
	}
	return nil
}

// Adopt: a recovery driver takes over an in-flight row (suspending,
// resuming, or pausing / unpausing).
func (c *Ctl) Adopt(s string) error {
	r, ok := c.Rows[s]
	inFlight := r.State == Suspending || r.State == Resuming || (r.State == Paused && r.Phase != PNone)
	if err := guard("Adopt", ok && c.Up && inFlight &&
		len(c.Drivers[s]) == 0 && !c.recoverable(s)); err != nil {
		return err
	}
	c.setDrivers(s, Recovery)
	return nil
}

// ============================================================== activity

// ObsReq: ask the broker/harness for the session's activity sequence.
func (c *Ctl) ObsReq(s string) error {
	o := c.Obs[s]
	if err := guard("ObsReq", c.Up && !o.Pending); err != nil {
		return err
	}
	o.Pending, o.ReqAt = true, c.Clock
	c.Obs[s] = o
	return nil
}

func (c *Ctl) GoIdle(s string) error {
	r := c.Rows[s]
	if err := guard("GoIdle", c.Up && r.State == Active && r.Inbox == 0 && c.idleSeen(s)); err != nil {
		return err
	}
	r.State = Idle
	c.Rows[s] = r
	return nil
}

func (c *Ctl) Touch(s string) error {
	r := c.Rows[s]
	if err := guard("Touch", c.Up && r.State == Idle && (r.Inbox > 0 || !c.idleSeen(s))); err != nil {
		return err
	}
	r.State = Active
	c.Rows[s] = r
	return nil
}

// Deliver: a held message reaches the running harness. instUp: the
// session's current instance exists and runs.
func (c *Ctl) Deliver(s string, instUp bool) error {
	r := c.Rows[s]
	if err := guard("Deliver", c.Up && (r.State == Active || r.State == Idle) && r.Inbox > 0 && instUp); err != nil {
		return err
	}
	r.State, r.Inbox = Active, r.Inbox-1
	c.Rows[s] = r
	return nil
}

// CredRefresh: the broker asks the STS for a credential (one per epoch).
func (c *Ctl) CredRefresh(s string) ([]Effect, error) {
	r := c.Rows[s]
	minted := false
	for _, o := range c.Ops {
		if o.Sess == s && o.Kind == OMint && o.Arg == r.CredEpoch {
			minted = true
		}
	}
	if err := guard("CredRefresh", c.Up && (r.State == Active || r.State == Idle) && c.opsLeft(1) && !minted); err != nil {
		return nil, err
	}
	_, e := c.newOp(OMint, s, r.Gen, r.CredEpoch)
	return []Effect{e}, nil
}

// =============================================================== suspend

// pausedLongEnough is Quint pausedLongEnough: a paused session idle for
// IdleAfter + SuspendHold.
func (c *Ctl) pausedLongEnough(s string) bool {
	r, o, p := c.Rows[s], c.Obs[s], c.policy(s)
	return r.State == Paused && r.Phase == PNone && o.Seq >= 0 && o.SeenAt+p.IdleAfter+p.SuspendHold <= c.Clock
}

func (c *Ctl) SuspendBegin(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendBegin", c.Up && ((r.State == Idle && c.idleSeen(s)) || c.pausedLongEnough(s)) &&
		!c.policy(s).KeepWarm && (c.Cfg.MaxGen == 0 || r.Gen < c.Cfg.MaxGen) && len(c.Drivers[s]) == 0 &&
		r.Inbox == 0 && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOp(OQuiesce, s, r.Gen+1, r.Inst)
	r.State, r.Phase, r.Gen, r.Ckpt, r.Op = Suspending, PQuiesce, r.Gen+1, 0, id
	r.DecidedAt, r.DecidedSeq = c.Clock, c.Obs[s].Seq
	c.Rows[s] = r
	c.setDrivers(s, Idler)
	return []Effect{e}, nil
}

func (c *Ctl) SuspendCheckpoint(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendCheckpoint", c.hasDriver(s) && c.inPhase(s, Suspending, PQuiesce) &&
		c.opsLeft(1) && c.opSt(r.Op) == Done); err != nil {
		return nil, err
	}
	id, e := c.newOp(OCheckpoint, s, r.Gen, 0)
	r.Phase, r.Ckpt, r.Op, r.QuiescedAt = PCheckpoint, id, id, c.Clock
	c.Rows[s] = r
	return []Effect{e}, nil
}

func (c *Ctl) SuspendCheckpointRetry(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendCheckpointRetry", c.hasDriver(s) && c.inPhase(s, Suspending, PCheckpoint) &&
		c.opSt(r.Op) == NotDone && c.opsLeft(2)); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	id, e := c.newOp(OCheckpoint, s, r.Gen, 0)
	r.Ckpt, r.Op = id, id
	c.Rows[s] = r
	return append(effs, e), nil
}

func (c *Ctl) SuspendDestroy(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendDestroy", c.hasDriver(s) && c.inPhase(s, Suspending, PCheckpoint) &&
		c.opSt(r.Op) == Done && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOp(ODestroy, s, r.Gen, r.Inst)
	r.Phase, r.Op = PDestroy, id
	c.Rows[s] = r
	return []Effect{e}, nil
}

func (c *Ctl) activityRechecked(s string) bool {
	o, r := c.Obs[s], c.Rows[s]
	return !o.Pending && o.AnsReqAt >= r.QuiescedAt && o.Seq == r.DecidedSeq && r.Inbox == 0
}

func (c *Ctl) SuspendCommit(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendCommit", c.hasDriver(s) && c.inPhase(s, Suspending, PDestroy) &&
		c.tokensLeft() && c.opSt(r.Op) == Done && c.activityRechecked(s)); err != nil {
		return nil, err
	}
	bytes := c.Ops[r.Ckpt].Bytes
	r.State, r.Phase, r.Op, r.Inst = Suspended, PNone, 0, 0
	r.Token = c.TokenOf(c.NextToken)
	r.CredEpoch++
	r.SuspendedAt = c.Clock
	c.NextToken++
	c.Rows[s] = r
	c.setDrivers(s)
	return []Effect{c.fact("suspend", s, c.Clock-r.DecidedAt, bytes)}, nil
}

func (c *Ctl) SuspendAbort(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendAbort", c.hasDriver(s) && r.State == Suspending &&
		(r.Phase == PQuiesce || r.Phase == PCheckpoint || r.Phase == PDestroy) &&
		c.resolved(r.Op) && c.opsLeft(2)); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	id, e := c.newOp(OUnquiesce, s, r.Gen, r.Inst)
	r.Phase, r.Op = PAbort, id
	c.Rows[s] = r
	return append(effs, e), nil
}

func (c *Ctl) SuspendAbortDone(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendAbortDone", c.hasDriver(s) && c.inPhase(s, Suspending, PAbort) && c.opSt(r.Op) == Done); err != nil {
		return nil, err
	}
	r.State, r.Phase, r.Op, r.Ckpt = Idle, PNone, 0, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return []Effect{c.fact("suspend_abort", s, c.Clock-r.DecidedAt, 0)}, nil
}

// SuspendFail: the abort's unquiesce is known not done and the instance is
// gone. instExists: the session's current instance exists.
func (c *Ctl) SuspendFail(s string, instExists bool) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendFail", c.hasDriver(s) && c.inPhase(s, Suspending, PAbort) &&
		c.opSt(r.Op) == NotDone && !instExists); err != nil {
		return nil, err
	}
	r.State, r.Phase, r.Op, r.Ckpt = Failed, PNone, 0, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return []Effect{c.fact("fail", s, 0, 0)}, nil
}

// ============================================== pause tier (SR1)

// PauseBegin: an idle session's processes are SIGSTOPped (frees CPU only).
func (c *Ctl) PauseBegin(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("PauseBegin", c.Up && r.State == Idle && c.policy(s).Pause && len(c.Drivers[s]) == 0 &&
		r.Inbox == 0 && c.idleSeen(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOp(OPause, s, r.Gen, r.Inst)
	r.State, r.Phase, r.Op = Paused, PPause, id
	c.Rows[s] = r
	c.setDrivers(s, Idler)
	return []Effect{e}, nil
}

func (c *Ctl) PauseDone(s string) error {
	r := c.Rows[s]
	if err := guard("PauseDone", c.hasDriver(s) && c.inPhase(s, Paused, PPause) && c.opSt(r.Op) == Done); err != nil {
		return err
	}
	r.Phase, r.Op = PNone, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return nil
}

// UnpauseBegin: a held message, new activity, or a pause known not done
// wakes the session. The fence (PAUSE_FENCE): never while the pause op can
// still land -- a late SIGSTOP after the SIGCONT would freeze an awake
// session (Quint noFrozenAwake).
func (c *Ctl) UnpauseBegin(s string) ([]Effect, error) {
	r := c.Rows[s]
	wake := r.Inbox > 0 || !c.idleSeen(s) || (r.Op != 0 && c.opSt(r.Op) == NotDone)
	if err := guard("UnpauseBegin", c.Up && r.State == Paused && (r.Phase == PNone || r.Phase == PPause) &&
		c.resolved(r.Op) && wake && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOp(OUnpause, s, r.Gen, r.Inst)
	r.Phase, r.Op = PUnpause, id
	c.Rows[s] = r
	c.setDrivers(s, Idler)
	return []Effect{e}, nil
}

func (c *Ctl) UnpauseDone(s string) error {
	r := c.Rows[s]
	if err := guard("UnpauseDone", c.hasDriver(s) && c.inPhase(s, Paused, PUnpause) && c.opSt(r.Op) == Done); err != nil {
		return err
	}
	r.State, r.Phase, r.Op = Idle, PNone, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return nil
}

// UnpauseFail: the unpause is known not done and the instance is gone.
func (c *Ctl) UnpauseFail(s string, instExists bool) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("UnpauseFail", c.hasDriver(s) && c.inPhase(s, Paused, PUnpause) &&
		c.opSt(r.Op) == NotDone && !instExists); err != nil {
		return nil, err
	}
	r.State, r.Phase, r.Op = Failed, PNone, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return []Effect{c.fact("fail", s, 0, 0)}, nil
}

// ================================================================ resume

// ResumeConsume is the token consume (Quint ResumeConsume, and with force
// ResumeConsumeForce: the request carries the override to resume on a
// workspace changed since the snapshot); a mismatch is ResumeReject
// (ErrTokenRejected, no change). The Store makes the same check a single
// conditional UPDATE. A session with a project goes to PKey first (its
// load is sent by ResumeLoadKey), others restore at once.
func (c *Ctl) ResumeConsume(s, d string, tok int64, force bool) ([]Effect, error) {
	r, ok := c.Rows[s]
	if !c.Up || !slices.Contains(c.Cfg.Clients, d) {
		return nil, guard("ResumeConsume", false)
	}
	if !ok || r.State != Suspended || tok == 0 || r.Token != tok {
		return nil, ErrTokenRejected
	}
	if err := guard("ResumeConsume", c.opsLeft(1)); err != nil {
		return nil, err
	}
	var effs []Effect
	r.State, r.Token, r.ConsumedAt, r.Force = Resuming, 0, c.Clock, force
	if r.Project != "" {
		r.Phase, r.Op = PKey, 0
	} else {
		id, e := c.newOpF(ORestore, s, r.Gen, r.Ckpt, force)
		r.Phase, r.Op = PRestore, id
		effs = append(effs, e)
	}
	c.Rows[s] = r
	c.Drivers[s][d] = true
	return effs, nil
}

// ResumeLoadKey sends the key load of a resume in PKey, once the project's
// unload (if any) is resolved: KEY_FENCE, a late unmount or unload-key
// would otherwise land after the load (Quint keyUnderActive).
func (c *Ctl) ResumeLoadKey(s, d string) ([]Effect, error) {
	r := c.Rows[s]
	pr := c.Projects[r.Project]
	if err := guard("ResumeLoadKey", c.drives(s, d) && c.inPhase(s, Resuming, PKey) && r.Op == 0 &&
		c.opsLeft(1) && pr.Phase == KNone && c.resolved(pr.Op)); err != nil {
		return nil, err
	}
	id, e := c.newOp(OLoadKey, s, r.Gen, 0)
	r.Op = id
	c.Rows[s] = r
	return []Effect{e}, nil
}

// ResumeKeyDone: the key is loaded; restore validates drift before mounting.
func (c *Ctl) ResumeKeyDone(s, d string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("ResumeKeyDone", c.drives(s, d) && c.inPhase(s, Resuming, PKey) && r.Op != 0 &&
		c.opSt(r.Op) == Done && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOpF(ORestore, s, r.Gen, r.Ckpt, r.Force)
	r.Phase, r.Op = PRestore, id
	c.Rows[s] = r
	p := c.Projects[r.Project]
	p.Loaded = true
	c.Projects[r.Project] = p
	return []Effect{e}, nil
}

// ResumeMint: restored; ask the STS for a credential of the new epoch.
// instUp: instance <gen> exists.
func (c *Ctl) ResumeMint(s, d string, instUp bool) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("ResumeMint", c.drives(s, d) && c.inPhase(s, Resuming, PRestore) &&
		c.opSt(r.Op) == Done && instUp && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id, e := c.newOp(OMint, s, r.Gen, r.CredEpoch)
	r.Phase, r.Op = PMint, id
	c.Rows[s] = r
	return []Effect{e}, nil
}

func (c *Ctl) ResumeComplete(s, d string, instUp bool) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("ResumeComplete", c.drives(s, d) && c.inPhase(s, Resuming, PMint) &&
		c.opSt(r.Op) == Done && instUp && c.opsLeft(1)); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	r.State, r.Phase, r.Op, r.Ckpt, r.Inst, r.Resumes = Active, PNone, 0, 0, r.Gen, r.Resumes+1
	r.Force, r.Drift = false, false
	c.Rows[s] = r
	c.setDrivers(s)
	f := c.fact("resume", s, c.Clock-r.ConsumedAt, 0)
	f.Fact.SuspendedMs = r.ConsumedAt - r.SuspendedAt
	return append(effs, f), nil
}

// ResumeAbort: the restore (or the key load) is known not done, or the
// restore refused a changed workspace: back to Suspended with a fresh
// token. A refusal is recorded on the row (Drift) and as its own fact.
func (c *Ctl) ResumeAbort(s, d string) ([]Effect, error) {
	r := c.Rows[s]
	st := c.opSt(r.Op)
	enabled := (r.Phase == PRestore && (st == NotDone || st == Refused)) || (r.Phase == PKey && r.Op != 0 && st == NotDone)
	if err := guard("ResumeAbort", c.drives(s, d) && r.State == Resuming && enabled && c.tokensLeft()); err != nil {
		return nil, err
	}
	refused := r.Phase == PRestore && st == Refused
	r.State, r.Phase, r.Op, r.Token = Suspended, PNone, 0, c.TokenOf(c.NextToken)
	r.Force, r.Drift = false, refused
	c.NextToken++
	c.Rows[s] = r
	c.setDrivers(s)
	name := "resume_abort"
	if refused {
		name = "resume_refused_drift"
	}
	return []Effect{c.fact(name, s, 0, 0)}, nil
}

func (c *Ctl) ResumeFail(s, d string, instUp bool) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("ResumeFail", c.drives(s, d) && r.State == Resuming &&
		(r.Phase == PRestore || r.Phase == PMint) && (r.Phase == PMint || c.opSt(r.Op) == Done) &&
		!instUp && c.opsLeft(1)); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	r.State, r.Phase, r.Op, r.Ckpt = Failed, PNone, 0, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return append(effs, c.fact("fail", s, 0, 0)), nil
}

// =================================================================== TTL

// Expire: the suspended age passed the class TTL and nothing is held for
// the session. The Store makes it a conditional UPDATE racing the consume.
func (c *Ctl) Expire(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("Expire", c.Up && r.State == Suspended && c.Clock >= r.SuspendedAt+c.policy(s).MaxAge &&
		r.Inbox == 0 && c.opsLeft(1)); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	r.State, r.Token, r.Ckpt = Expired, 0, 0
	c.Rows[s] = r
	return append(effs, c.fact("expire", s, c.Clock-r.SuspendedAt, 0)), nil
}

// ============================================ liveness (SR1 decision 3)

// ProbeReq asks whether an awake session's current instance is alive.
func (c *Ctl) ProbeReq(s string) error {
	r, ok := c.Rows[s]
	if err := guard("ProbeReq", ok && c.Up && (r.State == Active || r.State == Idle) && !c.Probes[s].Pending); err != nil {
		return err
	}
	c.Probes[s] = Probe{Pending: true, ReqAt: c.Clock, Inst: r.Inst, Gen: r.Gen}
	return nil
}

// ProbeAnswer: the probe's answer arrived (alive: the instance exists and
// has processes, as the probe read it).
func (c *Ctl) ProbeAnswer(s string, alive bool) error {
	p := c.Probes[s]
	if err := guard("ProbeAnswer", c.Up && p.Pending); err != nil {
		return err
	}
	p.Pending, p.Answered, p.Alive = false, true, alive
	c.Probes[s] = p
	return nil
}

// ProbeTimeout: no answer within OpTimeout: unknown, never dead
// (PROBE_TIMEOUT_UNKNOWN).
func (c *Ctl) ProbeTimeout(s string) error {
	p := c.Probes[s]
	if err := guard("ProbeTimeout", c.Up && p.Pending && c.Clock >= p.ReqAt+c.Cfg.OpTimeout); err != nil {
		return err
	}
	p.Pending, p.Answered, p.Alive = false, false, false
	c.Probes[s] = p
	return nil
}

// LostDetect: a definite "not alive" for the row's current instance and
// generation (PROBE_CURRENT; a suspend attempt bumps the generation): the
// instance died while the session was awake. The session fails.
func (c *Ctl) LostDetect(s string) ([]Effect, error) {
	r := c.Rows[s]
	p := c.Probes[s]
	if err := guard("LostDetect", c.Up && (r.State == Active || r.State == Idle) && len(c.Drivers[s]) == 0 &&
		p.Answered && !p.Alive && p.Inst == r.Inst && p.Gen == r.Gen); err != nil {
		return nil, err
	}
	r.State, r.Phase, r.Op = Failed, PNone, 0
	c.Rows[s] = r
	c.Probes[s] = Probe{}
	return []Effect{c.fact("lost", s, 0, 0)}, nil
}

// =================================== project keys (SR1 layout D)

var keyIdle = []State{Suspended, Expired, Failed, Removed}

// KeyUnloadBegin: no session of project p is active or in flight, and no
// key load of it is unresolved (KEY_GUARD): unmount every dataset of the
// project (then KeyUnmountDone unloads the key).
func (c *Ctl) KeyUnloadBegin(p string) ([]Effect, error) {
	pr, ok := c.Projects[p]
	idle := true
	for s, r := range c.Rows {
		if r.Project != p {
			continue
		}
		// JAIL_FIRST: the op the row waits on (a removed session's destroy:
		// its jail holds the clone) must be done, not merely resolved
		if !slices.Contains(keyIdle, r.State) || len(c.Drivers[s]) > 0 || (r.Op != 0 && c.opSt(r.Op) != Done) {
			idle = false
		}
	}
	for id, o := range c.Ops {
		if o.Kind == OLoadKey && c.Rows[o.Sess].Project == p && !c.resolved(id) {
			idle = false
		}
	}
	if err := guard("KeyUnloadBegin", ok && c.Up && c.opsLeft(1) && pr.Phase == KNone && pr.Loaded &&
		c.resolved(pr.Op) && idle); err != nil {
		return nil, err
	}
	id, e := c.newOp(OUnmount, p, 0, 0)
	pr.Phase, pr.Op = KUnmount, id
	c.Projects[p] = pr
	return []Effect{e}, nil
}

// KeyUnmountDone: every dataset of the project is unmounted: unload-key.
func (c *Ctl) KeyUnmountDone(p string) ([]Effect, error) {
	pr, ok := c.Projects[p]
	if err := guard("KeyUnmountDone", ok && c.Up && c.opsLeft(1) && pr.Phase == KUnmount && c.opSt(pr.Op) == Done); err != nil {
		return nil, err
	}
	id, e := c.newOp(OUnloadKey, p, 0, 0)
	pr.Phase, pr.Op = KUnload, id
	c.Projects[p] = pr
	return []Effect{e}, nil
}

// KeyUnloadDone: the key is unloaded.
func (c *Ctl) KeyUnloadDone(p string) ([]Effect, error) {
	pr, ok := c.Projects[p]
	if err := guard("KeyUnloadDone", ok && c.Up && pr.Phase == KUnload && c.opSt(pr.Op) == Done); err != nil {
		return nil, err
	}
	c.Projects[p] = Proj{Phase: KNone}
	return []Effect{{Kind: EffFact, Fact: Fact{Name: "key_unloaded", Session: p}}}, nil
}

// KeyUnloadAbort: the unmount or unload is known not done; give up (the key
// stays loaded as far as yard-ctl knows; a later KeyUnloadBegin tries again).
func (c *Ctl) KeyUnloadAbort(p string) error {
	pr, ok := c.Projects[p]
	if err := guard("KeyUnloadAbort", ok && c.Up && (pr.Phase == KUnmount || pr.Phase == KUnload) &&
		c.opSt(pr.Op) == NotDone); err != nil {
		return err
	}
	pr.Phase, pr.Op = KNone, 0
	c.Projects[p] = pr
	return nil
}

// RecoverProjOps: after a restart, a pending op of project p is unknown.
func (c *Ctl) RecoverProjOps(p string) error {
	if _, ok := c.Projects[p]; !ok {
		return guard("RecoverProjOps", false)
	}
	return c.RecoverOps(p)
}

// ============================================ removal (SR1 round 2)

// Remove is `yard-svc down` (Quint Remove): a session no suspend or resume
// is driving (REMOVE_GUARD) becomes Removed. A live instance is destroyed
// (the row waits on that op; the project key stays until it is done), the
// checkpoint deleted (owed), the token and held messages dropped. Terminal.
// instExists: the session's current instance exists (the backend's view).
func (c *Ctl) Remove(s string, instExists bool) ([]Effect, error) {
	r, ok := c.Rows[s]
	quiet := r.State == Active || r.State == Idle || r.State == Suspended || r.State == Expired || r.State == Failed ||
		(r.State == Paused && r.Phase == PNone && c.resolved(r.Op))
	if err := guard("Remove", ok && c.Up && c.opsLeft(2) && r.State != Removed && quiet && len(c.Drivers[s]) == 0); err != nil {
		return nil, err
	}
	effs := c.issueDelete(s, r.Ckpt)
	live := (r.State == Active || r.State == Idle || r.State == Paused) && instExists
	r.Op = 0
	if live {
		id, e := c.newOp(ODestroy, s, r.Gen, r.Inst)
		effs = append(effs, e)
		r.Op = id
	}
	r.State, r.Phase, r.Token, r.Ckpt, r.Inbox = Removed, PNone, 0, 0, 0
	c.Rows[s] = r
	c.setDrivers(s)
	return append(effs, c.fact("removed", s, 0, 0)), nil
}
