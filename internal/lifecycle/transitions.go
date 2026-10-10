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
	return id == 0 || c.opSt(id) == Done || c.opSt(id) == NotDone
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
	id := c.NextOp
	c.Ops[id] = Op{ID: id, Kind: k, Sess: s, Gen: gen, Arg: arg, St: Pending, SentAt: c.Clock, Attempts: 1, Inc: c.Inc}
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

var retryable = []OpKind{OQuiesce, ODestroy, OUnquiesce, OMint, ODelete}

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
// incarnation that sent the copy, and only while the op is Pending. ok:
// the process exited 0 (the effect holds); an error exit is Unknown.
func (c *Ctl) OpAnswer(id, inc int64, ok bool, bytes int64) {
	o, has := c.Ops[id]
	if !has || !c.Up || inc != c.Inc || o.St != Pending {
		return
	}
	if ok {
		o.St = Done
		o.Bytes = bytes
	} else {
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
	if err := guard("MessageArrive", ok && c.Up && r.State != Expired && r.State != Failed); err != nil {
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
		(c.Cfg.MaxAttempts == 0 || o.Attempts < c.Cfg.MaxAttempts)); err != nil {
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

// Adopt: a recovery driver takes over an in-flight row.
func (c *Ctl) Adopt(s string) error {
	r, ok := c.Rows[s]
	if err := guard("Adopt", ok && c.Up && (r.State == Suspending || r.State == Resuming) &&
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

func (c *Ctl) SuspendBegin(s string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("SuspendBegin", c.Up && r.State == Idle && !c.policy(s).KeepWarm &&
		(c.Cfg.MaxGen == 0 || r.Gen < c.Cfg.MaxGen) && len(c.Drivers[s]) == 0 && r.Inbox == 0 &&
		c.idleSeen(s) && c.opsLeft(1)); err != nil {
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

// ================================================================ resume

// ResumeConsume is the token consume (Quint ResumeConsume); a mismatch is
// ResumeReject (ErrTokenRejected, no change). The Store makes the same
// check a single conditional UPDATE.
func (c *Ctl) ResumeConsume(s, d string, tok int64) ([]Effect, error) {
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
	id, e := c.newOp(ORestore, s, r.Gen, r.Ckpt)
	r.State, r.Phase, r.Token, r.Op, r.ConsumedAt = Resuming, PRestore, 0, id, c.Clock
	c.Rows[s] = r
	c.Drivers[s][d] = true
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
	c.Rows[s] = r
	c.setDrivers(s)
	f := c.fact("resume", s, c.Clock-r.ConsumedAt, 0)
	f.Fact.SuspendedMs = r.ConsumedAt - r.SuspendedAt
	return append(effs, f), nil
}

func (c *Ctl) ResumeAbort(s, d string) ([]Effect, error) {
	r := c.Rows[s]
	if err := guard("ResumeAbort", c.drives(s, d) && c.inPhase(s, Resuming, PRestore) &&
		c.opSt(r.Op) == NotDone && c.tokensLeft()); err != nil {
		return nil, err
	}
	r.State, r.Phase, r.Op, r.Token = Suspended, PNone, 0, c.TokenOf(c.NextToken)
	c.NextToken++
	c.Rows[s] = r
	c.setDrivers(s)
	return []Effect{c.fact("resume_abort", s, 0, 0)}, nil
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
