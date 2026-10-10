package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"
)

// Machine runs Ctl for yard-ctl: every transition is computed on a clone,
// committed to SQLite, and only then made current and its effects started
// (copies of ops on the Executor, facts on the sink). The resume token
// consume and the TTL expiry are the Store's conditional UPDATEs, so a
// second process or handle on the same database cannot double-resume.
type Machine struct {
	mu      sync.Mutex
	ctl     *Ctl
	store   *Store
	ex      Executor
	facts   FactSink
	now     func() int64
	ctx     context.Context
	wg      sync.WaitGroup
	sending map[int64]int // copies this incarnation started that have not returned
}

// RandomToken is the production TokenOf: a fresh non-zero 63-bit secret.
func RandomToken(int64) int64 {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if v := int64(binary.BigEndian.Uint64(b[:]) >> 1); v != 0 {
			return v
		}
	}
}

// Start loads the store, begins a new incarnation (CtlRestart), marks the
// earlier incarnation's pending ops Unknown (RecoverOps) and adopts the
// rows that were suspending or resuming (Adopt). Recovery resolves them by
// observation in Poll, never by assumption.
func Start(ctx context.Context, st *Store, cfg Config, ex Executor, facts FactSink, now func() int64) (*Machine, error) {
	if enc, ok := ex.(interface {
		Encrypted(context.Context) (bool, error)
	}); ok {
		yes, err := enc.Encrypted(ctx)
		if err != nil {
			return nil, err
		}
		if !yes {
			return nil, errors.New("lifecycle: artifact dataset is not encrypted")
		}
	}
	loaded, err := st.Restore(cfg)
	if err != nil {
		return nil, err
	}
	loaded.TokenOf = RandomToken
	c := loaded.Clone()
	c.SetClock(now())
	if err := c.CtlRestart(); err != nil {
		return nil, err
	}
	ids := sortedIDs(c)
	before := maps.Clone(c.Ops)
	for _, s := range ids {
		_ = c.RecoverOps(s) // ErrGuard: nothing pending
	}
	var restarted []OpKind
	for id, o := range c.Ops {
		if before[id].St == Pending && o.St == Unknown {
			restarted = append(restarted, o.Kind)
		}
	}
	for _, s := range ids {
		_ = c.Adopt(s)
	}
	if err := st.Commit(loaded, c); err != nil {
		return nil, err
	}
	m := &Machine{ctl: c, store: st, ex: ex, facts: facts, now: now, ctx: ctx, sending: map[int64]int{}}
	for _, k := range restarted {
		m.count(k, "restart_unknown")
	}
	return m, nil
}

func (m *Machine) count(k OpKind, class string) {
	if oc, ok := m.facts.(OutcomeCounter); ok {
		oc.CountOutcome(k, class)
	}
}

// Epoch is the session's current credential epoch (issuer.EpochSource):
// the STS mints only it and the broker honours only it (invariant I3).
func (m *Machine) Epoch(sess string) (int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.ctl.Rows[sess]
	return r.CredEpoch, ok
}

func sortedIDs(c *Ctl) []string {
	ids := make([]string, 0, len(c.Rows))
	for id := range c.Rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// State returns a copy of the controller state.
func (m *Machine) State() *Ctl {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ctl.Clone()
}

// Wait blocks until every op copy this Machine started has returned.
func (m *Machine) Wait() { m.wg.Wait() }

// apply runs one transition: clone, transition, commit, swap, effects.
func (m *Machine) apply(f func(c *Ctl) ([]Effect, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(f)
}

func (m *Machine) applyLocked(f func(c *Ctl) ([]Effect, error)) error {
	next := m.ctl.Clone()
	next.SetClock(m.now())
	effs, err := f(next)
	if err != nil {
		return err
	}
	if err := m.store.Commit(m.ctl, next); err != nil {
		return err
	}
	m.ctl = next
	m.dispatch(effs)
	return nil
}

func (m *Machine) dispatch(effs []Effect) {
	for _, e := range effs {
		switch e.Kind {
		case EffFact:
			if m.facts != nil {
				m.facts.Emit(e.Fact)
			}
		case EffSend:
			op, row, inc := m.ctl.Ops[e.Op], m.ctl.Rows[m.ctl.Ops[e.Op].Sess], m.ctl.Inc
			m.sending[op.ID]++
			m.wg.Add(1)
			go m.runCopy(op, row, inc)
		}
	}
}

// runCopy is one copy of an op in flight; its answer reaches only this
// incarnation (OpAnswer checks inc).
func (m *Machine) runCopy(op Op, row Row, inc int64) {
	defer m.wg.Done()
	ok, bytes := m.ex.Exec(m.ctx, op, row)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sending[op.ID]--
	_ = m.applyLocked(func(c *Ctl) ([]Effect, error) {
		before := c.Ops[op.ID].St
		c.OpAnswer(op.ID, inc, ok, bytes)
		switch after := c.Ops[op.ID].St; {
		case before == Pending && after == Done:
			m.count(op.Kind, "answer_done")
		case before == Pending && after == Unknown:
			m.count(op.Kind, "answer_error")
		default:
			m.count(op.Kind, "answer_ignored")
		}
		return nil, nil
	})
}

// AddSession registers a new Active session of a run class and kind.
func (m *Machine) AddSession(id, class, kind string) error {
	if _, ok := m.ctl.Cfg.Policies[class]; !ok {
		return fmt.Errorf("lifecycle: no policy for run class %q", class)
	}
	return m.apply(func(c *Ctl) ([]Effect, error) {
		if _, dup := c.Rows[id]; dup {
			return nil, fmt.Errorf("lifecycle: session %q exists", id)
		}
		c.AddSession(id, class, kind)
		return nil, nil
	})
}

// Message holds an inbound message or approval for the session
// (MessageArrive). A suspended session is woken by Poll.
func (m *Machine) Message(sess string) error {
	return m.apply(func(c *Ctl) ([]Effect, error) { return nil, c.MessageArrive(sess) })
}

// Token returns the session's current resume token, for an internal
// trigger (scheduler, timer, approval) entitled to resume it.
func (m *Machine) Token(sess string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ctl.Rows[sess].Token
}

// Resume consumes the one-shot token (ResumeConsume / ResumeReject). The
// Store's conditional UPDATE decides: of any number of concurrent callers,
// in this or another process, one wins and the rest get ErrTokenRejected.
func (m *Machine) Resume(sess, client string, token int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.ctl.Clone()
	next.SetClock(m.now())
	effs, err := next.ResumeConsume(sess, client, token)
	if err != nil {
		return err
	}
	r := next.Rows[sess]
	won, err := m.store.ConsumeToken(sess, token, r, next.Ops[r.Op])
	if err != nil {
		return err
	}
	if !won {
		// another handle consumed or expired it: take the stored row
		if err := m.reloadRowLocked(sess); err != nil {
			return err
		}
		return ErrTokenRejected
	}
	// the UPDATE wrote the row and the op; commit anything else against that
	if err := m.store.Commit(written(m.ctl, next, sess, r.Op), next); err != nil {
		return err
	}
	m.ctl = next
	m.dispatch(effs)
	return nil
}

// written is prev with the row and op a conditional UPDATE already stored.
func written(prev, next *Ctl, sess string, op int64) *Ctl {
	w := prev.Clone()
	w.Rows[sess] = next.Rows[sess]
	if op != 0 {
		w.Ops[op] = next.Ops[op]
	}
	return w
}

func (m *Machine) reloadRowLocked(sess string) error {
	d, err := m.store.Load()
	if err != nil {
		return err
	}
	if r, ok := d.Rows[sess]; ok {
		m.ctl.Rows[sess] = r
	}
	for id, o := range d.Ops {
		m.ctl.Ops[id] = o
	}
	m.ctl.NextOp = max(m.ctl.NextOp, d.NextOp)
	return nil
}

// expire runs Expire through the Store's conditional UPDATE.
func (m *Machine) expireLocked(sess string) error {
	next := m.ctl.Clone()
	next.SetClock(m.now())
	prevTok := m.ctl.Rows[sess].Token
	effs, err := next.Expire(sess)
	if err != nil {
		return err
	}
	var del *Op
	for _, e := range effs {
		if e.Kind == EffSend {
			o := next.Ops[e.Op]
			del = &o
		}
	}
	won, err := m.store.Expire(sess, prevTok, next.Rows[sess], del)
	if err != nil {
		return err
	}
	if !won {
		return m.reloadRowLocked(sess)
	}
	var delID int64
	if del != nil {
		delID = del.ID
	}
	if err := m.store.Commit(written(m.ctl, next, sess, delID), next); err != nil {
		return err
	}
	m.ctl = next
	m.dispatch(effs)
	return nil
}

// Poll is one pass of the drivers: time out, resolve and retry ops; observe
// activity; move every session along whichever transition is enabled. It
// is the only scheduler; Run calls it on a timer.
func (m *Machine) Poll(ctx context.Context) error {
	m.pollOps(ctx)
	for _, s := range sortedIDs(m.State()) {
		m.observe(ctx, s)
		m.pollSession(ctx, s)
	}
	return nil
}

func (m *Machine) try(f func(c *Ctl) ([]Effect, error)) bool {
	return m.apply(f) == nil
}

func (m *Machine) pollOps(ctx context.Context) {
	c := m.State()
	ids := make([]int64, 0, len(c.Ops))
	for id := range c.Ops {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if m.try(func(c *Ctl) ([]Effect, error) { return nil, c.OpTimeout(id) }) {
			m.count(c.Ops[id].Kind, "timeout")
		}
		op := m.State().Ops[id]
		if op.St == Unknown {
			m.mu.Lock()
			local := m.sending[id]
			row := m.ctl.Rows[op.Sess]
			m.mu.Unlock()
			settled, err := m.ex.Settled(ctx, op, row)
			if err != nil || local > 0 || !settled {
				continue // wait: a copy may still land
			}
			done, err := m.ex.Observe(ctx, op, row)
			if err != nil {
				continue
			}
			if m.try(func(c *Ctl) ([]Effect, error) { return nil, c.OpResolve(id, true, done) }) {
				if done {
					m.count(op.Kind, "resolved_done")
				} else {
					m.count(op.Kind, "resolved_not_done")
				}
			}
		}
		if m.try(func(c *Ctl) ([]Effect, error) { return c.OpRetry(id) }) {
			m.count(c.Ops[id].Kind, "retry")
		}
	}
}

// observe is the slow activity observation: request, answer later (here:
// after the Activity call returns), dated at the answer.
func (m *Machine) observe(ctx context.Context, s string) {
	if !m.try(func(c *Ctl) ([]Effect, error) { return nil, c.ObsReq(s) }) {
		return
	}
	seq, err := m.ex.Activity(ctx, s)
	if err != nil {
		// no answer: the request stays pending until the next restart; try
		// again by clearing it (a lost observation answer)
		m.try(func(c *Ctl) ([]Effect, error) {
			o := c.Obs[s]
			o.Pending = false
			c.Obs[s] = o
			return nil, nil
		})
		return
	}
	m.try(func(c *Ctl) ([]Effect, error) { return nil, c.ObsAnswer(s, seq) })
}

func (m *Machine) instance(ctx context.Context, row Row, name int64) (exists, running bool) {
	e, r, err := m.ex.Instance(ctx, row, name)
	if err != nil {
		return true, false // unknown: neither "gone" nor "up"
	}
	return e, r
}

func (m *Machine) pollSession(ctx context.Context, s string) {
	c := m.State()
	r := c.Rows[s]
	switch r.State {
	case Active:
		if r.Inbox > 0 {
			if _, run := m.instance(ctx, r, r.Inst); run {
				m.try(func(c *Ctl) ([]Effect, error) { return nil, c.Deliver(s, true) })
			}
		}
		m.try(func(c *Ctl) ([]Effect, error) { return nil, c.GoIdle(s) })
	case Idle:
		if m.try(func(c *Ctl) ([]Effect, error) { return nil, c.Touch(s) }) {
			return
		}
		m.try(func(c *Ctl) ([]Effect, error) { return c.SuspendBegin(s) })
	case Suspending:
		o := c.Obs[s]
		changed := (o.Seq != r.DecidedSeq && o.Seq >= 0) || r.Inbox > 0
		if changed && r.Phase != PAbort {
			m.try(func(c *Ctl) ([]Effect, error) { return c.SuspendAbort(s) })
			return
		}
		for _, f := range []func(c *Ctl) ([]Effect, error){
			func(c *Ctl) ([]Effect, error) { return c.SuspendCheckpoint(s) },
			func(c *Ctl) ([]Effect, error) { return c.SuspendCheckpointRetry(s) },
			func(c *Ctl) ([]Effect, error) { return c.SuspendDestroy(s) },
			func(c *Ctl) ([]Effect, error) { return c.SuspendCommit(s) },
			func(c *Ctl) ([]Effect, error) { return c.SuspendAbortDone(s) },
		} {
			if m.try(f) {
				return
			}
		}
		if r.Phase == PAbort {
			exists, _ := m.instance(ctx, r, r.Inst)
			m.try(func(c *Ctl) ([]Effect, error) { return c.SuspendFail(s, exists) })
		}
	case Resuming:
		ds := c.DriverSet(s)
		if len(ds) == 0 {
			return
		}
		d := ds[0]
		exists, _ := m.instance(ctx, r, r.Gen)
		for _, f := range []func(c *Ctl) ([]Effect, error){
			func(c *Ctl) ([]Effect, error) { return c.ResumeMint(s, d, exists) },
			func(c *Ctl) ([]Effect, error) { return c.ResumeComplete(s, d, exists) },
			func(c *Ctl) ([]Effect, error) { return c.ResumeAbort(s, d) },
			func(c *Ctl) ([]Effect, error) { return c.ResumeFail(s, d, exists) },
		} {
			if m.try(f) {
				return
			}
		}
	case Suspended:
		if r.Inbox > 0 {
			_ = m.Resume(s, c.Cfg.Clients[0], r.Token) // a held message wakes it
			return
		}
		m.mu.Lock()
		_ = m.expireLocked(s)
		m.mu.Unlock()
	}
}
