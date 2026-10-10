package keysvc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"yard/internal/issuer"
	"yard/internal/wskey"
)

// Workspace is the ZFS consumer as the spill side needs it at a resume:
// load the session's project key and mount its clone (idempotent; already
// loaded is done), and observe it. internal/service.Backend implements it
// (lifecycle.Keys, through wskey); nil: the session has no workspace.
type Workspace interface {
	LoadKey(ctx context.Context, sess string) error
	KeyLoaded(ctx context.Context, sess string) (bool, error)
}

// Typed errors of Seal / Open / Discard.
var (
	ErrUnknown      = errors.New("keysvc: outcome unknown (verify later)")
	ErrNotDone      = errors.New("keysvc: not done")
	ErrEpochBurnt   = errors.New("keysvc: a spill at this epoch may have landed (aborted suspend): no seal until the epoch moves")
	ErrStale        = errors.New("keysvc: halo or the issuer refused a stale epoch")
	ErrFenced       = errors.New("keysvc: the epoch is fenced by a revoke")
	ErrUsed         = errors.New("keysvc: halo already used this epoch's key")
	ErrEntryGone    = errors.New("keysvc: the halo cache entry is gone (re-prefill)")
	ErrNotCommitted = errors.New("keysvc: the suspend is not committed (epoch not bumped): no open")
	ErrNoCheckpoint = errors.New("keysvc: no spill key for this checkpoint")
	ErrBusy         = errors.New("keysvc: an op of this session is still in flight")
	ErrOpConflict   = errors.New("keysvc: operation identity conflict")
	ErrRetryLater   = errors.New("keysvc: halo operation history is full (retry later)")
)

// Options configure a Service.
type Options struct {
	Cfg    Config
	Store  *Store
	KEK    *wskey.KEK
	Halo   HaloAPI
	Mint   Minter
	Epochs issuer.EpochSource // the lifecycle (Machine.Epoch)
	WS     Workspace
	Now    func() int64 // milliseconds
}

// ProductionConfig: tokens live 300 s (plus a 5 s margin for the mint's
// latency); halo's key TTL 600 s; 3 attempts per op.
func ProductionConfig() Config {
	return Config{TokenTTL: 305_000, HaloTTL: 600_000, OpTimeout: 15_000, MaxAttempts: 3}
}

// mutants are planted defects the tests must catch (never set in production).
type mutants struct {
	reuseKey          bool // a checkpoint reuses the session's previous key
	openBeforeCommit  bool // open without the commit's epoch bump
	shredBeforeSettle bool // claim the shred as soon as the wrapped key is deleted
	wrongEntry        bool // the seal claim names another cache entry
	implicitThrough   bool // revoke without `through` (halo's default)
	revokeUnburnt     bool // revoke an unspilled key too (fences a live epoch after an abort)
	blindRetry        bool // an unanswered seal is replaced by a fresh key, unverified
	noBurntGuard      bool // seal at an epoch an aborted spill burnt
	reuseOpID         bool // a new operation carries the session's previous op id (of the same use)
	noRenew           bool // a cancelled / outlived operation is retried, never renewed
}

// Service is the spill-key side of the key service: Ctl, run.
type Service struct {
	o       Options
	mu      sync.Mutex
	ctl     *Ctl
	sending map[int64]int
	last    map[int64]Answer // memory: each op's last answer (classifies refusals)
	wrapped map[int64][]byte // wrapped bytes of keys created in the transition being committed
	smu     map[string]*sync.Mutex
	mut     mutants
	reused  map[string][]byte // mutant reuseKey only
	nonce   int64             // the key database's id: op ids are "y<nonce>.<op id>"
}

// Start loads the store and begins a new incarnation (CtlRestart,
// RecoverOps): ops of an earlier process are Unknown, resolved by
// observation, never by assumption.
func Start(o Options) (*Service, error) {
	if o.Now == nil || o.Store == nil || o.KEK == nil || o.Halo == nil || o.Mint == nil || o.Epochs == nil {
		return nil, errors.New("keysvc: incomplete options")
	}
	loaded, err := o.Store.Load(o.Cfg)
	if err != nil {
		return nil, err
	}
	c := loaded.Clone()
	c.SetClock(o.Now())
	c.Up = false
	if err := c.CtlRestart(); err != nil {
		return nil, err
	}
	_ = c.RecoverOps()
	if err := o.Store.Commit(loaded, c, func(int64) []byte { return nil }); err != nil {
		return nil, err
	}
	nonce, err := o.Store.Nonce()
	if err != nil {
		return nil, err
	}
	return &Service{o: o, ctl: c, sending: map[int64]int{}, last: map[int64]Answer{}, wrapped: map[int64][]byte{},
		smu: map[string]*sync.Mutex{}, nonce: nonce}, nil
}

// State returns a copy of the controller.
func (s *Service) State() *Ctl {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctl.Clone()
}

func (s *Service) apply(f func(c *Ctl) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(f)
}

func (s *Service) applyLocked(f func(c *Ctl) error) error {
	next := s.ctl.Clone()
	next.SetClock(s.o.Now())
	clear(s.wrapped)
	if err := f(next); err != nil {
		return err
	}
	if !equalDurable(s.ctl, next) {
		if err := s.o.Store.Commit(s.ctl, next, func(id int64) []byte { return s.wrapped[id] }); err != nil {
			return err
		}
	}
	s.ctl = next
	return nil
}

func (s *Service) lockSess(sess string) func() {
	s.mu.Lock()
	m, ok := s.smu[sess]
	if !ok {
		m = &sync.Mutex{}
		s.smu[sess] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// key unwraps spill key id (the caller clears it).
func (s *Service) key(id int64) ([]byte, error) {
	s.mu.Lock()
	k := s.ctl.Keys[id]
	s.mu.Unlock()
	w, err := s.o.Store.Wrapped(id)
	if err != nil {
		return nil, err
	}
	return s.o.KEK.Unwrap(wskey.ConsumerSpill, k.Subj, id, w)
}

// suspendBegin is Ctl.SuspendBegin with a fresh random key wrapped in the
// same transaction.
func (s *Service) suspendBegin(sess string, ckpt int64, entry uint64) error {
	return s.apply(func(c *Ctl) error {
		id := c.NextKey
		k := make([]byte, 32)
		defer clear(k)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			return err
		}
		if s.mut.reuseKey { // keeps the session's first key in memory and uses it again
			if s.reused == nil {
				s.reused = map[string][]byte{}
			}
			if old, ok := s.reused[sess]; ok {
				copy(k, old)
			} else {
				s.reused[sess] = append([]byte(nil), k...)
			}
		}
		w, err := s.o.KEK.Wrap(wskey.ConsumerSpill, sess, id, k)
		if err != nil {
			return err
		}
		if _, err := c.SuspendBegin(sess, true, ckpt, entry); err != nil {
			return err
		}
		s.wrapped[id] = w
		return nil
	})
}

// ------------------------------------------------------------- one copy

// send runs one copy of op id and applies its answer: a definite refusal of
// a spill, restore or load whose request returned is resolved at once (its
// copy is gone: settled) by observation.
func (s *Service) send(ctx context.Context, id int64) Answer {
	s.mu.Lock()
	o, inc := s.ctl.Ops[id], s.ctl.Inc
	s.sending[id]++
	s.mu.Unlock()
	a := s.exec(ctx, o)
	s.mu.Lock()
	s.sending[id]--
	s.last[id] = a
	s.mu.Unlock()
	done := a.Out == OutDone
	_ = s.apply(func(c *Ctl) error { c.OpAnswer(id, inc, done); return nil })
	if !done && o.Kind != OReg && a.Status != 0 {
		if obs, err := s.observe(ctx, o); err == nil {
			_ = s.apply(func(c *Ctl) error { return c.OpResolve(id, true, obs) })
		}
	}
	return a
}

func (s *Service) exec(ctx context.Context, o Op) Answer {
	s.mu.Lock()
	k := s.ctl.Keys[o.Key]
	s.mu.Unlock()
	switch o.Kind {
	case OLoadKey:
		if s.o.WS == nil {
			return Answer{Out: OutDone, Status: 200}
		}
		if err := s.o.WS.LoadKey(ctx, o.Subj); err != nil {
			return Answer{Out: OutUnknown, Status: -1, Reason: err.Error()} // the zfs process exited: settled
		}
		return Answer{Out: OutDone, Status: 200}
	case OSpill:
		return s.o.Halo.Spill(ctx, k.Entry)
	case ORestore:
		return s.o.Halo.Restore(ctx, k.Entry)
	}
	claim := SpillClaim{Use: o.Use, Op: s.opID(o)}
	var key []byte
	if o.Use != Revoke {
		var err error
		if key, err = s.key(o.Key); err != nil {
			return Answer{Out: OutNotDone, Reason: "key: " + err.Error()}
		}
		defer clear(key)
		claim.KeySHA256 = KeyHash(key)
	}
	if o.Use == Seal {
		entry := k.Entry
		if s.mut.wrongEntry {
			entry++
		}
		id, err := s.entryID(ctx, entry)
		if err != nil {
			return Answer{Out: OutNotDone, Reason: err.Error()}
		}
		claim.Entry = id
	}
	if o.Use == Revoke && !s.mut.implicitThrough {
		claim.Through = o.Ver
	}
	tok, err := s.o.Mint.MintSpill(o.Subj, o.Tep, claim)
	if err != nil {
		if errors.Is(err, issuer.ErrStaleEpoch) {
			return Answer{Out: OutNotDone, Reason: "stale epoch (issuer): " + err.Error()}
		}
		return Answer{Out: OutNotDone, Reason: "mint: " + err.Error()} // nothing sent
	}
	return s.o.Halo.Register(ctx, o.Subj, strings.ToLower(string(o.Use)), tok, key)
}

// opID is the operation id an op's tokens carry: unique per operation (op
// row) and key database. Retries of the op (fresh tokens) carry the same id.
func (s *Service) opID(o Op) string {
	oid := o.Oid
	if s.mut.reuseOpID {
		s.mu.Lock()
		for id := o.ID - 1; id > 0; id-- {
			if p := s.ctl.Ops[id]; p.Kind == OReg && p.Use == o.Use && p.Subj == o.Subj {
				oid = p.Oid
				break
			}
		}
		s.mu.Unlock()
	}
	return "y" + itoa(s.nonce) + "." + itoa(oid)
}

// renew is Ctl.RenewOp; a seal's new key is drawn and wrapped in the same
// transaction.
func (s *Service) renew(sess string) error {
	return s.apply(func(c *Ctl) error {
		id := c.NextKey
		k := make([]byte, 32)
		defer clear(k)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			return err
		}
		w, err := s.o.KEK.Wrap(wskey.ConsumerSpill, sess, id, k)
		if err != nil {
			return err
		}
		if _, err := c.RenewOp(sess, true); err != nil {
			return err
		}
		if c.NextKey > id {
			s.wrapped[id] = w
		}
		return nil
	})
}

// over: halo said the operation is over (409 cancelled / outlived its TTL).
func over(a Answer) bool {
	return a.Out == OutNotDone && (a.Class() == RefCancelled || a.Class() == RefOutlived)
}

func (s *Service) entryID(ctx context.Context, entry uint64) (string, error) {
	es, err := s.o.Halo.Sessions(ctx)
	if err != nil {
		return "", err
	}
	for _, e := range es {
		if e.Key == entry {
			return e.EntryID, nil
		}
	}
	return "", fmt.Errorf("%w: entry %d", ErrEntryGone, entry)
}

// observe is an op's resolving observation (spec/keys observedDone).
func (s *Service) observe(ctx context.Context, o Op) (bool, error) {
	if o.Kind == OLoadKey {
		if s.o.WS == nil {
			return true, nil
		}
		return s.o.WS.KeyLoaded(ctx, o.Subj)
	}
	var name, fileID string
	if o.Key != 0 && (o.Kind != OReg || o.Use != Revoke) {
		key, err := s.key(o.Key)
		if err != nil {
			return false, err
		}
		name, fileID = KeyName(key), FileKeyID(key, o.Ver, o.Subj)
		clear(key)
	}
	v, err := s.o.Halo.Keys(ctx)
	if err != nil {
		return false, err
	}
	hs := v.Sess(o.Subj)
	switch o.Kind {
	case OReg:
		switch o.Use {
		case Seal:
			return hs.Seal != nil && hs.Seal.Epoch == o.Ver && hs.Seal.KeyName == name, nil
		case Open:
			return hs.Open != nil && hs.Open.Epoch == o.Ver && hs.Open.KeyName == name, nil
		}
		if hs.RevokedThrough == nil || *hs.RevokedThrough < o.Ver {
			return false, nil
		}
		return !(hs.Seal != nil && hs.Seal.Epoch <= o.Ver) && !(hs.Open != nil && hs.Open.Epoch-1 <= o.Ver), nil
	}
	s.mu.Lock()
	entry := s.ctl.Keys[o.Key].Entry
	s.mu.Unlock()
	es, err := s.o.Halo.Sessions(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range es {
		if e.Key != entry {
			continue
		}
		if o.Kind == OSpill {
			return e.Spilled && e.KeyID == fileID, nil
		}
		return !e.Spilled && hs.RestoredEpoch >= o.Ver, nil
	}
	return false, nil
}

// settled: no copy of op o can still apply. A registration: every token of
// it expired. A spill or restore: no copy of ours runs, and halo holds no
// seal (open) slot with its key (without one a spill (restore) cannot start).
func (s *Service) settled(ctx context.Context, o Op) bool {
	s.mu.Lock()
	local, now, ttl := s.sending[o.ID], s.ctl.Clock, s.ctl.Cfg.TokenTTL
	s.mu.Unlock()
	if local > 0 {
		return false
	}
	switch o.Kind {
	case OReg:
		return now > o.SentAt+ttl
	case OLoadKey:
		return true
	}
	key, err := s.key(o.Key)
	if err != nil {
		return now > o.SentAt+ttl // shredded: no slot outlives its last token
	}
	name := KeyName(key)
	clear(key)
	v, err := s.o.Halo.Keys(ctx)
	if err != nil {
		return false
	}
	hs := v.Sess(o.Subj)
	slot := hs.Seal
	if o.Kind == ORestore {
		slot = hs.Open
	}
	return slot == nil || slot.KeyName != name
}

// terminal maps a registration refusal that no retry can change.
func terminal(a Answer) error {
	if a.Out != OutNotDone {
		return nil
	}
	switch {
	case strings.Contains(a.Reason, ErrEntryGone.Error()):
		return ErrEntryGone
	case strings.HasPrefix(a.Reason, "stale epoch"):
		return ErrStale
	}
	switch a.Class() {
	case RefStale:
		return ErrStale
	case RefFenced:
		return ErrFenced
	case RefUsed:
		return ErrUsed
	case RefOpConflict:
		return ErrOpConflict
	case RefBackpressure:
		return ErrRetryLater
	}
	return nil
}

// ------------------------------------------------------------- drive

// drive moves session sess along until done holds, an error is definite,
// or the outcome is unknown.
func (s *Service) drive(ctx context.Context, sess string, done func(c *Ctl) bool) error {
	reseals := 0
	for i := 0; i < 64; i++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrUnknown, err)
		}
		c := s.State()
		if done(c) {
			return nil
		}
		r := c.Sess[sess]
		o, ok := c.Ops[r.Op]
		if !ok {
			return fmt.Errorf("%w: session %s in %s/%s has no op", ErrNotDone, sess, r.St, r.Phase)
		}
		switch o.St {
		case Pending:
			if o.Inc != c.Inc {
				_ = s.apply(func(c *Ctl) error { return c.RecoverOps() })
				continue
			}
			s.mu.Lock()
			busy := s.sending[o.ID] > 0
			s.mu.Unlock()
			if busy {
				return ErrBusy
			}
			if a := s.send(ctx, o.ID); o.Kind == OReg {
				if err := terminal(a); err != nil {
					return err
				}
			}
		case Unknown:
			if o.Kind == OReg {
				if s.mut.blindRetry && o.Use == Seal {
					var ent uint64
					ck := c.Keys[r.Spill]
					ent = ck.Entry
					err := s.apply(func(c *Ctl) error { // a fresh key without verifying (the model's SealFreshKey)
						id := c.NextKey
						k := make([]byte, 32)
						defer clear(k)
						_, _ = io.ReadFull(rand.Reader, k)
						w, err := s.o.KEK.Wrap(wskey.ConsumerSpill, sess, id, k)
						if err != nil {
							return err
						}
						nk := c.newKey(sess, r.Epoch, ck.Ckpt, ent)
						op := c.newOp(OReg, sess, nk, r.Epoch, Seal)
						rr := c.Sess[sess]
						rr.Op, rr.Spill = op, nk
						c.Sess[sess] = rr
						s.wrapped[id] = w
						return nil
					})
					if err != nil {
						return err
					}
					continue
				}
				obs, err := s.observe(ctx, o)
				if err != nil {
					return fmt.Errorf("%w: verify: %v", ErrUnknown, err)
				}
				s.mu.Lock()
				la := s.last[o.ID]
				s.mu.Unlock()
				if !obs && over(la) && o.Use != Revoke && !s.mut.noRenew {
					if err := s.renew(sess); err != nil {
						return err
					}
					continue
				}
				if !obs {
					if err := terminal(la); err != nil && !errors.Is(err, ErrRetryLater) {
						return err
					}
				}
				if err := s.apply(func(c *Ctl) error { _, err := c.OpVerifyRetry(o.ID, obs); return err }); err != nil {
					return fmt.Errorf("%w: %s %s at %d after %d attempts (%s)", ErrUnknown, o.Kind, o.Use, o.Ver, o.Attempts, la.Reason)
				}
				continue
			}
			if !s.settled(ctx, o) {
				return fmt.Errorf("%w: %s of %s may still land", ErrUnknown, o.Kind, sess)
			}
			obs, err := s.observe(ctx, o)
			if err != nil {
				return fmt.Errorf("%w: observe: %v", ErrUnknown, err)
			}
			_ = s.apply(func(c *Ctl) error { return c.OpResolve(o.ID, true, obs) })
		case Done, NotDone:
			var err error
			switch {
			case r.Phase == PSeal && o.St == Done:
				_, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.SuspendSpill(sess) })
			case r.Phase == POpen && o.St == Done:
				_, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.ResumeLoad(sess) })
			case r.Phase == PLoad && o.St == Done:
				_, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.ResumeRestore(sess) })
			case r.Phase == PSpill && o.St == NotDone:
				if reseals++; reseals > 2 {
					return fmt.Errorf("%w: spill refused %d times", ErrNotDone, reseals-1)
				}
				_, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.SuspendReseal(sess) })
			case r.Phase == PRestore && o.St == NotDone:
				if es, e := s.o.Halo.Sessions(ctx); e == nil && !hasEntry(es, c.Keys[r.Spill].Entry) {
					return ErrEntryGone // nothing to open: re-prefill
				}
				if reseals++; reseals > 2 {
					return fmt.Errorf("%w: restore refused %d times", ErrNotDone, reseals-1)
				}
				_, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.ResumeReopen(sess) })
			case o.St == NotDone:
				if _, err = s.ctlDo(func(c *Ctl) ([]int64, error) { return c.OpRetry(o.ID) }); err != nil {
					return fmt.Errorf("%w: %s %s not done", ErrNotDone, o.Kind, o.Use)
				}
			default:
				return fmt.Errorf("%w: %s/%s stuck", ErrNotDone, r.St, r.Phase)
			}
			if err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("%w: too many steps", ErrUnknown)
}

func hasEntry(es []Entry, key uint64) bool {
	for _, e := range es {
		if e.Key == key {
			return true
		}
	}
	return false
}

func (s *Service) ctlDo(f func(c *Ctl) ([]int64, error)) ([]int64, error) {
	var ids []int64
	err := s.apply(func(c *Ctl) error {
		var err error
		ids, err = f(c)
		return err
	})
	return ids, err
}

func (s *Service) epoch(sess string) (int64, error) {
	e, ok := s.o.Epochs.Epoch(sess)
	if !ok {
		return 0, fmt.Errorf("keysvc: unknown session %q", sess)
	}
	return e, nil
}

// keyOf finds the key of a lifecycle checkpoint.
func keyOf(c *Ctl, sess string, ckpt int64) (Key, bool) {
	for _, k := range c.Keys {
		if k.Subj == sess && k.Ckpt == ckpt {
			return k, true
		}
	}
	return Key{}, false
}

// ---------------------------------------------------------- the API

// Seal is the key half of the lifecycle's OCheckpoint for a halo session:
// a fresh K for checkpoint ckpt, registered for seal at the session's
// current epoch for cache entry `entry`, then the spill. Idempotent per
// ckpt (a retried copy continues; never a fresh key for the same ckpt).
// Returns the file's size.
func (s *Service) Seal(ctx context.Context, sess string, ckpt int64, entry uint64) (int64, error) {
	defer s.lockSess(sess)()
	e, err := s.epoch(sess)
	if err != nil {
		return 0, err
	}
	_ = s.apply(func(c *Ctl) error { c.AddSession(sess, e); return nil })
	c := s.State()
	r := c.Sess[sess]
	if r.St == SSuspending && c.Keys[r.Spill].Ckpt != ckpt {
		if err := s.abortLocked(ctx, sess); err != nil { // the lifecycle moved on to a new checkpoint
			return 0, err
		}
		c, r = s.State(), s.State().Sess[sess]
	}
	switch {
	case r.St == SActive:
		_ = s.apply(func(c *Ctl) error { return c.SyncEpoch(sess, e) })
		if c := s.State(); c.BurntEpoch(sess, c.Sess[sess].Epoch) && !s.mut.noBurntGuard {
			return 0, ErrEpochBurnt
		}
		if err := s.suspendBegin(sess, ckpt, entry); err != nil {
			return 0, err
		}
	case r.St == SSuspending:
	case r.St == SSuspended && c.Keys[r.Spill].Ckpt == ckpt:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: session %s is %s", ErrNotDone, sess, r.St)
	}
	err = s.drive(ctx, sess, func(c *Ctl) bool {
		r := c.Sess[sess]
		return r.St == SSuspending && r.Phase == PSpill && c.opSt(r.Op) == Done
	})
	if err != nil {
		return 0, err
	}
	k := s.State().Keys[s.State().Sess[sess].Spill]
	var n int64
	if es, err := s.o.Halo.Sessions(ctx); err == nil {
		for _, x := range es {
			if x.Key == k.Entry {
				n = x.FileBytes
			}
		}
	}
	return n, nil
}

// commitIfBumped applies SuspendCommit once the lifecycle's epoch is E+1.
func (s *Service) commitIfBumped(sess string) error {
	e, err := s.epoch(sess)
	if err != nil {
		return err
	}
	return s.apply(func(c *Ctl) error {
		r := c.Sess[sess]
		if r.St != SSuspending {
			return nil
		}
		if e != r.Epoch+1 && !s.mut.openBeforeCommit {
			return ErrNotCommitted
		}
		return c.SuspendCommit(sess)
	})
}

// Open is the key half of the lifecycle's ORestore: the open registration
// at E+1 (only after SuspendCommit bumped the epoch), the workspace key, the
// restore; then K's shred begins (it was used once).
func (s *Service) Open(ctx context.Context, sess string, ckpt int64) error {
	defer s.lockSess(sess)()
	c := s.State()
	r, ok := c.Sess[sess]
	if !ok || r.Spill == 0 || c.Keys[r.Spill].Ckpt != ckpt {
		if k, ok := keyOf(c, sess, ckpt); ok && k.Shredding && r.St == SActive {
			return nil // already restored (ResumeComplete)
		}
		return ErrNoCheckpoint
	}
	if r.St == SSuspending {
		if err := s.commitIfBumped(sess); err != nil {
			return err
		}
	}
	if s.State().Sess[sess].St == SSuspended {
		if _, err := s.ctlDo(func(c *Ctl) ([]int64, error) { return c.ResumeBegin(sess) }); err != nil {
			return err
		}
	}
	if err := s.drive(ctx, sess, func(c *Ctl) bool {
		r := c.Sess[sess]
		return r.St == SResuming && r.Phase == PRestore && c.opSt(r.Op) == Done
	}); err != nil {
		return err
	}
	return s.apply(func(c *Ctl) error { return c.ResumeComplete(sess) })
}

// abortLocked: SuspendAbort, resolving the current op first if it can be.
func (s *Service) abortLocked(ctx context.Context, sess string) error {
	c := s.State()
	r := c.Sess[sess]
	if o := c.Ops[r.Op]; o.St == Unknown && s.settled(ctx, o) {
		if obs, err := s.observe(ctx, o); err == nil {
			_ = s.apply(func(c *Ctl) error { return c.OpResolve(o.ID, true, obs) })
		}
	}
	if err := s.apply(func(c *Ctl) error { return c.SuspendAbort(sess) }); err != nil {
		return fmt.Errorf("%w: abort: %v", ErrBusy, err)
	}
	return nil
}

// Discard is the lifecycle's ODelete of checkpoint ckpt (SuspendAbort,
// SuspendCheckpointRetry, ResumeComplete, ResumeFail, Expire; SR1's Removed):
// the wrapped key is deleted now (crypto-shred begins); Poll sends the
// revoke and claims the shred at its settle bound.
func (s *Service) Discard(ctx context.Context, sess string, ckpt int64) error {
	defer s.lockSess(sess)()
	c := s.State()
	k, ok := keyOf(c, sess, ckpt)
	if !ok || !k.Wrapped {
		return nil
	}
	r := c.Sess[sess]
	if r.Spill != k.ID {
		return s.apply(func(c *Ctl) error { c.shredBegin(k.ID); return nil }) // not the current checkpoint (Go only)
	}
	switch r.St {
	case SSuspending:
		return s.abortLocked(ctx, sess)
	case SSuspended:
		return s.apply(func(c *Ctl) error { return c.Expire(sess) })
	case SResuming:
		if r.Phase == PRestore && c.opSt(r.Op) == Done {
			return s.apply(func(c *Ctl) error { return c.ResumeComplete(sess) })
		}
		return s.killLocked(ctx, sess)
	}
	return s.killLocked(ctx, sess)
}

func (s *Service) killLocked(ctx context.Context, sess string) error {
	c := s.State()
	r := c.Sess[sess]
	if o := c.Ops[r.Op]; r.Phase == PRestore && o.St == Unknown && s.settled(ctx, o) {
		if obs, err := s.observe(ctx, o); err == nil {
			_ = s.apply(func(c *Ctl) error { return c.OpResolve(o.ID, true, obs) })
		}
	}
	if err := s.apply(func(c *Ctl) error { return c.Kill(sess) }); err != nil {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	return nil
}

// Remove is the SR1 Removed transition's hook (yard-svc down): the
// session is gone; its current key's shred begins.
func (s *Service) Remove(ctx context.Context, sess string) error {
	defer s.lockSess(sess)()
	if r, ok := s.State().Sess[sess]; !ok || r.St == SGone {
		return nil
	}
	return s.killLocked(ctx, sess)
}

// InFlight: a spill or restore of checkpoint ckpt may still land.
func (s *Service) InFlight(ctx context.Context, sess string, ckpt int64) bool {
	c := s.State()
	k, ok := keyOf(c, sess, ckpt)
	if !ok {
		return false
	}
	for _, o := range c.Ops {
		if o.Key == k.ID && (o.Kind == OSpill || o.Kind == ORestore) &&
			(o.St == Pending || (o.St == Unknown && !s.settled(ctx, o))) {
			return true
		}
	}
	return false
}

// Shredded reports whether checkpoint ckpt's key shred is claimed complete
// (or the checkpoint never had a key).
func (s *Service) Shredded(sess string, ckpt int64) bool {
	k, ok := keyOf(s.State(), sess, ckpt)
	return !ok || k.Shredded
}

// Poll is one pass of the background work: lazy commits, resolution of
// settled unknowns, revokes of shredding burnt keys (explicit through),
// verified revokes, and shred claims.
func (s *Service) Poll(ctx context.Context) {
	c := s.State()
	for _, sess := range sortedKeys(c.Sess) {
		if r := c.Sess[sess]; r.St == SSuspending && r.Phase == PSpill && c.opSt(r.Op) == Done {
			_ = s.commitIfBumped(sess)
		}
	}
	for _, id := range sortedKeys(s.State().Ops) {
		o := s.State().Ops[id]
		if o.St == Pending && o.Inc != s.State().Inc {
			_ = s.apply(func(c *Ctl) error { return c.RecoverOps() })
		}
		if o.St == Unknown && s.settled(ctx, o) {
			if obs, err := s.observe(ctx, o); err == nil {
				_ = s.apply(func(c *Ctl) error { return c.OpResolve(id, true, obs) })
			}
		}
	}
	for _, kid := range sortedKeys(s.State().Keys) {
		if ids, err := s.ctlDo(func(c *Ctl) ([]int64, error) {
			if s.mut.revokeUnburnt {
				return c.sendRevokeAny(kid)
			}
			return c.SendRevoke(kid)
		}); err == nil {
			for _, id := range ids {
				s.send(ctx, id)
			}
		}
		for _, id := range s.State().revokeOf(kid) {
			o := s.State().Ops[id]
			switch o.St {
			case Unknown:
				if obs, err := s.observe(ctx, o); err == nil {
					if ids, err := s.ctlDo(func(c *Ctl) ([]int64, error) { return c.OpVerifyRetry(id, obs) }); err == nil {
						for _, id := range ids {
							s.send(ctx, id)
						}
					}
				}
			case NotDone:
				if ids, err := s.ctlDo(func(c *Ctl) ([]int64, error) { return c.OpRetry(id) }); err == nil {
					for _, id := range ids {
						s.send(ctx, id)
					}
				}
			}
		}
		_ = s.apply(func(c *Ctl) error {
			if s.mut.shredBeforeSettle {
				if kk := c.Keys[kid]; kk.Shredding && !kk.Shredded {
					kk.Shredded = true
					c.Keys[kid] = kk
					return nil
				}
			}
			return c.ShredSpill(kid)
		})
	}
}

// sendRevokeAny is SendRevoke without the burnt guard (mutant revokeUnburnt).
func (c *Ctl) sendRevokeAny(k int64) ([]int64, error) {
	kk, ok := c.Keys[k]
	if err := guard("SendRevoke", c.Up && ok && kk.Shredding && !kk.Shredded && len(c.revokeOf(k)) == 0 &&
		c.TokensExpired(k)); err != nil {
		return nil, err
	}
	id := c.newOp(OReg, kk.Subj, k, kk.Ver, Revoke)
	o := c.Ops[id]
	o.Tep = c.Sess[kk.Subj].Epoch
	c.Ops[id] = o
	return []int64{id}, nil
}

func sortedKeys[K int64 | string, V any](m map[K]V) []K {
	ks := make([]K, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
