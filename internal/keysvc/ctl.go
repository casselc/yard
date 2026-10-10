// Package keysvc is yard-ctl's key service: one key hierarchy (internal/wskey's
// KEK) with two consumers.
//
//   - ZFS workspace keys (consumer "zfs"): one raw key per project, held in
//     wskey.Store and loaded/unloaded by internal/service through the SR0
//     lifecycle (lifecycle.Keys). keysvc does not reimplement any of it: it
//     opens the wskey table in the key database (Open) and, at a resume,
//     calls the workspace's LoadKey (the model's ResumeLoad; idempotent).
//   - halo_serve spill keys (consumer "spill"): a fresh random 256-bit key K
//     per checkpoint, wrapped under the same KEK in the key database,
//     registered with halo_serve (POST /admin/keys/{sess}, a halo_spill JWT)
//     for seal at the session's credential epoch E, opened at E+1 after the
//     SR0 SuspendCommit bumped it, and crypto-shredded by deleting the
//     wrapped key and waiting for its settle bound (or a verified revoke).
//     IDENTITY.md "Spill keys"; halo's side is yard_keys.cpp (halo-flash
//     branch stream/spill-crypt).
//
// The Quint model spec/keys/keys.qnt is the ground truth. Ctl is the model's
// controller for the spill consumer: one method per controller action, with
// the same guard and update; the replay test drives it through ITF traces of
// the model's stepKeysvc and compares the state after every step. Ctl is
// pure (no I/O, clock or randomness); Service (service.go) runs it with the
// SQLite store, halo_serve, the issuer and the clock.
package keysvc

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// SState is a session's state as the key service sees it (Quint SState).
type SState string

const (
	SActive     SState = "Active"
	SSuspending SState = "Suspending"
	SSuspended  SState = "Suspended"
	SResuming   SState = "Resuming"
	SGone       SState = "Gone"
)

// Phase is the step within Suspending or Resuming (Quint SPhase).
type Phase string

const (
	PNone    Phase = "PNone"
	PSeal    Phase = "PSeal"    // seal registration at E
	PSpill   Phase = "PSpill"   // halo spill
	POpen    Phase = "POpen"    // open registration at E+1
	PLoad    Phase = "PLoad"    // the workspace key (zfs load-key, via the lifecycle's workspace)
	PRestore Phase = "PRestore" // halo restore
)

// Use is a registration's use (Quint Use).
type Use string

const (
	Seal   Use = "Seal"
	Open   Use = "Open"
	Revoke Use = "Revoke"
)

// OpKind is an external call (Quint OpKind, the spill consumer's subset).
type OpKind string

const (
	OReg     OpKind = "OReg"     // POST /admin/keys/{sess}
	OSpill   OpKind = "OSpill"   // POST /admin/sessions/{key}/spill
	ORestore OpKind = "ORestore" // POST /admin/sessions/{key}/restore
	OLoadKey OpKind = "OLoadKey" // the session's workspace key (lifecycle.Keys.LoadKey)
)

// OpSt is what the key service knows of an op (Quint OpSt).
type OpSt string

const (
	Pending OpSt = "Pending"
	Unknown OpSt = "Unknown"
	Done    OpSt = "Done"
	NotDone OpSt = "NotDone"
)

// Key is a spill key's record (Quint Key, cons "spill"). The key bytes are
// never here: the Store keeps them wrapped. Wrapped false: the wrapped key
// is deleted (the shred began); Shredded: the shred is claimed complete.
type Key struct {
	ID        int64
	Subj      string // the session
	Ver       int64  // the epoch E the checkpoint is sealed at
	Wrapped   bool
	Shredding bool
	Shredded  bool
	// Go only: the lifecycle checkpoint (OCheckpoint op id) it seals, and
	// the halo cache entry key the seal names.
	Ckpt  int64
	Entry uint64
}

// Sess is a session's key-service record (Quint Sess).
type Sess struct {
	St      SState
	Phase   Phase
	Epoch   int64
	Op      int64
	Spill   int64 // the current checkpoint's key, 0 none
	Resumes int64
}

// Op is a durable op row (Quint Op). Ver: the epoch (a revoke: `through`);
// Tep: the token's yard_epoch.
type Op struct {
	ID       int64
	Kind     OpKind
	Subj     string
	Key      int64
	Ver      int64
	Tep      int64
	Oid      int64 // the operation id its tokens carry (halo_spill.op, round 5): the op's own id
	Use      Use
	St       OpSt
	Attempts int64
	Inc      int64
	SentAt   int64
}

// Config holds the model's constants. Durations are in the clock's unit
// (milliseconds in production, ticks in the replay).
type Config struct {
	TokenTTL    int64 // a registration token's lifetime (iat to exp), plus margin
	HaloTTL     int64 // halo zeroes an unused key at most this long after its registration
	OpTimeout   int64
	MaxAttempts int64 // registration and spill attempts per op
	// model bounds (the replay sets them; production leaves 0 = none)
	MaxOps, MaxKeys, MaxEpoch int64
}

// Ctl is the spill-key controller (Quint Sys minus the environment).
// Everything but Clock and Up is durable (Store).
type Ctl struct {
	Cfg     Config
	Clock   int64
	Up      bool
	Inc     int64
	Keys    map[int64]Key
	Sess    map[string]Sess
	Ops     map[int64]Op
	NextOp  int64
	NextKey int64
	// noBurntGuard: mutant (tests only)
	noBurntGuard bool
}

// ErrGuard: the action is not enabled in this state.
var ErrGuard = errors.New("keysvc: action not enabled")

func guard(name string, ok bool) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrGuard, name)
}

// NewCtl returns an empty controller at incarnation 1.
func NewCtl(cfg Config) *Ctl {
	return &Ctl{Cfg: cfg, Up: true, Inc: 1, Keys: map[int64]Key{}, Sess: map[string]Sess{}, Ops: map[int64]Op{},
		NextOp: 1, NextKey: 1}
}

// Clone deep-copies the controller.
func (c *Ctl) Clone() *Ctl {
	n := *c
	n.Keys, n.Sess, n.Ops = maps.Clone(c.Keys), maps.Clone(c.Sess), maps.Clone(c.Ops)
	return &n
}

// AddSession registers an Active session at credential epoch e (Quint init).
func (c *Ctl) AddSession(s string, e int64) {
	if _, ok := c.Sess[s]; !ok {
		c.Sess[s] = Sess{St: SActive, Phase: PNone, Epoch: e}
	}
}

// SyncEpoch (Go only) takes the lifecycle's current epoch for an Active
// session with nothing in flight here: the lifecycle's epoch is the truth,
// and a cycle the key service did not see (a session without a spill)
// moves it on. It never moves an epoch back.
func (c *Ctl) SyncEpoch(s string, e int64) error {
	r, ok := c.Sess[s]
	if err := guard("SyncEpoch", c.Up && ok && r.St == SActive && r.Phase == PNone && e >= r.Epoch); err != nil {
		return err
	}
	r.Epoch = e
	c.Sess[s] = r
	return nil
}

// ------------------------------------------------------------------ helpers

func (c *Ctl) opSt(id int64) OpSt {
	if o, ok := c.Ops[id]; ok {
		return o.St
	}
	return NotDone
}

func (c *Ctl) resolved(id int64) bool { return id == 0 || c.opSt(id) == Done || c.opSt(id) == NotDone }

func (c *Ctl) opsLeft(n int64) bool { return c.Cfg.MaxOps == 0 || c.NextOp+n-1 <= c.Cfg.MaxOps }

func (c *Ctl) keysLeft() bool { return c.Cfg.MaxKeys == 0 || c.NextKey <= c.Cfg.MaxKeys }

func isReg(o Op) bool { return o.Kind == OReg && o.Use != Revoke }

func (c *Ctl) newOp(k OpKind, s string, key, ver int64, u Use) int64 {
	id := c.NextOp
	c.Ops[id] = Op{ID: id, Kind: k, Subj: s, Key: key, Ver: ver, Tep: ver, Oid: id, Use: u, St: Pending, Attempts: 1,
		Inc: c.Inc, SentAt: c.Clock}
	c.NextOp++
	return id
}

func (c *Ctl) newKey(s string, ver, ckpt int64, entry uint64) int64 {
	id := c.NextKey
	c.Keys[id] = Key{ID: id, Subj: s, Ver: ver, Wrapped: true, Ckpt: ckpt, Entry: entry}
	c.NextKey++
	return id
}

// shredBegin: the wrapped key is deleted (Store: wrapped NULL, secure_delete).
func (c *Ctl) shredBegin(k int64) {
	if kk, ok := c.Keys[k]; ok {
		kk.Wrapped, kk.Shredding = false, true
		c.Keys[k] = kk
	}
}

func (c *Ctl) inPhase(s string, st SState, p Phase) bool {
	r, ok := c.Sess[s]
	return ok && r.St == st && r.Phase == p
}

func (c *Ctl) curDone(s string) bool    { return c.opSt(c.Sess[s].Op) == Done }
func (c *Ctl) curNotDone(s string) bool { return c.opSt(c.Sess[s].Op) == NotDone }

func (c *Ctl) opCurrent(o Op) bool {
	if o.Kind == OReg && o.Use == Revoke {
		return true
	}
	return c.Sess[o.Subj].Op == o.ID
}

// Burnt reports whether a spill under key k may have landed: a spill op of
// k was sent and is not known not done (Quint burnt). halo then holds k's
// epoch as used.
func (c *Ctl) Burnt(k int64) bool {
	for _, o := range c.Ops {
		if o.Kind == OSpill && o.Key == k && o.St != NotDone {
			return true
		}
	}
	return false
}

// BurntEpoch: a key of session s at epoch e is burnt (Quint burntEpoch).
func (c *Ctl) BurntEpoch(s string, e int64) bool {
	for _, k := range c.Keys {
		if k.Subj == s && k.Ver == e && c.Burnt(k.ID) {
			return true
		}
	}
	return false
}

// LastIat is the latest send time of a registration carrying k.
func (c *Ctl) LastIat(k int64) int64 {
	var m int64
	for _, o := range c.Ops {
		if isReg(o) && o.Key == k && o.SentAt > m {
			m = o.SentAt
		}
	}
	return m
}

// TokensExpired: no registration token carrying k can still be accepted.
func (c *Ctl) TokensExpired(k int64) bool { return c.Clock > c.LastIat(k)+c.Cfg.TokenTTL }

func (c *Ctl) revokeOf(k int64) []int64 {
	var ids []int64
	for id, o := range c.Ops {
		if o.Kind == OReg && o.Use == Revoke && o.Key == k {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

func (c *Ctl) revokeOk(k int64) bool {
	for _, id := range c.revokeOf(k) {
		if c.Ops[id].St == Done {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------- environment

// Tick advances the replay clock.
func (c *Ctl) Tick() { c.Clock++ }

// SetClock sets the production clock (never backwards).
func (c *Ctl) SetClock(now int64) {
	if now > c.Clock {
		c.Clock = now
	}
}

// CtlCrash: yard-ctl dies (Quint CtlCrash, and the ctl side of Reboot).
func (c *Ctl) CtlCrash() { c.Up = false }

// CtlRestart: a new incarnation.
func (c *Ctl) CtlRestart() error {
	if err := guard("CtlRestart", !c.Up); err != nil {
		return err
	}
	c.Up, c.Inc = true, c.Inc+1
	return nil
}

// OpAnswer: a copy of op id sent by incarnation inc answered; done says the
// effect holds (Quint applyOpLand: heard only by its own incarnation, while
// the op is Pending; any other answer leaves it Unknown).
func (c *Ctl) OpAnswer(id, inc int64, done bool) {
	o, ok := c.Ops[id]
	if !ok || !c.Up || inc != c.Inc || o.St != Pending {
		return
	}
	if done {
		o.St = Done
	} else {
		o.St = Unknown
	}
	c.Ops[id] = o
}

// ---------------------------------------------------------- controller: ops

func (c *Ctl) OpTimeout(id int64) error {
	o, ok := c.Ops[id]
	if err := guard("OpTimeout", c.Up && ok && o.St == Pending && o.Inc == c.Inc && c.Clock >= o.SentAt+c.Cfg.OpTimeout); err != nil {
		return err
	}
	o.St = Unknown
	c.Ops[id] = o
	return nil
}

// OpResolve: an Unknown op whose copies have all settled is resolved by the
// observation.
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

func (c *Ctl) resend(o Op) []int64 {
	o.St, o.Attempts, o.SentAt, o.Inc = Pending, o.Attempts+1, c.Clock, c.Inc
	c.Ops[o.ID] = o
	return []int64{o.ID}
}

// OpRetry resends a NotDone op the session still waits on (or a revoke).
func (c *Ctl) OpRetry(id int64) ([]int64, error) {
	o, ok := c.Ops[id]
	if err := guard("OpRetry", c.Up && ok && o.St == NotDone && o.Attempts < c.Cfg.MaxAttempts &&
		o.Kind != ORestore && c.opCurrent(o)); err != nil {
		return nil, err
	}
	return c.resend(o), nil
}

// OpVerifyRetry: verify an Unknown registration (or revoke) with GET
// /admin/keys; seen done it is Done, else it is sent again (same use, epoch,
// key; a fresh token). A miss never makes it NotDone.
func (c *Ctl) OpVerifyRetry(id int64, observedDone bool) ([]int64, error) {
	o, ok := c.Ops[id]
	if err := guard("OpVerifyRetry", c.Up && ok && o.Kind == OReg && o.St == Unknown && c.opCurrent(o) &&
		(observedDone || o.Attempts < c.Cfg.MaxAttempts)); err != nil {
		return nil, err
	}
	if observedDone {
		o.St = Done
		c.Ops[id] = o
		return nil, nil
	}
	return c.resend(o), nil
}

// RecoverOps: after a restart, the earlier incarnations' Pending ops are Unknown.
func (c *Ctl) RecoverOps() error {
	any := false
	for id, o := range c.Ops {
		if o.St == Pending && o.Inc < c.Inc {
			o.St = Unknown
			c.Ops[id] = o
			any = true
		}
	}
	return guard("RecoverOps", c.Up && any)
}

// ------------------------------------------------------ controller: sessions

// SuspendBegin: a fresh spill key (created and wrapped in the same
// transaction as the op row) registered for seal at the session's epoch,
// unless that epoch is burnt. instUp: the session's instance runs (the
// lifecycle is checkpointing a live session). ckpt and entry are Go only.
func (c *Ctl) SuspendBegin(s string, instUp bool, ckpt int64, entry uint64) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("SuspendBegin", c.Up && c.inPhase(s, SActive, PNone) && instUp &&
		(c.Cfg.MaxEpoch == 0 || r.Epoch < c.Cfg.MaxEpoch) && c.keysLeft() && c.opsLeft(1) &&
		(!c.BurntEpoch(s, r.Epoch) || c.noBurntGuard)); err != nil {
		return nil, err
	}
	k := c.newKey(s, r.Epoch, ckpt, entry)
	id := c.newOp(OReg, s, k, r.Epoch, Seal)
	r.St, r.Phase, r.Op, r.Spill = SSuspending, PSeal, id, k
	c.Sess[s] = r
	return []int64{id}, nil
}

func (c *Ctl) SuspendSpill(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("SuspendSpill", c.Up && c.inPhase(s, SSuspending, PSeal) && c.curDone(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OSpill, s, r.Spill, r.Epoch, Seal)
	r.Phase, r.Op = PSpill, id
	c.Sess[s] = r
	return []int64{id}, nil
}

// SuspendReseal: the spill is known not done (halo lost the seal key):
// register the same key again.
func (c *Ctl) SuspendReseal(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("SuspendReseal", c.Up && c.inPhase(s, SSuspending, PSpill) && c.curNotDone(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OReg, s, r.Spill, r.Epoch, Seal)
	r.Phase, r.Op = PSeal, id
	c.Sess[s] = r
	return []int64{id}, nil
}

// SuspendCommit: the lifecycle committed the suspend; the epoch is E+1.
func (c *Ctl) SuspendCommit(s string) error {
	r := c.Sess[s]
	if err := guard("SuspendCommit", c.Up && c.inPhase(s, SSuspending, PSpill) && c.curDone(s)); err != nil {
		return err
	}
	r.St, r.Phase, r.Op, r.Epoch = SSuspended, PNone, 0, r.Epoch+1
	c.Sess[s] = r
	return nil
}

// SuspendAbort: the lifecycle aborted the suspend (SR0 SuspendAbort); back
// to Active at the same epoch; the key's shred begins.
func (c *Ctl) SuspendAbort(s string) error {
	r := c.Sess[s]
	if err := guard("SuspendAbort", c.Up && r.St == SSuspending && (r.Phase == PSeal || r.Phase == PSpill) &&
		c.resolved(r.Op)); err != nil {
		return err
	}
	c.shredBegin(r.Spill)
	r.St, r.Phase, r.Op, r.Spill = SActive, PNone, 0, 0
	c.Sess[s] = r
	return nil
}

// RenewOp: the current registration's operation is over at halo (409
// "cancelled" by a revoke, or "outlived its TTL"; opOver is that answer): a
// new operation with a new op id. A seal gets a new key (the old one's shred
// begins); an open keeps the file's key.
func (c *Ctl) RenewOp(s string, opOver bool) ([]int64, error) {
	r := c.Sess[s]
	o, ok := c.Ops[r.Op]
	if err := guard("RenewOp", c.Up && ok && ((r.St == SSuspending && r.Phase == PSeal) || (r.St == SResuming && r.Phase == POpen)) &&
		o.Kind == OReg && (o.St == Unknown || o.St == NotDone) && opOver && c.opsLeft(1) &&
		(r.St == SResuming || c.keysLeft())); err != nil {
		return nil, err
	}
	k := r.Spill
	if o.Use == Seal {
		old := c.Keys[r.Spill]
		c.shredBegin(r.Spill)
		k = c.newKey(s, r.Epoch, old.Ckpt, old.Entry)
	}
	id := c.newOp(OReg, s, k, r.Epoch, o.Use)
	r.Op, r.Spill = id, k
	c.Sess[s] = r
	return []int64{id}, nil
}

func (c *Ctl) ResumeBegin(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("ResumeBegin", c.Up && c.inPhase(s, SSuspended, PNone) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OReg, s, r.Spill, r.Epoch, Open)
	r.St, r.Phase, r.Op = SResuming, POpen, id
	c.Sess[s] = r
	return []int64{id}, nil
}

// ResumeLoad: the workspace key, always (reloadAlways; the lifecycle's
// KEY_FENCE has already ordered it after any unload).
func (c *Ctl) ResumeLoad(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("ResumeLoad", c.Up && c.inPhase(s, SResuming, POpen) && c.curDone(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OLoadKey, s, 0, 0, Seal)
	r.Phase, r.Op = PLoad, id
	c.Sess[s] = r
	return []int64{id}, nil
}

func (c *Ctl) ResumeRestore(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("ResumeRestore", c.Up && c.inPhase(s, SResuming, PLoad) && c.curDone(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(ORestore, s, r.Spill, r.Epoch, Open)
	r.Phase, r.Op = PRestore, id
	c.Sess[s] = r
	return []int64{id}, nil
}

// ResumeReopen: the restore is known not done (halo lost the open key):
// register open again.
func (c *Ctl) ResumeReopen(s string) ([]int64, error) {
	r := c.Sess[s]
	if err := guard("ResumeReopen", c.Up && c.inPhase(s, SResuming, PRestore) && c.curNotDone(s) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OReg, s, r.Spill, r.Epoch, Open)
	r.Phase, r.Op = POpen, id
	c.Sess[s] = r
	return []int64{id}, nil
}

// ResumeComplete: K was used once; its shred begins.
func (c *Ctl) ResumeComplete(s string) error {
	r := c.Sess[s]
	if err := guard("ResumeComplete", c.Up && c.inPhase(s, SResuming, PRestore) && c.curDone(s)); err != nil {
		return err
	}
	c.shredBegin(r.Spill)
	r.St, r.Phase, r.Op, r.Spill, r.Resumes = SActive, PNone, 0, 0, r.Resumes+1
	c.Sess[s] = r
	return nil
}

// Expire: a suspended session's TTL passed.
func (c *Ctl) Expire(s string) error {
	r := c.Sess[s]
	if err := guard("Expire", c.Up && c.inPhase(s, SSuspended, PNone)); err != nil {
		return err
	}
	c.shredBegin(r.Spill)
	r.St, r.Spill = SGone, 0
	c.Sess[s] = r
	return nil
}

// Kill: the session is failed or removed. The op it waited on is
// abandoned; its key's shred begins. Not while a restore may still land.
func (c *Ctl) Kill(s string) error {
	r, ok := c.Sess[s]
	en := ok && (r.St == SActive || r.St == SSuspending || r.St == SSuspended ||
		(r.St == SResuming && (r.Phase == POpen || r.Phase == PLoad)) ||
		(r.St == SResuming && r.Phase == PRestore && c.curNotDone(s)))
	if err := guard("Kill", c.Up && en); err != nil {
		return err
	}
	c.shredBegin(r.Spill)
	r.St, r.Phase, r.Op, r.Spill = SGone, PNone, 0, 0
	c.Sess[s] = r
	return nil
}

// ------------------------------------------------- controller: spill shred

// SendRevoke: once no registration of a burnt key can land, revoke with an
// explicit through = its checkpoint epoch, at the session's current epoch
// (the token's; halo bounds every revoke effect by it).
func (c *Ctl) SendRevoke(k int64) ([]int64, error) {
	kk, ok := c.Keys[k]
	if err := guard("SendRevoke", c.Up && ok && kk.Shredding && !kk.Shredded && len(c.revokeOf(k)) == 0 &&
		c.TokensExpired(k) && c.Burnt(k) && c.opsLeft(1)); err != nil {
		return nil, err
	}
	id := c.newOp(OReg, kk.Subj, k, kk.Ver, Revoke)
	o := c.Ops[id]
	o.Tep = c.Sess[kk.Subj].Epoch
	c.Ops[id] = o
	return []int64{id}, nil
}

// ShredSpill claims the shred: every token of k expired, and halo's TTL
// passed or a revoke was observed done.
func (c *Ctl) ShredSpill(k int64) error {
	kk, ok := c.Keys[k]
	if err := guard("ShredSpill", c.Up && ok && kk.Shredding && !kk.Shredded && c.TokensExpired(k) &&
		(c.Clock >= c.LastIat(k)+c.Cfg.TokenTTL+c.Cfg.HaloTTL || c.revokeOk(k))); err != nil {
		return err
	}
	kk.Shredded = true
	c.Keys[k] = kk
	return nil
}
