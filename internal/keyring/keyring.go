// Package keyring manages the STS signing keys: one active key that signs,
// one standby key that is already published, and at most one retiring key
// that is still published after a rotation (IDENTITY.md "Public
// reachability": publish old and new, wait out caches, sign with the new
// key, retire the old one).
//
// Lifecycle of the two TPM persistent handles (CONTROL-PLANE §3.1):
//
//	init:    A=active  B=standby            JWKS {A,B}
//	rotate:  A=retiring B=active            JWKS {B,A}   (needs B published >= PublishDelay)
//	retire:  A=standby(new key) B=active    JWKS {B,A'}  (needs A retiring >= RetireGrace)
//
// Every transition is written to the state file (atomic rename + fsync)
// before it takes effect, and the replace step of retire is crash-safe: the
// slot is first marked "replacing", then the old key is evicted, a new key
// is created, and the slot becomes standby. Open() finishes an interrupted
// replace.
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"yard/internal/sts"
)

// Handle names a key slot in the key store (a TPM persistent handle).
type Handle uint32

func (h Handle) String() string { return fmt.Sprintf("0x%08x", uint32(h)) }

// KeyStore is where keys live. The TPM store and the software fake implement it.
type KeyStore interface {
	// Exists reports whether a key is present at h.
	Exists(h Handle) (bool, error)
	// Open opens the existing key at h.
	Open(h Handle) (sts.KeySigner, error)
	// Create creates a new key at h; it must fail if h is occupied.
	Create(h Handle) (sts.KeySigner, error)
	// Evict destroys the key at h.
	Evict(h Handle) error
}

// SlotState is the role of a key.
type SlotState string

const (
	Active    SlotState = "active"
	Standby   SlotState = "standby"
	Retiring  SlotState = "retiring"
	Replacing SlotState = "replacing" // retire in progress: old key may or may not be evicted yet
)

// Slot is one key slot.
type Slot struct {
	Handle    Handle    `json:"handle"`
	Kid       string    `json:"kid"`
	State     SlotState `json:"state"`
	Since     time.Time `json:"since"`     // when the slot entered State
	Published time.Time `json:"published"` // when Kid first appeared in the JWKS
}

// State is the persisted keyring state.
type State struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"` // bumps on every transition
	Slots      []Slot `json:"slots"`
}

// Config holds the rotation timings.
type Config struct {
	// PublishDelay is how long a standby key must have been published before
	// it may become active (covers relying-party JWKS caches and the manual
	// push to inline-JWKS relying parties).
	PublishDelay time.Duration
	// RetireGrace is how long a retiring key stays published after rotation.
	// It must cover the longest token lifetime (sts.HardMaxTTL) plus caches.
	RetireGrace time.Duration
}

// DefaultConfig is conservative: a day to publish, an hour of grace.
var DefaultConfig = Config{PublishDelay: 24 * time.Hour, RetireGrace: time.Hour}

var (
	ErrNotDue        = errors.New("keyring: transition not due yet")
	ErrBusy          = errors.New("keyring: a rotation is still in flight (retiring key present)")
	ErrNoRetiring    = errors.New("keyring: no retiring key")
	ErrStateMismatch = errors.New("keyring: key store does not match state file")
)

// Ring is the live keyring.
type Ring struct {
	mu    sync.Mutex
	store KeyStore
	path  string
	cfg   Config
	now   func() time.Time
	st    State
	keys  map[Handle]sts.KeySigner
}

// Init creates (or adopts) keys at active and standby and writes a fresh
// state file. It refuses if the state file already exists.
func Init(store KeyStore, path string, active, standby Handle, cfg Config, now func() time.Time) (*Ring, error) {
	if now == nil {
		now = time.Now
	}
	if active == standby {
		return nil, errors.New("keyring: active and standby handles must differ")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("keyring: state file %s already exists", path)
	}
	r := &Ring{store: store, path: path, cfg: cfg, now: now, keys: map[Handle]sts.KeySigner{}}
	t := now().UTC()
	r.st = State{Version: 1, Generation: 1}
	for _, x := range []struct {
		h Handle
		s SlotState
	}{{active, Active}, {standby, Standby}} {
		k, err := openOrCreate(store, x.h)
		if err != nil {
			return nil, err
		}
		r.keys[x.h] = k
		r.st.Slots = append(r.st.Slots, Slot{Handle: x.h, Kid: sts.Thumbprint(k.Public()), State: x.s, Since: t, Published: t})
	}
	if err := r.save(); err != nil {
		return nil, err
	}
	return r, nil
}

func openOrCreate(store KeyStore, h Handle) (sts.KeySigner, error) {
	ok, err := store.Exists(h)
	if err != nil {
		return nil, err
	}
	if ok {
		return store.Open(h)
	}
	return store.Create(h)
}

// Open loads the state file, opens the keys, checks every kid against the
// store, and finishes an interrupted replace.
func Open(store KeyStore, path string, cfg Config, now func() time.Time) (*Ring, error) {
	if now == nil {
		now = time.Now
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &Ring{store: store, path: path, cfg: cfg, now: now, keys: map[Handle]sts.KeySigner{}}
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r.st); err != nil {
		return nil, fmt.Errorf("keyring: state %s: %w", path, err)
	}
	if err := r.st.validate(); err != nil {
		return nil, err
	}
	for i := range r.st.Slots {
		s := &r.st.Slots[i]
		if s.State == Replacing {
			if err := r.finishReplace(i); err != nil {
				return nil, err
			}
			continue
		}
		k, err := store.Open(s.Handle)
		if err != nil {
			return nil, fmt.Errorf("%w: open %s (%s): %v", ErrStateMismatch, s.Handle, s.State, err)
		}
		if kid := sts.Thumbprint(k.Public()); kid != s.Kid {
			return nil, fmt.Errorf("%w: %s holds kid %s, state says %s", ErrStateMismatch, s.Handle, kid, s.Kid)
		}
		r.keys[s.Handle] = k
	}
	return r, nil
}

func (st *State) validate() error {
	if st.Version != 1 {
		return fmt.Errorf("keyring: unknown state version %d", st.Version)
	}
	var na, nr int
	seen := map[Handle]bool{}
	for _, s := range st.Slots {
		if seen[s.Handle] {
			return fmt.Errorf("keyring: handle %s twice in state", s.Handle)
		}
		seen[s.Handle] = true
		switch s.State {
		case Active:
			na++
		case Retiring, Replacing:
			nr++
		case Standby:
		default:
			return fmt.Errorf("keyring: unknown slot state %q", s.State)
		}
	}
	if na != 1 {
		return fmt.Errorf("keyring: %d active keys in state, want 1", na)
	}
	if nr > 1 {
		return fmt.Errorf("keyring: %d retiring keys in state, want <= 1", nr)
	}
	return nil
}

// finishReplace completes slot i (state Replacing): evict whatever still
// holds the old kid, create a fresh key unless one is already there, and
// mark the slot standby. A key at the handle with a different kid than the
// old one means a crash after Create: it is adopted.
func (r *Ring) finishReplace(i int) error {
	s := &r.st.Slots[i]
	ok, err := r.store.Exists(s.Handle)
	if err != nil {
		return err
	}
	var k sts.KeySigner
	if ok {
		k, err = r.store.Open(s.Handle)
		if err != nil {
			return err
		}
		if sts.Thumbprint(k.Public()) == s.Kid {
			if err := r.store.Evict(s.Handle); err != nil {
				return fmt.Errorf("keyring: evict %s: %w", s.Handle, err)
			}
			k = nil
		}
	}
	if k == nil {
		if k, err = r.store.Create(s.Handle); err != nil {
			return fmt.Errorf("keyring: create %s: %w", s.Handle, err)
		}
	}
	t := r.now().UTC()
	s.Kid = sts.Thumbprint(k.Public())
	s.State = Standby
	s.Since = t
	s.Published = t
	r.st.Generation++
	if err := r.save(); err != nil {
		return err
	}
	r.keys[s.Handle] = k
	return nil
}

// save writes the state atomically: temp file, fsync, rename, fsync dir.
func (r *Ring) save() error {
	b, err := json.MarshalIndent(r.st, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(r.path, append(b, '\n'), 0o600)
}

// WriteFileAtomic replaces path with data via a synced temp file and rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (r *Ring) find(st SlotState) int {
	for i, s := range r.st.Slots {
		if s.State == st {
			return i
		}
	}
	return -1
}

// Active returns the signing key and its kid.
func (r *Ring) Active() (sts.KeySigner, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.st.Slots[r.find(Active)]
	return r.keys[s.Handle], s.Kid
}

// Snapshot returns a copy of the state.
func (r *Ring) Snapshot() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.st
	c.Slots = append([]Slot(nil), r.st.Slots...)
	return c
}

// JWKS returns every published key: active first, then standby, then retiring.
func (r *Ring) JWKS() sts.JWKS {
	r.mu.Lock()
	defer r.mu.Unlock()
	var set sts.JWKS
	for _, st := range []SlotState{Active, Standby, Retiring} {
		for _, s := range r.st.Slots {
			if s.State == st {
				set.Keys = append(set.Keys, sts.PublicJWK(r.keys[s.Handle].Public()))
			}
		}
	}
	return set
}

// Rotate promotes the standby key to active and moves the active key to
// retiring. It needs a standby published for at least PublishDelay and no
// rotation in flight.
func (r *Ring) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.find(Retiring) >= 0 || r.find(Replacing) >= 0 {
		return ErrBusy
	}
	si := r.find(Standby)
	if si < 0 {
		return errors.New("keyring: no standby key")
	}
	t := r.now().UTC()
	if age := t.Sub(r.st.Slots[si].Published); age < r.cfg.PublishDelay {
		return fmt.Errorf("%w: standby published %s ago, need %s", ErrNotDue, age.Round(time.Second), r.cfg.PublishDelay)
	}
	ai := r.find(Active)
	next := r.st
	next.Slots = append([]Slot(nil), r.st.Slots...)
	next.Slots[ai].State, next.Slots[ai].Since = Retiring, t
	next.Slots[si].State, next.Slots[si].Since = Active, t
	next.Generation++
	return r.commit(next)
}

// RetireDue reports whether Retire would do something now.
func (r *Ring) RetireDue() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.find(Retiring)
	return i >= 0 && r.now().Sub(r.st.Slots[i].Since) >= r.cfg.RetireGrace
}

// Retire drops the retiring key from the JWKS and replaces it in the store
// with a new standby key.
func (r *Ring) Retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := r.find(Replacing); i >= 0 { // an earlier Retire failed half-way: finish it
		return r.finishReplace(i)
	}
	i := r.find(Retiring)
	if i < 0 {
		return ErrNoRetiring
	}
	if age := r.now().Sub(r.st.Slots[i].Since); age < r.cfg.RetireGrace {
		return fmt.Errorf("%w: retiring for %s, grace %s", ErrNotDue, age.Round(time.Second), r.cfg.RetireGrace)
	}
	next := r.st
	next.Slots = append([]Slot(nil), r.st.Slots...)
	next.Slots[i].State = Replacing
	next.Generation++
	if err := r.commit(next); err != nil {
		return err
	}
	delete(r.keys, r.st.Slots[i].Handle)
	return r.finishReplace(i)
}

// commit persists next and only then makes it current.
func (r *Ring) commit(next State) error {
	old := r.st
	r.st = next
	if err := r.save(); err != nil {
		r.st = old
		return err
	}
	return nil
}

// WithActive runs f with the active key and its kid while holding the ring
// lock, so a concurrent Rotate cannot change the key between choosing the
// kid for the JWT header and signing.
func (r *Ring) WithActive(f func(k sts.KeySigner, kid string) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.st.Slots[r.find(Active)]
	return f(r.keys[s.Handle], s.Kid)
}
