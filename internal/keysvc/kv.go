package keysvc

import (
	"context"
	"errors"
	"sync"

	"yard/internal/lifecycle"
)

// The SR0 lifecycle wiring. A halo_serve KV session is a lifecycle session
// of kind "kv": its checkpoint is the spill of its cache entry, its restore
// the restore. Router.Backends["kv"] = &KV{...}; Router.Artifacts =
// &Artifacts{Inner: <the jail/service artifact store>, Svc: svc}. Then:
//   - suspend (OCheckpoint at epoch E): KV.Checkpoint -> Service.Seal (fresh
//     K, seal registration at E, spill);
//   - SuspendCommit bumps the epoch to E+1: the key service learns it from
//     the epoch source (lazily, at Open or Poll);
//   - resume (ORestore at E+1): KV.Restore -> Service.Open (refused before the
//     commit; open registration, workspace key, restore, K's shred begins);
//   - abort, checkpoint retry, resume complete/fail, expiry (ODelete of the
//     checkpoint): Artifacts.Delete -> Service.Discard;
//   - remove (SR1's Removed transition, not on this base yet): its ODelete
//     goes through Artifacts.Delete, and yard-svc down calls Service.Remove.

// EntryMap names the halo cache entry that holds a yard session's
// conversation (the harness binds them; SR5).
type EntryMap interface {
	EntryOf(sess string) (uint64, bool)
}

// KV is the lifecycle Backend of kind "kv".
type KV struct {
	Svc     *Service
	Entries EntryMap
}

var errNoEntry = errors.New("keysvc: the session has no halo cache entry")

func (b *KV) entry(sess string) (uint64, error) {
	e, ok := b.Entries.EntryOf(sess)
	if !ok {
		return 0, errNoEntry
	}
	return e, nil
}

// Quiesce: halo serves between generations; the harness stops sending.
func (b *KV) Quiesce(ctx context.Context, sess string, inst int64) error   { return nil }
func (b *KV) Unquiesce(ctx context.Context, sess string, inst int64) error { return nil }

// Destroy: the spill already freed the device state.
func (b *KV) Destroy(ctx context.Context, sess string, inst int64) error { return nil }

func (b *KV) Checkpoint(ctx context.Context, sess string, gen, ckpt int64) (int64, error) {
	e, err := b.entry(sess)
	if err != nil {
		return 0, err
	}
	return b.Svc.Seal(ctx, sess, ckpt, e)
}

// CheckpointOK observes the spill: the entry is spilled under this
// checkpoint's key at its epoch.
func (b *KV) CheckpointOK(ctx context.Context, sess string, ckpt int64) (bool, error) {
	k, ok := keyOf(b.Svc.State(), sess, ckpt)
	if !ok {
		return false, nil
	}
	return b.Svc.observe(ctx, Op{Kind: OSpill, Subj: sess, Key: k.ID, Ver: k.Ver})
}

func (b *KV) Restore(ctx context.Context, sess string, gen, ckpt int64, force bool) error {
	return b.Svc.Open(ctx, sess, ckpt)
}

// Instance: the session's KV state is resident in halo's cache.
func (b *KV) Instance(ctx context.Context, sess string, name int64) (bool, bool, error) {
	e, err := b.entry(sess)
	if err != nil {
		return false, false, nil
	}
	es, err := b.Svc.o.Halo.Sessions(ctx)
	if err != nil {
		return false, false, err
	}
	for _, x := range es {
		if x.Key == e && !x.Spilled {
			return true, true, nil
		}
	}
	return false, false, nil
}

func (b *KV) InFlight(ctx context.Context, op lifecycle.Op) (bool, error) {
	switch op.Kind {
	case lifecycle.OCheckpoint:
		return b.Svc.InFlight(ctx, op.Sess, op.ID), nil
	case lifecycle.ORestore:
		return b.Svc.InFlight(ctx, op.Sess, op.Arg), nil
	}
	return false, nil
}

// Artifacts wraps the lifecycle's artifact store: deleting a checkpoint
// also crypto-shreds its spill key (if it has one).
type Artifacts struct {
	Inner lifecycle.ArtifactStore
	Svc   *Service
}

func (a *Artifacts) Delete(ctx context.Context, sess string, ckpt int64) error {
	if err := a.Svc.Discard(ctx, sess, ckpt); err != nil {
		return err
	}
	if a.Inner == nil {
		return nil
	}
	return a.Inner.Delete(ctx, sess, ckpt)
}

// Exists: the wrapped key is still in the key database (or the inner
// artifact exists). The shred's completion is Service.Shredded.
func (a *Artifacts) Exists(ctx context.Context, sess string, ckpt int64) (bool, error) {
	if k, ok := keyOf(a.Svc.State(), sess, ckpt); ok && k.Wrapped {
		return true, nil
	}
	if a.Inner == nil {
		return false, nil
	}
	return a.Inner.Exists(ctx, sess, ckpt)
}

func (a *Artifacts) Encrypted(ctx context.Context) (bool, error) {
	if a.Inner == nil {
		return true, nil // halo spill files are format v2 (AES-256-GCM); halo refuses plaintext with a provider
	}
	return a.Inner.Encrypted(ctx)
}

func (a *Artifacts) InFlight(ctx context.Context, op lifecycle.Op) (bool, error) {
	if a.Inner == nil {
		return false, nil
	}
	return a.Inner.InFlight(ctx, op)
}

// LateEpochs is an issuer.EpochSource set after construction (the
// lifecycle Machine is built after its Router, which holds the key service).
type LateEpochs struct {
	mu  sync.Mutex
	src interface {
		Epoch(string) (int64, bool)
	}
}

func (l *LateEpochs) Set(src interface{ Epoch(string) (int64, bool) }) {
	l.mu.Lock()
	l.src = src
	l.mu.Unlock()
}

func (l *LateEpochs) Epoch(s string) (int64, bool) {
	l.mu.Lock()
	src := l.src
	l.mu.Unlock()
	if src == nil {
		return 0, false
	}
	return src.Epoch(s)
}

var (
	_ lifecycle.Backend       = (*KV)(nil)
	_ lifecycle.ArtifactStore = (*Artifacts)(nil)
)
