package lifecycle

import (
	"context"
	"errors"
	"fmt"
)

// ErrRefused, wrapped in a backend's error, is a definite refusal: the call
// did nothing (SR1 decision 2: Restore of a workspace changed since the
// suspend snapshot, without the override). The op becomes Refused, not
// Unknown. Return it only when nothing at all was done.
var ErrRefused = errors.New("lifecycle: refused")

// The interfaces SR1-SR4 implement. Every call here crosses a process
// boundary and may time out and still complete, fail and still have
// applied, or be killed half-way; the lifecycle never trusts anything but
// a successful return, and otherwise resolves the op by InFlight (the
// settle bound) and the matching observation (spec/sr0/README.md, the
// register).

// Backend is one instance kind: jail or service (SR1), fc (SR2), bhyve
// (SR3), kv engine session state (SR4). Instance names are (session,
// name) where name is the generation the instance was restored from (0:
// the original); Restore must treat the name as create-only (refuse, or
// succeed idempotently, when it exists).
type Backend interface {
	// Quiesce stops everything that can write the workspace or the
	// instance's state and returns once it has stopped: for a jail,
	// jail_remove and wait for every process to exit (closing a jail
	// descriptor does not kill them); for a VM, pause.
	Quiesce(ctx context.Context, sess string, inst int64) error
	Unquiesce(ctx context.Context, sess string, inst int64) error
	// Checkpoint takes the ZFS workspace snapshot and writes the artifact
	// for checkpoint ckpt (create-only path on the encrypted dataset);
	// returns its size.
	Checkpoint(ctx context.Context, sess string, gen, ckpt int64) (bytes int64, err error)
	// CheckpointOK checks the artifact's digest and size against its record.
	CheckpointOK(ctx context.Context, sess string, ckpt int64) (bool, error)
	Destroy(ctx context.Context, sess string, inst int64) error
	// Restore starts instance `gen` from checkpoint ckpt (workspace clone
	// from the snapshot, memory/spec/KV from the artifact). With force false
	// it refuses (ErrRefused, nothing done) a workspace that changed since
	// the checkpoint's snapshot; force is the request's explicit override.
	Restore(ctx context.Context, sess string, gen, ckpt int64, force bool) error
	Instance(ctx context.Context, sess string, name int64) (exists, running bool, err error)
	// InFlight reports whether a process started for op may still apply
	// its effect (the VMM, bhyvectl, jail teardown, engine spill), including
	// one started by an earlier yard-ctl incarnation.
	InFlight(ctx context.Context, op Op) (bool, error)
}

type opKey struct{}

// WithOp returns ctx carrying the op a backend call serves (the Router sets
// it), so a backend can name per-op resources -- a lock its child processes
// inherit, an artifact path -- by op id.
func WithOp(ctx context.Context, op Op) context.Context { return context.WithValue(ctx, opKey{}, op) }

// OpFrom returns the op WithOp put in ctx.
func OpFrom(ctx context.Context) (Op, bool) {
	op, ok := ctx.Value(opKey{}).(Op)
	return op, ok
}

// Pauser is the optional SR1 pause tier of a Backend: SIGSTOP / SIGCONT
// every process of an instance. A run class with Policy.Pause needs a
// backend that implements it.
type Pauser interface {
	Pause(ctx context.Context, sess string, inst int64) error
	Unpause(ctx context.Context, sess string, inst int64) error
	// Frozen observes the instance: whether it exists, and whether every
	// one of its processes is stopped (false when it has none).
	Frozen(ctx context.Context, sess string, inst int64) (exists, frozen bool, err error)
}

// Minter asks the STS for a session credential of an epoch. The STS
// (internal/issuer) refuses an epoch other than the session row's, and the
// broker honours only the current epoch.
type Minter interface {
	Mint(ctx context.Context, sess string, epoch int64) error
	Holds(ctx context.Context, sess string, epoch int64) (bool, error)
	InFlight(ctx context.Context, op Op) (bool, error)
}

// Keys is the SR1 workspace key service as the lifecycle drives it (layout
// D: ws/<project> is an encryption root whose raw key yard-ctl holds). Each
// call is an op: done, not done or unknown; InFlight is its settle bound.
type Keys interface {
	// LoadKey loads the key of the session's project (`zfs load-key` from
	// stdin; already loaded is done) and mounts the session's clone.
	LoadKey(ctx context.Context, sess string) error
	// KeyLoaded observes LoadKey: the key is available and the clone mounted.
	KeyLoaded(ctx context.Context, sess string) (bool, error)
	// Unmount unmounts every dataset of the project (never forced).
	Unmount(ctx context.Context, project string) error
	Unmounted(ctx context.Context, project string) (bool, error)
	// UnloadKey is `zfs unload-key` of the project root.
	UnloadKey(ctx context.Context, project string) error
	KeyUnloaded(ctx context.Context, project string) (bool, error)
	InFlight(ctx context.Context, op Op) (bool, error)
}

// ArtifactStore deletes and lists suspend artifacts by checkpoint id.
type ArtifactStore interface {
	Delete(ctx context.Context, sess string, ckpt int64) error
	Exists(ctx context.Context, sess string, ckpt int64) (bool, error)
	// Encrypted reports whether the artifact dataset is encrypted
	// (`zfs get -H -o value encryption`); the Machine refuses to start
	// otherwise (invariant 4).
	Encrypted(ctx context.Context) (bool, error)
	InFlight(ctx context.Context, op Op) (bool, error)
}

// ActivitySource reports a session's activity sequence (the broker's
// count of model and tool calls): a slow observation, dated by the caller
// when the answer arrives.
type ActivitySource interface {
	Activity(ctx context.Context, sess string) (int64, error)
}

// FactSink receives yard.fact records (an OTel log exporter in production;
// no network here).
type FactSink interface {
	Emit(Fact)
}

// OutcomeCounter is an optional extension of the FactSink: one count per
// op outcome, by op kind and outcome class (AMBIGUITY.md rule 5: an unknown
// that resolves silently is invisible in production). Classes:
// answer_done, answer_error (unknown), answer_ignored (late, or to an
// earlier incarnation), timeout (unknown), restart_unknown, resolved_done,
// resolved_not_done, retry.
type OutcomeCounter interface {
	CountOutcome(kind OpKind, class string)
}

// Executor runs ops; Router is the production one.
type Executor interface {
	Exec(ctx context.Context, op Op, row Row) (out Outcome, bytes int64)
	Settled(ctx context.Context, op Op, row Row) (bool, error)
	Observe(ctx context.Context, op Op, row Row) (bool, error)
	Instance(ctx context.Context, row Row, name int64) (exists, running bool, err error)
	Activity(ctx context.Context, sess string) (int64, error)
}

// Router dispatches ops to the backend of the session's kind, the minter
// and the artifact store.
type Router struct {
	Backends  map[string]Backend
	Mint      Minter
	Artifacts ArtifactStore
	Act       ActivitySource
	Keys      Keys // SR1 workspace keys; nil: no session has a project
}

func (r *Router) keys() (Keys, error) {
	if r.Keys == nil {
		return nil, errors.New("lifecycle: no key service")
	}
	return r.Keys, nil
}

// Encrypted reports whether the artifact dataset is encrypted (Start refuses otherwise).
func (r *Router) Encrypted(ctx context.Context) (bool, error) { return r.Artifacts.Encrypted(ctx) }

// CanPause reports whether the backend of kind implements Pauser.
func (r *Router) CanPause(kind string) bool {
	_, ok := r.Backends[kind].(Pauser)
	return ok
}

func (r *Router) pauser(kind string) (Pauser, error) {
	b, err := r.backend(kind)
	if err != nil {
		return nil, err
	}
	p, ok := b.(Pauser)
	if !ok {
		return nil, fmt.Errorf("lifecycle: backend %q has no pause tier", kind)
	}
	return p, nil
}

func (r *Router) backend(kind string) (Backend, error) {
	b, ok := r.Backends[kind]
	if !ok {
		return nil, fmt.Errorf("lifecycle: no backend for kind %q", kind)
	}
	return b, nil
}

func (r *Router) Exec(ctx context.Context, op Op, row Row) (Outcome, int64) {
	ctx = WithOp(ctx, op)
	var err error
	var n int64
	switch op.Kind {
	case OLoadKey, OUnmount, OUnloadKey:
		var k Keys
		if k, err = r.keys(); err == nil {
			switch op.Kind {
			case OLoadKey:
				err = k.LoadKey(ctx, op.Sess)
			case OUnmount:
				err = k.Unmount(ctx, op.Sess)
			default:
				err = k.UnloadKey(ctx, op.Sess)
			}
		}
	case OMint:
		err = r.Mint.Mint(ctx, op.Sess, op.Arg)
	case ODelete:
		err = r.Artifacts.Delete(ctx, op.Sess, op.Arg)
	case OPause, OUnpause:
		var p Pauser
		if p, err = r.pauser(row.Kind); err == nil {
			if op.Kind == OPause {
				err = p.Pause(ctx, op.Sess, op.Arg)
			} else {
				err = p.Unpause(ctx, op.Sess, op.Arg)
			}
		}
	default:
		var b Backend
		if b, err = r.backend(row.Kind); err != nil {
			return AnsError, 0
		}
		switch op.Kind {
		case OQuiesce:
			err = b.Quiesce(ctx, op.Sess, op.Arg)
		case OUnquiesce:
			err = b.Unquiesce(ctx, op.Sess, op.Arg)
		case OCheckpoint:
			n, err = b.Checkpoint(ctx, op.Sess, op.Gen, op.ID)
		case ODestroy:
			err = b.Destroy(ctx, op.Sess, op.Arg)
		case ORestore:
			err = b.Restore(ctx, op.Sess, op.Gen, op.Arg, op.Force)
		}
	}
	switch {
	case err == nil:
		return AnsDone, n
	case errors.Is(err, ErrRefused):
		return AnsRefused, 0
	}
	return AnsError, 0
}

func (r *Router) Settled(ctx context.Context, op Op, row Row) (bool, error) {
	var busy bool
	var err error
	switch op.Kind {
	case OLoadKey, OUnmount, OUnloadKey:
		var k Keys
		if k, err = r.keys(); err == nil {
			busy, err = k.InFlight(ctx, op)
		}
	case OMint:
		busy, err = r.Mint.InFlight(ctx, op)
	case ODelete:
		busy, err = r.Artifacts.InFlight(ctx, op)
	default:
		var b Backend
		if b, err = r.backend(row.Kind); err == nil {
			busy, err = b.InFlight(ctx, op)
		}
	}
	return !busy && err == nil, err
}

func (r *Router) Observe(ctx context.Context, op Op, row Row) (bool, error) {
	switch op.Kind {
	case OLoadKey, OUnmount, OUnloadKey:
		k, err := r.keys()
		if err != nil {
			return false, err
		}
		switch op.Kind {
		case OLoadKey:
			return k.KeyLoaded(ctx, op.Sess)
		case OUnmount:
			return k.Unmounted(ctx, op.Sess)
		}
		return k.KeyUnloaded(ctx, op.Sess)
	case OMint:
		return r.Mint.Holds(ctx, op.Sess, op.Arg)
	case ODelete:
		ok, err := r.Artifacts.Exists(ctx, op.Sess, op.Arg)
		return !ok, err
	case OPause, OUnpause:
		p, err := r.pauser(row.Kind)
		if err != nil {
			return false, err
		}
		exists, frozen, err := p.Frozen(ctx, op.Sess, op.Arg)
		if op.Kind == OPause {
			return exists && frozen, err
		}
		return exists && !frozen, err
	}
	b, err := r.backend(row.Kind)
	if err != nil {
		return false, err
	}
	switch op.Kind {
	case OQuiesce:
		_, running, err := b.Instance(ctx, op.Sess, op.Arg)
		return !running, err
	case OUnquiesce:
		// running and not frozen (Quint observedDone)
		_, running, err := b.Instance(ctx, op.Sess, op.Arg)
		if err != nil || !running {
			return false, err
		}
		if p, ok := b.(Pauser); ok {
			_, frozen, err := p.Frozen(ctx, op.Sess, op.Arg)
			return !frozen, err
		}
		return true, nil
	case ODestroy:
		exists, _, err := b.Instance(ctx, op.Sess, op.Arg)
		return !exists, err
	case OCheckpoint:
		return b.CheckpointOK(ctx, op.Sess, op.ID)
	case ORestore:
		exists, _, err := b.Instance(ctx, op.Sess, op.Gen)
		return exists, err
	}
	return false, fmt.Errorf("lifecycle: unknown op kind %q", op.Kind)
}

func (r *Router) Instance(ctx context.Context, row Row, name int64) (bool, bool, error) {
	b, err := r.backend(row.Kind)
	if err != nil {
		return false, false, err
	}
	return b.Instance(ctx, row.ID, name)
}

func (r *Router) Activity(ctx context.Context, sess string) (int64, error) {
	return r.Act.Activity(ctx, sess)
}
