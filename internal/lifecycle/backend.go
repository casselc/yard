package lifecycle

import (
	"context"
	"fmt"
)

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
	// from the snapshot, memory/spec/KV from the artifact).
	Restore(ctx context.Context, sess string, gen, ckpt int64) error
	Instance(ctx context.Context, sess string, name int64) (exists, running bool, err error)
	// InFlight reports whether a process started for op may still apply
	// its effect (the VMM, bhyvectl, jail teardown, engine spill), including
	// one started by an earlier yard-ctl incarnation.
	InFlight(ctx context.Context, op Op) (bool, error)
}

// Minter asks the STS for a session credential of an epoch. The STS
// (internal/issuer) refuses an epoch other than the session row's, and the
// broker honours only the current epoch.
type Minter interface {
	Mint(ctx context.Context, sess string, epoch int64) error
	Holds(ctx context.Context, sess string, epoch int64) (bool, error)
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
	Exec(ctx context.Context, op Op, row Row) (ok bool, bytes int64)
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
}

// Encrypted reports whether the artifact dataset is encrypted (Start refuses otherwise).
func (r *Router) Encrypted(ctx context.Context) (bool, error) { return r.Artifacts.Encrypted(ctx) }

func (r *Router) backend(kind string) (Backend, error) {
	b, ok := r.Backends[kind]
	if !ok {
		return nil, fmt.Errorf("lifecycle: no backend for kind %q", kind)
	}
	return b, nil
}

func (r *Router) Exec(ctx context.Context, op Op, row Row) (bool, int64) {
	var err error
	var n int64
	switch op.Kind {
	case OMint:
		err = r.Mint.Mint(ctx, op.Sess, op.Arg)
	case ODelete:
		err = r.Artifacts.Delete(ctx, op.Sess, op.Arg)
	default:
		var b Backend
		if b, err = r.backend(row.Kind); err != nil {
			return false, 0
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
			err = b.Restore(ctx, op.Sess, op.Gen, op.Arg)
		}
	}
	return err == nil, n
}

func (r *Router) Settled(ctx context.Context, op Op, row Row) (bool, error) {
	var busy bool
	var err error
	switch op.Kind {
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
	case OMint:
		return r.Mint.Holds(ctx, op.Sess, op.Arg)
	case ODelete:
		ok, err := r.Artifacts.Exists(ctx, op.Sess, op.Arg)
		return !ok, err
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
		_, running, err := b.Instance(ctx, op.Sess, op.Arg)
		return running, err
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
