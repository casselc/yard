package lifecycle

import (
	"context"
	"sync"
)

// fakeWorld is an in-memory environment for Machine tests: instances,
// artifacts, credentials and activity, with the same effects and
// observations as the Quint model (effect, observedDone). Ops of a kind in
// hold block until released, so a test can keep a copy in flight across a
// timeout or a restart.
type fakeWorld struct {
	mu        sync.Mutex
	insts     map[string]map[int64]bool // sess -> name -> running
	artifacts map[string]map[int64]bool // sess -> ckpt -> ok
	creds     map[string]map[int64]bool // sess -> epoch
	epoch     map[string]int64          // the STS's view of the current epoch (the row's)
	act       map[string]int64
	starts    map[int64]int // restores that started an instance, per checkpoint
	inflight  map[int64]int
	hold      map[OpKind]chan struct{}
	failAfter map[OpKind]bool // apply, then answer an error (lost answer)
	encrypted bool
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{insts: map[string]map[int64]bool{}, artifacts: map[string]map[int64]bool{},
		creds: map[string]map[int64]bool{}, epoch: map[string]int64{}, act: map[string]int64{},
		starts: map[int64]int{}, inflight: map[int64]int{}, hold: map[OpKind]chan struct{}{},
		failAfter: map[OpKind]bool{}, encrypted: true}
}

func (w *fakeWorld) addSession(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.insts[s] = map[int64]bool{0: true}
	w.artifacts[s] = map[int64]bool{}
	w.creds[s] = map[int64]bool{1: true}
	w.epoch[s] = 1
}

func (w *fakeWorld) holdKind(k OpKind) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch := make(chan struct{})
	w.hold[k] = ch
	return ch
}

func (w *fakeWorld) Exec(ctx context.Context, op Op, row Row) (bool, int64) {
	w.mu.Lock()
	w.inflight[op.ID]++
	ch := w.hold[op.Kind]
	w.mu.Unlock()
	if ch != nil {
		<-ch
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inflight[op.ID]--
	s := op.Sess
	var bytes int64
	switch op.Kind {
	case OQuiesce:
		if _, ok := w.insts[s][op.Arg]; ok {
			w.insts[s][op.Arg] = false
		}
	case OUnquiesce:
		if _, ok := w.insts[s][op.Arg]; ok {
			w.insts[s][op.Arg] = true
		}
	case ODestroy:
		delete(w.insts[s], op.Arg)
	case OCheckpoint:
		if len(w.insts[s]) > 0 {
			w.artifacts[s][op.ID] = true
			bytes = 4096
		}
	case ORestore:
		_, exists := w.insts[s][op.Gen]
		if !exists && w.artifacts[s][op.Arg] {
			w.insts[s][op.Gen] = true
			w.starts[op.Arg]++
		}
	case OMint:
		if op.Arg == row.CredEpoch {
			w.creds[s][op.Arg] = true
		}
	case ODelete:
		delete(w.artifacts[s], op.Arg)
	}
	ok := w.observeLocked(op) && !w.failAfter[op.Kind]
	return ok, bytes
}

func (w *fakeWorld) observeLocked(op Op) bool {
	s := op.Sess
	switch op.Kind {
	case OQuiesce:
		return !w.insts[s][op.Arg]
	case OUnquiesce:
		return w.insts[s][op.Arg]
	case ODestroy:
		_, ok := w.insts[s][op.Arg]
		return !ok
	case OCheckpoint:
		return w.artifacts[s][op.ID]
	case ORestore:
		_, ok := w.insts[s][op.Gen]
		return ok
	case OMint:
		return w.creds[s][op.Arg]
	case ODelete:
		_, ok := w.artifacts[s][op.Arg]
		return !ok
	}
	return false
}

func (w *fakeWorld) Settled(ctx context.Context, op Op, row Row) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.inflight[op.ID] == 0, nil
}

func (w *fakeWorld) Observe(ctx context.Context, op Op, row Row) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.observeLocked(op), nil
}

func (w *fakeWorld) Instance(ctx context.Context, row Row, name int64) (bool, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	run, ok := w.insts[row.ID][name]
	return ok, ok && run, nil
}

func (w *fakeWorld) Activity(ctx context.Context, s string) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.act[s], nil
}

func (w *fakeWorld) Encrypted(context.Context) (bool, error) { return w.encrypted, nil }

type factLog struct {
	mu     sync.Mutex
	facts  []Fact
	counts map[string]int // "<kind>/<class>"
}

func (f *factLog) CountOutcome(k OpKind, class string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[string(k)+"/"+class]++
}

func (f *factLog) count(k OpKind, class string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[string(k)+"/"+class]
}

func (f *factLog) Emit(x Fact) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.facts = append(f.facts, x)
}

func (f *factLog) named(n string) []Fact {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Fact
	for _, x := range f.facts {
		if x.Name == n {
			out = append(out, x)
		}
	}
	return out
}

// clock is a manual clock (ms).
type clock struct {
	mu sync.Mutex
	t  int64
}

func (c *clock) now() int64  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d int64) { c.mu.Lock(); c.t += d; c.mu.Unlock() }
