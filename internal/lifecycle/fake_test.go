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
	frozen    map[string]map[int64]bool // sess -> name -> SIGSTOPped (pause tier)
	artifacts map[string]map[int64]bool // sess -> ckpt -> ok
	creds     map[string]map[int64]bool // sess -> epoch
	epoch     map[string]int64          // the STS's view of the current epoch (the row's)
	act       map[string]int64
	starts    map[int64]int // restores that started an instance, per checkpoint
	inflight  map[int64]int
	hold      map[OpKind]chan struct{}
	failAfter map[OpKind]bool // apply, then answer an error (lost answer)
	encrypted bool
	// SR1 workspace keys and drift
	project   map[string]string // sess -> project ("" none)
	keyLoaded map[string]bool   // project -> key loaded (the kernel)
	mounted   map[string]bool   // sess -> clone mounted
	ws        map[string]int    // sess -> workspace version (bumped by an edit)
	snapWS    map[int64]int     // ckpt -> workspace version at the snapshot
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{insts: map[string]map[int64]bool{}, frozen: map[string]map[int64]bool{}, artifacts: map[string]map[int64]bool{},
		creds: map[string]map[int64]bool{}, epoch: map[string]int64{}, act: map[string]int64{},
		starts: map[int64]int{}, inflight: map[int64]int{}, hold: map[OpKind]chan struct{}{},
		failAfter: map[OpKind]bool{}, encrypted: true, project: map[string]string{}, keyLoaded: map[string]bool{},
		mounted: map[string]bool{}, ws: map[string]int{}, snapWS: map[int64]int{}}
}

// addProject gives session s project p (key loaded, clone mounted).
func (w *fakeWorld) addProject(s, p string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.project[s], w.keyLoaded[p], w.mounted[s] = p, true, true
}

// edit changes session s's workspace (decision 2 drift).
func (w *fakeWorld) edit(s string) { w.mu.Lock(); w.ws[s]++; w.mu.Unlock() }

func (w *fakeWorld) addSession(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.insts[s] = map[int64]bool{0: true}
	w.frozen[s] = map[int64]bool{}
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

func (w *fakeWorld) Exec(ctx context.Context, op Op, row Row) (Outcome, int64) {
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
			w.frozen[s][op.Arg] = false
		}
	case OUnquiesce:
		if _, ok := w.insts[s][op.Arg]; ok {
			w.insts[s][op.Arg] = true
			w.frozen[s][op.Arg] = false
		}
	case OPause:
		if w.insts[s][op.Arg] {
			w.frozen[s][op.Arg] = true
		}
	case OUnpause:
		w.frozen[s][op.Arg] = false
	case ODestroy:
		delete(w.insts[s], op.Arg)
	case OCheckpoint:
		if len(w.insts[s]) > 0 {
			w.artifacts[s][op.ID] = true
			w.snapWS[op.ID] = w.ws[s]
			bytes = 4096
		}
	case ORestore:
		_, exists := w.insts[s][op.Gen]
		if !exists && w.artifacts[s][op.Arg] && !op.Force && w.ws[s] != w.snapWS[op.Arg] {
			return AnsRefused, 0
		}
		if !exists && w.artifacts[s][op.Arg] {
			w.insts[s][op.Gen] = true
			w.starts[op.Arg]++
		}
	case OLoadKey:
		w.keyLoaded[w.project[s]], w.mounted[s] = true, true
	case OUnmount:
		for x, p := range w.project {
			if p == s {
				w.mounted[x] = false
			}
		}
	case OUnloadKey:
		busy := false
		for x, p := range w.project {
			busy = busy || (p == s && w.mounted[x])
		}
		if !busy {
			w.keyLoaded[s] = false
		}
	case OMint:
		if op.Arg == row.CredEpoch {
			w.creds[s][op.Arg] = true
		}
	case ODelete:
		delete(w.artifacts[s], op.Arg)
	}
	if w.observeLocked(op) && !w.failAfter[op.Kind] {
		return AnsDone, bytes
	}
	return AnsError, 0
}

func (w *fakeWorld) observeLocked(op Op) bool {
	s := op.Sess
	switch op.Kind {
	case OQuiesce:
		return !w.insts[s][op.Arg]
	case OUnquiesce:
		return w.insts[s][op.Arg] && !w.frozen[s][op.Arg]
	case OPause:
		_, ok := w.insts[s][op.Arg]
		return ok && w.frozen[s][op.Arg]
	case OUnpause:
		_, ok := w.insts[s][op.Arg]
		return ok && !w.frozen[s][op.Arg]
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
	case OLoadKey:
		return w.keyLoaded[w.project[s]] && w.mounted[s]
	case OUnmount:
		for x, p := range w.project {
			if p == s && w.mounted[x] {
				return false
			}
		}
		return true
	case OUnloadKey:
		return !w.keyLoaded[s]
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

func (w *fakeWorld) CanPause(string) bool { return true }

func (w *fakeWorld) isFrozen(s string, name int64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.frozen[s][name]
}

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
