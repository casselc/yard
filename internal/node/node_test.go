package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"
)

// fakeVM runs until killed, or until the test finishes it (the guest wrote its result and powered off).
type fakeVM struct {
	once sync.Once
	done chan struct{}
	err  error
}

func (v *fakeVM) Wait() error { <-v.done; return v.err }
func (v *fakeVM) Kill() error {
	v.once.Do(func() { v.err = fmt.Errorf("killed"); close(v.done) })
	return nil
}
func (v *fakeVM) CPU() (time.Duration, time.Duration, int64) { return 0, 0, 0 }
func (v *fakeVM) finish()                                    { v.once.Do(func() { close(v.done) }) }

type fakeLauncher struct {
	mu   sync.Mutex
	vms  map[string]*fakeVM
	runs map[string]int // how many times each id was launched
}

func (l *fakeLauncher) Launch(id, dir string, s Spec) (VM, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := &fakeVM{done: make(chan struct{})}
	l.vms[id] = v
	l.runs[id]++
	return v, nil
}

// machine: the node driven by start (possibly late), finish (with or without a result), stop, tombstone, lease
// expiry, and node restarts (the VMs die with it). Properties: an id is launched at most once; a tombstoned id
// never runs; "running" only while the VM is alive; a finished VM's result is reported.
type machine struct {
	root  string
	n     *Node
	l     *fakeLauncher
	clock atomic.Int64 // unix ms, read by the node's reapers concurrently
	ids   []string
	tomb  map[string]bool
	alive map[string]bool
}

func (m *machine) now() time.Time { return time.UnixMilli(m.clock.Load()) }

func (m *machine) id(t hegel.TestCase) string {
	return m.ids[hegel.Draw(t, hegel.Integers(0, len(m.ids)-1))]
}

func (m *machine) RuleStart(t hegel.TestCase) {
	id := m.id(t)
	lease := int64(hegel.Draw(t, hegel.Integers(0, 5000)))
	st, err := m.n.Start(id, Spec{LeaseMs: lease})
	if m.tomb[id] {
		if err == nil || st.State != "tombstoned" {
			t.Errorf("tombstoned %s started: %+v %v", id, st, err)
		}
		return
	}
	if err == nil && st.State == "running" && m.l.runs[id] == 1 {
		m.alive[id] = true
	}
}

func (m *machine) RuleFinish(t hegel.TestCase) {
	id := m.id(t)
	v, ok := m.l.vms[id]
	t.Assume(ok && m.alive[id])
	if hegel.Draw(t, hegel.Booleans()) {
		os.WriteFile(filepath.Join(m.root, id, "result.json"), []byte(`{"type":"result"}`), 0o600)
	}
	v.finish()
	m.n.Stop(context.Background(), id, "guest") // wait for the reap
	m.alive[id] = false
}

func (m *machine) RuleStop(t hegel.TestCase) {
	id := m.id(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.n.Stop(ctx, id, "stopped"); err != nil {
		t.Errorf("stop: %v", err)
	}
	m.alive[id] = false
}

func (m *machine) RuleTombstone(t hegel.TestCase) {
	id := m.id(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if st, err := m.n.Tombstone(ctx, id); err != nil || st.State != "tombstoned" {
		t.Errorf("tombstone: %+v %v", st, err)
	}
	m.tomb[id], m.alive[id] = true, false
}

func (m *machine) RuleTime(t hegel.TestCase) {
	m.clock.Add(int64(hegel.Draw(t, hegel.Integers(0, 6000))))
	m.n.Watchdog(context.Background())
	m.n.mu.Lock()
	for id, a := range m.n.alloc { // F8: after the watchdog, nothing runs on an expired lease
		if a.State.State == "running" && !a.lease.IsZero() && m.now().After(a.lease) {
			t.Errorf("%s runs past its lease", id)
		}
	}
	m.n.mu.Unlock()
	for id := range m.alive {
		if m.alive[id] && m.n.get(id).State != "running" {
			m.alive[id] = false // the lease expired
		}
	}
}

// the node process dies: its files stay as they were, and its VMs die with it (parent-death signal)
func (m *machine) RuleCrash(t hegel.TestCase) {
	m.n.crash()
	for _, v := range m.l.vms {
		v.Kill()
	}
	n, err := New(m.root, m.l)
	if err != nil {
		t.Errorf("restart: %v", err)
	}
	n.now = m.now
	m.n = n
	for id := range m.alive {
		m.alive[id] = false
	}
}

func (m *machine) InvariantOnce(t hegel.TestCase) {
	for id, k := range m.l.runs {
		if k > 1 {
			t.Errorf("%s launched %d times", id, k)
		}
		if m.tomb[id] && m.n.get(id).State == "running" {
			t.Errorf("tombstoned %s is running", id)
		}
	}
}

func (m *machine) InvariantRunningIsAlive(t hegel.TestCase) {
	for _, st := range m.n.List() {
		v := m.l.vms[st.ID]
		if st.State == "running" {
			select {
			case <-v.done:
				// the reaper may not have run yet; give it a moment
				time.Sleep(10 * time.Millisecond)
				if m.n.get(st.ID).State == "running" {
					t.Errorf("%s reported running after its VM exited", st.ID)
				}
			default:
			}
		}
		if fileExists(filepath.Join(m.root, st.ID, "result.json")) && st.State == "exited" && !st.Finished {
			t.Errorf("%s has a result but is not reported finished", st.ID)
		}
	}
}

func TestNodeMachine(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		root := t.TempDir()
		l := &fakeLauncher{vms: map[string]*fakeVM{}, runs: map[string]int{}}
		n, err := New(root, l)
		if err != nil {
			t.Fatal(err)
		}
		m := &machine{root: root, n: n, l: l, ids: []string{"aa000001", "aa000002", "aa000003"},
			tomb: map[string]bool{}, alive: map[string]bool{}}
		m.clock.Store(1_800_000_000_000)
		n.now = m.now
		hegel.RunStateful(ht, m)
	})
}

// Regression (hegel, shrunk): a tombstone under an id recovery would not reload was lost across a restart, and a
// late start then ran. Ids are now validated where state is written.
func TestShortIDRefused(t *testing.T) {
	n, err := New(t.TempDir(), &fakeLauncher{vms: map[string]*fakeVM{}, runs: map[string]int{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Tombstone(context.Background(), "aa02"); err == nil {
		t.Fatal("tombstone of an invalid id accepted")
	}
	if _, err := n.Start("aa02", Spec{}); err == nil {
		t.Fatal("start of an invalid id accepted")
	}
}
