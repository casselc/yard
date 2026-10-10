package guestagent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fakes

// events is a shared, ordered log of side effects (clock step, entropy, restarts, reports).
type events struct {
	mu sync.Mutex
	l  []string
}

func (e *events) add(s string) { e.mu.Lock(); e.l = append(e.l, s); e.mu.Unlock() }
func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.l...)
}
func (e *events) index(prefix string) int {
	for i, s := range e.list() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

// fakeClock: the guest wall clock = real time + off; Step moves off.
type fakeClock struct {
	mu  sync.Mutex
	off time.Duration
	ev  *events
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.off) }
func (c *fakeClock) Step(d time.Duration) error {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
	c.ev.add("step")
	return nil
}
func (c *fakeClock) offset() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.off }

// fakeGen: the cached sysctl.
type fakeGen struct {
	mu sync.Mutex
	g  Gen
}

func (f *fakeGen) ReadGen() (Gen, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.g, nil }
func (f *fakeGen) set(g Gen)             { f.mu.Lock(); f.g = g; f.mu.Unlock() }

// fakeEntropy is FreeBSD 15's Fortuna as ReseedPlan describes it: every write puts 4 events of 12
// accounting bytes into the next 4 pools (one static counter, a random phase); a read reseeds iff pool 0
// holds >= minPool bytes and more than interval passed since the last reseed (exact clock here: the
// plan's 2 ticks cover the kernel's coarse one). It counts the host events in pool 0 and how many of
// them a reseed has put into the generator (consumed). Pool 0 starts full of other events, so the run's
// first read (kr_pre) reseeds: a recent reseed, as in a guest with other readers.
type fakeEntropy struct {
	mu         sync.Mutex
	added      [][]byte
	passes     int
	reads      int
	ev         *events
	minPool    int
	tick       time.Duration
	interval   time.Duration
	dest       int
	pool0      int // accounting bytes in pool 0
	pool0Host  int // host events in pool 0
	consumed   int // host events a reseed has consumed
	lastReseed time.Time
	reseeds    int
	paramsErr  error
	failAt     int // Add fails at this write (0: never)
}

func newFakeEntropy(ev *events, interval time.Duration) *fakeEntropy {
	return &fakeEntropy{ev: ev, minPool: 64, tick: time.Millisecond, interval: interval, dest: 5, pool0: 200}
}

func (f *fakeEntropy) Params() (EntropyParams, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return EntropyParams{MinPoolSize: f.minPool, Tick: f.tick}, f.paramsErr
}
func (f *fakeEntropy) Add(b []byte, passes int) (int, error) {
	f.mu.Lock()
	f.added = append(f.added, append([]byte(nil), b...))
	f.passes = passes
	n := passes
	var err error
	if f.failAt > 0 && f.failAt <= passes {
		n, err = f.failAt-1, errors.New("EIO")
	}
	for i := 0; i < n*eventsPerWrite; i++ {
		if f.dest%fortunaPools == 0 {
			f.pool0 += eventAcct
			f.pool0Host++
		}
		f.dest++
	}
	f.mu.Unlock()
	f.ev.add(fmt.Sprintf("entropy %d", len(b)))
	return n, err
}
func (f *fakeEntropy) Read8() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if now := time.Now(); f.pool0 >= f.minPool && (f.lastReseed.IsZero() || now.Sub(f.lastReseed) > f.interval) {
		f.consumed += f.pool0Host
		f.pool0, f.pool0Host, f.lastReseed = 0, 0, now
		f.reseeds++
	}
	return fmt.Sprintf("%08x%08x", f.reseeds, f.reads), nil
}

// fresh: the generator holds at least T = ceil(minPool/12) of the host's events (ReseedPlan's bound).
func (f *fakeEntropy) fresh() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.consumed >= (f.minPool+eventAcct-1)/eventAcct
}

// fakeServices: Restart gives a new pid; hang blocks it until release (or ctx); late: the restart
// still lands after a hang (a late effect).
type fakeServices struct {
	mu      sync.Mutex
	pid     map[string]int
	next    int
	hang    chan struct{}
	late    bool
	killed  []int
	ev      *events
	started chan string
	seedOK  func() bool // the RNG a new process seeds from holds the host bytes
	stale   []string    // restarts that seeded from a stale RNG
}

func newFakeServices(ev *events, names ...string) *fakeServices {
	s := &fakeServices{pid: map[string]int{}, next: 100, ev: ev, started: make(chan string, 16)}
	for _, n := range names {
		s.next++
		s.pid[n] = s.next
	}
	return s
}
func (s *fakeServices) Pid(ctx context.Context, name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pid[name]
	if !ok || p == 0 {
		return 0, errors.New("not running")
	}
	return p, nil
}
func (s *fakeServices) Restart(ctx context.Context, name string) error {
	s.ev.add("restart " + name)
	select {
	case s.started <- name:
	default:
	}
	s.mu.Lock()
	h := s.hang
	s.mu.Unlock()
	if h != nil {
		select {
		case <-h:
		case <-ctx.Done():
			if !s.late {
				return ctx.Err()
			}
			<-h // the effect lands later
		}
	}
	s.mu.Lock()
	s.next++
	s.pid[name] = s.next
	if s.seedOK != nil && !s.seedOK() {
		s.stale = append(s.stale, name)
	}
	s.mu.Unlock()
	return nil
}
func (s *fakeServices) Kill(pid int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killed = append(s.killed, pid)
	for n, p := range s.pid {
		if p == pid {
			s.pid[n] = 0
		}
	}
	return nil
}
func (s *fakeServices) alivePid(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pid[name]
}

// fakeHost answers with the host clock (real time + off) and its epoch; staleFirst: the first answer
// echoes another nonce and carries a host time an hour off (an answer from before the snapshot).
type fakeHost struct {
	mu         sync.Mutex
	name       string
	rank       int
	off        time.Duration
	epoch      uint64
	fail       bool
	staleFirst bool
	nbytes     int
	rtt        time.Duration
	sent       []Record
	asked      int
	ev         *events
}

func (h *fakeHost) Name() string { return h.name }
func (h *fakeHost) Rank() int    { return h.rank }
func (h *fakeHost) setEpoch(e uint64) {
	h.mu.Lock()
	h.epoch = e
	h.mu.Unlock()
}
func (h *fakeHost) Exchange(ctx context.Context, req Request) (Sample, error) {
	h.mu.Lock()
	fail, stale, off, ep, nb, rtt := h.fail, h.staleFirst && h.asked == 0, h.off, h.epoch, h.nbytes, h.rtt
	h.asked++
	h.mu.Unlock()
	if fail {
		<-ctx.Done()
		return Sample{}, ctx.Err()
	}
	if stale {
		rtt = 0 // it was already in the receive buffer: the fastest "answer"
	}
	sent := time.Now()
	time.Sleep(rtt / 2)
	b := make([]byte, nb)
	rand.Read(b)
	a := Answer{Gen: req.Gen, Seq: req.Seq, Epoch: ep, HostRxNs: time.Now().Add(off).UnixNano(), Entropy: b}
	if stale {
		a.Seq = req.Seq + 1000
		a.HostRxNs = time.Now().Add(off - time.Hour).UnixNano()
	}
	a.HostTxNs = a.HostRxNs
	time.Sleep(rtt / 2)
	return Sample{Ans: a, Sent: sent, Recv: time.Now()}, nil
}

// sample times are real time; the agent's view is the fake clock: shift them into it
type shifted struct {
	*fakeHost
	c *fakeClock
}

func (s shifted) Exchange(ctx context.Context, req Request) (Sample, error) {
	sm, err := s.fakeHost.Exchange(ctx, req)
	if err == nil {
		o := s.c.offset()
		sm.Sent, sm.Recv = sm.Sent.Add(o), sm.Recv.Add(o)
	}
	return sm, err
}
func (s shifted) Send(rec Record) error {
	s.mu.Lock()
	s.sent = append(s.sent, rec)
	s.mu.Unlock()
	s.ev.add("report")
	return nil
}
func (h *fakeHost) records() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Record(nil), h.sent...)
}

// testReseedInterval stands in for Fortuna's 100 ms: longer than an exchange with the fake host (3 x
// 2 ms), so a read right after the writes finds the kr_pre reseed too recent.
const testReseedInterval = 40 * time.Millisecond

// rig is one agent with fakes; the guest clock starts 7 s behind the host (a restored guest).
type rig struct {
	ev     *events
	clock  *fakeClock
	gen    *fakeGen
	ent    *fakeEntropy
	svc    *fakeServices
	host   *fakeHost
	h      Host
	r      *Resumer
	cancel context.CancelFunc
	done   chan struct{}
}

func newRig(t testing.TB, ru rules, mod func(*Config)) *rig {
	ev := &events{}
	g := &rig{ev: ev, clock: &fakeClock{off: -7 * time.Second, ev: ev}, gen: &fakeGen{g: "aa"}, ent: newFakeEntropy(ev, testReseedInterval)}
	g.svc = newFakeServices(ev, "keyd")
	g.svc.seedOK = g.ent.fresh
	g.host = &fakeHost{name: "tcp:test", epoch: 1, nbytes: 64, rtt: 2 * time.Millisecond, ev: ev}
	g.h = shifted{g.host, g.clock}
	cfg := Config{Services: []string{"keyd"}, Settle: 200 * time.Millisecond, ExchangeTimeout: 200 * time.Millisecond, HostWait: 50 * time.Millisecond,
		ReseedInterval: testReseedInterval, ServiceTimeout: 300 * time.Millisecond, Samples: 3}
	if mod != nil {
		mod(&cfg)
	}
	g.r = newWithRules(cfg, Deps{Clock: g.clock, Gen: g.gen, Entropy: g.ent, Services: g.svc, Log: t.Logf}, ru)
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel, g.done = cancel, make(chan struct{})
	go func() { g.r.Run(ctx); close(g.done) }()
	g.r.ObserveEpoch(1, g.h) // boot: the first HELLO's epoch is adopted
	t.Cleanup(g.stop)
	return g
}

func (g *rig) stop() {
	g.cancel()
	<-g.done
}

// waitRuns waits until n runs completed and the agent is Ready; error on timeout.
func (g *rig) waitRuns(n uint64, d time.Duration) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		st := g.r.Status()
		if st.Runs >= n && st.Phase == Ready {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	st := g.r.Status()
	return fmt.Errorf("after %v: runs %d phase %s, want %d runs and ready", d, st.Runs, st.Phase, n)
}

// quiet: no further run starts within d.
func (g *rig) quiet(n uint64, d time.Duration) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		st := g.r.Status()
		if st.Runs > n || st.Phase != Ready {
			return fmt.Errorf("a duplicate signal started run %d (phase %s)", st.Runs, st.Phase)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

// fresh checks the guest after a run: clock within 0.1 s of the host, host bytes added, the service
// restarted after them (a new pid) -- the model's noStaleWork.
func (g *rig) fresh() error {
	if d := g.clock.offset() - g.host.off; d > 100*time.Millisecond || d < -100*time.Millisecond {
		return fmt.Errorf("guest clock %v off the host after the run", d)
	}
	ie, ir := g.ev.index("entropy 64"), g.ev.index("restart keyd")
	if ie < 0 {
		return errors.New("host entropy never added")
	}
	if ir >= 0 && ir < ie {
		return fmt.Errorf("service restarted before the entropy: %v", g.ev.list())
	}
	if p := g.svc.alivePid("keyd"); p == 101 {
		return errors.New("the old key-holding process (pid 101) still runs")
	}
	g.svc.mu.Lock()
	stale := len(g.svc.stale)
	g.svc.mu.Unlock()
	if stale > 0 {
		return errors.New("a service restarted before a reseed put the host bytes into the generator")
	}
	if l := g.r.Status().Last; l != nil && l.Entropy.Outcome.Outcome == "done" && !g.ent.fresh() {
		return errors.New("entropy recorded done, but no reseed has put the host bytes into the generator")
	}
	return nil
}

// ---------------------------------------------------------------- scenarios (shared by tests and mutants)

type scenario struct {
	name string
	run  func(t testing.TB, ru rules) error
}

var scenarios = []scenario{
	// gen first (the usual order), then duplicates of both signals: one run, key (bb, 2)
	{"genFirstDup", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.gen.set("bb")
		g.host.setEpoch(2)
		g.r.ObserveGen("bb", "devd")
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		g.r.ObserveEpoch(2, g.h)
		g.r.ObserveGen("bb", "devd")
		g.r.ObserveGen("bb", "poll")
		if err := g.quiet(1, 300*time.Millisecond); err != nil {
			return err
		}
		l := g.r.Status().Last
		if l.GenNew != "bb" || l.EpochNew != 2 || l.GenOld != "aa" || l.EpochOld != 1 {
			return fmt.Errorf("record key %+v", l)
		}
		if len(g.host.records()) != 1 {
			return fmt.Errorf("host got %d records", len(g.host.records()))
		}
		return g.fresh()
	}},
	// epoch first: waits for the notify (Settle), keys by the new generation; the late devd event is a no-op
	{"epochFirst", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.host.setEpoch(2)
		g.r.ObserveEpoch(2, g.h)
		time.Sleep(50 * time.Millisecond)
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		if l := g.r.Status().Last; l.GenNew != "bb" || l.EpochNew != 2 {
			return fmt.Errorf("record key %s/%d, want bb/2", l.GenNew, l.EpochNew)
		}
		g.r.ObserveGen("bb", "devd")
		return g.quiet(1, 300*time.Millisecond)
	}},
	// only the epoch (notify lost): after Settle, run keyed (aa, 2)
	{"lostNotify", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.host.setEpoch(2)
		if err := g.r.AllowEpoch(2); err == nil && ru.gateWork {
			return errors.New("exec accepted with a new epoch before any run")
		} else if err == nil {
			return errors.New("work accepted on a stale guest (lost notify)")
		}
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		if l := g.r.Status().Last; l.GenNew != "aa" || l.EpochNew != 2 {
			return fmt.Errorf("record key %s/%d, want aa/2", l.GenNew, l.EpochNew)
		}
		return g.fresh()
	}},
	// only the generation (a clone): the gate's own sysctl read catches it before devd
	{"clone", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.gen.set("cc")
		if err := g.r.Allow(); err == nil {
			return errors.New("work accepted on a clone before its run")
		}
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		if l := g.r.Status().Last; l.GenNew != "cc" || l.EpochNew != 1 {
			return fmt.Errorf("record key %s/%d, want cc/1", l.GenNew, l.EpochNew)
		}
		return g.fresh()
	}},
	// a stale HELLO (epoch 1, from before the restore) after the run: ignored
	{"staleHello", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.gen.set("bb")
		g.host.setEpoch(2)
		g.r.ObserveGen("bb", "devd")
		g.r.ObserveEpoch(2, g.h)
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		g.r.ObserveEpoch(1, g.h)
		return g.quiet(1, 300*time.Millisecond)
	}},
	// exec is refused while the actions run (a slow service), and the order is clock, entropy, services, report
	{"gateAndOrder", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.svc.hang = make(chan struct{})
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		if err := g.waitStarted(); err != nil {
			return err
		}
		err := g.r.Allow()
		close(g.svc.hang)
		if err == nil {
			return errors.New("exec accepted while resuming")
		}
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		if g.r.Allow() != nil {
			return errors.New("exec refused after the run")
		}
		want := []string{"step", "entropy 64", "restart keyd", "report"}
		got := g.ev.list()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			return fmt.Errorf("order %v, want %v", got, want)
		}
		if g.ent.passes != 88 {
			return fmt.Errorf("entropy written %d times, want 88 (minpool 64: 8 x (2 x 6 - 1))", g.ent.passes)
		}
		if e := g.r.Status().Last.Entropy; e.Outcome.Outcome != "done" || e.Writes != 88 || e.GapUs <= e.NeedUs || e.NeedUs != 42000 {
			return fmt.Errorf("entropy %+v, want done, 88 writes, gap > need = 42 ms", e)
		}
		return g.fresh()
	}},
	// an answer to another nonce (an hour off) is dropped; the clock comes from the right one
	{"staleAnswer", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.host.staleFirst = true
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		if l := g.r.Status().Last; l.Stale != 1 {
			return fmt.Errorf("stale answers dropped: %d, want 1", l.Stale)
		}
		return g.fresh()
	}},
	// the generation changes again during a run (a second notify): another run follows at once
	{"changeDuringRun", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		h := make(chan struct{})
		g.svc.mu.Lock()
		g.svc.hang = h
		g.svc.mu.Unlock()
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		if err := g.waitStarted(); err != nil {
			return err
		}
		g.gen.set("dd")
		g.r.ObserveGen("dd", "devd")
		g.svc.mu.Lock()
		g.svc.hang = nil
		g.svc.mu.Unlock()
		close(h)
		return g.waitAfterRelease()
	}},
	// a run whose answer reports an older epoch than one the agent saw before it arrived (an answer from
	// before the restore): the run is keyed by the answer's epoch, and the recheck runs again
	{"answerEpochOlder", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		h := make(chan struct{})
		g.svc.mu.Lock()
		g.svc.hang = h
		g.svc.mu.Unlock()
		g.host.setEpoch(2)
		g.r.ObserveEpoch(2, g.h)
		g.r.ObserveEpoch(3, nil) // seen before the answer, which says 2
		err := g.waitStarted()
		g.host.setEpoch(3)
		close(h)
		if err != nil {
			return err
		}
		if err := g.waitRuns(2, 1500*time.Millisecond); err != nil {
			return fmt.Errorf("no recheck run: %v", err)
		}
		if l := g.r.Status().Last; l.EpochNew != 3 {
			return fmt.Errorf("last key epoch %d, want 3", l.EpochNew)
		}
		return nil
	}},
	// a write to /dev/random fails: entropy notdone, nothing restarted, the gate stays shut; the retry
	// (after HostWait) completes the key
	{"entropyFailRetry", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.ent.mu.Lock()
		g.ent.failAt = 10
		g.ent.mu.Unlock()
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		end := time.Now().Add(1500 * time.Millisecond)
		for g.r.Status().Runs < 1 && time.Now().Before(end) {
			time.Sleep(time.Millisecond)
		}
		st := g.r.Status()
		if st.Runs < 1 {
			return errors.New("no run")
		}
		if e := st.Last.Entropy; e.Outcome.Outcome != "notdone" || e.Writes != 9 {
			return fmt.Errorf("entropy %+v, want notdone after 9 writes", e)
		}
		if g.r.Allow() == nil {
			return errors.New("exec accepted after a run whose entropy step failed")
		}
		if p := g.svc.alivePid("keyd"); p != 101 {
			return fmt.Errorf("keyd restarted (pid %d) although the entropy step failed", p)
		}
		g.ent.mu.Lock()
		g.ent.failAt = 0
		g.ent.mu.Unlock()
		if err := g.waitRuns(2, 1500*time.Millisecond); err != nil {
			return fmt.Errorf("no retry: %v", err)
		}
		if l := g.r.Status().Last; l.GenNew != "bb" || !strings.HasPrefix(l.Trigger, "retry:") {
			return fmt.Errorf("retry run %s trigger %s", l.GenNew, l.Trigger)
		}
		return g.fresh()
	}},
	// the restart hangs: after the timeout the old pid is killed and the outcome is "unknown"
	{"serviceHang", func(t testing.TB, ru rules) error {
		g := newRig(t, ru, nil)
		g.svc.hang = make(chan struct{})
		defer close(g.svc.hang)
		g.gen.set("bb")
		g.r.ObserveGen("bb", "devd")
		if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
			return err
		}
		s := g.r.Status().Last.Services[0]
		if s.Outcome.Outcome != "unknown" || !s.Killed || s.PidOld != 101 {
			return fmt.Errorf("service result %+v, want unknown, killed pid 101", s)
		}
		if g.svc.alivePid("keyd") != 0 {
			return errors.New("the old key-holding process still runs after the timeout")
		}
		return nil
	}},
}

func (g *rig) waitStarted() error {
	select {
	case <-g.svc.started:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("the service restart never started")
	}
}

// waitAfterRelease is changeDuringRun's tail (kept separate for readability).
func (g *rig) waitAfterRelease() error {
	if err := g.waitRuns(2, 1500*time.Millisecond); err != nil {
		return fmt.Errorf("no second run after a change during the first: %v", err)
	}
	if l := g.r.Status().Last; l.GenNew != "dd" || l.Trigger != "recheck" {
		return fmt.Errorf("second run %s trigger %s, want dd/recheck", l.GenNew, l.Trigger)
	}
	return nil
}

func TestDesignScenarios(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			if err := sc.run(t, design); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The Quint model's mutants, planted in the Go code: each must fail at least one scenario.
func TestMutantsCaught(t *testing.T) {
	muts := []struct {
		name string
		f    func(*rules)
	}{
		{"actOnlyOnEpoch", func(r *rules) { r.actOnGen = false }},
		{"actOnlyOnGen", func(r *rules) { r.actOnEpoch = false }},
		{"epochNotMonotonic", func(r *rules) { r.epochMonotonic = false }},
		{"noDedupe", func(r *rules) { r.dedupe = false }},
		{"acceptWhileResuming", func(r *rules) { r.gateWork = false }},
		{"skipEntropy", func(r *rules) { r.addEntropy = false }},
		{"servicesBeforeEntropy", func(r *rules) { r.entropyFirst = false }},
		{"staleReply", func(r *rules) { r.nonceCheck = false }},
		{"clearOnComplete", func(r *rules) { r.recheckAtEnd = false }},
		{"timeoutIgnored", func(r *rules) { r.killOnTimeout = false }},
		{"timeoutCountsDone", func(r *rules) { r.timeoutUnknown = false }},
		{"keyFromSeen", func(r *rules) { r.keyFromAnswer = false }},
		{"entropyDoneEarly", func(r *rules) { r.verifyReseed = false }},
		{"entropyFailOpen", func(r *rules) { r.entropyGate = false }},
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			ru := design
			m.f(&ru)
			var caught []string
			for _, sc := range scenarios {
				if err := sc.run(quietTB{t}, ru); err != nil {
					caught = append(caught, sc.name+": "+err.Error())
				}
			}
			if len(caught) == 0 {
				t.Fatalf("mutant %s survived every scenario", m.name)
			}
			t.Logf("caught by %d scenario(s): %s", len(caught), strings.Join(caught, " | "))
		})
	}
}

// quietTB drops the agent's log lines (mutant runs are noisy) but keeps Cleanup.
type quietTB struct{ *testing.T }

func (quietTB) Logf(string, ...any) {}

// The clock step's error is bounded by RTT/2 of the best sample.
func TestClockBound(t *testing.T) {
	g := newRig(t, design, func(c *Config) { c.Samples = 5 })
	g.host.rtt = 20 * time.Millisecond
	g.host.off = 3 * time.Second
	g.gen.set("bb")
	g.r.ObserveGen("bb", "devd")
	if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	l := g.r.Status().Last
	err := g.clock.offset() - g.host.off
	if err < 0 {
		err = -err
	}
	if l.Clock.Outcome.Outcome != "done" || time.Duration(l.Clock.BoundNs) < 5*time.Millisecond || time.Duration(l.Clock.BoundNs) > 30*time.Millisecond {
		t.Fatalf("clock %+v", l.Clock)
	}
	if err > time.Duration(l.Clock.BoundNs)+2*time.Millisecond {
		t.Fatalf("error %v exceeds the bound %v", err, time.Duration(l.Clock.BoundNs))
	}
	if l.Clock.Samples != 5 || l.Clock.Via != "tcp:test" {
		t.Fatalf("samples %d via %s", l.Clock.Samples, l.Clock.Via)
	}
}

// A dead host (the old connection) is skipped for a live one; a host that sends too few bytes makes the
// entropy step notdone (and is recorded, not hidden).
func TestHostFailoverAndShortEntropy(t *testing.T) {
	g := newRig(t, design, nil)
	dead := shifted{&fakeHost{name: "tcp:dead", fail: true, ev: g.ev}, g.clock}
	g.r.Offer(dead) // newest: tried first
	g.gen.set("bb")
	g.r.ObserveGen("bb", "devd")
	if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if l := g.r.Status().Last; l.Clock.Via != "tcp:test" || l.HostTries != 2 {
		t.Fatalf("via %s tries %d", l.Clock.Via, l.HostTries)
	}
	g.r.Remove(dead)
	g.host.mu.Lock()
	g.host.nbytes = 16
	g.host.mu.Unlock()
	g.gen.set("cc")
	g.r.ObserveGen("cc", "devd")
	end := time.Now().Add(1500 * time.Millisecond)
	for g.r.Status().Runs < 2 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	st := g.r.Status()
	if e := st.Last.Entropy; st.Runs != 2 || e.Outcome.Outcome != "notdone" || e.Bytes != 16 || st.Phase != Resuming {
		t.Fatalf("runs %d phase %s entropy %+v, want notdone and still resuming", st.Runs, st.Phase, e)
	}
	g.host.mu.Lock()
	g.host.nbytes = 64
	g.host.mu.Unlock()
	if err := g.waitRuns(3, 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if l := g.r.Status().Last; l.GenNew != "cc" || l.Entropy.Outcome.Outcome != "done" {
		t.Fatalf("retry %+v", l)
	}
}

func TestReseedPlan(t *testing.T) {
	for _, c := range []struct {
		pool, hz, passes int
		gap              time.Duration
	}{{64, 100, 88, 120 * time.Millisecond}, {64, 1000, 88, 102 * time.Millisecond}, {16, 100, 24, 120 * time.Millisecond},
		{256, 100, 344, 120 * time.Millisecond}, {12, 100, 8, 120 * time.Millisecond}} {
		p, g := ReseedPlan(EntropyParams{MinPoolSize: c.pool, Tick: time.Second / time.Duration(c.hz)}, 100*time.Millisecond)
		if p != c.passes || g != c.gap {
			t.Errorf("minpool %d hz %d: %d writes, gap %v; want %d, %v", c.pool, c.hz, p, g, c.passes, c.gap)
		}
	}
}

// ReseedPlan's argument, checked over every interleaving it covers: the counter's phase, what pool 0
// already holds, and up to two reseeds by other readers at any event of the writes (each happens only if
// pool 0 is full enough), plus one possibly after the writes. Then the verifying read, which by the
// gap sees the time rule satisfied. At least T host events must have been consumed; with 8(2T-1)-8
// writes (one pool-0 event less) some interleaving must leave fewer (the bound is tight).
func TestReseedPlanCoversInterleavings(t *testing.T) {
	for _, minPool := range []int{16, 64, 100} {
		need := (minPool + eventAcct - 1) / eventAcct
		passes, _ := ReseedPlan(EntropyParams{MinPoolSize: minPool, Tick: time.Millisecond}, 0)
		worst := func(passes int) int {
			nev := passes * eventsPerWrite
			w := 1 << 30
			for phase := 0; phase < fortunaPools; phase++ {
				// a reseed only matters by how many pool-0 events precede it: try it just before each one,
				// before all (-1) and after all (nev)
				at := []int{-1, nev}
				for i := 0; i < nev; i++ {
					if (phase+i)%fortunaPools == 0 {
						at = append(at, i)
					}
				}
				for _, pre := range []int{0, 24, minPool - 1, minPool, 400} {
					for _, r1 := range at {
						for _, r2 := range at {
							pool, host, consumed := pre, 0, 0
							reseed := func() {
								if pool >= minPool {
									consumed += host
									pool, host = 0, 0
								}
							}
							for i := 0; i < nev; i++ {
								if i == r1 || (i == r2 && r2 != r1) {
									reseed()
								}
								if (phase+i)%fortunaPools == 0 {
									pool += eventAcct
									host++
								}
							}
							if r1 == nev || r2 == nev {
								reseed() // another reader between the writes and the verifying read
							}
							reseed() // the verifying read
							w = min(w, consumed)
						}
					}
				}
			}
			return w
		}
		if got := worst(passes); got < need {
			t.Errorf("minpool %d: %d writes leave %d host events consumed in the worst case, want >= %d", minPool, passes, got, need)
		}
		if got := worst(passes - fortunaPools/eventsPerWrite); got >= need {
			t.Errorf("minpool %d: %d writes already guarantee %d: the plan is not tight", minPool, passes-8, got)
		}
	}
}

// No host at all: the agent stays Resuming (pings say so) and runs as soon as one connects.
func TestWaitsForHost(t *testing.T) {
	g := newRig(t, design, nil)
	g.r.Remove(g.h)
	g.gen.set("bb")
	g.r.ObserveGen("bb", "devd")
	time.Sleep(200 * time.Millisecond)
	if st := g.r.Status(); st.Phase != Resuming || st.Runs != 0 {
		t.Fatalf("status %+v without a host", st)
	}
	g.r.ObserveEpoch(1, g.h)
	if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

// Many goroutines signalling at once (every stream reconnecting after a restore): one run.
func TestConcurrentSignalsOneRun(t *testing.T) {
	g := newRig(t, design, nil)
	g.gen.set("bb")
	g.host.setEpoch(2)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				switch (i + j) % 3 {
				case 0:
					g.r.ObserveGen("bb", "devd")
				case 1:
					g.r.ObserveEpoch(2, g.h)
				default:
					g.r.Allow()
					g.r.Status()
				}
			}
		}(i)
	}
	wg.Wait()
	if err := g.waitRuns(1, 1500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := g.quiet(1, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
