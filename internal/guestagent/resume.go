// Package guestagent holds the in-guest agent's resume duties: what a guest restored from a snapshot must
// do before it is safe to use, and the gate that keeps privileged host work out until it has.
//
// The design is the Quint model spec/guestresume/guestresume.qnt; docs/guest-resume.md has the mapping
// from model actions to the methods below and the reasoning. In short:
//
//   - Two signals say "restored": a new VM generation (vmgenc(4): devd "VMGenerationCounter", or the 1 s
//     poll / SIGUSR1 of sysctl dev.vmgenc.0.guid, the kernel's CACHED copy) and a newer host resume epoch
//     (every HELLO carries it). Either one starts a run; a signal equal to the last run's key is a no-op;
//     an epoch lower than the done one is stale (a HELLO from before the snapshot) and ignored.
//   - A run: read the generation (sysctl), read 8 bytes of /dev/random (kr_pre), ask a live host for its
//     time, epoch and >= 64 fresh random bytes (nonce = generation + sequence; any other answer is
//     dropped), then (a) step the clock by the NTP offset (error <= RTT/2), (b) write the host bytes to
//     /dev/random (ReseedPlan: enough writes that a reseed must consume them) and read kr_post only once
//     the kernel's reseed rule provably holds, so that read reseeds Fortuna if nothing else did (outcome
//     "done" only then), (c) restart the configured services (`service X restart`, timeout; on timeout
//     the old pid is killed and the outcome is "unknown"), (d) send the record to the host(s). A run
//     whose entropy step is not "done" restarts nothing, completes no key and is retried after HostWait.
//   - The run's key is (generation read at its start, epoch from the host's answer). At the end the agent
//     re-reads the generation and compares the epochs seen meanwhile; anything not covered starts another
//     run at once. Until a run ends with nothing left, Allow() refuses privileged work.
package guestagent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Phase is the agent's resume state.
type Phase string

const (
	Ready    Phase = "ready"
	Resuming Phase = "resuming"
)

// ErrResuming is returned by Allow while the resume actions have not finished.
var ErrResuming = errors.New("resuming: resume actions not finished")

// Gen is the VM generation ID: hex of the 16-byte dev.vmgenc.0.guid, "" when the guest has no vmgenc(4).
type Gen string

// Request is the agent's ask for host inputs; (Gen, Seq) is the nonce the answer must echo.
type Request struct {
	Gen Gen    `json:"gen"`
	Seq uint64 `json:"seq"`
}

// Answer is the host's reply: its wall clock when the request arrived and when it answered, its current
// resume epoch, and fresh random bytes.
type Answer struct {
	Gen      Gen    `json:"gen"`
	Seq      uint64 `json:"seq"`
	Epoch    uint64 `json:"epoch"`
	HostRxNs int64  `json:"host_rx_ns"`
	HostTxNs int64  `json:"host_tx_ns"`
	Entropy  []byte `json:"entropy"`
}

// Sample is one exchange as the agent saw it: guest wall-clock send and receive times (before any step).
type Sample struct {
	Ans        Answer
	Sent, Recv time.Time
}

// offset and error bound of one sample (NTP): theta = ((T1 - t0) + (T2 - t3)) / 2,
// delta = (t3 - t0) - (T2 - T1), bound = delta / 2.
func (s Sample) offset() (theta, bound time.Duration) {
	t0, t3 := s.Sent.UnixNano(), s.Recv.UnixNano()
	theta = time.Duration(((s.Ans.HostRxNs - t0) + (s.Ans.HostTxNs - t3)) / 2)
	delta := s.Recv.Sub(s.Sent) - time.Duration(s.Ans.HostTxNs-s.Ans.HostRxNs)
	if delta < 0 {
		delta = 0
	}
	return theta, delta / 2
}

// Host is a live connection to the host side that can answer a resume request and take a record.
type Host interface {
	// Exchange sends req and returns the first answer frame that arrives (it may be a stale one: the
	// caller checks the nonce), or an error when ctx ends first.
	Exchange(ctx context.Context, req Request) (Sample, error)
	// Send delivers a resume record (best effort).
	Send(rec Record) error
	// Name for the record; Rank orders candidates (lower first: TCP before the UART).
	Name() string
	Rank() int
}

// Clock reads and steps the guest's wall clock.
type Clock interface {
	Now() time.Time
	Step(d time.Duration) error
}

// GenReader reads the generation (the sysctl).
type GenReader interface{ ReadGen() (Gen, error) }

// Entropy adds host bytes to the kernel RNG and reads 8 bytes of it (kr).
type Entropy interface {
	// Params reads the inputs of the kernel's reseed rule.
	Params() (EntropyParams, error)
	// Add writes b `passes` times (one write(2) each) and returns how many writes completed.
	Add(b []byte, passes int) (int, error)
	Read8() (string, error)
}

// EntropyParams are the inputs of FreeBSD Fortuna's reseed rule (sys/dev/random/fortuna.c
// random_fortuna_pre_read): a read reseeds iff pool 0 holds >= MinPoolSize bytes of accounting and more
// than 100 ms of getsbinuptime() passed since the last reseed. getsbinuptime() is tick-granular.
type EntropyParams struct {
	MinPoolSize int           // sysctl kern.random.fortuna.minpoolsize (64)
	Tick        time.Duration // 1/kern.hz (a FreeBSD VM guest: hz 100, 10 ms)
}

// The FreeBSD 15 write path (sys/dev/random/randomdev.c randomdev_accumulate): each write(2) of <= one
// page is hashed with two cycle counts into 32 bytes, fed SYNCHRONOUSLY (no harvest queue) to Fortuna as
// 4 events of 8 bytes with destinations from one static counter (one per event, pool = counter % 32);
// each event adds 4 + 8 = 12 bytes to its pool's accounting.
const (
	fortunaPools   = 32
	eventsPerWrite = 4
	eventAcct      = 12
	maxPasses      = 4096
)

// ReseedPlan returns how many writes of the host bytes to make and how long after the last one returns
// the verifying read must start.
//
// Writes: a reseed needs T = ceil(minpool/12) host events in pool 0, and 8 consecutive writes put exactly
// one event in pool 0, so 8(2T-1) writes put exactly E = 2T-1 there. Whatever other readers do meanwhile,
// at least T of them are consumed by a reseed before the verifying read returns: let L be the last
// reseed before the writes end and k the host pool-0 events after it. Every event before L was consumed
// by the first reseed after it (<= L). If k >= T, pool 0 has >= minpool bytes, so a reseed after the
// writes consumes the k (another reader's, or the verifying read's: see the gap); otherwise E-k >= T were
// consumed by L at the latest. Assumes no other writer of /dev/random interleaves (only rc.d/random
// writes it, at boot and shutdown).
//
// Gap: the read's pre_read compares two getsbinuptime() values, each up to one tick stale; L happened
// before the last write returned, so a read that starts more than interval + 2 ticks after it sees
// "more than 100 ms" since L and reseeds when pool 0 is full enough.
func ReseedPlan(p EntropyParams, interval time.Duration) (passes int, gap time.Duration) {
	t := (p.MinPoolSize + eventAcct - 1) / eventAcct
	if t < 1 {
		t = 1
	}
	return (fortunaPools / eventsPerWrite) * (2*t - 1), interval + 2*p.Tick
}

// Services restarts rc.d services.
type Services interface {
	Pid(ctx context.Context, name string) (int, error)
	Restart(ctx context.Context, name string) error
	Kill(pid int) error
}

// Config holds the knobs; zero values take the defaults below.
type Config struct {
	Services        []string      // key-holding services to restart (default none)
	Settle          time.Duration // epoch first, generation unchanged: wait this long for the notify (1 s)
	ExchangeTimeout time.Duration // per host try (1 s)
	Samples         int           // NTP samples per run, the lowest-RTT one wins (4)
	HostWait        time.Duration // no host answered: wait this long for a new one before retrying (1 s)
	ClockTimeout    time.Duration // (2 s)
	EntropyTimeout  time.Duration // the writes (2 s)
	ServiceTimeout  time.Duration // per service (30 s)
	ReseedInterval  time.Duration // Fortuna's minimum time between reseeds (fortuna.c: SBT_1S/10 = 100 ms)
	MinEntropy      int           // the host must send at least this many bytes (64)
	StepMin         time.Duration // offsets below this are not stepped (1 ms)
	ReportTimeout   time.Duration // per host (2 s)
	// SelfRekey re-derives the agent's own key material after the entropy step (none in sr3j-chan).
	SelfRekey func() error
}

func (c *Config) defaults() {
	d := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	d(&c.Settle, time.Second)
	d(&c.ExchangeTimeout, time.Second)
	d(&c.HostWait, time.Second)
	d(&c.ClockTimeout, 2*time.Second)
	d(&c.EntropyTimeout, 2*time.Second)
	d(&c.ServiceTimeout, 30*time.Second)
	d(&c.ReseedInterval, 100*time.Millisecond)
	d(&c.StepMin, time.Millisecond)
	d(&c.ReportTimeout, 2*time.Second)
	if c.Samples <= 0 {
		c.Samples = 4
	}
	if c.MinEntropy <= 0 {
		c.MinEntropy = 64
	}
}

// rules mirror the Quint model's consts. All true is the design; tests flip one at a time (mutants).
type rules struct {
	actOnGen, actOnEpoch, epochMonotonic, dedupe, gateWork, addEntropy, entropyFirst, nonceCheck,
	recheckAtEnd, killOnTimeout, timeoutUnknown, keyFromAnswer, verifyReseed, entropyGate bool
}

var design = rules{true, true, true, true, true, true, true, true, true, true, true, true, true, true}

// Outcome of one action: "done", "notdone" (it did not happen), "unknown" (timed out: it may have), "skip".
type Outcome struct {
	Outcome string `json:"outcome"`
	Err     string `json:"err,omitempty"`
	Ms      int64  `json:"ms"`
}

type ClockResult struct {
	Outcome
	StepNs   int64  `json:"step_ns"` // applied step (0 if none)
	OffsetNs int64  `json:"offset_ns"`
	BoundNs  int64  `json:"bound_ns"` // |error| <= this after the step (RTT/2 of the best sample)
	RttNs    int64  `json:"rtt_ns"`
	Samples  int    `json:"samples"`
	Via      string `json:"via"`
}

// EntropyResult: "done" only when every planned write completed and the read started more than NeedUs
// after the last one returned (ReseedPlan); "notdone" (too few host bytes, no reseed rule, a write
// failed), "unknown" (the writes timed out and may still land, or the verifying read failed).
type EntropyResult struct {
	Outcome
	Bytes   int   `json:"bytes"`
	Passes  int   `json:"passes"`   // planned writes (ReseedPlan)
	Writes  int   `json:"writes"`   // completed writes
	MinPool int   `json:"min_pool"` // kern.random.fortuna.minpoolsize
	TickUs  int64 `json:"tick_us"`  // 1/kern.hz
	NeedUs  int64 `json:"need_us"`  // required gap: last write -> verifying read
	GapUs   int64 `json:"gap_us"`   // measured gap (monotonic clock)
}

type ServiceResult struct {
	Outcome
	Name   string `json:"name"`
	PidOld int    `json:"pid_old"`
	PidNew int    `json:"pid_new"`
	Killed bool   `json:"killed,omitempty"` // timed out: the old pid was killed
}

// Record is what a run did; the host logs it (keyed by n, gen_new, epoch_new).
type Record struct {
	N         uint64          `json:"n"` // runs since the agent started
	GenOld    Gen             `json:"gen_old"`
	GenNew    Gen             `json:"gen_new"`
	EpochOld  uint64          `json:"epoch_old"`
	EpochNew  uint64          `json:"epoch_new"`
	Trigger   string          `json:"trigger"` // what started it: "gen:devd", "gen:poll", "epoch", "recheck", ...
	KrPre     string          `json:"kr_pre"`  // first /dev/random read of the run (before the host bytes)
	KrPost    string          `json:"kr_post"` // the verifying read (after the host bytes and the gap)
	Clock     ClockResult     `json:"clock"`
	Entropy   EntropyResult   `json:"entropy"`
	Services  []ServiceResult `json:"services"`
	SelfRekey string          `json:"self_rekey"`
	Stale     int             `json:"stale_answers"` // answers dropped: wrong nonce
	HostTries int             `json:"host_tries"`
	StartNs   int64           `json:"start_ns"` // guest clock, before the step
	EndNs     int64           `json:"end_ns"`
	Reported  int             `json:"reported"` // hosts the record was sent to (set after the sends)
}

// Status is what a ping (WELCOME) reports.
type Status struct {
	Phase Phase   `json:"phase"`
	Runs  uint64  `json:"runs"`
	Last  *Record `json:"last,omitempty"`
}

// Deps are the outside world.
type Deps struct {
	Clock    Clock
	Gen      GenReader
	Entropy  Entropy
	Services Services
	// Log receives one line per notable event (optional).
	Log func(format string, args ...any)
}

type hostEntry struct {
	h   Host
	seq uint64 // offer order
}

// Resumer is the agent's resume state machine. Observe* and Allow are called from the connection and
// watcher goroutines; Run executes the runs.
type Resumer struct {
	cfg  Config
	deps Deps
	r    rules

	mu                   sync.Mutex
	phase                Phase
	running              bool // a run is between its start and its report
	doneGen, seenGen     Gen
	doneEpoch, seenEpoch uint64
	adopted              bool // the first epoch after start was taken as the boot epoch
	trigger              string
	settleUntil          time.Time
	retryAt              time.Time // a run whose entropy step was not done: the next one not before this
	hosts                []hostEntry
	hostSeq              uint64
	nextSeq              uint64
	runs                 uint64
	last                 *Record
	wake                 chan struct{}
}

// New returns a Resumer in phase Ready, with the generation read now as the boot generation.
func New(cfg Config, deps Deps) *Resumer {
	return newWithRules(cfg, deps, design)
}

func newWithRules(cfg Config, deps Deps, r rules) *Resumer {
	cfg.defaults()
	if deps.Log == nil {
		deps.Log = func(string, ...any) {}
	}
	g, _ := deps.Gen.ReadGen()
	return &Resumer{cfg: cfg, deps: deps, r: r, phase: Ready, doneGen: g, seenGen: g, nextSeq: 1, wake: make(chan struct{}, 1)}
}

func (r *Resumer) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// triggerLocked: a change starts a run (or, a run active, leaves the phase Resuming for the recheck).
func (r *Resumer) triggerLocked(why string, settle bool) {
	if r.phase == Ready && !r.running {
		r.trigger = why
		r.settleUntil = time.Time{}
		if settle {
			r.settleUntil = r.deps.Clock.Now().Add(r.cfg.Settle)
		}
	}
	r.phase = Resuming
	r.poke()
}

// ObserveGen: a generation read after a devd event, a poll, SIGUSR1 or in Allow (model: onGen).
func (r *Resumer) ObserveGen(g Gen, src string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observeGenLocked(g, src)
}

func (r *Resumer) observeGenLocked(g Gen, src string) {
	if !r.r.actOnGen {
		return
	}
	r.seenGen = g
	if g != r.doneGen || !r.r.dedupe {
		if g != r.doneGen && r.phase == Ready {
			r.deps.Log("resume: generation %s -> %s (%s)", short(r.doneGen), short(g), src)
		}
		r.triggerLocked("gen:"+src, false)
	} else if r.running {
		r.poke() // a settle wait may end early
	}
}

// ObserveEpoch: a HELLO's epoch; h (may be nil) is the connection it came on (model: onEpoch).
func (r *Resumer) ObserveEpoch(e uint64, h Host) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h != nil {
		r.offerLocked(h)
	}
	r.observeEpochLocked(e)
}

func (r *Resumer) observeEpochLocked(e uint64) {
	if !r.r.actOnEpoch || e == 0 {
		return
	}
	if !r.adopted {
		// the first epoch after the agent started is the boot epoch (a fresh process holds no state
		// from before a snapshot), unless a run is already pending
		r.adopted = true
		if r.phase == Ready && r.doneEpoch == 0 {
			r.doneEpoch, r.seenEpoch = e, e
			return
		}
	}
	newer := e > r.doneEpoch
	if !r.r.epochMonotonic {
		newer = e != r.doneEpoch
		r.seenEpoch = e
	} else if e > r.seenEpoch {
		r.seenEpoch = e
	}
	if newer || !r.r.dedupe {
		if newer && r.phase == Ready {
			r.deps.Log("resume: epoch %d -> %d", r.doneEpoch, e)
		}
		r.triggerLocked("epoch", r.seenGen == r.doneGen)
	}
}

// Offer registers a live host connection (each accepted HELLO); Remove drops it (connection closed).
func (r *Resumer) Offer(h Host) {
	r.mu.Lock()
	r.offerLocked(h)
	r.mu.Unlock()
}

func (r *Resumer) offerLocked(h Host) {
	for i := range r.hosts {
		if r.hosts[i].h == h {
			r.hostSeq++
			r.hosts[i].seq = r.hostSeq
			r.poke()
			return
		}
	}
	r.hostSeq++
	r.hosts = append(r.hosts, hostEntry{h, r.hostSeq})
	r.poke()
}

func (r *Resumer) Remove(h Host) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.hosts {
		if r.hosts[i].h == h {
			r.hosts = append(r.hosts[:i], r.hosts[i+1:]...)
			return
		}
	}
}

// candidates: lower Rank first (TCP before the UART), then the most recently offered.
func (r *Resumer) candidates() []Host {
	r.mu.Lock()
	hs := append([]hostEntry(nil), r.hosts...)
	r.mu.Unlock()
	sort.SliceStable(hs, func(i, j int) bool {
		if a, b := hs[i].h.Rank(), hs[j].h.Rank(); a != b {
			return a < b
		}
		return hs[i].seq > hs[j].seq
	})
	out := make([]Host, len(hs))
	for i := range hs {
		out[i] = hs[i].h
	}
	return out
}

// Allow is the privileged-work gate: it reads the generation first (a restore whose devd event has not
// arrived yet is caught here), then refuses unless Ready (model: Work).
func (r *Resumer) Allow() error {
	g, err := r.deps.Gen.ReadGen()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.observeGenLocked(g, "allow")
	}
	if r.r.gateWork && r.phase != Ready {
		return ErrResuming
	}
	return nil
}

// AllowEpoch is Allow for work that arrives with a HELLO epoch (the epoch is observed first).
func (r *Resumer) AllowEpoch(e uint64) error {
	r.mu.Lock()
	r.observeEpochLocked(e)
	r.mu.Unlock()
	return r.Allow()
}

// Status for pings.
func (r *Resumer) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{Phase: r.phase, Runs: r.runs, Last: r.last}
}

// Run executes runs until ctx ends.
func (r *Resumer) Run(ctx context.Context) {
	for {
		r.mu.Lock()
		pending, retry := r.phase == Resuming, time.Until(r.retryAt)
		r.mu.Unlock()
		if !pending {
			select {
			case <-ctx.Done():
				return
			case <-r.wake:
				continue
			}
		}
		if retry > 0 {
			t := time.NewTimer(retry)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		if _, err := r.runOnce(ctx); err != nil {
			return
		}
	}
}

func short(g Gen) string {
	if g == "" {
		return "none"
	}
	if len(g) > 8 {
		return string(g[:8])
	}
	return string(g)
}

func ms(t0 time.Time) int64 { return time.Since(t0).Milliseconds() }

// within runs f with a timeout; a late f is left running (its effect may land later: "unknown").
func within(ctx context.Context, d time.Duration, f func(ctx context.Context) error) (string, error) {
	c, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f(c) }()
	select {
	case err := <-done:
		if err != nil {
			return "notdone", err
		}
		return "done", nil
	case <-c.Done():
		return "unknown", fmt.Errorf("timeout after %v", d)
	}
}

// runOnce is one run (model: RunStart, RunAnswer, SvcDone/SvcTimeout, RunReport). It returns the record,
// or an error only when ctx ends.
func (r *Resumer) runOnce(ctx context.Context) (*Record, error) {
	// --- settle (model: SSettle -> RunStart): an epoch-triggered run waits for the generation signal
	for {
		r.mu.Lock()
		until, changed := r.settleUntil, r.seenGen != r.doneGen
		r.mu.Unlock()
		if g, err := r.deps.Gen.ReadGen(); err == nil {
			r.ObserveGen(g, "settle")
			changed = changed || g != r.doneGenLocked()
		}
		left := until.Sub(r.deps.Clock.Now())
		if changed || until.IsZero() || left <= 0 {
			break
		}
		t := time.NewTimer(min(left, 50*time.Millisecond))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-r.wake:
		case <-t.C:
		}
		t.Stop()
	}
	// --- RunStart: read the generation, the first RNG read, pick the nonce
	r.mu.Lock()
	r.running = true
	gen := r.seenGen
	r.mu.Unlock()
	if r.r.actOnGen {
		if g, err := r.deps.Gen.ReadGen(); err == nil {
			gen = g
			r.mu.Lock()
			r.seenGen = g
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	rec := &Record{GenOld: r.doneGen, GenNew: gen, EpochOld: r.doneEpoch, Trigger: r.trigger, StartNs: r.deps.Clock.Now().UnixNano()}
	r.mu.Unlock()
	if kr, err := r.deps.Entropy.Read8(); err == nil {
		rec.KrPre = kr
	}
	// --- the exchange: best of cfg.Samples answers from one host, nonce-checked
	best, via, err := r.exchange(ctx, gen, rec)
	if err != nil {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		return nil, err
	}
	ans := best.Ans
	rec.EpochNew = ans.Epoch
	if !r.r.keyFromAnswer {
		r.mu.Lock()
		rec.EpochNew = max(r.seenEpoch, ans.Epoch)
		r.mu.Unlock()
	}
	r.mu.Lock()
	if ans.Epoch > r.seenEpoch {
		r.seenEpoch = ans.Epoch
	}
	r.mu.Unlock()
	// (c) first when the order is wrong (mutant servicesBeforeEntropy)
	if !r.r.entropyFirst {
		rec.Services = r.restartAll(ctx)
	}
	// --- (a) clock
	theta, bound := best.offset()
	rec.Clock.OffsetNs, rec.Clock.BoundNs, rec.Clock.RttNs, rec.Clock.Via = int64(theta), int64(bound), int64(best.Recv.Sub(best.Sent)), via
	t0 := time.Now()
	if theta < r.cfg.StepMin && theta > -r.cfg.StepMin {
		rec.Clock.Outcome.Outcome = "skip"
	} else {
		o, err := within(ctx, r.cfg.ClockTimeout, func(context.Context) error { return r.deps.Clock.Step(theta) })
		rec.Clock.Outcome.Outcome = o
		if err != nil {
			rec.Clock.Err = err.Error()
		}
		if o == "done" {
			rec.Clock.StepNs = int64(theta)
		}
	}
	rec.Clock.Ms = ms(t0)
	// --- (b) entropy (model: RunAnswer writes, EntVerify reads)
	t0 = time.Now()
	if err := r.entropy(ctx, ans.Entropy, rec); err != nil {
		return nil, err
	}
	if rec.KrPost == "" {
		if kr, err := r.deps.Entropy.Read8(); err == nil {
			rec.KrPost = kr
		}
	}
	rec.Entropy.Ms = ms(t0)
	eo := rec.Entropy.Outcome.Outcome
	entOK := eo == "done" || eo == "skip" || !r.r.entropyGate
	rec.SelfRekey = "none"
	if r.cfg.SelfRekey != nil {
		if !entOK {
			rec.SelfRekey = "skip: entropy " + eo
		} else if err := r.cfg.SelfRekey(); err != nil {
			rec.SelfRekey = "notdone: " + err.Error()
		} else {
			rec.SelfRekey = "done"
		}
	}
	// --- (c) services: only once the generator provably holds the host bytes (a restart before that
	// seeds the new process from the snapshot's RNG state)
	if r.r.entropyFirst {
		if entOK {
			rec.Services = r.restartAll(ctx)
		} else {
			for _, name := range r.cfg.Services {
				rec.Services = append(rec.Services, ServiceResult{Name: name, Outcome: Outcome{Outcome: "skip", Err: "entropy " + eo}})
			}
		}
	}
	// --- (d) report, done key, recheck (model: RunReport); an incomplete run keys nothing
	rec.EndNs = r.deps.Clock.Now().UnixNano()
	r.mu.Lock()
	r.runs++
	rec.N = r.runs
	if !entOK {
		// the key stays undone: the gate stays shut and the run is retried
	} else if r.r.recheckAtEnd {
		r.doneGen, r.doneEpoch = gen, rec.EpochNew
	} else {
		r.doneGen, r.doneEpoch = r.seenGen, max(r.seenEpoch, rec.EpochNew)
	}
	r.mu.Unlock()
	rec.Reported = r.report(ctx, *rec)
	again := false
	g2, gerr := r.deps.Gen.ReadGen()
	r.mu.Lock()
	if r.r.recheckAtEnd {
		again = (gerr == nil && g2 != gen && r.r.actOnGen) || r.seenGen != gen || r.seenEpoch > rec.EpochNew
	}
	r.running = false
	r.last = rec // complete (Reported set): never mutated after this
	if !entOK {
		r.phase, r.trigger, r.settleUntil = Resuming, "retry:entropy-"+eo, time.Time{}
		r.retryAt = time.Now().Add(r.cfg.HostWait)
	} else if again {
		r.phase, r.trigger, r.settleUntil = Resuming, "recheck", time.Time{}
	} else {
		r.phase = Ready
	}
	r.mu.Unlock()
	r.deps.Log("resume: run %d done: gen %s epoch %d, clock %s %+.3f ms (bound %.3f ms), entropy %s, %d services, again=%v",
		rec.N, short(gen), rec.EpochNew, rec.Clock.Outcome.Outcome, float64(rec.Clock.StepNs)/1e6, float64(rec.Clock.BoundNs)/1e6,
		rec.Entropy.Outcome.Outcome, len(rec.Services), again)
	return rec, nil
}

// entropy is step (b): write the host bytes per ReseedPlan, wait for the gap, then the verifying read
// (kr_post). Its error is only ctx's.
func (r *Resumer) entropy(ctx context.Context, b []byte, rec *Record) error {
	e := &rec.Entropy
	e.Bytes = len(b)
	set := func(o, msg string) { e.Outcome.Outcome, e.Err = o, msg }
	if !r.r.addEntropy {
		set("skip", "")
		return nil
	}
	if len(b) < r.cfg.MinEntropy {
		set("notdone", fmt.Sprintf("host sent %d bytes, need %d", len(b), r.cfg.MinEntropy))
		return nil
	}
	p, err := r.deps.Entropy.Params()
	if err != nil {
		set("notdone", "reseed rule: "+err.Error())
		return nil
	}
	passes, need := ReseedPlan(p, r.cfg.ReseedInterval)
	e.Passes, e.MinPool, e.TickUs, e.NeedUs = passes, p.MinPoolSize, p.Tick.Microseconds(), need.Microseconds()
	if passes > maxPasses {
		set("notdone", fmt.Sprintf("minpoolsize %d needs %d writes (> %d)", p.MinPoolSize, passes, maxPasses))
		return nil
	}
	var nw atomic.Int64
	o, err := within(ctx, r.cfg.EntropyTimeout, func(context.Context) error {
		n, err := r.deps.Entropy.Add(b, passes)
		nw.Store(int64(n))
		if err == nil && n < passes {
			err = fmt.Errorf("%d of %d writes", n, passes)
		}
		return err
	})
	last := time.Now() // monotonic: the same uptime clock Fortuna's getsbinuptime() reads
	e.Writes = int(nw.Load())
	if o != "done" {
		set(o, err.Error()) // notdone: a write failed; unknown: they timed out and may still land
		return nil
	}
	if r.r.verifyReseed {
		for {
			left := need - time.Since(last)
			if left < 0 {
				break
			}
			t := time.NewTimer(left + time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	start := time.Now()
	kr, err := r.deps.Entropy.Read8()
	gap := start.Sub(last)
	e.GapUs = gap.Microseconds()
	switch {
	case err != nil:
		set("unknown", "verifying read: "+err.Error()) // its pre_read may or may not have reseeded
	case r.r.verifyReseed && gap <= need:
		set("unknown", fmt.Sprintf("read %v after the writes, need > %v", gap, need))
	default:
		rec.KrPost = kr
		set("done", "")
	}
	return nil
}

func (r *Resumer) doneGenLocked() Gen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.doneGen
}

// exchange gets cfg.Samples answers from the best host that answers, waiting for a new host when none
// does. Every sample uses a fresh nonce; answers with another nonce are counted and dropped.
func (r *Resumer) exchange(ctx context.Context, gen Gen, rec *Record) (Sample, string, error) {
	for {
		for _, h := range r.candidates() {
			rec.HostTries++
			var best *Sample
			got := 0
			deadline := time.Now().Add(r.cfg.ExchangeTimeout * time.Duration(r.cfg.Samples))
			for got < r.cfg.Samples && time.Now().Before(deadline) {
				r.mu.Lock()
				req := Request{Gen: gen, Seq: r.nextSeq}
				r.nextSeq++
				r.mu.Unlock()
				c, cancel := context.WithTimeout(ctx, r.cfg.ExchangeTimeout)
				s, err := h.Exchange(c, req)
				cancel()
				if ctx.Err() != nil {
					return Sample{}, "", ctx.Err()
				}
				if err != nil {
					break // this host does not answer: next one
				}
				if r.r.nonceCheck && (s.Ans.Gen != req.Gen || s.Ans.Seq != req.Seq) {
					rec.Stale++
					continue
				}
				got++
				if best == nil || s.Recv.Sub(s.Sent) < best.Recv.Sub(best.Sent) {
					sc := s
					best = &sc
				}
			}
			if best != nil {
				rec.Clock.Samples = got
				return *best, h.Name(), nil
			}
		}
		t := time.NewTimer(r.cfg.HostWait)
		select {
		case <-ctx.Done():
			t.Stop()
			return Sample{}, "", ctx.Err()
		case <-r.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func (r *Resumer) restartAll(ctx context.Context) []ServiceResult {
	out := []ServiceResult{}
	for _, name := range r.cfg.Services {
		t0 := time.Now()
		sr := ServiceResult{Name: name}
		if p, err := r.deps.Services.Pid(ctx, name); err == nil {
			sr.PidOld = p
		}
		o, err := within(ctx, r.cfg.ServiceTimeout, func(c context.Context) error { return r.deps.Services.Restart(c, name) })
		if err != nil {
			sr.Err = err.Error()
		}
		if o == "unknown" {
			if r.r.killOnTimeout && sr.PidOld > 0 {
				if r.deps.Services.Kill(sr.PidOld) == nil {
					sr.Killed = true
				}
			}
			if !r.r.timeoutUnknown {
				o = "done"
			}
		}
		pc, cancel := context.WithTimeout(ctx, 5*time.Second)
		if p, err := r.deps.Services.Pid(pc, name); err == nil {
			sr.PidNew = p
		}
		cancel()
		// "done" only if the answer said so AND a new process runs; a clean exit with the same pid is notdone
		if o == "done" && r.r.timeoutUnknown && (sr.PidNew == 0 || sr.PidNew == sr.PidOld) {
			o = "notdone"
			if sr.Err == "" {
				sr.Err = fmt.Sprintf("restart returned 0 but pid %d -> %d", sr.PidOld, sr.PidNew)
			}
		}
		sr.Outcome.Outcome = o
		sr.Ms = ms(t0)
		out = append(out, sr)
	}
	return out
}

// report sends the record to every live host (each with its own timeout), returns how many took it.
func (r *Resumer) report(ctx context.Context, rec Record) int {
	hs := r.candidates()
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for _, h := range hs {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			if o, _ := within(ctx, r.cfg.ReportTimeout, func(context.Context) error { return h.Send(rec) }); o == "done" {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return n
}
