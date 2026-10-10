package keysvc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"yard/internal/issuer"
	"yard/internal/keyring"
	"yard/internal/sts"
	"yard/internal/wskey"
)

type epochMap struct {
	mu sync.Mutex
	m  map[string]int64
}

func (e *epochMap) Epoch(s string) (int64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[s]
	return v, ok
}
func (e *epochMap) set(s string, v int64) { e.mu.Lock(); e.m[s] = v; e.mu.Unlock() }

type fakeWS struct{ loads atomic.Int64 }

func (w *fakeWS) LoadKey(ctx context.Context, s string) error           { w.loads.Add(1); return nil }
func (w *fakeWS) KeyLoaded(ctx context.Context, s string) (bool, error) { return true, nil }

type env struct {
	t      *testing.T
	clock  atomic.Int64 // ms
	ring   *keyring.Ring
	is     *issuer.Issuer
	halo   *fakeHalo
	st     *Store
	kek    *wskey.KEK
	epochs *epochMap
	ws     *fakeWS
	svc    *Service
	mut    mutants
	dbPath string
	ctx    context.Context
}

const testIss = "https://id.example.org/yard"

func newEnv(t *testing.T, mut mutants) *env {
	return newEnvWithBits(t, mut, 1024)
}

func newEnvWithBits(t *testing.T, mut mutants, bits int) *env {
	t.Helper()
	e := &env{t: t, epochs: &epochMap{m: map[string]int64{}}, ws: &fakeWS{}, mut: mut, ctx: context.Background()}
	e.clock.Store(1_800_000_000_000)
	now := func() time.Time { return time.UnixMilli(e.clock.Load()) }
	ks := keyring.NewMemStore()
	ks.Bits = bits
	dir := t.TempDir()
	ring, err := keyring.Init(ks, filepath.Join(dir, "k.json"), 0x81010010, 0x81010011, keyring.Config{}, now)
	if err != nil {
		t.Fatal(err)
	}
	e.ring = ring
	e.is, err = issuer.New(issuer.Config{Issuer: testIss, TrustDomain: "home.arpa", InternalAudiences: []string{HaloAudience},
		RatePerSecond: 1e6, Burst: 1e6}, ring, sts.NewSeqLog(&nopSync{}, 0, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	e.is.SetEpochs(e.epochs)
	e.halo = newFakeHalo(t, func() int64 { return e.clock.Load() / 1000 }, testIss, ring.JWKS)
	kf := filepath.Join(dir, "kek")
	k := make([]byte, 32)
	rand.Read(k)
	if err := os.WriteFile(kf, k, 0o600); err != nil {
		t.Fatal(err)
	}
	if e.kek, err = wskey.KEKFromFile(kf); err != nil {
		t.Fatal(err)
	}
	e.dbPath = filepath.Join(dir, "keys.db")
	e.start()
	return e
}

type nopSync struct{}

func (nopSync) Write(b []byte) (int, error) { return len(b), nil }
func (nopSync) Sync() error                 { return nil }

// start (re)starts the service on the same database: a yard-ctl restart.
func (e *env) start() {
	e.t.Helper()
	if e.st != nil {
		e.st.Close()
	}
	st, err := OpenStore(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	e.st = st
	svc, err := Start(Options{Cfg: ProductionConfig(), Store: st, KEK: e.kek,
		Halo: NewUnixHalo(e.halo.path, os.Getuid(), 2*time.Second),
		Mint: &IssuerMinter{Is: e.is, Caller: issuer.Caller{Name: "yard-ctl"}, User: "yard-ctl", TTL: 300,
			Workload: issuer.WorkloadID{Harness: "yard", Policy: "keysvc", Node: "halo", Sandbox: "yard-ctl", Run: "keysvc"}},
		Epochs: e.epochs, WS: e.ws, Now: func() int64 { return e.clock.Load() }})
	if err != nil {
		e.t.Fatal(err)
	}
	svc.mut = e.mut
	svc.ctl.noBurntGuard = e.mut.noBurntGuard
	e.svc = svc
	e.t.Cleanup(func() { st.Close() })
}

func (e *env) advance(d time.Duration) { e.clock.Add(d.Milliseconds()) }

// commit is the lifecycle's SuspendCommit: the epoch moves on.
func (e *env) commit(s string) { v, _ := e.epochs.Epoch(s); e.epochs.set(s, v+1) }

// cycle: suspend (seal + spill) checkpoint ckpt of s on entry, commit, resume.
func (e *env) cycle(s string, ckpt int64, entry uint64) error {
	if _, err := e.svc.Seal(e.ctx, s, ckpt, entry); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	e.commit(s)
	if err := e.svc.Open(e.ctx, s, ckpt); err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return nil
}

// keyBytes unwraps a key (test inspection only).
func (e *env) keyBytes(id int64) []byte {
	k, err := e.svc.key(id)
	if err != nil {
		return nil
	}
	return k
}

// accounted: K4: every wrapped spill key is some session's current key.
func (e *env) accounted() error {
	c := e.svc.State()
	for id, k := range c.Keys {
		if k.Wrapped && c.Sess[k.Subj].Spill != id {
			return fmt.Errorf("orphan wrapped key %d (%s ckpt %d)", id, k.Subj, k.Ckpt)
		}
	}
	return nil
}

// --------------------------------------------------------------- scenarios
// Each returns an error when a property the design keeps is violated. The
// design passes all; each planted mutant fails at least its own.

type scenario struct {
	name string
	run  func(e *env) error
}

var scenarios = []scenario{
	{"happyCycleAndShred", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		en, _ := e.halo.entry(7)
		if !en.spilled || !strings.Contains(en.keyID, ":e1:s1") {
			return fmt.Errorf("not spilled at e1: %+v", en)
		}
		if err := e.svc.Open(e.ctx, "s1", 10); !errors.Is(err, ErrNotCommitted) {
			return fmt.Errorf("open before commit: %v", err)
		}
		for _, r := range e.halo.regs {
			if strings.Contains(r, "open") {
				return errors.New("an open registration reached halo before the commit")
			}
		}
		e.commit("s1")
		if err := e.svc.Open(e.ctx, "s1", 10); err != nil {
			return err
		}
		if en, _ := e.halo.entry(7); en.spilled {
			return errors.New("not restored")
		}
		if e.ws.loads.Load() == 0 {
			return errors.New("the workspace key was not loaded at the resume")
		}
		k := e.svc.State().Keys[1]
		if k.Wrapped || !k.Shredding {
			return fmt.Errorf("key not deleted after the restore: %+v", k)
		}
		e.svc.Poll(e.ctx)
		if e.svc.Shredded("s1", 10) {
			return errors.New("shred claimed while its tokens are unexpired")
		}
		e.advance(306 * time.Second)
		e.svc.Poll(e.ctx)
		if !e.svc.Shredded("s1", 10) {
			return errors.New("shred not claimed after the verified revoke")
		}
		st := e.halo.state("s1")
		if st.fence == nil || *st.fence != 1 {
			f := int64(-1)
			if st.fence != nil {
				f = *st.fence
			}
			return fmt.Errorf("revoke fence %d, want 1", f)
		}
		if _, err := e.st.Wrapped(1); !errors.Is(err, ErrShredded) {
			return fmt.Errorf("wrapped bytes still in the store: %v", err)
		}
		return e.accounted()
	}},
	{"freshKeyPerCheckpoint", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		var ids []string
		for i := int64(0); i < 3; i++ {
			if _, err := e.svc.Seal(e.ctx, "s1", 10+i, 7); err != nil {
				return err
			}
			en, _ := e.halo.entry(7)
			ids = append(ids, strings.Split(en.keyID, ":")[1])
			e.commit("s1")
			if err := e.svc.Open(e.ctx, "s1", 10+i); err != nil {
				return err
			}
		}
		if ids[0] == ids[1] || ids[1] == ids[2] || ids[0] == ids[2] {
			return fmt.Errorf("a key was reused across checkpoints: %v", ids)
		}
		return nil
	}},
	{"lostSealAnswerVerified", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		n := 0
		e.halo.setFault(func(path, use string) Fault {
			if use == "seal" && n == 0 {
				n++
				return FLoseAnswer
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		c := e.svc.State()
		if len(c.Keys) != 1 || c.Ops[1].Attempts != 1 {
			return fmt.Errorf("lost answer: keys %d, seal attempts %d (want 1, 1: verify saw the slot)", len(c.Keys), c.Ops[1].Attempts)
		}
		return e.accounted()
	}},
	{"droppedSealRetriedSameKey", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		n := 0
		e.halo.setFault(func(path, use string) Fault {
			if use == "seal" && n == 0 {
				n++
				return FDrop
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		c := e.svc.State()
		if len(c.Keys) != 1 {
			return fmt.Errorf("%d keys for one checkpoint (a fresh key on retry)", len(c.Keys))
		}
		return e.accounted()
	}},
	{"lateSealAfterSpillRefused", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		n := 0
		e.halo.setFault(func(path, use string) Fault {
			if use == "seal" && n == 0 {
				n++
				return FHold
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		e.commit("s1")
		e.halo.Release() // the first copy lands late, after the spill used the epoch
		if st := e.halo.state("s1"); st.seal != nil {
			return errors.New("a late seal copy reinstalled a used key")
		}
		return e.svc.Open(e.ctx, "s1", 10)
	}},
	{"duplicateSealIdempotent", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		for i := 0; i < 2; i++ {
			if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
				return err
			}
		}
		if n := len(e.svc.State().Keys); n != 1 {
			return fmt.Errorf("%d keys", n)
		}
		return nil
	}},
	{"wrongEntryNeverSeals", func(e *env) error {
		e.epochs.set("s1", 1)
		e.epochs.set("s2", 1)
		e.halo.AddEntry(7)
		e.halo.AddEntry(8)
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		if st := e.halo.state("s1"); st.lastSpill != 1 {
			return errors.New("s1's own entry was not spilled under its key")
		}
		if en, _ := e.halo.entry(8); en.spilled || en.session != "" {
			return errors.New("another conversation's entry was sealed")
		}
		return nil
	}},
	{"haloRestartLosesEntry", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		e.halo.setFault(func(path, use string) Fault {
			if strings.HasSuffix(path, "/spill") {
				return FDrop
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("dropped spill: %v, want unknown", err)
		}
		e.halo.setFault(nil)
		e.halo.Restart()
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrEntryGone) && !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("after halo restart: %v", err)
		}
		return e.accounted()
	}},
	{"crashMidSpillSameKey", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		e.halo.setFault(func(path, use string) Fault {
			if strings.HasSuffix(path, "/spill") {
				return FDrop
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("dropped spill: %v", err)
		}
		e.halo.setFault(nil)
		e.start() // yard-ctl restarts
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("spill unsettled (the seal slot is live): %v, want unknown", err)
		}
		e.advance(306 * time.Second) // the seal slot expires: the spill is settled, not done
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		c := e.svc.State()
		if len(c.Keys) != 1 || c.Inc != 2 {
			return fmt.Errorf("keys %d inc %d", len(c.Keys), c.Inc)
		}
		return e.accounted()
	}},
	{"abortAfterSpillBurnsEpoch", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		if err := e.svc.Discard(e.ctx, "s1", 10); err != nil { // SuspendAbort
			return err
		}
		before := len(e.halo.regs)
		if _, err := e.svc.Seal(e.ctx, "s1", 11, 7); !errors.Is(err, ErrEpochBurnt) {
			return fmt.Errorf("seal at a burnt epoch: %v", err)
		}
		if len(e.halo.regs) != before {
			return errors.New("a seal at a burnt epoch reached halo")
		}
		e.advance(306 * time.Second)
		e.svc.Poll(e.ctx)
		if !e.svc.Shredded("s1", 10) {
			return errors.New("aborted key not shredded")
		}
		return e.accounted()
	}},
	{"abortBeforeSpillNoRevoke", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		e.halo.setFault(func(path, use string) Fault {
			if strings.HasSuffix(path, "/spill") {
				return FDrop
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("dropped spill: %v", err)
		}
		e.halo.setFault(nil)
		e.advance(306 * time.Second) // settled: not spilled
		if err := e.svc.Discard(e.ctx, "s1", 10); err != nil {
			return err
		}
		if _, err := e.svc.Seal(e.ctx, "s1", 11, 7); err != nil { // the epoch is not burnt
			return err
		}
		e.svc.Poll(e.ctx) // no revoke for the unspilled key (it would fence epoch 1)
		e.commit("s1")
		if err := e.svc.Open(e.ctx, "s1", 11); err != nil {
			return fmt.Errorf("the new checkpoint at the same epoch: %w", err)
		}
		e.advance(906 * time.Second)
		e.svc.Poll(e.ctx)
		if !e.svc.Shredded("s1", 10) {
			return errors.New("unspilled key not shredded by the time bound")
		}
		return nil
	}},
	{"delayedRevokeKeepsNewerCheckpoint", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if err := e.cycle("s1", 10, 7); err != nil { // K1 at e1; now epoch 2
			return err
		}
		e.advance(306 * time.Second)
		e.halo.setFault(func(path, use string) Fault {
			if use == "revoke" {
				return FHold
			}
			return FNone
		})
		e.svc.Poll(e.ctx) // K1's revoke (token epoch 2) is delayed
		e.halo.setFault(nil)
		if _, err := e.svc.Seal(e.ctx, "s1", 11, 7); err != nil { // K2 sealed + spilled at e2
			return err
		}
		e.commit("s1")
		e.halo.Release() // the delayed revoke lands
		if en, ok := e.halo.entry(7); !ok || !en.spilled {
			return errors.New("a delayed revoke for the older checkpoint erased the newer one")
		}
		return e.svc.Open(e.ctx, "s1", 11)
	}},
	{"delayedRevokeUnboundedHalo", func(e *env) error {
		// the halo round-3 rule (unbounded default); yard's explicit through still keeps T+1's checkpoint
		e.halo.setUnbounded(true)
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if err := e.cycle("s1", 10, 7); err != nil {
			return err
		}
		e.advance(306 * time.Second)
		e.halo.setFault(func(path, use string) Fault {
			if use == "revoke" {
				return FHold
			}
			return FNone
		})
		e.svc.Poll(e.ctx) // revoke for K1 at token epoch 2, delayed
		e.halo.setFault(nil)
		if err := e.cycle("s1", 11, 7); err != nil { // K2 at e2, resumed: epoch 3
			return err
		}
		if _, err := e.svc.Seal(e.ctx, "s1", 12, 7); err != nil { // K3 at e3 = T+1
			return err
		}
		e.commit("s1")
		e.halo.Release()
		if en, ok := e.halo.entry(7); !ok || !en.spilled {
			return errors.New("a delayed revoke erased a checkpoint spilled after its token epoch")
		}
		return e.svc.Open(e.ctx, "s1", 12)
	}},
	{"noShredBeforeSettle", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if err := e.cycle("s1", 10, 7); err != nil {
			return err
		}
		e.svc.Poll(e.ctx)
		if e.svc.Shredded("s1", 10) {
			return errors.New("shred claimed before the settle bound (tokens unexpired, no verified revoke)")
		}
		e.advance(100 * time.Second)
		e.svc.Poll(e.ctx)
		if e.svc.Shredded("s1", 10) {
			return errors.New("shred claimed before the settle bound")
		}
		return nil
	}},
	{"lateOpenAfterRestoreRefused", func(e *env) error {
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
			return err
		}
		e.commit("s1")
		n := 0
		e.halo.setFault(func(path, use string) Fault {
			if use == "open" && n == 0 {
				n++
				return FHold
			}
			return FNone
		})
		if err := e.svc.Open(e.ctx, "s1", 10); err != nil {
			return err
		}
		e.halo.Release()
		if st := e.halo.state("s1"); st.open != nil || st.lastRestore != 2 {
			return fmt.Errorf("a late open copy re-armed a used key (open %v, restored %d)", st.open != nil, st.lastRestore)
		}
		return nil
	}},
}

func runScenario(t *testing.T, mut mutants, sc scenario) error {
	e := newEnv(t, mut)
	return sc.run(e)
}

func TestScenarios(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			if err := runScenario(t, mutants{}, sc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestMutantsCaught: each planted defect makes at least one scenario fail.
func TestMutantsCaught(t *testing.T) {
	for _, m := range []struct {
		name string
		mut  mutants
	}{
		{"reuseKey", mutants{reuseKey: true}},
		{"openBeforeCommit", mutants{openBeforeCommit: true}},
		{"shredBeforeSettle", mutants{shredBeforeSettle: true}},
		{"wrongEntry", mutants{wrongEntry: true}},
		{"implicitThrough", mutants{implicitThrough: true}},
		{"revokeUnburnt", mutants{revokeUnburnt: true}},
		{"blindRetry", mutants{blindRetry: true}},
		{"noBurntGuard", mutants{noBurntGuard: true}},
		{"reuseOpID", mutants{reuseOpID: true}},
		{"noRenew", mutants{noRenew: true}},
	} {
		t.Run(m.name, func(t *testing.T) {
			var caught []string
			for _, sc := range scenarios {
				if err := runScenario(t, m.mut, sc); err != nil {
					caught = append(caught, sc.name+": "+err.Error())
				}
			}
			if len(caught) == 0 {
				t.Fatalf("mutant %s not caught by any scenario", m.name)
			}
			t.Logf("mutant %s caught by %v", m.name, caught)
		})
	}
}

// TestRevokeBoundRound4: with yard relying on halo's default `through` (the
// implicitThrough mutant), a revoke delayed past a checkpoint spilled at
// T+1 erases it under halo round 3 (unbounded) and keeps it under round 4
// (bounded by the token epoch). spec/keys: mutants unboundedRevoke and
// revokeDefaultThrough; the design sends an explicit through either way.
func TestRevokeBoundRound4(t *testing.T) {
	var sc scenario
	for _, s := range scenarios {
		if s.name == "delayedRevokeUnboundedHalo" {
			sc = s
		}
	}
	for _, unbounded := range []bool{false, true} {
		e := newEnv(t, mutants{implicitThrough: true})
		err := sc.run(envBound{e, unbounded}.env())
		if unbounded && err == nil {
			t.Fatal("round 3 (unbounded) + server default: the T+1 checkpoint survived; expected it erased")
		}
		if !unbounded && err != nil {
			t.Fatalf("round 4 (bounded) + server default: %v", err)
		}
	}
}

type envBound struct {
	e         *env
	unbounded bool
}

// env returns e with the fake's bound fixed (the scenario's own setting is ignored).
func (b envBound) env() *env {
	b.e.halo.mu.Lock()
	b.e.halo.fixBound = &b.unbounded
	b.e.halo.mu.Unlock()
	return b.e
}

// TestPeerUID: a socket served by another uid is never sent a key.
func TestPeerUID(t *testing.T) {
	e := newEnv(t, mutants{})
	c := NewUnixHalo(e.halo.path, os.Getuid()+1, time.Second)
	if _, err := c.Keys(context.Background()); !errors.Is(err, ErrPeer) && (err == nil || !strings.Contains(err.Error(), ErrPeer.Error())) {
		t.Fatalf("wrong peer uid: %v", err)
	}
	if _, err := NewUnixHalo(e.halo.path, os.Getuid(), time.Second).Keys(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestClaims: the halo_spill token carries exactly what halo checks.
func TestClaims(t *testing.T) {
	e := newEnv(t, mutants{})
	e.epochs.set("s1", 3)
	m := &IssuerMinter{Is: e.is, Caller: issuer.Caller{Name: "yard-ctl"}, User: "yard-ctl", TTL: 300,
		Workload: issuer.WorkloadID{Harness: "yard", Policy: "keysvc", Node: "halo", Sandbox: "yard-ctl", Run: "keysvc"}}
	tok, err := m.MintSpill("s1", 3, SpillClaim{Use: Seal, KeySHA256: "abc", Entry: "0123456789abcdef.7", Op: "y123.7"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := sts.Verify(tok, e.ring.JWKS(), sts.VerifyOptions{Issuer: testIss, Audience: HaloAudience,
		MaxTTL: 300 * time.Second, Now: time.UnixMilli(e.clock.Load())})
	if err != nil {
		t.Fatal(err)
	}
	hs := c["halo_spill"].(map[string]any)
	if c["yard_sess"] != "s1" || fmt.Sprint(c["yard_epoch"]) != "3" || hs["use"] != "seal" || hs["entry"] != "0123456789abcdef.7" ||
		hs["key_sha256"] != "abc" || hs["op"] != "y123.7" || len(hs) != 4 {
		t.Fatalf("claims %v", c)
	}
	if _, err := m.MintSpill("s1", 2, SpillClaim{Use: Revoke, Through: 2}); !errors.Is(err, issuer.ErrStaleEpoch) {
		t.Fatalf("a stale-epoch mint: %v", err)
	}
	tok, _ = m.MintSpill("s1", 3, SpillClaim{Use: Revoke, Through: 2})
	c, _ = sts.Verify(tok, e.ring.JWKS(), sts.VerifyOptions{Issuer: testIss, Audience: HaloAudience, Now: time.UnixMilli(e.clock.Load())})
	if hs := c["halo_spill"].(map[string]any); fmt.Sprint(hs["through"]) != "2" || len(hs) != 2 {
		t.Fatalf("revoke claim %v", hs)
	}
}

// TestDelayedRevokeAfterNewerSeal (round 4, K7 revokeBoundedByAuthority): a
// revoke for K1 at token epoch T = 2 (explicit through 1) is delayed and lands
// after K3's seal registration at T+1 = 3, just before its spill. A scoped
// halo leaves K3's seal key (one seal registration at e3); an unscoped one
// (spec/keys before round 4) zeroes it, and yard must re-register.
func TestDelayedRevokeAfterNewerSeal(t *testing.T) {
	for _, unscoped := range []bool{false, true} {
		e := newEnv(t, mutants{})
		e.halo.setUnscoped(unscoped)
		e.epochs.set("s1", 1)
		e.halo.AddEntry(7)
		if err := e.cycle("s1", 10, 7); err != nil {
			t.Fatal(err)
		}
		e.advance(306 * time.Second)
		e.halo.setFault(func(path, use string) Fault {
			if use == "revoke" {
				return FHold
			}
			return FNone
		})
		e.svc.Poll(e.ctx) // K1's revoke at T = 2, delayed
		e.halo.setFault(nil)
		if err := e.cycle("s1", 11, 7); err != nil { // K2 at e2; epoch 3
			t.Fatal(err)
		}
		released := false
		e.halo.setFault(func(path, use string) Fault {
			if strings.HasSuffix(path, "/spill") && !released {
				released = true
				e.halo.Release() // the delayed revoke lands between K3's seal and its spill
			}
			return FNone
		})
		if _, err := e.svc.Seal(e.ctx, "s1", 12, 7); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range e.halo.regs {
			if r == "s1 seal e3" {
				n++
			}
		}
		if st := e.halo.state("s1"); st.fence == nil || *st.fence != 1 {
			t.Fatalf("unscoped=%v: fence %v, want 1", unscoped, st.fence)
		}
		if want := map[bool]int{false: 1, true: 2}[unscoped]; n != want {
			t.Fatalf("unscoped=%v: %d seal registrations at e3, want %d", unscoped, n, want)
		}
	}
}
