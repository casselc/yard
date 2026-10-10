package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"yard/internal/lifecycle"
	"yard/internal/spawn"
)

const (
	testDS  = "zroot/yard/data/ws/t1"
	testWS  = "/yard/data/ws/t1"
	testArt = "zroot/yard/data/sr1"
)

type rig struct {
	t   *testing.T
	f   *fakeOS
	b   *Backend
	s   *Session
	sbx *spawn.Sandbox
}

func testSpec() Spec {
	return Spec{Name: "devsrv", Argv: []string{"/workspace/devsrv"}, Ports: []uint16{8080},
		Ready:     Probe{Kind: "http", Port: 8080, Path: "/healthz", Interval: Duration(time.Millisecond), Timeout: Duration(20 * time.Millisecond)},
		StopGrace: Duration(40 * time.Millisecond), KillWait: Duration(40 * time.Millisecond),
		PauseWait: Duration(40 * time.Millisecond), StartTimeout: Duration(200 * time.Millisecond)}
}

func newRig(t *testing.T, b behavior) *rig {
	t.Helper()
	base, state := t.TempDir(), t.TempDir()
	sbx := &spawn.Sandbox{ID: "t1", Base: base, Template: "/yard/tmpl/base", Net: spawn.SbxBroker, Subnet: 5,
		BrokerPort: 8099, Epair: "epair5a", Expose: []uint16{8080}, WorkspacePath: testWS, JID: 7}
	if err := os.MkdirAll(sbx.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(sbx)
	if err := os.WriteFile(sbx.StateFile(), j, 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFakeOS()
	f.behave["/workspace/devsrv"] = b
	f.ds[testDS+" encryption,mountpoint,mounted"] = "aes-256-gcm\t" + testWS + "\tyes"
	f.ds[testArt+" encryption"] = "aes-256-gcm"
	sp := &spawn.Spawner{Sys: f, Shim: "/x/yard-exec-shim"}
	be := (&Backend{OS: f, Spawn: sp, Probe: fakeProber{f}, State: state, ArtDir: filepath.Join(state, "art"),
		ArtDS: testArt, Poll: time.Millisecond}).Init()
	s := &Session{ID: "web", Sandbox: "t1", Base: base, UID: 2000001, GID: 2000000, Class: "yard_task",
		AuditUID: -1, Devfs: 10, Dataset: testDS, Spec: testSpec()}
	return &rig{t: t, f: f, b: be, s: s, sbx: sbx}
}

func (r *rig) up() {
	r.t.Helper()
	if err := r.b.Up(context.Background(), r.s); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) name(gen int64) string { return jailName(r.sbx, "web", gen) }

// opCtx is the context the lifecycle Router gives a backend call.
func opCtx(id int64) context.Context {
	return lifecycle.WithOp(context.Background(), lifecycle.Op{ID: id})
}

// lastTiming returns the most recent timing of op.
func (r *rig) lastTiming(op string) Timing {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.b.State, "timings.jsonl"))
	if err != nil {
		r.t.Fatal(err)
	}
	var last Timing
	found := false
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var t Timing
		if json.Unmarshal([]byte(l), &t) == nil && t.Op == op {
			last, found = t, true
		}
	}
	if !found {
		r.t.Fatalf("no %s timing", op)
	}
	return last
}

func TestSpecValidate(t *testing.T) {
	r := newRig(t, behavior{})
	ok := testSpec()
	ok.Defaults()
	if err := ok.Validate(r.sbx); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Spec){
		"name":          func(s *Spec) { s.Name = "Web Server" },
		"argv":          func(s *Spec) { s.Argv = nil },
		"env":           func(s *Spec) { s.Env = []string{"no-equals"} },
		"cwd":           func(s *Spec) { s.Cwd = "workspace" },
		"port 0":        func(s *Spec) { s.Ports = []uint16{0} },
		"port repeated": func(s *Spec) { s.Ports = []uint16{8080, 8080} },
		"probe port":    func(s *Spec) { s.Ready.Port = 9090 },
		"not exposed":   func(s *Spec) { s.Ports = append(s.Ports, 9090); s.Ready.Port = 9090 },
		"probe kind":    func(s *Spec) { s.Ready.Kind = "udp" },
		"cmd no argv":   func(s *Spec) { s.Ready = Probe{Kind: "cmd", Interval: 1, Timeout: 1} },
		"grace":         func(s *Spec) { s.StopGrace = Duration(time.Hour) },
		"timeout <= 0":  func(s *Spec) { s.Ready.Timeout = -1 },
		"mem":           func(s *Spec) { s.Mem = "lots" },
		"nul":           func(s *Spec) { s.Argv = []string{"a\x00b"} },
	} {
		s := testSpec()
		s.Defaults()
		mut(&s)
		if err := s.Validate(r.sbx); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a net=none sandbox has no address for a network probe
	none := *r.sbx
	none.Net, none.Expose = spawn.SbxNone, nil
	if err := ok.Validate(&none); err == nil {
		t.Fatal("http probe accepted in a net=none sandbox")
	}
}

// The suspend path (quiesce, checkpoint, destroy) and the resume path
// (restore from the artifact, readiness), then the owed delete.
func TestSuspendResumePath(t *testing.T) {
	r := newRig(t, behavior{listens: true, readyAfter: 2})
	r.up()
	ctx := context.Background()
	if n := r.f.live(r.name(0)); n != 1 {
		t.Fatalf("after up: %d processes", n)
	}
	ex, run, err := r.b.Instance(ctx, "web", 0)
	if !ex || !run || err != nil {
		t.Fatalf("instance 0: %v %v %v", ex, run, err)
	}
	if err := r.b.Quiesce(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if tm := r.lastTiming("quiesce"); tm.Info["escalated"] != false || !tm.OK {
		t.Fatalf("quiesce timing %+v", tm)
	}
	ex, run, _ = r.b.Instance(ctx, "web", 0)
	if !ex || run {
		t.Fatalf("after quiesce: exists %v running %v (the jail stays, nothing runs)", ex, run)
	}
	bytes, err := r.b.Checkpoint(opCtx(2), "web", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	snap := testDS + "@ysr1-web-g1-c2"
	if r.f.snapList()[0] != snap || bytes <= 12288 {
		t.Fatalf("snapshots %v bytes %d", r.f.snapList(), bytes)
	}
	if ok, err := r.b.CheckpointOK(ctx, "web", 2); !ok || err != nil {
		t.Fatalf("CheckpointOK %v %v", ok, err)
	}
	if err := r.b.Destroy(opCtx(3), "web", 0); err != nil {
		t.Fatal(err)
	}
	if ex, _, _ := r.b.Instance(ctx, "web", 0); ex || r.f.mountCount() != 0 || r.f.jailCount() != 0 {
		t.Fatalf("after destroy: exists %v mounts %d jails %d", ex, r.f.mountCount(), r.f.jailCount())
	}
	if err := r.b.Restore(opCtx(4), "web", 1, 2, false); err != nil {
		t.Fatal(err)
	}
	if n := r.f.live(r.name(1)); n != 1 {
		t.Fatalf("after restore: %d processes in instance 1", n)
	}
	tm := r.lastTiming("restore")
	if tm.Info["drift_bytes"] != float64(0) || tm.Info["probes"] != float64(3) || tm.Steps["ready"] <= 0 {
		t.Fatalf("restore timing %+v", tm)
	}
	if err := r.b.Delete(opCtx(5), "web", 2); err != nil {
		t.Fatal(err)
	}
	if ex, err := r.b.Exists(ctx, "web", 2); ex || err != nil || len(r.f.snapList()) != 0 {
		t.Fatalf("after delete: exists %v %v snaps %v", ex, err, r.f.snapList())
	}
	if err := r.b.Delete(opCtx(6), "web", 2); err != nil { // idempotent
		t.Fatal(err)
	}
}

// A process that ignores SIGTERM: the stop escalates to SIGKILL after the
// grace period, bounded, and verifies nothing is left.
func TestQuiesceEscalatesToKill(t *testing.T) {
	r := newRig(t, behavior{listens: true, ignoreTerm: true})
	r.up()
	t0 := time.Now()
	if err := r.b.Quiesce(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	el := time.Since(t0)
	if el < 40*time.Millisecond || el > 2*time.Second {
		t.Fatalf("stop took %s (grace 40ms)", el)
	}
	if tm := r.lastTiming("quiesce"); tm.Info["escalated"] != true || tm.Steps["kill"] <= 0 {
		t.Fatalf("%+v", tm)
	}
	if n := r.f.live(r.name(0)); n != 0 {
		t.Fatalf("%d left", n)
	}
}

// Children forked as the parent handles SIGTERM appear after the listing;
// they are signalled too, and the stop waits for them.
func TestQuiesceCatchesLateChildren(t *testing.T) {
	r := newRig(t, behavior{listens: true, forkOnTerm: 3})
	r.up()
	if err := r.b.Quiesce(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if n := r.f.live(r.name(0)); n != 0 {
		t.Fatalf("%d left", n)
	}
	if tm := r.lastTiming("quiesce"); tm.Info["escalated"] != false {
		t.Fatalf("children needed SIGKILL: %+v", tm)
	}
}

// A process not even SIGKILL ends (stuck in the kernel): the stop answers
// an error after KillWait (unknown), and the instance still runs, so the
// lifecycle observes the quiesce as not done.
func TestQuiesceUnkillableIsNotDone(t *testing.T) {
	r := newRig(t, behavior{listens: true, unkillable: true})
	r.up()
	err := r.b.Quiesce(opCtx(1), "web", 0)
	if err == nil || !strings.Contains(err.Error(), "after SIGKILL") {
		t.Fatalf("got %v", err)
	}
	if _, run, _ := r.b.Instance(context.Background(), "web", 0); !run {
		t.Fatal("observed not running")
	}
}

// A paused (SIGSTOPped) service is stopped gracefully: SIGTERM is not acted
// on by a stopped process until SIGCONT, so the stop sends both.
func TestQuiescePausedIsGraceful(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	if err := r.b.Pause(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Quiesce(opCtx(2), "web", 0); err != nil {
		t.Fatal(err)
	}
	if tm := r.lastTiming("quiesce"); tm.Info["escalated"] != false {
		t.Fatalf("a paused service needed SIGKILL: %+v", tm)
	}
}

// Pause stops every process, also one forked while SIGSTOP went out;
// Frozen observes it; Unpause runs them again.
func TestPauseUnpause(t *testing.T) {
	r := newRig(t, behavior{listens: true, forkOnStop: 1})
	r.up()
	ctx := context.Background()
	if ex, fr, _ := r.b.Frozen(ctx, "web", 0); !ex || fr {
		t.Fatalf("before: %v %v", ex, fr)
	}
	if err := r.b.Pause(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if ex, fr, _ := r.b.Frozen(ctx, "web", 0); !ex || !fr {
		t.Fatalf("after pause: exists %v frozen %v", ex, fr)
	}
	if n := r.f.live(r.name(0)); n != 2 {
		t.Fatalf("%d processes (want the forked child too)", n)
	}
	if err := r.b.Unpause(opCtx(2), "web", 0); err != nil {
		t.Fatal(err)
	}
	if ex, fr, _ := r.b.Frozen(ctx, "web", 0); !ex || fr {
		t.Fatalf("after unpause: %v %v", ex, fr)
	}
	// nothing to pause: an error, observed not frozen
	if err := r.b.Quiesce(opCtx(3), "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Pause(opCtx(4), "web", 0); err == nil {
		t.Fatal("paused an instance with no process")
	}
	if _, fr, _ := r.b.Frozen(ctx, "web", 0); fr {
		t.Fatal("frozen with no process")
	}
}

// checkpointed is a rig with instance 0 quiesced, checkpoint 2 taken and
// instance 0 destroyed.
func checkpointed(t *testing.T, b behavior) *rig {
	r := newRig(t, behavior{listens: true})
	r.up()
	for _, err := range []error{r.b.Quiesce(opCtx(1), "web", 0), r.b.Destroy(opCtx(3), "web", 0)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.b.Checkpoint(opCtx(2), "web", 1, 2); err != nil {
		t.Fatal(err)
	}
	r.f.behave["/workspace/devsrv"] = b
	return r
}

// A readiness probe that never succeeds: the restore gives up at
// StartTimeout, removes the jail it made, and is observed not done.
func TestRestoreReadinessTimeout(t *testing.T) {
	r := checkpointed(t, behavior{listens: false})
	t0 := time.Now()
	err := r.b.Restore(opCtx(4), "web", 1, 2, false)
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("got %v", err)
	}
	if el := time.Since(t0); el < 200*time.Millisecond || el > 2*time.Second {
		t.Fatalf("gave up after %s (start timeout 200ms)", el)
	}
	if ex, _, _ := r.b.Instance(context.Background(), "web", 1); ex || r.f.mountCount() != 0 {
		t.Fatalf("left: exists %v mounts %d", ex, r.f.mountCount())
	}
}

// A probe attempt that hangs is cut at its own timeout; the restore still
// ends at StartTimeout.
func TestRestoreHangingProbeIsBounded(t *testing.T) {
	r := checkpointed(t, behavior{listens: true})
	r.f.hang = true
	done := make(chan error, 1)
	go func() { done <- r.b.Restore(opCtx(4), "web", 1, 2, false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ready with a hanging probe")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restore did not return: probe attempts are not bounded")
	}
	if tm := r.lastTiming("restore"); tm.Info["probes"].(float64) < 5 {
		t.Fatalf("probes %v: each attempt should time out at 20ms", tm.Info["probes"])
	}
}

// The service exits before it is ready: the restore fails at once.
func TestRestoreExitBeforeReady(t *testing.T) {
	r := checkpointed(t, behavior{exitAtStart: true})
	t0 := time.Now()
	err := r.b.Restore(opCtx(4), "web", 1, 2, false)
	if err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("got %v", err)
	}
	if time.Since(t0) > 150*time.Millisecond {
		t.Fatal("waited for the start timeout")
	}
	if r.f.jailCount() != 0 {
		t.Fatal("jail left")
	}
}

// The instance name is create-only: a second copy of a restore finds the
// jail and answers done without starting anything.
func TestRestoreCreateOnly(t *testing.T) {
	r := checkpointed(t, behavior{listens: true})
	if err := r.b.Restore(opCtx(4), "web", 1, 2, false); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Restore(opCtx(4), "web", 1, 2, false); err != nil {
		t.Fatal(err)
	}
	if n := r.f.live(r.name(1)); n != 1 || r.f.jailCount() != 1 {
		t.Fatalf("processes %d jails %d", n, r.f.jailCount())
	}
	if !r.lastTiming("restore").Info["existed"].(bool) {
		t.Fatal("second copy not recognised")
	}
}

// Leftovers of a restore copy that died before jail_set (mounts, root) are
// cleaned up before the next copy sets the instance up.
func TestRestoreCleansLeftovers(t *testing.T) {
	r := checkpointed(t, behavior{listens: true})
	c := r.b.call(r.s, r.sbx, 1, testSpec())
	stale := c.Root() + "/tmp"
	r.f.mounts = append(r.f.mounts, stale)
	if err := r.b.Restore(opCtx(4), "web", 1, 2, false); err != nil {
		t.Fatal(err)
	}
	if r.f.mountCount() != 4 {
		t.Fatalf("mounts %v", r.f.mounts)
	}
}

// The snapshot fails midway (zfs answers an error, nothing applied): the
// checkpoint answers an error and is observed not done. A lost answer
// (applied, then an error) is observed not done too (no artifact), and the
// retake under a new checkpoint id does not collide with it; deleting the
// old checkpoint leaves the new one.
func TestCheckpointFailures(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	if err := r.b.Quiesce(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	r.f.zfsFail["snapshot"] = "fail"
	if _, err := r.b.Checkpoint(opCtx(2), "web", 1, 2); err == nil {
		t.Fatal("no error")
	}
	if ok, _ := r.b.CheckpointOK(context.Background(), "web", 2); ok {
		t.Fatal("observed done")
	}
	r.f.zfsFail["snapshot"] = "lost"
	if _, err := r.b.Checkpoint(opCtx(3), "web", 1, 3); err == nil {
		t.Fatal("no error")
	}
	if ok, _ := r.b.CheckpointOK(context.Background(), "web", 3); ok {
		t.Fatal("observed done without an artifact")
	}
	if ex, _ := r.b.Exists(context.Background(), "web", 3); !ex {
		t.Fatal("the applied snapshot is not seen by Exists (its delete would be skipped)")
	}
	if _, err := r.b.Checkpoint(opCtx(5), "web", 1, 5); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Delete(opCtx(4), "web", 3); err != nil {
		t.Fatal(err)
	}
	if got := r.f.snapList(); len(got) != 1 || got[0] != testDS+"@ysr1-web-g1-c5" {
		t.Fatalf("snapshots %v", got)
	}
	if ok, _ := r.b.CheckpointOK(context.Background(), "web", 5); !ok {
		t.Fatal("the retaken checkpoint does not verify")
	}
}

// An artifact killed mid-write (only the temp file) does not verify, is
// seen by Exists, and Delete removes it; an edited one does not verify.
func TestPartialAndEditedArtifact(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	if _, err := r.b.Checkpoint(opCtx(2), "web", 1, 2); err != nil {
		t.Fatal(err)
	}
	final := r.b.artPath("web", 2)
	if err := os.Rename(final, final+".tmp.999"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, _ := r.b.CheckpointOK(ctx, "web", 2); ok {
		t.Fatal("partial artifact verified")
	}
	if ex, _ := r.b.Exists(ctx, "web", 2); !ex {
		t.Fatal("partial artifact not seen")
	}
	if err := r.b.Delete(opCtx(3), "web", 2); err != nil {
		t.Fatal(err)
	}
	if ex, _ := r.b.Exists(ctx, "web", 2); ex {
		t.Fatal("partial artifact left")
	}
	if _, err := r.b.Checkpoint(opCtx(4), "web", 1, 4); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(r.b.artPath("web", 4))
	if err := os.WriteFile(r.b.artPath("web", 4), []byte(strings.Replace(string(b), "devsrv", "evilsrv", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.b.CheckpointOK(ctx, "web", 4); ok {
		t.Fatal("edited artifact verified")
	}
	if err := r.b.Restore(opCtx(5), "web", 1, 4, false); err == nil {
		t.Fatal("restored from an edited artifact")
	}
}

// jail_remove kills, but the processes take a while to go: Destroy waits
// for them before it unmounts and answers.
func TestDestroyWaitsForProcesses(t *testing.T) {
	r := newRig(t, behavior{listens: true, lingers: 5})
	r.up()
	jid, _ := r.f.JID(r.name(0))
	if err := r.b.Destroy(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if ps, _ := r.f.Procs(jid); len(ps) != 0 {
		t.Fatalf("Destroy answered with %d processes of the jail left", len(ps))
	}
}

// Unquiesce (abort path): SIGCONT a frozen instance; restart a stopped one
// in its own jail.
func TestUnquiesce(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	ctx := context.Background()
	if err := r.b.Pause(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Unquiesce(opCtx(2), "web", 0); err != nil {
		t.Fatal(err)
	}
	if _, fr, _ := r.b.Frozen(ctx, "web", 0); fr || r.lastTiming("unquiesce").Info["restart"] != false {
		t.Fatal("not continued")
	}
	if err := r.b.Quiesce(opCtx(3), "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Unquiesce(opCtx(4), "web", 0); err != nil {
		t.Fatal(err)
	}
	if n := r.f.live(r.name(0)); n != 1 || r.f.jailCount() != 1 || r.lastTiming("unquiesce").Info["restart"] != true {
		t.Fatalf("processes %d jails %d", n, r.f.jailCount())
	}
	if err := r.b.Destroy(opCtx(5), "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Unquiesce(opCtx(6), "web", 0); err == nil {
		t.Fatal("unquiesced a destroyed instance")
	}
}

// InFlight sees a copy running here, and a process elsewhere (an earlier
// incarnation's zfs or shim) holding the op's lock.
func TestInFlightLock(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	op := lifecycle.Op{ID: 42}
	if busy, _ := r.b.InFlight(context.Background(), op); busy {
		t.Fatal("in flight before anything ran")
	}
	lock, release, err := r.b.opLock(42)
	if err != nil {
		t.Fatal(err)
	}
	if busy, _ := r.b.InFlight(context.Background(), op); !busy {
		t.Fatal("own copy not in flight")
	}
	// a child holding the inherited lock: another open file description
	other, err := os.OpenFile(lock.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if busy, _ := r.b.InFlight(context.Background(), op); !busy {
		t.Fatal("a lock held by another process not seen")
	}
	if _, _, err := r.b.opLock(42); err == nil {
		t.Fatal("a second copy ran while the first's child holds the lock")
	}
	other.Close()
	if busy, _ := r.b.InFlight(context.Background(), op); busy {
		t.Fatal("still in flight after the holder exited")
	}
}

// A cmd probe runs in the service's jail; exit 0 is ready.
func TestCmdProbe(t *testing.T) {
	r := newRig(t, behavior{listens: false})
	r.s.Spec.Ready = Probe{Kind: "cmd", Argv: []string{"/bin/probe"}, Interval: Duration(time.Millisecond), Timeout: Duration(20 * time.Millisecond)}
	r.up()
	if n := r.f.live(r.name(0)); n != 1 {
		t.Fatalf("%d processes", n)
	}
	r2 := newRig(t, behavior{listens: false, probeExit: 1})
	r2.f.behave["/bin/probe"] = behavior{probeExit: 1}
	r2.s.Spec.Ready = r.s.Spec.Ready
	if err := r2.b.Up(context.Background(), r2.s); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("got %v", err)
	}
}

// Up refuses a workspace dataset that is not encrypted or not mounted at
// the sandbox workspace.
func TestUpChecksDataset(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.f.ds[testDS+" encryption,mountpoint,mounted"] = "off\t" + testWS + "\tyes"
	if err := r.b.Up(context.Background(), r.s); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Fatalf("got %v", err)
	}
	r.f.ds[testDS+" encryption,mountpoint,mounted"] = "aes-256-gcm\t/elsewhere\tyes"
	if err := r.b.Up(context.Background(), r.s); err == nil || !strings.Contains(err.Error(), "mounted at") {
		t.Fatalf("got %v", err)
	}
	if r.f.jailCount() != 0 {
		t.Fatal("started anyway")
	}
}

func TestSnapOf(t *testing.T) {
	for _, c := range []struct {
		name string
		ckpt int64
		want bool
	}{
		{"p/ws@ysr1-web-g1-c2", 2, true},
		{"p/ws@ysr1-web-g1-c2", -1, true},
		{"p/ws@ysr1-web-g1-c22", 2, false},
		{"p/ws@ysr1-webx-g1-c2", 2, false},
		{"p/ws@ysr1-web-gx-c2", 2, false},
		{"p/ws@manual", -1, false},
	} {
		if got := snapOf(c.name, "web", c.ckpt); got != c.want {
			t.Errorf("snapOf(%s, %d) = %v", c.name, c.ckpt, got)
		}
	}
}
