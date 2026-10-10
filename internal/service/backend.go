package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yard/internal/lifecycle"
	"yard/internal/spawn"
)

// Backend is the lifecycle backend of kind "service" (lifecycle.Backend,
// lifecycle.Pauser) and its artifact store (lifecycle.ArtifactStore).
type Backend struct {
	OS    OS
	Spawn *spawn.Spawner // its Sys is OS: instances are set up by yard-spawn's own path
	Probe Prober
	// State holds session records (svc/<sess>/session.json), service logs
	// (svc/<sess>/g<gen>.log), op locks (ops/<id>.lock) and timings.jsonl.
	State string
	// ArtDir holds the artifacts (<sess>/<ckpt>.json); it must be on the
	// encrypted dataset ArtDS (SR0 invariant 4).
	ArtDir string
	ArtDS  string
	// WS is the workspace tree (layout of 2026-10-07): sessions with a
	// Project have their clone there and the key ops (lifecycle.Keys) act on
	// it. nil: no session has a project.
	WS   *Workspaces
	Poll time.Duration // process and probe polling (default 5ms)
	Now  func() time.Time
	// OnTiming, if set, also gets every Timing (the CLI prints them).
	OnTiming func(Timing)

	mu       sync.Mutex
	inflight map[int64]int       // op id -> copies running in this process
	procs    map[string]*mainRef // jail name -> the instance's main process, while this process holds it
}

// mainRef is a started instance's main process (the shim, then the
// service), reaped by a goroutine so its exit is observed.
type mainRef struct {
	proc   spawn.Proc
	exited chan struct{}
	exit   spawn.Exit
}

var (
	_ lifecycle.Backend       = (*Backend)(nil)
	_ lifecycle.Pauser        = (*Backend)(nil)
	_ lifecycle.ArtifactStore = (*Backend)(nil)
	_ lifecycle.Keys          = (*Backend)(nil)
)

// Init prepares the in-memory maps; call once before use.
func (b *Backend) Init() *Backend {
	b.inflight = map[int64]int{}
	b.procs = map[string]*mainRef{}
	if b.Poll == 0 {
		b.Poll = 5 * time.Millisecond
	}
	if b.Probe == nil {
		b.Probe = NetProber{}
	}
	return b
}

func (b *Backend) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func opID(ctx context.Context) int64 {
	if op, ok := lifecycle.OpFrom(ctx); ok {
		return op.ID
	}
	return 0
}

// withLock runs f holding the op's lock (when ctx carries an op).
func (b *Backend) withLock(ctx context.Context, f func(lock *os.File) error) error {
	id := opID(ctx)
	if id == 0 {
		return f(nil)
	}
	lock, release, err := b.opLock(id)
	if err != nil {
		return err
	}
	defer release()
	return f(lock)
}

func (b *Backend) sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// load returns the session record and its sandbox.
func (b *Backend) load(sess string) (*Session, *spawn.Sandbox, error) {
	s, err := b.LoadSession(sess)
	if err != nil {
		return nil, nil, err
	}
	sbx, err := spawn.LoadSandbox(s.Base, s.Sandbox)
	if err != nil {
		return nil, nil, err
	}
	return s, sbx, nil
}

// call is the yard-spawn call of instance gen of the session running spec.
func (b *Backend) call(s *Session, sbx *spawn.Sandbox, gen int64, spec Spec) *spawn.Call {
	id := spawn.ServiceID(s.ID, gen)
	env := append([]string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin", "HOME=/workspace",
		"YARD_SERVICE=" + s.ID, "YARD_GEN=" + strconv.FormatInt(gen, 10)}, spec.Env...)
	net := spawn.NetNone
	if sbx.Net == spawn.SbxBroker {
		net = spawn.NetInherit
	}
	return &spawn.Call{Sandbox: sbx, ID: id, Service: true, Argv: spec.Argv, Env: env, Cwd: spec.Cwd,
		UID: s.UID, GID: s.GID, Class: s.Class, AuditUID: s.AuditUID, Net: net, Workspace: "rw",
		WorkspaceSrc: s.Workspace, TmpSize: spec.TmpSize, Mem: spec.Mem, Devfs: s.Devfs}
}

func jailName(sbx *spawn.Sandbox, sess string, gen int64) string {
	return sbx.JailName() + "." + spawn.ServiceID(sess, gen)
}

// ===================================================== processes in a jail

// target is an instance's jail and who its processes run as.
type target struct {
	s   *Session
	sbx *spawn.Sandbox
	jid int
}

// signal sends sig to pids from inside the jail, as the service's uid
// (yard-exec-shim attaches, drops to the uid, execs /bin/kill). The kernel's
// prison and credential checks confine the signal to that jail's processes
// of that uid: a pid from the listing that exited and was reused by a host
// process meanwhile is out of reach. Signalling by pid from the host (as
// pkill -j does) is not: with kern.randompid (1023 on the NUC) the pid
// space wraps every few hundred forks. kill(1) exits 1 when a pid is
// already gone; that is not an error.
func (b *Backend) signal(t target, sig string, pids []int) error {
	if len(pids) == 0 {
		return nil
	}
	c := b.call(t.s, t.sbx, 0, t.s.Spec)
	c.Argv = []string{"/bin/kill", "-s", sig}
	for _, p := range pids {
		c.Argv = append(c.Argv, strconv.Itoa(p))
	}
	c.Cwd, c.Class = "/", ""
	p, err := b.Spawn.Exec(c, t.jid)
	if err != nil {
		return fmt.Errorf("kill -s %s: %w", sig, err)
	}
	e, err := p.Wait()
	if err != nil {
		return fmt.Errorf("kill -s %s: %w", sig, err)
	}
	if e.Code >= 120 && e.Code <= 127 {
		return fmt.Errorf("kill -s %s: yard-exec-shim failed (exit %d)", sig, e.Code)
	}
	return nil
}

// stop is the graceful stop of every process in jail jid: SIGTERM (and
// SIGCONT to a stopped process, which would not act on SIGTERM before it),
// repeated for processes that appear meanwhile, until none is left or the
// grace period is over; then SIGKILL until none is left or KillWait is
// over. jail(8) stops a jail the same way (SIGTERM, stop.timeout, kill).
// It returns an error, never a guess, when processes are still there.
func (b *Backend) stop(ctx context.Context, tg target, spec Spec, t *timer) error {
	jid := tg.jid
	ps, err := b.OS.Procs(jid)
	if err != nil {
		return err
	}
	t.info("procs", len(ps))
	if len(ps) == 0 {
		return nil
	}
	termed := map[int]bool{}
	term := func(ps []Proc) error {
		var fresh, stopped []int
		for _, p := range ps {
			if !termed[p.PID] {
				fresh = append(fresh, p.PID)
				termed[p.PID] = true
			}
			if p.Stopped {
				stopped = append(stopped, p.PID)
			}
		}
		// SIGTERM once per process (a second one is "force quit" to some
		// servers), then SIGCONT to the stopped ones so they act on it
		if err := b.signal(tg, "TERM", fresh); err != nil {
			return err
		}
		return b.signal(tg, "CONT", stopped)
	}
	deadline := b.now().Add(spec.StopGrace.D())
	for {
		if err := term(ps); err != nil {
			return err
		}
		if err := b.sleep(ctx, b.Poll); err != nil {
			return err
		}
		if ps, err = b.OS.Procs(jid); err != nil {
			return err
		}
		if len(ps) == 0 {
			t.step("term")
			t.info("escalated", false)
			return nil
		}
		if !b.now().Before(deadline) {
			break
		}
	}
	t.step("term")
	t.info("escalated", true)
	t.info("left_after_term", len(ps))
	deadline = b.now().Add(spec.KillWait.D())
	for {
		pids := make([]int, len(ps))
		for i, p := range ps {
			pids[i] = p.PID
		}
		if err := b.signal(tg, "KILL", pids); err != nil {
			return err
		}
		if err := b.sleep(ctx, b.Poll); err != nil {
			return err
		}
		if ps, err = b.OS.Procs(jid); err != nil {
			return err
		}
		if len(ps) == 0 {
			t.step("kill")
			return nil
		}
		if !b.now().Before(deadline) {
			t.step("kill")
			return fmt.Errorf("%d process(es) still in jail %d %s after SIGKILL", len(ps), jid, spec.KillWait.D())
		}
	}
}

// waitGone waits until jail jid has no process (after jail_remove).
func (b *Backend) waitGone(ctx context.Context, jid int, wait time.Duration) error {
	deadline := b.now().Add(wait)
	for {
		ps, err := b.OS.Procs(jid)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			return nil
		}
		if !b.now().Before(deadline) {
			return fmt.Errorf("%d process(es) of removed jail %d still there after %s", len(ps), jid, wait)
		}
		if err := b.sleep(ctx, b.Poll); err != nil {
			return err
		}
	}
}

// signalUntil sends sig (STOP or CONT) to every process whose Stopped
// differs from want, until all of them match or wait is over.
func (b *Backend) signalUntil(ctx context.Context, tg target, sig string, want bool, wait time.Duration) (int, error) {
	jid := tg.jid
	deadline := b.now().Add(wait)
	for {
		ps, err := b.OS.Procs(jid)
		if err != nil {
			return 0, err
		}
		if len(ps) == 0 {
			return 0, fmt.Errorf("jail %d has no process", jid)
		}
		var pids []int
		for _, p := range ps {
			if p.Stopped != want {
				pids = append(pids, p.PID)
			}
		}
		n := len(pids)
		if err := b.signal(tg, sig, pids); err != nil {
			return 0, err
		}
		if n == 0 {
			return len(ps), nil
		}
		if !b.now().Before(deadline) {
			return len(ps), fmt.Errorf("%d of %d process(es) in jail %d not %s after %s", n, len(ps), jid,
				map[bool]string{true: "stopped", false: "running"}[want], wait)
		}
		if err := b.sleep(ctx, b.Poll); err != nil {
			return 0, err
		}
	}
}

// =================================================================== start

// track keeps the started main process and reaps it.
func (b *Backend) track(name string, p spawn.Proc) *mainRef {
	r := &mainRef{proc: p, exited: make(chan struct{})}
	b.mu.Lock()
	b.procs[name] = r
	b.mu.Unlock()
	go func() {
		r.exit, _ = p.Wait()
		close(r.exited)
	}()
	return r
}

func (b *Backend) logFile(sess string, gen int64) (*os.File, error) {
	if err := os.MkdirAll(b.sessDir(sess), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(b.sessDir(sess), fmt.Sprintf("g%d.log", gen)), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// startNew sets up instance gen in a new jail (spawn.Start: the per-call
// path) and waits for readiness. On a failure it removes what it made; if
// that fails too, the instance may exist (the lifecycle observes it).
func (b *Backend) startNew(ctx context.Context, s *Session, sbx *spawn.Sandbox, gen int64, spec Spec, lock *os.File, t *timer) error {
	c := b.call(s, sbx, gen, spec)
	if err := b.Spawn.Teardown(c); err != nil { // leftovers of an earlier copy that made no jail
		return fmt.Errorf("leftovers of %s: %w", c.Name(), err)
	}
	t.step("clean")
	log, err := b.logFile(s.ID, gen)
	if err != nil {
		return err
	}
	defer log.Close()
	c.Stdout, c.Stderr = log, log
	if lock != nil {
		c.ExtraFiles = []*os.File{lock}
	}
	st, err := b.Spawn.Start(c)
	if err != nil {
		return err
	}
	t.step("jail")
	t.info("jid", st.JID)
	ref := b.track(c.Name(), st.Proc)
	if err := b.waitReady(ctx, s, sbx, spec, st.JID, ref, t); err != nil {
		if rerr := b.remove(context.WithoutCancel(ctx), c, st.JID, spec, t); rerr != nil {
			return fmt.Errorf("%w; and removing it: %v", err, rerr)
		}
		return err
	}
	return nil
}

// startIn starts the service again in its existing jail jid (Unquiesce).
func (b *Backend) startIn(ctx context.Context, s *Session, sbx *spawn.Sandbox, gen int64, jid int, spec Spec, lock *os.File, t *timer) error {
	c := b.call(s, sbx, gen, spec)
	log, err := b.logFile(s.ID, gen)
	if err != nil {
		return err
	}
	defer log.Close()
	c.Stdout, c.Stderr = log, log
	if lock != nil {
		c.ExtraFiles = []*os.File{lock}
	}
	p, err := b.Spawn.Exec(c, jid)
	if err != nil {
		return err
	}
	t.step("exec")
	ref := b.track(c.Name(), p)
	if err := b.waitReady(ctx, s, sbx, spec, jid, ref, t); err != nil {
		if serr := b.stop(context.WithoutCancel(ctx), target{s, sbx, jid}, spec, t); serr != nil {
			return fmt.Errorf("%w; and stopping it: %v", err, serr)
		}
		return err
	}
	return nil
}

// waitReady probes until the service is ready, it exits, or StartTimeout
// is over. Each attempt has its own timeout, cut to what is left.
func (b *Backend) waitReady(ctx context.Context, s *Session, sbx *spawn.Sandbox, spec Spec, jid int, ref *mainRef, t *timer) error {
	deadline := b.now().Add(spec.StartTimeout.D())
	var last error
	for n := 1; ; n++ {
		left := deadline.Sub(b.now())
		at := min(spec.Ready.Timeout.D(), left)
		if at <= 0 {
			t.info("probes", n-1)
			return fmt.Errorf("not ready after %s (%d probes): %v", spec.StartTimeout.D(), n-1, last)
		}
		actx, cancel := context.WithTimeout(ctx, at)
		last = b.probe(actx, s, sbx, spec, jid)
		cancel()
		if last == nil {
			t.step("ready")
			t.info("probes", n)
			return nil
		}
		select {
		case <-ref.exited:
			t.info("probes", n)
			return fmt.Errorf("service exited (code %d signal %d) before ready: %v", ref.exit.Code, ref.exit.Signal, last)
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if wait := min(spec.Ready.Interval.D(), deadline.Sub(b.now())); wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ref.exited:
			case <-time.After(wait):
			}
		}
	}
}

// probe is one readiness attempt.
func (b *Backend) probe(ctx context.Context, s *Session, sbx *spawn.Sandbox, spec Spec, jid int) error {
	addr := net.JoinHostPort(sbx.JailAddr().String(), strconv.Itoa(int(spec.Ready.Port)))
	switch spec.Ready.Kind {
	case "tcp":
		return b.Probe.TCP(ctx, addr)
	case "http":
		code, err := b.Probe.HTTP(ctx, "http://"+addr+spec.Ready.Path)
		if err != nil {
			return err
		}
		if code < 200 || code >= 400 {
			return fmt.Errorf("http %d", code)
		}
		return nil
	case "cmd":
		c := b.call(s, sbx, 0, spec)
		c.Argv = spec.Ready.Argv
		p, err := b.Spawn.Exec(c, jid)
		if err != nil {
			return err
		}
		done := make(chan spawn.Exit, 1)
		go func() { e, _ := p.Wait(); done <- e }()
		select {
		case e := <-done:
			if e.Code != 0 {
				return fmt.Errorf("probe exit %d signal %d", e.Code, e.Signal)
			}
			return nil
		case <-ctx.Done():
			p.Kill() // our own child: the pid cannot have been reused
			<-done
			return ctx.Err()
		}
	}
	return fmt.Errorf("probe kind %q", spec.Ready.Kind)
}

// remove is jail_remove, the wait for its processes, and the teardown of
// its mounts and root.
func (b *Backend) remove(ctx context.Context, c *spawn.Call, jid int, spec Spec, t *timer) error {
	if jid > 0 {
		if err := b.OS.RemoveJail(jid); err != nil {
			return fmt.Errorf("jail_remove %s: %w", c.Name(), err)
		}
		t.step("jail_remove")
		if err := b.waitGone(ctx, jid, spec.KillWait.D()); err != nil {
			return err
		}
		t.step("gone")
	}
	b.mu.Lock()
	delete(b.procs, c.Name())
	b.mu.Unlock()
	if err := b.Spawn.Teardown(c); err != nil {
		return err
	}
	t.step("teardown")
	return nil
}

// ================================================================ session

// Up registers a session and starts its first instance (generation 0, the
// lifecycle's "original"), then the caller adds the lifecycle row.
func (b *Backend) Up(ctx context.Context, s *Session) (err error) {
	t := b.timer("up", s.ID, 0, 0, 0)
	defer t.done(&err)
	if err := s.validate(); err != nil {
		return err
	}
	sbx, err := spawn.LoadSandbox(s.Base, s.Sandbox)
	if err != nil {
		return err
	}
	s.Spec.Defaults()
	if err := s.Spec.Validate(sbx); err != nil {
		return err
	}
	if err := b.checkDataset(ctx, s, sbx); err != nil {
		return err
	}
	if _, err := b.OS.JID(jailName(sbx, s.ID, 0)); err == nil {
		return fmt.Errorf("session %s: instance 0 exists already", s.ID)
	}
	if err := b.saveSession(s); err != nil {
		return err
	}
	return b.startNew(ctx, s, sbx, 0, s.Spec, nil, t)
}

// checkDataset: the workspace is the dataset, it is mounted there, and it
// is encrypted (its snapshots are suspend artifacts, SR0 invariant 4).
func (b *Backend) checkDataset(ctx context.Context, s *Session, sbx *spawn.Sandbox) error {
	out, err := b.OS.Zfs(ctx, nil, "get", "-H", "-o", "value", "encryption,mountpoint,mounted", s.Dataset)
	if err != nil {
		return err
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		return fmt.Errorf("zfs get %s: %q", s.Dataset, out)
	}
	if f[0] == "off" || f[0] == "-" {
		return fmt.Errorf("workspace dataset %s is not encrypted", s.Dataset)
	}
	if f[1] != s.workspaceDir(sbx) || f[2] != "yes" {
		return fmt.Errorf("workspace dataset %s is mounted at %s (mounted=%s), the session workspace is %s",
			s.Dataset, f[1], f[2], s.workspaceDir(sbx))
	}
	return nil
}

// Down stops and removes every instance of the session up to generation
// maxGen, its snapshots and artifacts, and its record. It is for tests and
// cleanup; the lifecycle row is the caller's.
func (b *Backend) Down(ctx context.Context, sess string, maxGen int64) error {
	if err := b.CleanupSession(ctx, sess, maxGen); err != nil {
		return err
	}
	return os.Remove(filepath.Join(b.sessDir(sess), "session.json"))
}

// CleanupSession removes instances, snapshots and artifacts but retains the
// session record. Operator removal uses it before waiting for project cleanup:
// a failed wait can then be retried, and late lifecycle Delete/Exists calls can
// still resolve the session's dataset. Down retires the record after settlement.
func (b *Backend) CleanupSession(ctx context.Context, sess string, maxGen int64) error {
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	var errs []error
	for g := int64(0); g <= maxGen; g++ {
		c := b.call(s, sbx, g, s.Spec)
		jid, jerr := b.OS.JID(c.Name())
		if jerr != nil {
			jid = 0
		}
		t := b.timer("down", sess, g, 0, 0)
		errs = append(errs, b.remove(ctx, c, jid, s.Spec, t))
	}
	snaps, err := b.snapshots(ctx, s, -1)
	errs = append(errs, err)
	for _, n := range snaps {
		_, err := b.OS.Zfs(ctx, nil, "destroy", n)
		errs = append(errs, err)
	}
	errs = append(errs, os.RemoveAll(filepath.Join(b.ArtDir, sess)))
	return errors.Join(errs...)
}

// ====================================================== lifecycle.Backend

// Quiesce stops every process of instance inst (graceful, then SIGKILL)
// and verifies none is left. The jail stays for the checkpoint; Destroy
// removes it. No jail: nothing runs, done.
func (b *Backend) Quiesce(ctx context.Context, sess string, inst int64) (err error) {
	t := b.timer("quiesce", sess, inst, 0, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	jid, jerr := b.OS.JID(jailName(sbx, sess, inst))
	if jerr != nil {
		t.info("jail", "absent")
		return nil
	}
	return b.stop(ctx, target{s, sbx, jid}, s.Spec, t)
}

// Unquiesce (the suspend abort path): SIGCONT what is still there, or
// start the service again in its jail and wait for readiness.
func (b *Backend) Unquiesce(ctx context.Context, sess string, inst int64) (err error) {
	t := b.timer("unquiesce", sess, inst, 0, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	jid, err := b.OS.JID(jailName(sbx, sess, inst))
	if err != nil {
		return fmt.Errorf("instance %d of %s is gone: %w", inst, sess, err)
	}
	ps, err := b.OS.Procs(jid)
	if err != nil {
		return err
	}
	if len(ps) > 0 {
		t.info("restart", false)
		_, err := b.signalUntil(ctx, target{s, sbx, jid}, "CONT", false, s.Spec.PauseWait.D())
		return err
	}
	t.info("restart", true)
	return b.withLock(ctx, func(lock *os.File) error {
		return b.startIn(ctx, s, sbx, inst, jid, s.Spec, lock, t)
	})
}

// Checkpoint takes the workspace snapshot and writes the artifact.
func (b *Backend) Checkpoint(ctx context.Context, sess string, gen, ckpt int64) (bytes int64, err error) {
	t := b.timer("checkpoint", sess, gen, ckpt, opID(ctx))
	defer t.done(&err)
	s, _, err := b.load(sess)
	if err != nil {
		return 0, err
	}
	snap := SnapName(s.Dataset, sess, gen, ckpt)
	err = b.withLock(ctx, func(lock *os.File) error {
		if _, err := b.OS.Zfs(ctx, lock, "snapshot", snap); err != nil {
			if !strings.Contains(err.Error(), "exists") {
				return err
			}
			t.info("existed", true) // a copy of this op took it
		}
		t.step("snapshot")
		out, err := b.OS.Zfs(ctx, lock, "get", "-Hp", "-o", "value", "written", snap)
		if err != nil {
			return err
		}
		if bytes, err = strconv.ParseInt(strings.TrimSpace(out), 10, 64); err != nil {
			return fmt.Errorf("written of %s: %q", snap, out)
		}
		t.step("written")
		n, err := b.writeArtifact(Artifact{Session: sess, Gen: gen, Ckpt: ckpt, Snapshot: snap, Spec: s.Spec,
			Created: b.now().UTC()})
		if err != nil {
			return err
		}
		t.step("artifact")
		t.info("snapshot_written", bytes)
		bytes += n
		return nil
	})
	t.info("snapshot", snap)
	return bytes, err
}

// CheckpointOK: the artifact verifies and its snapshot exists.
func (b *Backend) CheckpointOK(ctx context.Context, sess string, ckpt int64) (bool, error) {
	a, err := b.readArtifact(sess, ckpt)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "artifact") {
			return false, nil
		}
		return false, err
	}
	_, err = b.OS.Zfs(ctx, nil, "list", "-H", "-o", "name", "-t", "snapshot", a.Snapshot)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Destroy removes instance inst: jail_remove (which kills anything left;
// closing a jail descriptor would not), wait until its processes are gone,
// unmount and remove its root.
func (b *Backend) Destroy(ctx context.Context, sess string, inst int64) (err error) {
	t := b.timer("destroy", sess, inst, 0, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	c := b.call(s, sbx, inst, s.Spec)
	jid, jerr := b.OS.JID(c.Name())
	if jerr != nil {
		jid = 0
		t.info("jail", "absent")
	}
	return b.remove(ctx, c, jid, s.Spec, t)
}

// Restore starts instance gen from checkpoint ckpt: the artifact's spec on
// the same workspace. The name (session, gen) is create-only: if that jail
// exists, an earlier copy made it, and this is done.
//
// Decision 2 (2026-10-07): the workspace is not rolled back, and a
// workspace that changed since the checkpoint's snapshot (`written@snap`
// > 0, read after a `zpool sync`) is refused -- lifecycle.ErrRefused, before anything is created --
// unless force (the resume request's explicit override). Failing to read
// it is an error (unknown), never a guess. Check before writable mounting:
// mount-time ZIL housekeeping changes written@ without file edits. After
// acceptance, mount and validate the encrypted clone before creating a jail.
func (b *Backend) Restore(ctx context.Context, sess string, gen, ckpt int64, force bool) (err error) {
	t := b.timer("restore", sess, gen, ckpt, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	a, err := b.readArtifact(sess, ckpt)
	if err != nil {
		return err
	}
	if _, err := b.OS.JID(jailName(sbx, sess, gen)); err == nil {
		t.info("existed", true)
		return nil
	}
	// written@ counts only synced data: a write in the open txg (up to
	// zfs_txg_timeout, 5 s) would read as 0 without this sync
	// This pre-lock prefix creates no instance or mount; sync/property reads
	// are idempotent. Trusted host writers must not race the read-to-mount gap.
	pool, _, _ := strings.Cut(s.Dataset, "/")
	if err := b.OS.ZpoolSync(ctx, pool); err != nil {
		return fmt.Errorf("workspace drift of %s: %w", s.Dataset, err)
	}
	t.step("sync")
	out, err := b.OS.Zfs(ctx, nil, "get", "-Hp", "-o", "value", "written@"+strings.SplitN(a.Snapshot, "@", 2)[1], s.Dataset)
	if err != nil {
		return fmt.Errorf("workspace drift of %s: %w", s.Dataset, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return fmt.Errorf("workspace drift of %s: %q", s.Dataset, out)
	}
	t.info("drift_bytes", n)
	t.info("force", force)
	if n > 0 && !force {
		t.info("refused", true)
		return fmt.Errorf("%w: workspace %s changed since %s (%d bytes written); resume with the override to use it as it is",
			lifecycle.ErrRefused, s.Dataset, a.Snapshot, n)
	}
	spec := a.Spec
	spec.Defaults()
	return b.withLock(ctx, func(lock *os.File) error {
		// One op lock spans the mount, validation, start and readiness/cleanup.
		// A timeout/restart observer must not see a settled gap after mounting.
		if s.Project != "" {
			w, err := b.ws()
			if err != nil {
				return err
			}
			if s.Dataset != w.SessionDS(s.Project, sess) {
				return fmt.Errorf("session %s dataset %s is not its project clone", sess, s.Dataset)
			}
			if err := w.MountSession(ctx, lock, s.Project, sess); err != nil {
				return err
			}
			t.step("mount")
		}
		if err := b.checkDataset(ctx, s, sbx); err != nil {
			return err
		}
		t.step("artifact")
		return b.startNew(ctx, s, sbx, gen, spec, lock, t)
	})
}

// Instance: the jail of (session, name) exists; it runs if it has a process.
func (b *Backend) Instance(ctx context.Context, sess string, name int64) (exists, running bool, err error) {
	_, sbx, err := b.load(sess)
	if err != nil {
		return false, false, err
	}
	jid, jerr := b.OS.JID(jailName(sbx, sess, name))
	if jerr != nil {
		return false, false, nil
	}
	ps, err := b.OS.Procs(jid)
	return true, len(ps) > 0, err
}

// InFlight: a copy runs in this process, or a process started by a copy
// (zfs, the shim before it execs the service) still holds the op's lock --
// also one left by an earlier yard-ctl incarnation.
func (b *Backend) InFlight(ctx context.Context, op lifecycle.Op) (bool, error) {
	b.mu.Lock()
	n := b.inflight[op.ID]
	b.mu.Unlock()
	if n > 0 {
		return true, nil
	}
	return b.lockHeld(op.ID)
}

// ======================================================= lifecycle.Pauser

// Pause sends SIGSTOP to every process of the instance until all are
// stopped (new ones included) or PauseWait is over.
func (b *Backend) Pause(ctx context.Context, sess string, inst int64) (err error) {
	t := b.timer("pause", sess, inst, 0, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	jid, err := b.OS.JID(jailName(sbx, sess, inst))
	if err != nil {
		return fmt.Errorf("instance %d of %s is gone", inst, sess)
	}
	n, err := b.signalUntil(ctx, target{s, sbx, jid}, "STOP", true, s.Spec.PauseWait.D())
	t.info("procs", n)
	return err
}

// Unpause sends SIGCONT until no process of the instance is stopped.
func (b *Backend) Unpause(ctx context.Context, sess string, inst int64) (err error) {
	t := b.timer("unpause", sess, inst, 0, opID(ctx))
	defer t.done(&err)
	s, sbx, err := b.load(sess)
	if err != nil {
		return err
	}
	jid, err := b.OS.JID(jailName(sbx, sess, inst))
	if err != nil {
		return fmt.Errorf("instance %d of %s is gone", inst, sess)
	}
	n, err := b.signalUntil(ctx, target{s, sbx, jid}, "CONT", false, s.Spec.PauseWait.D())
	t.info("procs", n)
	return err
}

// Frozen: the instance exists, and it has processes, all stopped.
func (b *Backend) Frozen(ctx context.Context, sess string, inst int64) (exists, frozen bool, err error) {
	_, sbx, err := b.load(sess)
	if err != nil {
		return false, false, err
	}
	jid, jerr := b.OS.JID(jailName(sbx, sess, inst))
	if jerr != nil {
		return false, false, nil
	}
	ps, err := b.OS.Procs(jid)
	if err != nil {
		return true, false, err
	}
	for _, p := range ps {
		if !p.Stopped {
			return true, false, nil
		}
	}
	return true, len(ps) > 0, nil
}

// ================================================ lifecycle.ArtifactStore

// snapshots lists the workspace snapshots of checkpoint ckpt (-1: all) of
// the session.
func (b *Backend) snapshots(ctx context.Context, s *Session, ckpt int64) ([]string, error) {
	out, err := b.OS.Zfs(ctx, nil, "list", "-H", "-o", "name", "-t", "snapshot", "-d", "1", s.Dataset)
	if err != nil {
		return nil, err
	}
	var snaps []string
	for _, n := range strings.Fields(out) {
		if snapOf(n, s.ID, ckpt) {
			snaps = append(snaps, n)
		}
	}
	return snaps, nil
}

// Delete destroys checkpoint ckpt's snapshot and removes its artifact
// files (a partial temp file included). Idempotent.
func (b *Backend) Delete(ctx context.Context, sess string, ckpt int64) (err error) {
	t := b.timer("delete", sess, 0, ckpt, opID(ctx))
	defer t.done(&err)
	s, err := b.LoadSession(sess)
	if err != nil {
		return err
	}
	return b.withLock(ctx, func(lock *os.File) error {
		snaps, err := b.snapshots(ctx, s, ckpt)
		if err != nil {
			return err
		}
		for _, n := range snaps {
			if _, err := b.OS.Zfs(ctx, lock, "destroy", n); err != nil && !strings.Contains(err.Error(), "could not find") {
				return err
			}
		}
		t.step("snapshot")
		for _, f := range b.artFiles(sess, ckpt) {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		t.step("artifact")
		return nil
	})
}

// Exists: any file of the artifact, or its snapshot, is still there.
func (b *Backend) Exists(ctx context.Context, sess string, ckpt int64) (bool, error) {
	if len(b.artFiles(sess, ckpt)) > 0 {
		return true, nil
	}
	s, err := b.LoadSession(sess)
	if err != nil {
		return false, err
	}
	snaps, err := b.snapshots(ctx, s, ckpt)
	return len(snaps) > 0, err
}

// Encrypted: the artifact dataset is encrypted (Machine.Start refuses
// otherwise; Up checks each workspace dataset).
func (b *Backend) Encrypted(ctx context.Context) (bool, error) {
	out, err := b.OS.Zfs(ctx, nil, "get", "-H", "-o", "value", "encryption", b.ArtDS)
	if err != nil {
		return false, err
	}
	v := strings.TrimSpace(out)
	return v != "off" && v != "-" && v != "", nil
}

// ======================================================= lifecycle.Keys

func (b *Backend) ws() (*Workspaces, error) {
	if b.WS == nil {
		return nil, errors.New("no workspace tree configured")
	}
	return b.WS, nil
}

// LoadKey loads only the project key. Restore checks drift before mounting.
func (b *Backend) LoadKey(ctx context.Context, sess string) (err error) {
	t := b.timer("load_key", sess, 0, 0, opID(ctx))
	defer t.done(&err)
	s, err := b.LoadSession(sess)
	if err != nil {
		return err
	}
	w, err := b.ws()
	if err != nil {
		return err
	}
	if s.Project == "" {
		return fmt.Errorf("session %s has no project", sess)
	}
	return b.withLock(ctx, func(lock *os.File) error { return w.LoadProjectKey(ctx, lock, s.Project) })
}

func (b *Backend) KeyLoaded(ctx context.Context, sess string) (bool, error) {
	s, err := b.LoadSession(sess)
	if err != nil {
		return false, err
	}
	w, err := b.ws()
	if err != nil {
		return false, err
	}
	return w.ProjectKeyLoaded(ctx, s.Project)
}

// Unmount unmounts every dataset of the project.
func (b *Backend) Unmount(ctx context.Context, project string) (err error) {
	t := b.timer("unmount", project, 0, 0, opID(ctx))
	defer t.done(&err)
	w, err := b.ws()
	if err != nil {
		return err
	}
	return b.withLock(ctx, func(lock *os.File) error { return w.Unmount(ctx, lock, project) })
}

func (b *Backend) Unmounted(ctx context.Context, project string) (bool, error) {
	w, err := b.ws()
	if err != nil {
		return false, err
	}
	return w.Unmounted(ctx, project)
}

// UnloadKey unloads the project key.
func (b *Backend) UnloadKey(ctx context.Context, project string) (err error) {
	t := b.timer("unload_key", project, 0, 0, opID(ctx))
	defer t.done(&err)
	w, err := b.ws()
	if err != nil {
		return err
	}
	return b.withLock(ctx, func(lock *os.File) error { return w.UnloadKey(ctx, lock, project) })
}

func (b *Backend) KeyUnloaded(ctx context.Context, project string) (bool, error) {
	w, err := b.ws()
	if err != nil {
		return false, err
	}
	return w.KeyUnloaded(ctx, project)
}
