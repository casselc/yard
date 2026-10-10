package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"yard/internal/lifecycle"
)

// The SR1 decisions of 2026-10-07 on the backend and through the
// lifecycle: workspace keys (layout D), the drift refusal (decision 2) and
// the dead-instance detection (decision 3).

const projDS = "zroot/yard/ws/app"

// newProjRig is the backend rig with the session on a project clone
// (ws/app/web) in a fakeZFS that carries every zfs call.
func newProjRig(t *testing.T, b behavior) (*rig, *wsRig) {
	t.Helper()
	r := newRig(t, b)
	wr := newWSRig(t)
	wr.z.ds[testArt] = &fds{encryption: "aes-256-gcm", origin: "-", mounted: true}
	wr.project("app", "web")
	r.f.z = wr.z
	r.b.WS = wr.w
	r.s.Project, r.s.Dataset, r.s.Workspace = "app", projDS+"/web", "/yard/ws/app/web"
	return r, wr
}

// suspendBackend runs quiesce, checkpoint 2, destroy of instance 0.
func suspendBackend(t *testing.T, r *rig) {
	t.Helper()
	if err := r.b.Quiesce(opCtx(1), "web", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.b.Checkpoint(opCtx(2), "web", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Destroy(opCtx(3), "web", 0); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreRefusesDrift(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	suspendBackend(t, r)
	r.f.drift = 4096
	err := r.b.Restore(opCtx(4), "web", 1, 2, false)
	if !errors.Is(err, lifecycle.ErrRefused) || r.f.live(r.name(1)) != -1 || r.f.jailCount() != 0 {
		t.Fatalf("restore of a changed workspace: %v, jail %d", err, r.f.live(r.name(1)))
	}
	if tm := r.lastTiming("restore"); tm.Info["refused"] != true || tm.Info["drift_bytes"] != float64(4096) {
		t.Fatalf("timing %+v", tm)
	}
	// written@ is read after a txg sync of the pool
	r.f.mu.Lock()
	log := strings.Join(r.f.log, "\n")
	r.f.mu.Unlock()
	if i, j := strings.Index(log, "zpool sync zroot"), strings.Index(log, "written@"); i < 0 || j < i {
		t.Fatalf("no zpool sync before the drift read:\n%s", log)
	}
	// the override: resumed on the workspace as it is
	if err := r.b.Restore(opCtx(5), "web", 1, 2, true); err != nil {
		t.Fatal(err)
	}
	if r.f.live(r.name(1)) != 1 {
		t.Fatal("forced restore did not start the instance")
	}
}

// Failing to read the drift is unknown (an error), never a refusal or a go.
func TestRestoreDriftUnreadableIsUnknown(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	suspendBackend(t, r)
	r.f.zfsFail["get -Hp -o value written@"] = "fail"
	err := r.b.Restore(opCtx(4), "web", 1, 2, false)
	if err == nil || errors.Is(err, lifecycle.ErrRefused) || r.f.jailCount() != 0 {
		t.Fatalf("unreadable drift: %v jails %d", err, r.f.jailCount())
	}
}

// A restore onto an unmounted clone (the key not loaded) fails closed: the
// jail would otherwise nullfs-mount an empty directory.
func TestRestoreNeedsMountedClone(t *testing.T) {
	r, wr := newProjRig(t, behavior{listens: true})
	r.up()
	suspendBackend(t, r)
	ctx := context.Background()
	wr.w.Unmount(ctx, nil, "app")
	wr.w.UnloadKey(ctx, nil, "app")
	if err := r.b.Restore(opCtx(4), "web", 1, 2, false); err == nil || r.f.jailCount() != 0 {
		t.Fatalf("restore without the key: %v", err)
	}
	if err := r.b.LoadKey(opCtx(5), "web"); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.b.KeyLoaded(ctx, "web"); !ok || err != nil {
		t.Fatal("LoadKey not observed")
	}
	if err := r.b.Restore(opCtx(6), "web", 1, 2, false); err != nil {
		t.Fatal(err)
	}
}

func pollFor(t *testing.T, m *lifecycle.Machine, what string, cond func(c *lifecycle.Ctl) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond(m.State()) {
			return
		}
		m.Poll(context.Background())
		time.Sleep(time.Millisecond)
	}
	c := m.State()
	t.Fatalf("timed out waiting for %s: %+v %+v", what, c.Rows["web"], c.Projects)
}

func idleProject(c *lifecycle.Ctl) bool {
	p := c.Projects["app"]
	return settledOps(c) && p.Phase == lifecycle.KNone
}

// Layout D through the lifecycle: suspending the project's only session
// unmounts and unloads the key; the resume loads it and mounts the clone
// before the restore.
func TestLifecycleProjectKeyCycle(t *testing.T) {
	r, wr := newProjRig(t, behavior{listens: true})
	r.up()
	m, fx := machine(t, r, lifecycle.Policy{IdleAfter: 0, MaxAge: 3_600_000})
	if err := m.AddSession("web", "svc", lifecycle.KindService, "app"); err != nil {
		t.Fatal(err)
	}
	pollFor(t, m, "suspended, key unloaded", func(c *lifecycle.Ctl) bool {
		return c.Rows["web"].State == lifecycle.Suspended && idleProject(c) && !c.Projects["app"].Loaded
	})
	if loaded, mounted := wr.z.state(projDS + "/web"); loaded || mounted {
		t.Fatalf("after suspend: key loaded %v, clone mounted %v", loaded, mounted)
	}
	if len(fx.named("key_unloaded")) != 1 {
		t.Fatal("no key_unloaded fact")
	}
	if err := m.Resume("web", "msg", m.Token("web")); err != nil {
		t.Fatal(err)
	}
	pollFor(t, m, "active", func(c *lifecycle.Ctl) bool { return c.Rows["web"].State == lifecycle.Active })
	if loaded, mounted := wr.z.state(projDS + "/web"); !loaded || !mounted || r.f.live(r.name(1)) != 1 {
		t.Fatalf("after resume: key %v mounted %v instance %d", loaded, mounted, r.f.live(r.name(1)))
	}
	log := strings.Join(wr.z.log, "\n")
	if strings.Index(log, "load-key "+projDS) > strings.LastIndex(log, "written@") {
		t.Fatal("the restore read the workspace before the key was loaded")
	}
}

// Decision 2 through the lifecycle: a resume of a changed workspace is
// refused (recorded as Drift, fact resume_refused_drift), the session is
// suspended again with a fresh token and a held message does not retry it;
// the override resumes it.
func TestLifecycleDriftRefusedThenForced(t *testing.T) {
	r, wr := newProjRig(t, behavior{listens: true})
	r.up()
	m2, fx2 := machine(t, r, lifecycle.Policy{IdleAfter: 0, MaxAge: 3_600_000})
	m2.AddSession("web", "svc", lifecycle.KindService, "app")
	pollFor(t, m2, "suspended", func(c *lifecycle.Ctl) bool {
		return c.Rows["web"].State == lifecycle.Suspended && idleProject(c) && !c.Projects["app"].Loaded
	})
	ctx := context.Background()
	// something mounts the clone and writes to it while suspended
	if err := wr.w.LoadKey(ctx, nil, "app", "web"); err != nil {
		t.Fatal(err)
	}
	wr.z.write(projDS+"/web", 512)
	tok := m2.Token("web")
	if err := m2.Resume("web", "msg", tok); err != nil {
		t.Fatal(err)
	}
	pollFor(t, m2, "refused", func(c *lifecycle.Ctl) bool {
		return c.Rows["web"].State == lifecycle.Suspended && c.Rows["web"].Drift && settledOps(c)
	})
	if len(fx2.named("resume_refused_drift")) != 1 || r.f.jailCount() != 0 {
		t.Fatalf("refusal: facts %v jails %d", fx2.named("resume_refused_drift"), r.f.jailCount())
	}
	tok2 := m2.Token("web")
	if tok2 == 0 || tok2 == tok {
		t.Fatal("no fresh token")
	}
	// a held message does not retry a refused resume
	m2.Message("web")
	for i := 0; i < 20; i++ {
		m2.Poll(ctx)
	}
	if c := m2.State(); c.Rows["web"].State != lifecycle.Suspended || c.Rows["web"].Token != tok2 {
		t.Fatalf("auto-resumed after a refusal: %+v", c.Rows["web"])
	}
	if err := m2.ResumeWith("web", "msg", tok2, true); err != nil {
		t.Fatal(err)
	}
	pollFor(t, m2, "active (forced)", func(c *lifecycle.Ctl) bool { return c.Rows["web"].State == lifecycle.Active })
	if r.f.live(r.name(1)) != 1 {
		t.Fatal("forced resume: no instance")
	}
}

// Decision 3: the probe finds the instance alive while it runs; once its
// jail is gone the session fails (fact lost); nothing else fails it.
func TestLifecycleLostDetected(t *testing.T) {
	r := newRig(t, behavior{listens: true})
	r.up()
	m, fx := machineWith(t, r, lifecycle.Policy{KeepWarm: true, MaxAge: 3_600_000}, 5)
	m.AddSession("web", "svc", lifecycle.KindService, "")
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		m.Poll(context.Background())
		time.Sleep(time.Millisecond)
	}
	if st := m.State().Rows["web"].State; (st != lifecycle.Active && st != lifecycle.Idle) || len(fx.named("lost")) != 0 {
		t.Fatalf("a live instance was declared lost: %s", st)
	}
	jid, err := r.f.JID(r.name(0))
	if err != nil {
		t.Fatal(err)
	}
	r.f.RemoveJail(jid) // the instance dies (OOM, a crash, an operator)
	t0 := time.Now()
	pollFor(t, m, "lost", func(c *lifecycle.Ctl) bool { return c.Rows["web"].State == lifecycle.Failed })
	if len(fx.named("lost")) != 1 {
		t.Fatal("no lost fact")
	}
	t.Logf("detected in %s", time.Since(t0))
}
