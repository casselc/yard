package service

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yard/internal/wskey"
)

const wsRoot = "zroot/yard/ws"

type wsRig struct {
	t    *testing.T
	z    *fakeZFS
	keys *wskey.Store
	w    *Workspaces
}

func newWSRig(t *testing.T) *wsRig {
	t.Helper()
	dir := t.TempDir()
	kp := filepath.Join(dir, "kek")
	k := make([]byte, 32)
	rand.Read(k)
	if err := os.WriteFile(kp, k, 0o400); err != nil {
		t.Fatal(err)
	}
	kek, err := wskey.KEKFromFile(kp)
	if err != nil {
		t.Fatal(err)
	}
	st, err := wskey.Open(filepath.Join(dir, "yard.db"), kek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	z := newFakeZFS(wsRoot)
	return &wsRig{t: t, z: z, keys: st, w: &Workspaces{Z: z, Root: wsRoot, Mnt: "/yard/ws", Keys: st}}
}

// project creates project p with a base @base-1 and the given sessions.
func (r *wsRig) project(p string, sessions ...string) {
	r.t.Helper()
	ctx := context.Background()
	key, _, err := r.keys.Create(wskey.ConsumerZFS, p, 1)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.w.CreateProject(ctx, p, key); err != nil {
		r.t.Fatal(err)
	}
	if _, m := r.z.state(r.w.ProjectDS(p)); !m {
		r.t.Fatal("base not mounted for populating")
	}
	if g, err := r.w.SnapshotBase(ctx, p); err != nil || g != 1 {
		r.t.Fatalf("base: %d %v", g, err)
	}
	for _, s := range sessions {
		if err := r.w.CloneSession(ctx, p, s, 0, "1G"); err != nil {
			r.t.Fatal(err)
		}
	}
}

func TestWorkspaceLayout(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web", "kill")
	d := r.z.ds["zroot/yard/ws/app"]
	if !d.encRoot || d.canmount != "noauto" || d.mountpoint != "/yard/ws/app/.base" || d.mounted {
		t.Fatalf("project root %+v", d)
	}
	if !r.z.exists("zroot/yard/ws/app@base-1") {
		t.Fatal("no @base-1")
	}
	w := r.z.ds["zroot/yard/ws/app/web"]
	if w.origin != "zroot/yard/ws/app@base-1" || w.mountpoint != "/yard/ws/app/web" || w.refquota != "1G" || !w.mounted {
		t.Fatalf("session clone %+v", w)
	}
	if ok, err := r.w.KeyLoaded(ctx, "app", "web"); !ok || err != nil {
		t.Fatalf("key loaded: %v %v", ok, err)
	}
	// a second base generation; new clones take the newest
	if err := r.w.MountBase(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	if g, err := r.w.SnapshotBase(ctx, "app"); g != 2 || err != nil {
		t.Fatalf("base 2: %d %v", g, err)
	}
	if err := r.w.CloneSession(ctx, "app", "new", 0, ""); err != nil {
		t.Fatal(err)
	}
	if o := r.z.ds["zroot/yard/ws/app/new"].origin; o != "zroot/yard/ws/app@base-2" {
		t.Fatalf("new clone from %s", o)
	}
	if err := r.w.CloneSession(ctx, "Bad", "x", 0, ""); err == nil {
		t.Fatal("bad project name accepted")
	}
}

func TestWorkspaceKeyCycle(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web", "kill")
	// unload-key refuses while a dataset is mounted (ZFS), so Unmount first
	if err := r.w.UnloadKey(ctx, nil, "app"); err == nil {
		t.Fatal("unload-key with mounted clones succeeded")
	}
	// a busy clone (a jail's nullfs mount): the unmount is an error, not done
	r.z.busy["zroot/yard/ws/app/web"] = true
	if err := r.w.Unmount(ctx, nil, "app"); err == nil {
		t.Fatal("unmount of a busy clone succeeded")
	}
	if ok, _ := r.w.Unmounted(ctx, "app"); ok {
		t.Fatal("observed unmounted with a busy clone")
	}
	delete(r.z.busy, "zroot/yard/ws/app/web")
	if err := r.w.Unmount(ctx, nil, "app"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.w.Unmounted(ctx, "app"); !ok {
		t.Fatal("not unmounted")
	}
	if err := r.w.UnloadKey(ctx, nil, "app"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.w.KeyUnloaded(ctx, "app"); !ok {
		t.Fatal("key still loaded")
	}
	// idempotent: unloading again is done
	if err := r.w.UnloadKey(ctx, nil, "app"); err != nil {
		t.Fatal(err)
	}
	// no clone can be made or mounted without the key
	if err := r.w.CloneSession(ctx, "app", "x", 1, ""); err == nil {
		t.Fatal("clone without the key")
	}
	// load: the key comes from the wrapped store on stdin; only web mounts
	if err := r.w.LoadKey(ctx, nil, "app", "web"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.w.KeyLoaded(ctx, "app", "web"); !ok {
		t.Fatal("not loaded/mounted")
	}
	if _, m := r.z.state("zroot/yard/ws/app/kill"); m {
		t.Fatal("kill's clone mounted by web's load")
	}
	// idempotent: loading again is done (already loaded, already mounted)
	if err := r.w.LoadKey(ctx, nil, "app", "web"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.z.log, "\n"), "zfs load-key zroot/yard/ws/app") {
		t.Fatal("no load-key")
	}
}

func TestWorkspaceWrongKeyRefused(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web")
	r.w.Unmount(ctx, nil, "app")
	r.w.UnloadKey(ctx, nil, "app")
	// the stored key is shredded and replaced (another version): ZFS refuses it
	r.keys.Shred(wskey.ConsumerZFS, "app", 2)
	if _, _, err := r.keys.Create(wskey.ConsumerZFS, "app", 3); err != nil {
		t.Fatal(err)
	}
	if err := r.w.LoadKey(ctx, nil, "app", "web"); err == nil || !strings.Contains(err.Error(), "Incorrect key") {
		t.Fatalf("load with another key: %v", err)
	}
}

func TestWorkspaceRetireBase(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web", "kill")
	// with live clones a base snapshot cannot be destroyed: deferred
	if what, err := r.w.RetireBase(ctx, "app", 1, false); err != nil || what != "deferred" {
		t.Fatalf("retire: %s %v", what, err)
	}
	if !r.z.exists("zroot/yard/ws/app@base-1") {
		t.Fatal("deferred snapshot destroyed early")
	}
	if err := r.w.DestroySession(ctx, "app", "web"); err != nil {
		t.Fatal(err)
	}
	if !r.z.exists("zroot/yard/ws/app@base-1") {
		t.Fatal("deferred snapshot destroyed with a clone left")
	}
	if err := r.w.DestroySession(ctx, "app", "kill"); err != nil {
		t.Fatal(err)
	}
	if r.z.exists("zroot/yard/ws/app@base-1") {
		t.Fatal("deferred snapshot outlived its last clone")
	}
	// no clones: destroyed at once
	r.w.MountBase(ctx, "app")
	r.w.SnapshotBase(ctx, "app")
	if what, err := r.w.RetireBase(ctx, "app", 2, false); err != nil || what != "destroyed" {
		t.Fatalf("retire: %s %v (generations must not repeat after base-1 is gone)", what, err)
	}
}

func TestWorkspacePromote(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web", "kill")
	r.w.MountBase(ctx, "app")
	r.w.SnapshotBase(ctx, "app") // base-2
	if err := r.w.CloneSession(ctx, "app", "s2", 2, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.w.RetireBase(ctx, "app", 2, true); err == nil {
		t.Fatal("promote of a base with an older generation was allowed")
	}
	what, err := r.w.RetireBase(ctx, "app", 1, true)
	if err != nil || what != "promoted:zroot/yard/ws/app/web" {
		t.Fatalf("promote: %s %v", what, err)
	}
	if r.z.exists("zroot/yard/ws/app@base-1") || !r.z.exists("zroot/yard/ws/app/web@base-1") {
		t.Fatal("the snapshot did not move to the promoted clone")
	}
	if o := r.z.ds["zroot/yard/ws/app/kill"].origin; o != "zroot/yard/ws/app/web@base-1" {
		t.Fatalf("kill's origin %s", o)
	}
	// destroying the promoted session promotes the project back first
	if err := r.w.DestroySession(ctx, "app", "kill"); err != nil {
		t.Fatal(err)
	}
	if err := r.w.DestroySession(ctx, "app", "web"); err != nil {
		t.Fatal(err)
	}
	if !r.z.exists("zroot/yard/ws/app@base-1") || r.z.exists("zroot/yard/ws/app/web") {
		t.Fatal("promote back + destroy")
	}
}

func TestWorkspaceShred(t *testing.T) {
	r := newWSRig(t)
	ctx := context.Background()
	r.project("app", "web")
	if err := r.w.ShredProject(ctx, "app", r.keys, 9); err != nil {
		t.Fatal(err)
	}
	if r.z.exists("zroot/yard/ws/app") || r.z.exists("zroot/yard/ws/app/web") {
		t.Fatal("datasets left")
	}
	if _, _, err := r.keys.Key(wskey.ConsumerZFS, "app"); !errors.Is(err, wskey.ErrNoKey) {
		t.Fatalf("key after shred: %v", err)
	}
	// a busy clone stops the shred before the key goes
	r.project("b2", "web")
	r.z.busy["zroot/yard/ws/b2/web"] = true
	if err := r.w.ShredProject(ctx, "b2", r.keys, 10); err == nil {
		t.Fatal("shred with a busy clone")
	}
	if _, _, err := r.keys.Key(wskey.ConsumerZFS, "b2"); err != nil {
		t.Fatal("the key was shredded although the data was still mounted")
	}
}
