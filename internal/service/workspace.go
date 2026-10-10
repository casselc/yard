package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"yard/internal/wskey"
)

// Workspace layout (decided 2026-10-07; CONTROL-PLANE.md "Workspace
// layout"):
//
//	zroot/yard/ws                  its own encryption root (key file on the
//	                               data root), exec=on setuid=off
//	                               compression=zstd atime=off; /yard/ws
//	ws/<project>                   an encryption root of its own: keyformat=raw,
//	                               keylocation=prompt, the key held (wrapped) by
//	                               yard-ctl (internal/wskey). Holds the checked-out
//	                               base: canmount=noauto, mounted at
//	                               /yard/ws/<project>/.base only while it is
//	                               populated; snapshots @base-<n>.
//	ws/<project>/<session>         a clone of @base-<n> with a refquota, mounted
//	                               at /yard/ws/<project>/<session>; the session's
//	                               suspend snapshots are taken on it.
//
// Clones inherit the project's key: the project key is loaded while any
// session of the project is active or resuming and unloaded (unmount, then
// unload-key) once none is (the lifecycle's KeyUnloadBegin). Destroying the
// project's key is the crypto-shred of the project.
//
// ZFS dependency rules handled here: a snapshot with clones cannot be
// destroyed (RetireBase defers it, `zfs destroy -d`, or promotes a clone);
// a promoted session holds the base snapshot, so DestroySession promotes
// the project back first.

// ZFS runs zfs(8); ZfsIn feeds stdin (a raw key for create / load-key).
type ZFS interface {
	Zfs(ctx context.Context, lock *os.File, args ...string) (string, error)
	ZfsIn(ctx context.Context, lock *os.File, stdin []byte, args ...string) (string, error)
}

// KeySource returns a project's raw key (wskey.Store).
type KeySource interface {
	Key(consumer, subject string) ([]byte, int64, error)
}

// Workspaces manages the ws tree.
type Workspaces struct {
	Z    ZFS
	Root string // zroot/yard/ws
	Mnt  string // /yard/ws
	Keys KeySource
}

var projRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func checkProject(p string) error {
	if !projRe.MatchString(p) {
		return fmt.Errorf("project %q: want [a-z][a-z0-9-]{0,31}", p)
	}
	return nil
}

func (w *Workspaces) ProjectDS(p string) string         { return w.Root + "/" + p }
func (w *Workspaces) SessionDS(p, s string) string      { return w.Root + "/" + p + "/" + s }
func (w *Workspaces) BaseMnt(p string) string           { return w.Mnt + "/" + p + "/.base" }
func (w *Workspaces) SessionMnt(p, s string) string     { return w.Mnt + "/" + p + "/" + s }
func baseSnap(ds string, gen int64) string              { return fmt.Sprintf("%s@base-%d", ds, gen) }
func (w *Workspaces) BaseSnap(p string, g int64) string { return baseSnap(w.ProjectDS(p), g) }

func (w *Workspaces) get(ctx context.Context, prop, ds string) (string, error) {
	out, err := w.Z.Zfs(ctx, nil, "get", "-H", "-o", "value", prop, ds)
	return strings.TrimSpace(out), err
}

// CreateProject makes ws/<project>, an encryption root with the raw key
// key (from wskey.Store.Create), and mounts its base for populating.
func (w *Workspaces) CreateProject(ctx context.Context, p string, key []byte) error {
	if err := checkProject(p); err != nil {
		return err
	}
	if len(key) != 32 {
		return errors.New("workspace key must be 32 raw bytes")
	}
	ds := w.ProjectDS(p)
	if _, err := w.Z.ZfsIn(ctx, nil, key, "create", "-o", "encryption=aes-256-gcm", "-o", "keyformat=raw",
		"-o", "keylocation=prompt", "-o", "canmount=noauto", "-o", "mountpoint="+w.BaseMnt(p), ds); err != nil {
		return err
	}
	_, err := w.Z.Zfs(ctx, nil, "mount", ds)
	return err
}

// MountBase mounts the project's base (to update it before the next
// SnapshotBase); the key must be loaded.
func (w *Workspaces) MountBase(ctx context.Context, p string) error {
	if m, err := w.get(ctx, "mounted", w.ProjectDS(p)); err != nil || m == "yes" {
		return err
	}
	_, err := w.Z.Zfs(ctx, nil, "mount", w.ProjectDS(p))
	return err
}

// BaseGens lists the project's base snapshot generations, oldest first.
func (w *Workspaces) BaseGens(ctx context.Context, p string) ([]int64, error) {
	out, err := w.Z.Zfs(ctx, nil, "list", "-H", "-o", "name", "-t", "snapshot", "-d", "1", w.ProjectDS(p))
	if err != nil {
		return nil, err
	}
	var gens []int64
	for _, n := range strings.Fields(out) {
		if _, short, ok := strings.Cut(n, "@base-"); ok {
			if g, err := strconv.ParseInt(short, 10, 64); err == nil {
				gens = append(gens, g)
			}
		}
	}
	slices.Sort(gens)
	return gens, nil
}

// SnapshotBase unmounts the base and takes the next @base-<n>.
func (w *Workspaces) SnapshotBase(ctx context.Context, p string) (int64, error) {
	ds := w.ProjectDS(p)
	gens, err := w.BaseGens(ctx, p)
	if err != nil {
		return 0, err
	}
	// generations never repeat, also after old ones were destroyed: the
	// counter is a user property of the project (yard:basegen)
	g := int64(1)
	if len(gens) > 0 {
		g = gens[len(gens)-1] + 1
	}
	if v, err := w.get(ctx, "yard:basegen", ds); err == nil {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= g {
			g = n + 1
		}
	}
	if _, err := w.Z.Zfs(ctx, nil, "set", "yard:basegen="+strconv.FormatInt(g, 10), ds); err != nil {
		return 0, err
	}
	if m, err := w.get(ctx, "mounted", ds); err != nil {
		return 0, err
	} else if m == "yes" {
		if _, err := w.Z.Zfs(ctx, nil, "unmount", ds); err != nil {
			return 0, err
		}
	}
	_, err = w.Z.Zfs(ctx, nil, "snapshot", baseSnap(ds, g))
	return g, err
}

// CloneSession makes ws/<project>/<session> from @base-<gen> (0: the
// newest), with a refquota ("" none), mounted at its own mountpoint.
func (w *Workspaces) CloneSession(ctx context.Context, p, s string, gen int64, refquota string) error {
	if err := checkProject(p); err != nil {
		return err
	}
	if !sessRe.MatchString(s) {
		return fmt.Errorf("session id %q", s)
	}
	if gen == 0 {
		gens, err := w.BaseGens(ctx, p)
		if err != nil {
			return err
		}
		if len(gens) == 0 {
			return fmt.Errorf("project %s has no base snapshot", p)
		}
		gen = gens[len(gens)-1]
	}
	args := []string{"clone", "-o", "mountpoint=" + w.SessionMnt(p, s)}
	if refquota != "" {
		args = append(args, "-o", "refquota="+refquota)
	}
	_, err := w.Z.Zfs(ctx, nil, append(args, w.BaseSnap(p, gen), w.SessionDS(p, s))...)
	return err
}

// DestroySession destroys a session clone and its snapshots. If the
// session was promoted (it holds base snapshots the project depends on),
// the project is promoted back first.
func (w *Workspaces) DestroySession(ctx context.Context, p, s string) error {
	ds := w.SessionDS(p, s)
	origin, err := w.get(ctx, "origin", ds)
	if err != nil {
		return err
	}
	if origin == "-" || origin == "" {
		porigin, err := w.get(ctx, "origin", w.ProjectDS(p))
		if err != nil {
			return err
		}
		if strings.HasPrefix(porigin, ds+"@") {
			if _, err := w.Z.Zfs(ctx, nil, "promote", w.ProjectDS(p)); err != nil {
				return fmt.Errorf("promote %s back before destroying %s: %w", w.ProjectDS(p), ds, err)
			}
		}
	}
	_, err = w.Z.Zfs(ctx, nil, "destroy", "-r", ds)
	return err
}

// RetireBase retires @base-<gen>: destroyed if it has no clones; with
// live clones, marked for deferred destruction (`zfs destroy -d`: gone with
// its last clone) -- or, with promote, the newest clone is promoted so it
// holds the snapshot (only for the oldest base generation: a promote moves
// every older snapshot too). It returns what it did.
func (w *Workspaces) RetireBase(ctx context.Context, p string, gen int64, promote bool) (string, error) {
	snap := w.BaseSnap(p, gen)
	clones, err := w.get(ctx, "clones", snap)
	if err != nil {
		return "", err
	}
	if clones == "" || clones == "-" {
		_, err := w.Z.Zfs(ctx, nil, "destroy", snap)
		return "destroyed", err
	}
	if !promote {
		_, err := w.Z.Zfs(ctx, nil, "destroy", "-d", snap)
		return "deferred", err
	}
	gens, err := w.BaseGens(ctx, p)
	if err != nil {
		return "", err
	}
	if len(gens) == 0 || gens[0] != gen {
		return "", fmt.Errorf("promote: @base-%d is not the oldest base snapshot of %s (a promote would move the older ones too)", gen, p)
	}
	cl := strings.Split(clones, ",")
	slices.Sort(cl)
	newest := cl[len(cl)-1]
	if _, err := w.Z.Zfs(ctx, nil, "promote", newest); err != nil {
		return "", err
	}
	return "promoted:" + newest, nil
}

// ---------------------------------------------------- key load / unload

// LoadProjectKey loads only the project key. Resume must not writable-mount
// the clone before checking drift: ZIL housekeeping can itself dirty it.
func (w *Workspaces) LoadProjectKey(ctx context.Context, lock *os.File, p string) error {
	ds := w.ProjectDS(p)
	ks, err := w.get(ctx, "keystatus", ds)
	if err != nil {
		return err
	}
	if ks != "available" {
		key, _, err := w.Keys.Key(wskey.ConsumerZFS, p)
		if err != nil {
			return err
		}
		_, lerr := w.Z.ZfsIn(ctx, lock, key, "load-key", ds)
		clear(key)
		if lerr != nil && !strings.Contains(lerr.Error(), "already loaded") {
			return lerr
		}
	}
	return nil
}

// MountSession mounts the clone after the caller's drift check.
func (w *Workspaces) MountSession(ctx context.Context, lock *os.File, p, s string) error {
	sds := w.SessionDS(p, s)
	if m, err := w.get(ctx, "mounted", sds); err != nil {
		return err
	} else if m != "yes" {
		if _, err := w.Z.Zfs(ctx, lock, "mount", sds); err != nil {
			return err
		}
	}
	return nil
}

// LoadKey is the explicit workspace-admin operation: load and mount.
// Lifecycle resume instead calls LoadProjectKey, then mounts in Restore.
func (w *Workspaces) LoadKey(ctx context.Context, lock *os.File, p, s string) error {
	if err := w.LoadProjectKey(ctx, lock, p); err != nil {
		return err
	}
	return w.MountSession(ctx, lock, p, s)
}

// ProjectKeyLoaded observes the key-only lifecycle load operation.
func (w *Workspaces) ProjectKeyLoaded(ctx context.Context, p string) (bool, error) {
	ks, err := w.get(ctx, "keystatus", w.ProjectDS(p))
	return ks == "available", err
}

// KeyLoaded observes LoadKey.
func (w *Workspaces) KeyLoaded(ctx context.Context, p, s string) (bool, error) {
	ks, err := w.get(ctx, "keystatus", w.ProjectDS(p))
	if err != nil {
		return false, err
	}
	m, err := w.get(ctx, "mounted", w.SessionDS(p, s))
	return ks == "available" && m == "yes", err
}

// mountedDS lists the mounted datasets of the project, deepest first.
func (w *Workspaces) mountedDS(ctx context.Context, p string) ([]string, error) {
	out, err := w.Z.Zfs(ctx, nil, "list", "-H", "-r", "-t", "filesystem", "-o", "name,mounted", w.ProjectDS(p))
	if err != nil {
		return nil, err
	}
	var ms []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[1] == "yes" {
			ms = append(ms, f[0])
		}
	}
	slices.SortFunc(ms, func(a, b string) int { return strings.Count(b, "/") - strings.Count(a, "/") })
	return ms, nil
}

// Unmount unmounts every dataset of the project (never forced: a busy
// dataset is an error, and the op is not done).
func (w *Workspaces) Unmount(ctx context.Context, lock *os.File, p string) error {
	ms, err := w.mountedDS(ctx, p)
	if err != nil {
		return err
	}
	for _, ds := range ms {
		if _, err := w.Z.Zfs(ctx, lock, "unmount", ds); err != nil {
			return err
		}
	}
	return nil
}

// Unmounted observes Unmount.
func (w *Workspaces) Unmounted(ctx context.Context, p string) (bool, error) {
	ms, err := w.mountedDS(ctx, p)
	return len(ms) == 0, err
}

// UnloadKey unloads the project key (ZFS refuses while anything is mounted).
func (w *Workspaces) UnloadKey(ctx context.Context, lock *os.File, p string) error {
	ks, err := w.get(ctx, "keystatus", w.ProjectDS(p))
	if err != nil || ks != "available" {
		return err
	}
	_, err = w.Z.Zfs(ctx, lock, "unload-key", w.ProjectDS(p))
	return err
}

// KeyUnloaded observes UnloadKey.
func (w *Workspaces) KeyUnloaded(ctx context.Context, p string) (bool, error) {
	ks, err := w.get(ctx, "keystatus", w.ProjectDS(p))
	return ks == "unavailable", err
}

// Shredder deletes a project's wrapped key (wskey.Store.Shred).
type Shredder interface {
	Shred(consumer, subject string, now int64) error
}

// ShredProject is the crypto-shred of a project: everything unmounted and
// the key unloaded (both observed), then the wrapped key deleted, then the
// datasets destroyed. The caller makes sure no session of the project is
// active and no key load of it can still land (spec/keys).
func (w *Workspaces) ShredProject(ctx context.Context, p string, sh Shredder, now int64) error {
	if err := w.Unmount(ctx, nil, p); err != nil {
		return err
	}
	if err := w.UnloadKey(ctx, nil, p); err != nil {
		return err
	}
	if ok, err := w.KeyUnloaded(ctx, p); err != nil || !ok {
		return fmt.Errorf("project %s: key still loaded (%v)", p, err)
	}
	if err := sh.Shred(wskey.ConsumerZFS, p, now); err != nil {
		return err
	}
	_, err := w.Z.Zfs(ctx, nil, "destroy", "-R", w.ProjectDS(p))
	return err
}
