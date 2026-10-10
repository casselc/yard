package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// fakeZFS is an in-memory zfs(8) with the rules the workspace layout
// depends on: encryption roots with raw keys read from stdin (keylocation
// prompt), keystatus, mount needing the key, unload-key refusing while a
// dataset of the root is mounted, an unmount refusing a busy dataset,
// clones inheriting the origin's encryption root, a snapshot with clones
// not destroyable (unless deferred, -d: gone with its last clone), promote
// moving the origin's snapshots up to the clone's origin, written@snap
// counting writes since the snapshot.
type fakeZFS struct {
	mu    sync.Mutex
	ds    map[string]*fds
	snaps map[string]*fsnap
	busy  map[string]bool // dataset -> an unmount fails (a jail's nullfs mount holds it)
	txg   int
	log   []string
	fail  map[string]string // command prefix -> "fail" | "lost", once
}

type fds struct {
	encRoot    bool
	key        []byte // on an encryption root
	loaded     bool   // on an encryption root
	encryption string
	mounted    bool
	mountpoint string
	canmount   string
	origin     string
	refquota   string
	writes     int64 // bytes written so far
	user       map[string]string
}

type fsnap struct {
	txg    int
	writes int64 // the dataset's writes at the snapshot
	defer_ bool
}

func newFakeZFS(root string) *fakeZFS {
	z := &fakeZFS{ds: map[string]*fds{}, snaps: map[string]*fsnap{}, busy: map[string]bool{}, fail: map[string]string{}}
	z.ds[root] = &fds{encRoot: true, loaded: true, encryption: "aes-256-gcm", mounted: true, mountpoint: "/yard/ws",
		canmount: "on", origin: "-"}
	return z
}

func (z *fakeZFS) Zfs(ctx context.Context, lock *os.File, args ...string) (string, error) {
	return z.ZfsIn(ctx, lock, nil, args...)
}

func (z *fakeZFS) ZfsIn(_ context.Context, _ *os.File, stdin []byte, args ...string) (string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	cmd := strings.Join(args, " ")
	z.log = append(z.log, "zfs "+cmd)
	mode := ""
	for p, m := range z.fail {
		if strings.HasPrefix(cmd, p) {
			mode = m
			delete(z.fail, p)
		}
	}
	if mode == "fail" {
		return "", fmt.Errorf("zfs %s: injected failure", cmd)
	}
	out, err := z.run(stdin, args)
	if err != nil {
		return out, fmt.Errorf("zfs %s: %v", cmd, err)
	}
	if mode == "lost" {
		return "", fmt.Errorf("zfs %s: answer lost (applied)", cmd)
	}
	return out, nil
}

// encRootOf is the dataset's encryption root.
func (z *fakeZFS) encRootOf(name string) *fds {
	for n := name; n != ""; {
		if d := z.ds[n]; d != nil && d.encRoot {
			return d
		}
		i := strings.LastIndex(n, "/")
		if i < 0 {
			return nil
		}
		n = n[:i]
	}
	return nil
}

func (z *fakeZFS) parent(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i]
	}
	return ""
}

func opts(args []string) (map[string]string, []string) {
	o := map[string]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" && i+1 < len(args) {
			k, v, _ := strings.Cut(args[i+1], "=")
			o[k] = v
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return o, rest
}

func (z *fakeZFS) clones(snap string) []string {
	var cl []string
	for n, d := range z.ds {
		if d.origin == snap {
			cl = append(cl, n)
		}
	}
	slices.Sort(cl)
	return cl
}

func (z *fakeZFS) run(stdin []byte, a []string) (string, error) {
	switch a[0] {
	case "create":
		o, rest := opts(a[1:])
		name := rest[len(rest)-1]
		if z.ds[name] != nil {
			return "", fmt.Errorf("dataset already exists")
		}
		if z.ds[z.parent(name)] == nil {
			return "", fmt.Errorf("parent does not exist")
		}
		d := &fds{origin: "-", canmount: "on", mountpoint: o["mountpoint"]}
		if v, ok := o["canmount"]; ok {
			d.canmount = v
		}
		if o["encryption"] != "" {
			if o["keyformat"] != "raw" || len(stdin) != 32 {
				return "", fmt.Errorf("raw key must be 32 bytes on stdin")
			}
			d.encRoot, d.key, d.loaded, d.encryption = true, bytes.Clone(stdin), true, o["encryption"]
		} else if r := z.encRootOf(z.parent(name)); r != nil {
			d.encryption = r.encryption
		}
		z.ds[name] = d
		if d.canmount == "on" && d.mountpoint != "" {
			d.mounted = true
		}
	case "mount":
		d := z.ds[a[1]]
		if d == nil {
			return "", fmt.Errorf("dataset does not exist")
		}
		if r := z.encRootOf(a[1]); r != nil && !r.loaded {
			return "", fmt.Errorf("encryption key not loaded")
		}
		if d.mounted {
			return "", fmt.Errorf("filesystem already mounted")
		}
		d.mounted = true
	case "unmount":
		force := a[1] == "-f"
		if force {
			a = a[1:]
		}
		d := z.ds[a[1]]
		if d == nil || !d.mounted {
			return "", fmt.Errorf("not currently mounted")
		}
		if z.busy[a[1]] && !force {
			return "", fmt.Errorf("unmount failed: Device busy")
		}
		d.mounted = false
	case "load-key":
		d := z.ds[a[1]]
		if d == nil || !d.encRoot {
			return "", fmt.Errorf("not an encryption root")
		}
		if d.loaded {
			return "", fmt.Errorf("Key already loaded for '%s'", a[1])
		}
		if !bytes.Equal(stdin, d.key) {
			return "", fmt.Errorf("Incorrect key provided for '%s'", a[1])
		}
		d.loaded = true
	case "unload-key":
		d := z.ds[a[1]]
		if d == nil || !d.encRoot || !d.loaded {
			return "", fmt.Errorf("key unavailable")
		}
		for n, x := range z.ds {
			if x.mounted && z.encRootOf(n) == d {
				return "", fmt.Errorf("'%s' is busy", n)
			}
		}
		d.loaded = false
	case "snapshot":
		ds, _, _ := strings.Cut(a[1], "@")
		d := z.ds[ds]
		if d == nil {
			return "", fmt.Errorf("dataset does not exist")
		}
		if z.snaps[a[1]] != nil {
			return "", fmt.Errorf("cannot create snapshot '%s': dataset already exists", a[1])
		}
		z.txg++
		z.snaps[a[1]] = &fsnap{txg: z.txg, writes: d.writes}
	case "clone":
		o, rest := opts(a[1:])
		src, name := rest[0], rest[1]
		if z.snaps[src] == nil {
			return "", fmt.Errorf("snapshot does not exist")
		}
		if z.ds[name] != nil {
			return "", fmt.Errorf("dataset already exists")
		}
		r := z.encRootOf(strings.SplitN(src, "@", 2)[0])
		if r != nil && !r.loaded {
			return "", fmt.Errorf("encryption key not loaded")
		}
		if pr := z.encRootOf(z.parent(name)); pr != r {
			return "", fmt.Errorf("clone must stay in the origin's encryption root")
		}
		origDS := z.ds[strings.SplitN(src, "@", 2)[0]]
		z.ds[name] = &fds{origin: src, canmount: "on", mountpoint: o["mountpoint"], refquota: o["refquota"],
			mounted: o["mountpoint"] != "", encryption: origDS.encryption, writes: z.snaps[src].writes}
	case "destroy":
		return "", z.destroy(a[1:])
	case "promote":
		return "", z.promote(a[1])
	case "set":
		d := z.ds[a[2]]
		k, v, _ := strings.Cut(a[1], "=")
		if d == nil || !strings.Contains(k, ":") {
			return "", fmt.Errorf("fake zfs set: %v", a)
		}
		if d.user == nil {
			d.user = map[string]string{}
		}
		d.user[k] = v
	case "get":
		return z.get(a[1:])
	case "list":
		return z.list(a[1:])
	default:
		return "", fmt.Errorf("fake zfs: %v", a)
	}
	return "", nil
}

func (z *fakeZFS) destroy(a []string) error {
	deferred, rec := false, false
	for len(a) > 1 && strings.HasPrefix(a[0], "-") {
		deferred = deferred || a[0] == "-d"
		rec = rec || a[0] == "-r" || a[0] == "-R"
		a = a[1:]
	}
	name := a[0]
	if strings.Contains(name, "@") {
		s := z.snaps[name]
		if s == nil {
			return fmt.Errorf("could not find any snapshots to destroy")
		}
		if len(z.clones(name)) > 0 {
			if deferred {
				s.defer_ = true
				return nil
			}
			return fmt.Errorf("snapshot has dependent clones")
		}
		delete(z.snaps, name)
		return nil
	}
	if z.ds[name] == nil {
		return fmt.Errorf("dataset does not exist")
	}
	var victims []string
	for n := range z.ds {
		if n == name || (rec && strings.HasPrefix(n, name+"/")) {
			victims = append(victims, n)
		}
	}
	slices.SortFunc(victims, func(x, y string) int { return strings.Count(y, "/") - strings.Count(x, "/") })
	for _, v := range victims {
		for sn := range z.snaps {
			if strings.HasPrefix(sn, v+"@") {
				for _, c := range z.clones(sn) {
					if !slices.Contains(victims, c) {
						return fmt.Errorf("snapshot %s has dependent clone %s", sn, c)
					}
				}
			}
		}
	}
	for _, v := range victims {
		if z.ds[v].mounted && z.busy[v] {
			return fmt.Errorf("%s is busy", v)
		}
	}
	for _, v := range victims {
		origin := z.ds[v].origin
		for sn := range z.snaps {
			if strings.HasPrefix(sn, v+"@") {
				delete(z.snaps, sn)
			}
		}
		delete(z.ds, v)
		if s := z.snaps[origin]; s != nil && s.defer_ && len(z.clones(origin)) == 0 {
			delete(z.snaps, origin)
		}
	}
	return nil
}

// promote: the clone takes the origin's snapshots up to (and including) its
// origin snapshot; the origin dataset becomes a clone of it.
func (z *fakeZFS) promote(name string) error {
	d := z.ds[name]
	if d == nil || d.origin == "-" {
		return fmt.Errorf("not a cloned filesystem")
	}
	ods, osn, _ := strings.Cut(d.origin, "@")
	cut := z.snaps[d.origin].txg
	moved := map[string]string{}
	for sn, s := range z.snaps {
		if p, short, _ := strings.Cut(sn, "@"); p == ods && s.txg <= cut {
			moved[sn] = name + "@" + short
		}
	}
	for from, to := range moved {
		z.snaps[to] = z.snaps[from]
		delete(z.snaps, from)
	}
	for _, x := range z.ds {
		if to, ok := moved[x.origin]; ok {
			x.origin = to
		}
	}
	d.origin = "-"
	z.ds[ods].origin = name + "@" + osn
	return nil
}

func (z *fakeZFS) prop(name, p string) (string, error) {
	if strings.Contains(name, "@") {
		s := z.snaps[name]
		if s == nil {
			return "", fmt.Errorf("dataset does not exist")
		}
		switch p {
		case "clones":
			return strings.Join(z.clones(name), ","), nil
		case "defer_destroy":
			return map[bool]string{true: "on", false: "off"}[s.defer_], nil
		case "written":
			return "0", nil
		}
		return "-", nil
	}
	d := z.ds[name]
	if d == nil {
		return "", fmt.Errorf("cannot open '%s': dataset does not exist", name)
	}
	r := z.encRootOf(name)
	switch {
	case p == "keystatus":
		if r == nil {
			return "-", nil
		}
		return map[bool]string{true: "available", false: "unavailable"}[r.loaded], nil
	case p == "encryption":
		if d.encryption == "" {
			return "off", nil
		}
		return d.encryption, nil
	case p == "mounted":
		return map[bool]string{true: "yes", false: "no"}[d.mounted], nil
	case p == "mountpoint":
		return d.mountpoint, nil
	case p == "origin":
		return d.origin, nil
	case p == "refquota":
		return d.refquota, nil
	case strings.HasPrefix(p, "written@"):
		s := z.snaps[name+"@"+strings.TrimPrefix(p, "written@")]
		if s == nil {
			return "", fmt.Errorf("snapshot does not exist")
		}
		return strconv.FormatInt(d.writes-s.writes, 10), nil
	case p == "written":
		return "0", nil
	case strings.Contains(p, ":"):
		if v, ok := d.user[p]; ok {
			return v, nil
		}
	}
	return "-", nil
}

func (z *fakeZFS) get(a []string) (string, error) {
	name, props := a[len(a)-1], a[len(a)-2]
	var out []string
	for _, p := range strings.Split(props, ",") {
		v, err := z.prop(name, p)
		if err != nil {
			return "", err
		}
		out = append(out, v)
	}
	return strings.Join(out, "\n") + "\n", nil
}

func (z *fakeZFS) list(a []string) (string, error) {
	target := a[len(a)-1]
	switch {
	case slices.Contains(a, "snapshot") && slices.Contains(a, "-d"):
		var out []string
		for n := range z.snaps {
			if strings.HasPrefix(n, target+"@") {
				out = append(out, n)
			}
		}
		slices.SortFunc(out, func(x, y string) int { return z.snaps[x].txg - z.snaps[y].txg })
		return strings.Join(out, "\n") + "\n", nil
	case slices.Contains(a, "-r"):
		var out []string
		for n, d := range z.ds {
			if n == target || strings.HasPrefix(n, target+"/") {
				out = append(out, n+"\t"+map[bool]string{true: "yes", false: "no"}[d.mounted])
			}
		}
		if len(out) == 0 {
			return "", fmt.Errorf("dataset does not exist")
		}
		slices.Sort(out)
		return strings.Join(out, "\n") + "\n", nil
	case strings.Contains(target, "@"):
		if z.snaps[target] == nil {
			return "", fmt.Errorf("cannot open '%s': dataset does not exist", target)
		}
		return target + "\n", nil
	}
	if z.ds[target] == nil {
		return "", fmt.Errorf("cannot open '%s': dataset does not exist", target)
	}
	return target + "\n", nil
}

// write records n bytes written to a mounted dataset (a file write).
func (z *fakeZFS) write(name string, n int64) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	d := z.ds[name]
	if d == nil || !d.mounted {
		return fmt.Errorf("%s not mounted", name)
	}
	d.writes += n
	return nil
}

func (z *fakeZFS) state(name string) (loaded, mounted bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if r := z.encRootOf(name); r != nil {
		loaded = r.loaded
	}
	if d := z.ds[name]; d != nil {
		mounted = d.mounted
	}
	return
}

func (z *fakeZFS) exists(name string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	if strings.Contains(name, "@") {
		return z.snaps[name] != nil
	}
	return z.ds[name] != nil
}
