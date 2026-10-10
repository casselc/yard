package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"yard/internal/jail"
	"yard/internal/mount"
	"yard/internal/spawn"
)

// behavior is how a fake process reacts; set per started argv[0].
type behavior struct {
	ignoreTerm  bool // SIGTERM does nothing (escalation to SIGKILL needed)
	unkillable  bool // not even SIGKILL or jail_remove ends it (stuck in the kernel)
	forkOnTerm  int  // on SIGTERM, fork this many children first (they appear after the listing)
	forkOnStop  int  // on SIGSTOP, fork this many running children first (fork racing the signal)
	listens     bool // the service's port answers once readyAfter probes have hit it
	readyAfter  int
	exitAtStart bool   // exits right away (code 1)
	lingers     int    // after jail_remove / SIGKILL it takes this many Procs listings to disappear
	probeExit   int    // cmd probe processes exit with this code
	writeDS     string // optional startup workspace write, before readiness
	writeBytes  int64
}

type fproc struct {
	pid, jid    int
	argv        []string
	b           behavior
	stopped     bool
	pendingTerm bool
	dead        bool
	dying       int // listings left before it disappears
	probes      int
	done        chan struct{}
	exit        spawn.Exit
}

type fakeOS struct {
	mu      sync.Mutex
	log     []string
	jails   map[int]string
	nextJID int
	mounts  []string
	procs   map[int]*fproc
	nextPID int
	snaps   map[string]int64 // snapshot -> written
	ds      map[string]string
	drift   int64
	behave  map[string]behavior // argv[0] -> behavior
	zfsFail map[string]string   // args prefix -> "fail" (not applied) | "lost" (applied, then an error); once
	hang    bool                // network probes block until their timeout
	signals []string
	z       *fakeZFS // if set, every zfs call goes to it (the workspace layout tests)
}

func newFakeOS() *fakeOS {
	return &fakeOS{jails: map[int]string{}, nextJID: 100, procs: map[int]*fproc{}, nextPID: 1000,
		snaps: map[string]int64{}, ds: map[string]string{}, behave: map[string]behavior{}, zfsFail: map[string]string{}}
}

func (f *fakeOS) rec(s string) {
	f.log = append(f.log, s)
}

func (f *fakeOS) AddRule(r string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec("rctl+ " + r)
	return nil
}
func (f *fakeOS) RemoveRules(r string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec("rctl- " + r)
	return nil
}
func (f *fakeOS) Mount(s mount.Spec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec("mount " + s.Target)
	f.mounts = append(f.mounts, s.Target)
	if f.z != nil && s.Type == "nullfs" {
		f.z.holdView(s.Source, s.Target) // a jail's view of a clone keeps it busy
	}
	return nil
}
func (f *fakeOS) Unmount(t string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.Index(f.mounts, t)
	if i < 0 {
		return fmt.Errorf("%s not mounted", t)
	}
	f.rec("umount " + t)
	f.mounts = append(f.mounts[:i], f.mounts[i+1:]...)
	if f.z != nil {
		f.z.releaseView(t)
	}
	return nil
}
func (f *fakeOS) Mounts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.mounts), nil
}
func (f *fakeOS) Mkdir(p string, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec("mkdir " + p)
	return nil
}
func (f *fakeOS) Rmdir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec("rmdir " + p)
	return nil
}
func (f *fakeOS) Chown(string, uint32, uint32) error { return nil }
func (f *fakeOS) CreateJail(ps []jail.Param, flags int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := ""
	for _, p := range ps {
		if p.Name == "name" {
			name = strings.TrimRight(string(p.Val), "\x00")
		}
	}
	for _, n := range f.jails {
		if n == name {
			return -1, syscall.EEXIST
		}
	}
	f.nextJID++
	f.jails[f.nextJID] = name
	f.rec("jail_set " + name)
	return f.nextJID, nil
}

// RemoveJail kills every process of the jail (they may linger a while).
func (f *fakeOS) RemoveJail(jid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.jails[jid]; !ok {
		return syscall.EINVAL
	}
	delete(f.jails, jid)
	f.rec("jail_remove " + strconv.Itoa(jid))
	for _, p := range f.procs {
		if p.jid == jid {
			f.killLocked(p, 9)
		}
	}
	return nil
}
func (f *fakeOS) JID(name string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for j, n := range f.jails {
		if n == name {
			return j, nil
		}
	}
	return -1, errors.New("jail not found")
}
func (f *fakeOS) Run(stdin string, argv ...string) (string, error) { return "", nil }

// Start is the shim: it attaches to -j and execs the argv after "--".
func (f *fakeOS) Start(ps spawn.ProcSpec) (spawn.Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	jid, _ := strconv.Atoi(ps.Args[1])
	argv := ps.Args[slices.Index(ps.Args, "--")+1:]
	if _, ok := f.jails[jid]; !ok {
		return nil, errors.New("jail_attach: no such jail")
	}
	if argv[0] == "/bin/kill" { // the signal round, from inside the jail
		return &fakeHandle{f: f, p: f.killCmdLocked(jid, argv)}, nil
	}
	p := f.spawnLocked(jid, argv, f.behave[argv[0]])
	if p.b.writeBytes > 0 && f.z != nil {
		if err := f.z.write(p.b.writeDS, p.b.writeBytes); err != nil {
			return nil, err
		}
	}
	f.rec("start " + strings.Join(argv, " "))
	if p.b.exitAtStart {
		f.dieLocked(p, spawn.Exit{Code: 1})
	}
	if strings.HasSuffix(argv[0], "probe") {
		f.dieLocked(p, spawn.Exit{Code: p.b.probeExit})
	}
	return &fakeHandle{f: f, p: p}, nil
}

func (f *fakeOS) spawnLocked(jid int, argv []string, b behavior) *fproc {
	f.nextPID++
	p := &fproc{pid: f.nextPID, jid: jid, argv: argv, b: b, done: make(chan struct{})}
	f.procs[p.pid] = p
	return p
}

func (f *fakeOS) dieLocked(p *fproc, e spawn.Exit) {
	if p.dead || p.dying > 0 {
		return
	}
	p.exit = e
	if p.b.lingers > 0 {
		p.dying = p.b.lingers
		return
	}
	p.dead = true
	close(p.done)
}

func (f *fakeOS) killLocked(p *fproc, sig int) {
	if p.b.unkillable {
		return
	}
	f.dieLocked(p, spawn.Exit{Code: -1, Signal: sig})
}

type fakeHandle struct {
	f *fakeOS
	p *fproc
}

func (h *fakeHandle) Pid() int { return h.p.pid }
func (h *fakeHandle) Wait() (spawn.Exit, error) {
	<-h.p.done
	return h.p.exit, nil
}
func (h *fakeHandle) Kill() error {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	h.f.killLocked(h.p, 9)
	return nil
}

func (f *fakeOS) Procs(jid int) ([]Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Proc
	for _, p := range f.procs {
		if p.jid != jid || p.dead {
			continue
		}
		if p.dying > 0 {
			p.dying--
			if p.dying == 0 {
				p.dead = true
				close(p.done)
				continue
			}
		}
		out = append(out, Proc{PID: p.pid, Stopped: p.stopped})
	}
	slices.SortFunc(out, func(a, b Proc) int { return a.PID - b.PID })
	return out, nil
}

// killCmdLocked is /bin/kill -s SIG pid... run in jail jid: the prison
// check confines it to processes of that jail.
func (f *fakeOS) killCmdLocked(jid int, argv []string) *fproc {
	sig, code := argv[2], 0
	for _, a := range argv[3:] {
		pid, _ := strconv.Atoi(a)
		f.signals = append(f.signals, fmt.Sprintf("%s:%d", sig, pid))
		p, ok := f.procs[pid]
		if !ok || p.dead || p.jid != jid {
			code = 1 // ESRCH: gone, or not in this jail
			continue
		}
		f.signalLocked(p, sig)
	}
	k := &fproc{pid: -1, jid: jid, done: make(chan struct{}), dead: true, exit: spawn.Exit{Code: code}}
	close(k.done)
	return k
}

func (f *fakeOS) signalLocked(p *fproc, sig string) {
	switch sig {
	case "KILL":
		f.killLocked(p, 9)
	case "STOP":
		for i := 0; i < p.b.forkOnStop; i++ {
			f.spawnLocked(p.jid, []string{"child"}, behavior{})
		}
		p.b.forkOnStop = 0
		p.stopped = true
	case "CONT":
		p.stopped = false
		if p.pendingTerm {
			p.pendingTerm = false
			f.termLocked(p)
		}
	case "TERM":
		if p.stopped {
			p.pendingTerm = true // not acted on before SIGCONT
			return
		}
		f.termLocked(p)
	}
}

func (f *fakeOS) termLocked(p *fproc) {
	if p.b.ignoreTerm || p.b.unkillable {
		return
	}
	for i := 0; i < p.b.forkOnTerm; i++ {
		f.spawnLocked(p.jid, []string{"child"}, behavior{})
	}
	f.dieLocked(p, spawn.Exit{Code: 0})
}

func (f *fakeOS) ZpoolSync(ctx context.Context, pool string) error {
	f.mu.Lock()
	f.rec("zpool sync " + pool)
	f.mu.Unlock()
	return nil
}

// ZfsIn: the backend tests' zfs takes no stdin (the workspace tests use fakeZFS).
func (f *fakeOS) ZfsIn(ctx context.Context, lock *os.File, stdin []byte, args ...string) (string, error) {
	if f.z != nil {
		return f.z.ZfsIn(ctx, lock, stdin, args...)
	}
	return f.Zfs(ctx, lock, args...)
}

// Zfs emulates the zfs(8) calls the backend makes.
func (f *fakeOS) Zfs(ctx context.Context, lock *os.File, args ...string) (string, error) {
	if f.z != nil {
		return f.z.ZfsIn(ctx, lock, nil, args...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(args, " ")
	f.rec("zfs " + cmd)
	mode := ""
	for p, m := range f.zfsFail {
		if strings.HasPrefix(cmd, p) {
			mode = m
			delete(f.zfsFail, p)
		}
	}
	if mode == "fail" {
		return "", fmt.Errorf("zfs %s: injected failure", cmd)
	}
	out, err := f.zfsLocked(args)
	if mode == "lost" {
		return "", fmt.Errorf("zfs %s: answer lost (applied)", cmd)
	}
	return out, err
}

func (f *fakeOS) zfsLocked(a []string) (string, error) {
	switch {
	case a[0] == "snapshot":
		if _, ok := f.snaps[a[1]]; ok {
			return "", fmt.Errorf("cannot create snapshot '%s': dataset already exists", a[1])
		}
		f.snaps[a[1]] = 12288
		return "", nil
	case a[0] == "destroy":
		if _, ok := f.snaps[a[1]]; !ok {
			return "", fmt.Errorf("could not find any snapshots to destroy")
		}
		delete(f.snaps, a[1])
		return "", nil
	case a[0] == "list":
		target := a[len(a)-1]
		if slices.Contains(a, "-d") { // all snapshots of a dataset
			var out []string
			for n := range f.snaps {
				if strings.HasPrefix(n, target+"@") {
					out = append(out, n)
				}
			}
			slices.Sort(out)
			return strings.Join(out, "\n") + "\n", nil
		}
		if _, ok := f.snaps[target]; !ok {
			return "", fmt.Errorf("cannot open '%s': dataset does not exist", target)
		}
		return target + "\n", nil
	case a[0] == "get":
		prop, target := a[len(a)-2], a[len(a)-1]
		switch {
		case prop == "written":
			return fmt.Sprintln(f.snaps[target]), nil
		case strings.HasPrefix(prop, "written@"):
			return fmt.Sprintln(f.drift), nil
		default:
			v, ok := f.ds[target+" "+prop]
			if !ok {
				return "", fmt.Errorf("cannot open '%s'", target)
			}
			return v + "\n", nil
		}
	}
	return "", fmt.Errorf("fake zfs: %v", a)
}

// probe answers a network probe: ready when a listening, running process
// has been probed readyAfter times.
func (f *fakeOS) probe(ctx context.Context) error {
	f.mu.Lock()
	if f.hang {
		f.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	defer f.mu.Unlock()
	for _, p := range f.procs {
		if p.dead || p.dying > 0 || !p.b.listens || p.stopped {
			continue
		}
		p.probes++
		if p.probes > p.b.readyAfter {
			return nil
		}
	}
	return errors.New("connection refused")
}

type fakeProber struct{ f *fakeOS }

func (p fakeProber) TCP(ctx context.Context, addr string) error { return p.f.probe(ctx) }
func (p fakeProber) HTTP(ctx context.Context, url string) (int, error) {
	if err := p.f.probe(ctx); err != nil {
		return 0, err
	}
	return 200, nil
}

// live counts the live processes of the jail named name (-1: no such jail).
func (f *fakeOS) live(name string) int {
	jid, err := f.JID(name)
	if err != nil {
		return -1
	}
	ps, _ := f.Procs(jid)
	return len(ps)
}

func (f *fakeOS) snapList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.snaps {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func (f *fakeOS) mountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mounts)
}

func (f *fakeOS) jailCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.jails)
}
