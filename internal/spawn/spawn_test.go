package spawn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yard/internal/jail"
	"yard/internal/mount"
)

// fakeSys records every privileged effect in order.
type fakeSys struct {
	mu     sync.Mutex
	log    []string
	mounts []string
	jails  map[int]string
	next   int
	failOn map[string]error // prefix of a log entry -> error (once)
	busy   map[string]int   // unmount target -> EBUSY count before success
	proc   func(ProcSpec) *fakeProc
	runOut map[string]string
}

func newFake() *fakeSys {
	return &fakeSys{jails: map[int]string{}, next: 10, failOn: map[string]error{}, busy: map[string]int{}, runOut: map[string]string{}}
}

func (f *fakeSys) rec(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, s)
	for p, err := range f.failOn {
		if strings.HasPrefix(s, p) {
			delete(f.failOn, p)
			return err
		}
	}
	return nil
}

func (f *fakeSys) AddRule(r string) error     { return f.rec("rctl+ " + r) }
func (f *fakeSys) RemoveRules(r string) error { return f.rec("rctl- " + r) }
func (f *fakeSys) Mount(s mount.Spec) error {
	if err := f.rec("mount " + s.Type + " " + s.Target); err != nil {
		return err
	}
	f.mu.Lock()
	f.mounts = append(f.mounts, s.Target)
	f.mu.Unlock()
	return nil
}
func (f *fakeSys) Unmount(t string, force bool) error {
	f.mu.Lock()
	if n := f.busy[t]; n > 0 && !force {
		f.busy[t] = n - 1
		f.mu.Unlock()
		return errors.New("device busy")
	}
	f.mu.Unlock()
	if err := f.rec(fmt.Sprintf("umount %s force=%v", t, force)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, m := range f.mounts {
		if m == t {
			f.mounts = append(f.mounts[:i], f.mounts[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%s not mounted", t)
}
func (f *fakeSys) Mounts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.mounts...), nil
}
func (f *fakeSys) Mkdir(p string, _ uint32) error { return f.rec("mkdir " + p) }
func (f *fakeSys) Rmdir(p string) error           { return f.rec("rmdir " + p) }
func (f *fakeSys) Chown(p string, u, g uint32) error {
	return f.rec(fmt.Sprintf("chown %s %d:%d", p, u, g))
}
func (f *fakeSys) CreateJail(ps []jail.Param, flags int) (int, error) {
	name := ""
	for _, p := range ps {
		if p.Name == "name" {
			name = strings.TrimRight(string(p.Val), "\x00")
		}
	}
	if err := f.rec(fmt.Sprintf("jail_set %s flags=%d", name, flags)); err != nil {
		return -1, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if flags&jail.Update != 0 {
		return 1, nil
	}
	f.next++
	f.jails[f.next] = name
	return f.next, nil
}
func (f *fakeSys) RemoveJail(jid int) error {
	if err := f.rec(fmt.Sprintf("jail_remove %d", jid)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.jails[jid]; !ok {
		return errors.New("no such jail")
	}
	delete(f.jails, jid)
	return nil
}
func (f *fakeSys) JID(name string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for j, n := range f.jails {
		if n == name {
			return j, nil
		}
	}
	return -1, errors.New("not found")
}
func (f *fakeSys) Run(stdin string, argv ...string) (string, error) {
	cmd := strings.Join(argv, " ")
	if err := f.rec("run " + cmd); err != nil {
		return "", err
	}
	return f.runOut[cmd], nil
}
func (f *fakeSys) Start(p ProcSpec) (Proc, error) {
	if err := f.rec("start " + strings.Join(p.Args, " ")); err != nil {
		return nil, err
	}
	fp := &fakeProc{done: make(chan Exit, 1), sys: f}
	if f.proc != nil {
		fp = f.proc(p)
		fp.sys = f
	}
	return fp, nil
}

// fakeProc exits with exit after delay, or when the jail is removed / it is killed.
type fakeProc struct {
	done  chan Exit
	sys   *fakeSys
	once  sync.Once
	exit  Exit
	delay time.Duration
	hang  bool // ignores kill (simulates an unkillable process)
}

func (p *fakeProc) Pid() int { return 4242 }
func (p *fakeProc) Kill() error {
	p.sys.rec("kill")
	if !p.hang {
		p.once.Do(func() { p.done <- Exit{Code: -1, Signal: 9} })
	}
	return nil
}
func (p *fakeProc) Wait() (Exit, error) {
	if p.delay > 0 || p.hang {
		select {
		case e := <-p.done:
			return e, nil
		case <-time.After(p.delay):
			if p.hang {
				select {} // never returns
			}
		}
	}
	p.once.Do(func() { p.done <- p.exit })
	return <-p.done, nil
}

func testSandbox(t *testing.T) *Sandbox {
	return &Sandbox{ID: "s1", Base: "/yard/jails", Template: "/yard/tmpl/base", Net: SbxNone}
}

func testCall(s *Sandbox) *Call {
	return &Call{Sandbox: s, ID: "c1", Argv: []string{"true"}, UID: 2000001, GID: 2000000, Class: "yard_task",
		AuditUID: 1001, Net: NetNone, Workspace: "rw", Mem: "64m", Timeout: time.Second, Devfs: 10}
}

func idx(t *testing.T, log []string, prefix string) int {
	t.Helper()
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	t.Fatalf("%q not in log:\n%s", prefix, strings.Join(log, "\n"))
	return -1
}

func TestRunOrderAndTeardown(t *testing.T) {
	f := newFake()
	sp := &Spawner{Sys: f, Shim: "/x/yard-exec-shim"}
	res, err := sp.Run(context.Background(), testCall(testSandbox(t)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Exit != 0 || res.Poisoned || res.TimedOut || res.JID != 11 || res.Jail != "ysbx_s1.c1" {
		t.Fatalf("%+v", res)
	}
	L := f.log
	root := "/yard/jails/s1/root/.yard/calls/c1"
	order := []string{
		"rctl+ jail:ysbx_s1.c1:vmemoryuse:deny=67108864",
		"mkdir " + root,
		"mount nullfs " + root,
		"mount nullfs " + root + "/workspace",
		"mount tmpfs " + root + "/tmp",
		"mount devfs " + root + "/dev",
		"jail_set ysbx_s1.c1 flags=1",
		"start -j 11 -u 2000001 -g 2000000 -d /workspace -c yard_task -a 1001 -m 0x40000080 -- true",
		"jail_remove 11",
		"umount " + root + "/dev",
		"umount " + root + "/tmp",
		"umount " + root + "/workspace",
		"umount " + root + " ",
		"rmdir " + root,
		"rctl- jail:ysbx_s1.c1",
	}
	last := -1
	for _, o := range order {
		i := idx(t, L, o)
		if i <= last {
			t.Fatalf("%q out of order:\n%s", o, strings.Join(L, "\n"))
		}
		last = i
	}
	if len(f.mounts) != 0 || len(f.jails) != 0 {
		t.Fatalf("leftovers: mounts=%v jails=%v", f.mounts, f.jails)
	}
}

func TestRunTimeoutRemovesJailBeforeWaitReturns(t *testing.T) {
	f := newFake()
	f.proc = func(ProcSpec) *fakeProc { return &fakeProc{done: make(chan Exit, 1), delay: time.Hour} }
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	c := testCall(testSandbox(t))
	c.Timeout = 50 * time.Millisecond
	t0 := time.Now()
	res, err := sp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal != 9 || res.Poisoned {
		t.Fatalf("%+v", res)
	}
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("took %s", el)
	}
	// jail_remove happened exactly once (the timeout path), before teardown unmounts
	n := strings.Count(strings.Join(f.log, "\n"), "jail_remove")
	if n != 1 {
		t.Fatalf("jail_remove %d times:\n%s", n, strings.Join(f.log, "\n"))
	}
	if idx(t, f.log, "jail_remove") > idx(t, f.log, "umount") {
		t.Fatal("unmount before jail_remove")
	}
	if len(f.jails) != 0 || len(f.mounts) != 0 {
		t.Fatal("leftovers")
	}
}

func TestRunCancel(t *testing.T) {
	f := newFake()
	f.proc = func(ProcSpec) *fakeProc { return &fakeProc{done: make(chan Exit, 1), delay: time.Hour} }
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	res, _ := sp.Run(ctx, testCall(testSandbox(t)))
	if !res.Canceled || res.TimedOut {
		t.Fatalf("%+v", res)
	}
}

func TestRunUnkillableProcessPoisons(t *testing.T) {
	old := KillWait
	KillWait = 50 * time.Millisecond
	defer func() { KillWait = old }()
	f := newFake()
	f.proc = func(ProcSpec) *fakeProc { return &fakeProc{done: make(chan Exit, 1), hang: true, delay: time.Hour} }
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	c := testCall(testSandbox(t))
	c.Timeout = 20 * time.Millisecond
	res, err := sp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Poisoned || !res.TimedOut {
		t.Fatalf("%+v", res)
	}
}

func TestRunMountFailureUnwinds(t *testing.T) {
	f := newFake()
	f.failOn["mount tmpfs"] = errors.New("ENOSPC")
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	_, err := sp.Run(context.Background(), testCall(testSandbox(t)))
	if err == nil {
		t.Fatal("want error")
	}
	j := strings.Join(f.log, "\n")
	if strings.Contains(j, "jail_set") || strings.Contains(j, "start") {
		t.Fatalf("got past a failed mount:\n%s", j)
	}
	if len(f.mounts) != 0 {
		t.Fatalf("mounts left: %v", f.mounts)
	}
	idx(t, f.log, "rctl- jail:ysbx_s1.c1")
	idx(t, f.log, "rmdir ")
}

func TestRunBusyUnmountRetriesThenForces(t *testing.T) {
	oldR, oldB := UnmountRetries, UnmountBackoff
	UnmountRetries, UnmountBackoff = 3, time.Millisecond
	defer func() { UnmountRetries, UnmountBackoff = oldR, oldB }()
	f := newFake()
	root := "/yard/jails/s1/root/.yard/calls/c1"
	f.busy[root+"/tmp"] = 2   // succeeds on the 3rd try
	f.busy[root+"/dev"] = 100 // only a forced unmount works
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	res, err := sp.Run(context.Background(), testCall(testSandbox(t)))
	if err != nil || res.Poisoned {
		t.Fatalf("%v %+v", err, res)
	}
	idx(t, f.log, "umount "+root+"/dev force=true")
	idx(t, f.log, "umount "+root+"/tmp force=false")
}

func TestRunFailedForcedUnmountPoisons(t *testing.T) {
	f := newFake()
	root := "/yard/jails/s1/root/.yard/calls/c1"
	f.failOn["umount "+root+"/workspace"] = errors.New("EBUSY")
	f.busy[root+"/workspace"] = 1000
	oldR, oldB := UnmountRetries, UnmountBackoff
	UnmountRetries, UnmountBackoff = 2, time.Millisecond
	defer func() { UnmountRetries, UnmountBackoff = oldR, oldB }()
	sp := &Spawner{Sys: f, Shim: "/x/shim"}
	res, _ := sp.Run(context.Background(), testCall(testSandbox(t)))
	if !res.Poisoned || len(res.Errors) == 0 {
		t.Fatalf("%+v", res)
	}
}

func TestShimErrorFlag(t *testing.T) {
	f := newFake()
	f.proc = func(ProcSpec) *fakeProc { return &fakeProc{done: make(chan Exit, 1), exit: Exit{Code: 123}} }
	res, _ := (&Spawner{Sys: f, Shim: "/s"}).Run(context.Background(), testCall(testSandbox(t)))
	if !res.ShimError {
		t.Fatalf("%+v", res)
	}
}

func TestCallValidation(t *testing.T) {
	s := testSandbox(t)
	bad := map[string]func(c *Call){
		"no argv":          func(c *Call) { c.Argv = nil },
		"uid 0":            func(c *Call) { c.UID = 0 },
		"bad id":           func(c *Call) { c.ID = "x.y" },
		"id digits":        func(c *Call) { c.ID = "1234" },
		"inherit w/o vnet": func(c *Call) { c.Net = NetInherit },
		"bad mem":          func(c *Call) { c.Mem = "64m,user:0:maxproc:deny=1" },
		"bad ws":           func(c *Call) { c.Workspace = "maybe" },
		"no timeout":       func(c *Call) { c.Timeout = 0 },
	}
	for name, mut := range bad {
		c := testCall(s)
		mut(c)
		f := newFake()
		if _, err := (&Spawner{Sys: f, Shim: "/s"}).Run(context.Background(), c); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(f.log) != 0 {
			t.Errorf("%s: touched the host: %v", name, f.log)
		}
	}
}

func TestJailParamsForNetProfiles(t *testing.T) {
	s := &Sandbox{ID: "s1", Base: "/b", Template: "/t", Net: SbxBroker, Subnet: 3, BrokerPort: 8099}
	c := testCall(s)
	c.Net = NetInherit
	got := map[string][]byte{}
	for _, p := range c.JailParams() {
		got[p.Name] = p.Val
	}
	if got["ip4"][0] != jail.SysInherit || got["ip6"][0] != jail.SysInherit {
		t.Fatal("inherit not set")
	}
	for _, k := range []string{"allow.noset_hostname", "allow.noreserved_ports", "persist"} {
		if v, ok := got[k]; !ok || v != nil {
			t.Fatalf("%s missing or not boolean", k)
		}
	}
	if got["children.max"][0] != 0 || got["securelevel"][0] != 3 || got["enforce_statfs"][0] != 2 {
		t.Fatal("hardening params")
	}
	if string(got["path"]) != "/b/s1/root/.yard/calls/c1\x00" {
		t.Fatalf("path %q", got["path"])
	}
}

func TestCreateBrokerSandboxAndDestroy(t *testing.T) {
	f := newFake()
	f.runOut["/sbin/ifconfig epair create"] = "epair7a\n"
	base := t.TempDir()
	s := &Sandbox{ID: "s2", Base: base, Template: "/yard/tmpl/base", Net: SbxBroker, Subnet: 5, BrokerPort: 8099, OwnerUID: 2000001, OwnerGID: 2000000}
	sp := &Spawner{Sys: f, Shim: "/s"}
	// the fake Mkdir does not create directories; the state file needs the real one
	os.MkdirAll(s.Dir(), 0o700)
	if err := sp.CreateSandbox(s, SandboxOpts{Devfs: 10}); err != nil {
		t.Fatal(err)
	}
	j := strings.Join(f.log, "\n")
	for _, want := range []string{
		"run /sbin/ifconfig epair7a inet 10.77.5.1/30 up",
		"run /sbin/ifconfig epair7b vnet 11",
		"run /usr/sbin/jexec 11 /sbin/ifconfig epair7b inet 10.77.5.2/30 up",
		"run /sbin/pfctl -q -a yard/sbx-s2 -f -",
		"jail_set ysbx_s2 flags=2",
		"chown " + base + "/s2/ws 2000001:2000000",
	} {
		if !strings.Contains(j, want) {
			t.Fatalf("missing %q in:\n%s", want, j)
		}
	}
	if idx(t, f.log, "jail_set ysbx_s2 flags=2") < idx(t, f.log, "run /usr/sbin/jexec 11 /sbin/route") {
		t.Fatal("securelevel raised before network setup")
	}
	s2, err := LoadSandbox(base, "s2")
	if err != nil || s2.Epair != "epair7a" || s2.JID != 11 {
		t.Fatalf("%v %+v", err, s2)
	}
	if err := sp.DestroySandbox(s2, false); err != nil {
		t.Fatal(err)
	}
	if len(f.mounts) != 0 || len(f.jails) != 0 {
		t.Fatalf("leftovers %v %v", f.mounts, f.jails)
	}
	idx(t, f.log, "run /sbin/pfctl -q -a yard/sbx-s2 -f /dev/null")
	idx(t, f.log, "run /sbin/ifconfig epair7a destroy")
	if _, err := os.Stat(filepath.Join(base, "s2", "sandbox.json")); !os.IsNotExist(err) {
		t.Fatal("state file left")
	}
}

func TestCreateSandboxFailureUnwinds(t *testing.T) {
	f := newFake()
	f.runOut["/sbin/ifconfig epair create"] = "epair7a\n"
	f.failOn["run /sbin/pfctl"] = errors.New("pf not enabled")
	base := t.TempDir()
	s := &Sandbox{ID: "s3", Base: base, Template: "/t", Net: SbxBroker, Subnet: 1, BrokerPort: 8099}
	if err := (&Spawner{Sys: f, Shim: "/s"}).CreateSandbox(s, SandboxOpts{}); err == nil {
		t.Fatal("want error")
	}
	if len(f.mounts) != 0 || len(f.jails) != 0 {
		t.Fatalf("leftovers %v %v\n%s", f.mounts, f.jails, strings.Join(f.log, "\n"))
	}
	idx(t, f.log, "run /sbin/ifconfig epair7a destroy")
}

func TestTasksAllocation(t *testing.T) {
	f := newFake()
	tk := &Tasks{Dir: t.TempDir(), Conf: DefaultTasksConf, Sys: f}
	tk.Conf.UIDMax = tk.Conf.UIDMin + 2
	u1, err := tk.Begin("task-a")
	if err != nil || u1 != 2000000 {
		t.Fatal(u1, err)
	}
	if again, _ := tk.Begin("task-a"); again != u1 {
		t.Fatal("Begin not idempotent")
	}
	u2, _ := tk.Begin("task-b")
	u3, _ := tk.Begin("task-c")
	if u2 == u1 || u3 == u2 {
		t.Fatal("duplicate uid")
	}
	if _, err := tk.Begin("task-d"); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("want exhaustion, got %v", err)
	}
	j := strings.Join(f.log, "\n")
	if !strings.Contains(j, "rctl+ user:2000000:vmemoryuse:deny=8589934592") || !strings.Contains(j, "rctl+ user:2000002:pcpu:deny=200") {
		t.Fatalf("rules:\n%s", j)
	}
	if u, err := tk.End("task-b"); err != nil || u != u2 {
		t.Fatal(u, err)
	}
	idx(t, f.log, "rctl- user:2000001")
	if u4, _ := tk.Begin("task-d"); u4 != u2 {
		t.Fatalf("freed uid not reused: %d", u4)
	}
	if _, err := tk.Begin("Bad/Task"); err == nil {
		t.Fatal("bad task id accepted")
	}
}

func TestParseTasksConf(t *testing.T) {
	c, err := ParseTasksConf(strings.NewReader("# c\ntask_uid_min=3000000\ntask_uid_max=3000009\ntask_gid=3000000\ntask_login_class=k\ntask_rctl=maxproc:deny=10 vmemoryuse:deny=1g\ndevfs_ruleset=4\n"))
	if err != nil || c.UIDMin != 3000000 || c.Class != "k" || len(c.Rctl) != 2 || c.Devfs != 4 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{"task_rctl=maxproc:deny=1,user:0:x\n", "nope=1\n", "task_uid_min=5\n", "task_rctl=bogus:deny=1\n"} {
		if _, err := ParseTasksConf(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
