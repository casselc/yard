//go:build freebsd

// yard-spawn J0: sandbox jails, per-call child jails and per-task uids on a
// FreeBSD host. Runs as root. HARNESS.md "Executor design".
//
//	yard-spawn sbx-create  -id ID [-net none|broker -subnet N -broker-port P] [-template DIR] [-base DIR]
//	yard-spawn sbx-destroy -id ID [-purge]
//	yard-spawn task-begin  -task T            prints the task uid
//	yard-spawn task-end    -task T
//	yard-spawn run   -sbx ID (-task T | -uid U) [-call cNNN] [-net none|inherit] [-ws ro|rw|none]
//	                 [-mem 512m] [-tmp 64m] [-timeout 30s] [-auid N|-1] [-json] -- argv...
//	yard-spawn bench -sbx ID -uid U -n 200 [-mem 64m] -- argv...
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"yard/internal/spawn"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "yard-spawn: "+f+"\n", a...)
	os.Exit(1)
}

type common struct {
	base, template, tasksConf, stateDir, shim string
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.base, "base", "/yard/jails", "sandbox base directory")
	fs.StringVar(&c.template, "template", "/yard/tmpl/base", "read-only jail template")
	fs.StringVar(&c.tasksConf, "tasks-conf", "/usr/local/etc/yard/tasks.conf", "task uid/rctl config")
	fs.StringVar(&c.stateDir, "state", "/var/db/yard-spawn", "state directory (task uid allocations)")
	exe, _ := os.Executable()
	fs.StringVar(&c.shim, "shim", filepath.Join(filepath.Dir(exe), "yard-exec-shim"), "yard-exec-shim path")
}

func (c *common) conf() spawn.TasksConf {
	tc, err := spawn.LoadTasksConf(c.tasksConf)
	if err != nil {
		die("%v", err)
	}
	return tc
}

func main() {
	if len(os.Args) < 2 {
		die("usage: yard-spawn <sbx-create|sbx-destroy|task-begin|task-end|run|bench> [flags]")
	}
	if os.Geteuid() != 0 {
		die("must run as root")
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "sbx-create":
		sbxCreate(args)
	case "sbx-destroy":
		sbxDestroy(args)
	case "task-begin", "task-end":
		task(cmd, args)
	case "run":
		run(args)
	case "bench":
		bench(args)
	default:
		die("unknown command %q", cmd)
	}
}

func spawner(c *common) *spawn.Spawner { return &spawn.Spawner{Sys: spawn.HostSys{}, Shim: c.shim} }

func sbxCreate(args []string) {
	fs := flag.NewFlagSet("sbx-create", flag.ExitOnError)
	var c common
	c.flags(fs)
	id := fs.String("id", "", "sandbox id [a-z0-9]{1,16}")
	netp := fs.String("net", "none", "none|broker")
	subnet := fs.Int("subnet", 0, "broker: 10.77.<subnet>.0/30")
	bport := fs.Uint("broker-port", 8099, "broker: port on the host side of the epair")
	owner := fs.Uint("owner", 0, "task uid that owns the workspace (from task-begin)")
	fs.Parse(args)
	tc := c.conf()
	s := &spawn.Sandbox{ID: *id, Base: c.base, Template: c.template, Net: spawn.SbxNet(*netp), Subnet: *subnet, BrokerPort: uint16(*bport)}
	if *owner != 0 {
		if uint32(*owner) < tc.UIDMin || uint32(*owner) > tc.UIDMax {
			die("owner %d outside the task uid range", *owner)
		}
		s.OwnerUID, s.OwnerGID = uint32(*owner), tc.GID
	}
	t0 := time.Now()
	if err := spawner(&c).CreateSandbox(s, spawn.SandboxOpts{Devfs: tc.Devfs}); err != nil {
		die("%v", err)
	}
	out(map[string]any{"sandbox": s, "jail": s.JailName(), "create_ms": ms(time.Since(t0)), "broker_addr": brokerAddr(s)})
}

func brokerAddr(s *spawn.Sandbox) string {
	if s.Net != spawn.SbxBroker {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.HostAddr(), s.BrokerPort)
}

func sbxDestroy(args []string) {
	fs := flag.NewFlagSet("sbx-destroy", flag.ExitOnError)
	var c common
	c.flags(fs)
	id := fs.String("id", "", "sandbox id")
	purge := fs.Bool("purge", false, "also delete the workspace directory")
	fs.Parse(args)
	s, err := spawn.LoadSandbox(c.base, *id)
	if err != nil {
		die("%v", err)
	}
	t0 := time.Now()
	if err := spawner(&c).DestroySandbox(s, *purge); err != nil {
		die("%v", err)
	}
	out(map[string]any{"destroyed": s.ID, "destroy_ms": ms(time.Since(t0))})
}

func task(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var c common
	c.flags(fs)
	t := fs.String("task", "", "task id")
	fs.Parse(args)
	tk := &spawn.Tasks{Dir: filepath.Join(c.stateDir, "tasks"), Conf: c.conf(), Sys: spawn.HostSys{}}
	var uid uint32
	var err error
	if cmd == "task-begin" {
		uid, err = tk.Begin(*t)
	} else {
		uid, err = tk.End(*t)
	}
	if err != nil {
		die("%v", err)
	}
	fmt.Println(uid)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func out(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func callID() string {
	var b [6]byte
	rand.Read(b[:])
	return "c" + hex.EncodeToString(b[:])
}

type runFlags struct {
	c                  common
	sbx, taskID, call  string
	uid                uint
	netp, ws, mem, tmp string
	timeout            time.Duration
	auid               int64
	asJSON             bool
}

func (r *runFlags) set(fs *flag.FlagSet) {
	r.c.flags(fs)
	fs.StringVar(&r.sbx, "sbx", "", "sandbox id")
	fs.StringVar(&r.taskID, "task", "", "task id (uid looked up from task-begin)")
	fs.UintVar(&r.uid, "uid", 0, "task uid (instead of -task)")
	fs.StringVar(&r.call, "call", "", "call id (default random)")
	fs.StringVar(&r.netp, "net", "none", "none|inherit")
	fs.StringVar(&r.ws, "ws", "rw", "workspace: ro|rw|none")
	fs.StringVar(&r.mem, "mem", "", "per-call vmemoryuse deny (e.g. 512m)")
	fs.StringVar(&r.tmp, "tmp", "64m", "per-call tmpfs size")
	fs.DurationVar(&r.timeout, "timeout", 30*time.Second, "kill the call after this")
	auidDef := int64(-1)
	if s := os.Getenv("SUDO_UID"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			auidDef = v
		}
	}
	fs.Int64Var(&r.auid, "auid", auidDef, "audit user id set before attach (-1 = none; default $SUDO_UID)")
	fs.BoolVar(&r.asJSON, "json", false, "print the result as JSON on stderr")
}

func (r *runFlags) build(argv []string) (*spawn.Spawner, *spawn.Call) {
	s, err := spawn.LoadSandbox(r.c.base, r.sbx)
	if err != nil {
		die("%v", err)
	}
	tc := r.c.conf()
	uid := uint32(r.uid)
	if r.taskID != "" {
		tk := &spawn.Tasks{Dir: filepath.Join(r.c.stateDir, "tasks"), Conf: tc, Sys: spawn.HostSys{}}
		if uid, err = tk.Lookup(r.taskID); err != nil || uid == 0 {
			die("task %q has no uid (task-begin first): %v", r.taskID, err)
		}
	}
	if uid < tc.UIDMin || uid > tc.UIDMax {
		die("uid %d outside the task range %d-%d", uid, tc.UIDMin, tc.UIDMax)
	}
	id := r.call
	if id == "" {
		id = callID()
	}
	return spawner(&r.c), &spawn.Call{Sandbox: s, ID: id, Argv: argv, Env: []string{"PATH=/bin:/usr/bin", "HOME=/workspace", "YARD_CALL=" + id},
		UID: uid, GID: tc.GID, Class: tc.Class, AuditUID: r.auid, Net: spawn.Net(r.netp), Workspace: r.ws,
		TmpSize: r.tmp, Mem: r.mem, Timeout: r.timeout, Devfs: tc.Devfs, Stdout: os.Stdout, Stderr: os.Stderr}
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var r runFlags
	r.set(fs)
	fs.Parse(args)
	if fs.NArg() == 0 {
		die("run: no command")
	}
	sp, call := r.build(fs.Args())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := sp.Run(ctx, call)
	if r.asJSON || err != nil || res.Poisoned {
		b, _ := json.Marshal(res)
		fmt.Fprintln(os.Stderr, "RESULT "+string(b))
	}
	if err != nil {
		die("%v", err)
	}
	switch {
	case res.TimedOut:
		os.Exit(124)
	case res.Signal != 0:
		os.Exit(128 + res.Signal)
	case res.Poisoned:
		os.Exit(125)
	}
	os.Exit(res.Exit)
}

func bench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	var r runFlags
	r.set(fs)
	n := fs.Int("n", 200, "calls")
	fs.Parse(args)
	if fs.NArg() == 0 {
		die("bench: no command")
	}
	var tot, setup, runT, td []float64
	bad := 0
	t0 := time.Now()
	for i := 0; i < *n; i++ {
		r.call = fmt.Sprintf("b%06d", i)
		r.call = "c" + r.call
		sp, call := r.build(fs.Args())
		call.Stdout, call.Stderr = nil, nil
		res, err := sp.Run(context.Background(), call)
		if err != nil || res.Exit != 0 || res.Poisoned {
			bad++
			if bad <= 3 {
				b, _ := json.Marshal(res)
				fmt.Fprintf(os.Stderr, "call %d: err=%v %s\n", i, err, b)
			}
			continue
		}
		tot = append(tot, ms(res.Total))
		setup = append(setup, ms(res.Setup))
		runT = append(runT, ms(res.Run))
		td = append(td, ms(res.Teardown))
	}
	wall := time.Since(t0)
	st := func(v []float64) map[string]float64 {
		if len(v) == 0 {
			return nil
		}
		sort.Float64s(v)
		p := func(q float64) float64 { return v[int(float64(len(v)-1)*q)] }
		return map[string]float64{"p50": p(.5), "p90": p(.9), "p99": p(.99), "max": v[len(v)-1]}
	}
	out(map[string]any{"n": *n, "ok": len(tot), "bad": bad, "wall_s": wall.Seconds(), "calls_per_s": float64(len(tot)) / wall.Seconds(),
		"mem": r.mem, "total_ms": st(tot), "setup_ms": st(setup), "run_ms": st(runT), "teardown_ms": st(td)})
}
