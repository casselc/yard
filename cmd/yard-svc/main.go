//go:build freebsd

// yard-svc drives SR1 service sessions through the SR0 lifecycle
// (internal/lifecycle Machine + internal/service Backend) on a FreeBSD host.
// Runs as root. It is the e2e's and the operator's front end until yard-ctl
// runs the Machine as a daemon; every command is one Machine incarnation on
// the same SQLite database (a restart, as far as the lifecycle can tell).
//
//	yard-svc up      -sess S -sbx ID (-task T | -uid U) -spec FILE (-project P | -dataset DS)
//	yard-svc suspend -sess S          idle -> suspended (from Paused too); the last active
//	                                  session of a project also unmounts it and unloads its key
//	yard-svc resume  -sess S [-force] token -> load key -> check drift -> mount/start -> mint/delete
//	                                  refused if the workspace changed
//	                                  since the snapshot, unless -force (decision 2)
//	yard-svc pause   -sess S          idle -> paused (SIGSTOP)
//	yard-svc unpause -sess S          a message wakes it (SIGCONT, delivered)
//	yard-svc probe   -sess S [-for D] liveness probes while awake; a dead instance fails it (decision 3)
//	yard-svc status  -sess S
//	yard-svc down    -sess S          fence Removed -> session effects -> leftovers -> project cleanup
//
// Workspaces (layout of 2026-10-07: ws/<project> encryption roots with keys
// held by the key service, ws/<project>/<session> clones; needs -kek):
//
//	yard-svc ws-init    -project P    create the key and ws/P, its base mounted for populating
//	yard-svc ws-base    -project P    unmount the base, take the next @base-<n>
//	yard-svc ws-clone   -project P -sess S [-gen N] [-refquota Q]
//	yard-svc ws-load    -project P -sess S   load the key, mount S's clone (by hand)
//	                                  RW mounting can dirty ZIL metadata; later resume may need -force
//	yard-svc ws-destroy -project P -sess S
//	yard-svc ws-retire  -project P -gen N [-promote]
//	yard-svc ws-shred   -project P    unmount, unload, delete the key, destroy ws/P
//
// Common: -root DIR (db, state, artifacts; default /yard/data/sr1),
// -artifact-ds DS (the encrypted dataset holding -root; default
// zroot/yard/data/sr1), -base, -template, -shim, -tasks-conf, -timeout,
// -ws-root (zroot/yard/ws), -ws-mnt (/yard/ws), -kek file:PATH | tpm:HANDLE
// (the key service's KEK: a 32-byte file for tests, or a dedicated TPM key).
//
// Each command prints one JSON line: the row after it, the lifecycle facts,
// the backend timings measured inside each op, and wall times. The policy
// is the command: suspend uses IdleAfter 0, the others keep the session
// warm, so no command suspends behind the operator's back.
//
// Stand-ins (no broker in SR1): the credential mint writes the epoch to
// <state>/svc/<sess>/epoch; the activity count is <state>/svc/<sess>/activity
// (the e2e may bump it).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yard/internal/keyring"
	"yard/internal/lifecycle"
	"yard/internal/service"
	"yard/internal/spawn"
	"yard/internal/sts"
	"yard/internal/tpmkey"
	"yard/internal/wskey"
)

const class = "sr1"

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "yard-svc: "+f+"\n", a...)
	os.Exit(1)
}

type opts struct {
	root, artDS, base, template, shim, tasksConf, stateDir string
	sess                                                   string
	timeout                                                time.Duration
	wsRoot, wsMnt, kek, project, keysDB                    string
	force                                                  bool
	probeFor                                               time.Duration
}

func (o *opts) flags(fs *flag.FlagSet) {
	fs.StringVar(&o.root, "root", "/yard/data/sr1", "lifecycle db, service state and artifacts (encrypted dataset)")
	fs.StringVar(&o.artDS, "artifact-ds", "zroot/yard/data/sr1", "the encrypted dataset mounted at -root")
	fs.StringVar(&o.base, "base", "/yard/jails", "sandbox base directory")
	fs.StringVar(&o.template, "template", "/yard/tmpl/base", "read-only jail template")
	fs.StringVar(&o.tasksConf, "tasks-conf", "/usr/local/etc/yard/tasks.conf", "task uid/rctl config")
	fs.StringVar(&o.stateDir, "spawn-state", "/var/db/yard-spawn", "yard-spawn state (task uids)")
	exe, _ := os.Executable()
	fs.StringVar(&o.shim, "shim", filepath.Join(filepath.Dir(exe), "yard-exec-shim"), "yard-exec-shim path")
	fs.StringVar(&o.sess, "sess", "", "session id [a-z0-9]{1,16}")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Minute, "give up on the command after this")
	fs.StringVar(&o.wsRoot, "ws-root", "zroot/yard/ws", "the workspace tree (its own encryption root)")
	fs.StringVar(&o.wsMnt, "ws-mnt", "/yard/ws", "its mountpoint")
	fs.StringVar(&o.kek, "kek", "", "key service KEK: file:PATH (32 raw bytes, tests) or tpm:HANDLE (a dedicated TPM key)")
	fs.StringVar(&o.project, "project", "", "workspace project")
	fs.StringVar(&o.keysDB, "keys-db", "/yard/data/keys/wskeys.db",
		"the key service's database (wrapped keys) on its own dataset, never snapshotted or backed up")
}

// loadKEK opens the key service's KEK.
func loadKEK(spec string) (*wskey.KEK, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "file":
		return wskey.KEKFromFile(arg)
	case "tpm":
		h, err := strconv.ParseUint(arg, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("-kek tpm:%s: %w", arg, err)
		}
		d, err := tpmkey.OpenDev("/dev/tpm0")
		if err != nil {
			return nil, err
		}
		k, err := keyring.TPMStore{T: d}.Open(keyring.Handle(h))
		if err != nil {
			return nil, err
		}
		return wskey.KEKFromSigner(k)
	}
	return nil, fmt.Errorf("-kek %q: want file:PATH or tpm:HANDLE", spec)
}

// ------------------------------------------------------------ stand-ins

type fileMinter struct{ b *service.Backend }

func (m fileMinter) path(s string) string { return filepath.Join(m.b.State, "svc", s, "epoch") }
func (m fileMinter) Mint(_ context.Context, s string, e int64) error {
	if cur, _ := m.read(s); cur > e {
		return fmt.Errorf("epoch %d is older than %d", e, cur)
	}
	return keyring.WriteFileAtomic(m.path(s), []byte(strconv.FormatInt(e, 10)+"\n"), 0o600)
}
func (m fileMinter) read(s string) (int64, error) {
	b, err := os.ReadFile(m.path(s))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
func (m fileMinter) Holds(_ context.Context, s string, e int64) (bool, error) {
	cur, err := m.read(s)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return cur == e, err
}
func (fileMinter) InFlight(context.Context, lifecycle.Op) (bool, error) { return false, nil }

type fileActivity struct{ b *service.Backend }

func (a fileActivity) Activity(_ context.Context, s string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(a.b.State, "svc", s, "activity"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

type sink struct {
	mu      sync.Mutex
	facts   []lifecycle.Fact
	counts  map[string]int
	timings []service.Timing
}

func (s *sink) Emit(f lifecycle.Fact) { s.mu.Lock(); s.facts = append(s.facts, f); s.mu.Unlock() }
func (s *sink) CountOutcome(k lifecycle.OpKind, c string) {
	s.mu.Lock()
	s.counts[string(k)+"/"+c]++
	s.mu.Unlock()
}
func (s *sink) timing(t service.Timing) { s.mu.Lock(); s.timings = append(s.timings, t); s.mu.Unlock() }

// ------------------------------------------------------------- machine

type env struct {
	o    *opts
	b    *service.Backend
	st   *lifecycle.Store
	keys *wskey.Store // nil without -kek
	m    *lifecycle.Machine
	out  *sink
	t0   time.Time
}

func policy(cmd string) lifecycle.Policy {
	p := lifecycle.Policy{MaxAge: int64(24 * time.Hour / time.Millisecond)}
	switch cmd {
	case "suspend":
		p.IdleAfter = 0
	case "pause":
		p.IdleAfter, p.Pause, p.KeepWarm = 0, true, true
	default:
		p.IdleAfter, p.KeepWarm = 1<<50, true
	}
	return p
}

func open(o *opts, cmd string) *env {
	t0 := time.Now()
	sp := &spawn.Spawner{Sys: service.HostOS{}, Shim: o.shim}
	out := &sink{counts: map[string]int{}}
	b := (&service.Backend{OS: service.HostOS{}, Spawn: sp, State: filepath.Join(o.root, "state"),
		ArtDir: filepath.Join(o.root, "art"), ArtDS: o.artDS, OnTiming: out.timing}).Init()
	if err := os.MkdirAll(b.State, 0o700); err != nil {
		die("%v", err)
	}
	st, err := lifecycle.OpenOwned(filepath.Join(o.root, "lifecycle.db"))
	if err != nil {
		die("%v", err)
	}
	rt := &lifecycle.Router{Backends: map[string]lifecycle.Backend{lifecycle.KindService: b},
		Mint: fileMinter{b}, Artifacts: b, Act: fileActivity{b}}
	var keys *wskey.Store
	if o.kek != "" {
		kek, err := loadKEK(o.kek)
		if err != nil {
			die("%v", err)
		}
		if keys, err = wskey.Open(o.keysDB, kek); err != nil {
			die("%v", err)
		}
		b.WS = &service.Workspaces{Z: service.HostOS{}, Root: o.wsRoot, Mnt: o.wsMnt, Keys: keys}
		rt.Keys = b
	}
	// the op timeout bounds every backend call: stop grace + kill wait,
	// start timeout, zfs; the spec's own bounds are well inside it
	cfg := lifecycle.Config{OpTimeout: 120_000, MaxAttempts: 3, Clients: []string{"cli"},
		Policies:        map[string]lifecycle.Policy{class: policy("status")},
		SessionPolicies: map[string]lifecycle.Policy{o.sess: policy(cmd)}}
	if cmd == "probe" {
		cfg.ProbeEvery = 20
	}
	ctx := context.Background()
	m, err := lifecycle.Start(ctx, st, cfg, rt, out, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		die("%v", err)
	}
	return &env{o: o, b: b, st: st, keys: keys, m: m, out: out, t0: t0}
}

// settled: no op of the session (or of its project) is open, and its
// project's key is not about to be, or being, unloaded.
func settled(c *lifecycle.Ctl, sess string) bool {
	if !lifecycle.SessionOpsSettled(c, sess) {
		return false
	}
	p := c.Rows[sess].Project
	for _, op := range c.Ops {
		if (op.Sess == sess || (p != "" && op.Sess == p)) && (op.St == lifecycle.Pending || op.St == lifecycle.Unknown) {
			return false
		}
	}
	if p != "" {
		if c.Projects[p].Phase != lifecycle.KNone {
			return false
		}
		if _, err := c.Clone().KeyUnloadBegin(p); err == nil {
			return false // the next Poll begins the unload
		}
	}
	return true
}

// drive polls the Machine until done holds and the session's ops are
// settled, or the session fails, or the timeout.
func (e *env) drive(done func(lifecycle.Row) bool) error {
	return e.driveUntil(done, settled)
}

func (e *env) driveUntil(done func(lifecycle.Row) bool, isSettled func(*lifecycle.Ctl, string) bool) error {
	ctx := context.Background()
	deadline := time.Now().Add(e.o.timeout)
	for {
		c := e.m.State()
		r, ok := c.Rows[e.o.sess]
		if !ok {
			return fmt.Errorf("no session %q", e.o.sess)
		}
		if done(r) && isSettled(c, e.o.sess) {
			return nil
		}
		if r.State == lifecycle.Failed || r.State == lifecycle.Expired {
			return fmt.Errorf("session %s is %s", e.o.sess, r.State)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %s: %s/%s", e.o.timeout, r.State, r.Phase)
		}
		e.m.Poll(ctx)
		time.Sleep(time.Millisecond)
	}
}

func (e *env) finish(cmd string, tCmd time.Time, err error, extra map[string]any) {
	e.m.Wait()
	c := e.m.State()
	res := map[string]any{"cmd": cmd, "sess": e.o.sess, "ok": err == nil, "row": c.Rows[e.o.sess],
		"wall_ms": ms(time.Since(e.t0)), "cmd_ms": ms(time.Since(tCmd)), "start_ms": ms(tCmd.Sub(e.t0))}
	if err != nil {
		res["err"] = err.Error()
	}
	e.out.mu.Lock()
	res["facts"], res["timings"], res["outcomes"] = e.out.facts, e.out.timings, e.out.counts
	e.out.mu.Unlock()
	for k, v := range extra {
		res[k] = v
	}
	j, _ := json.Marshal(res)
	fmt.Println(string(j))
	sum := e.summary(cmd, c.Rows[e.o.sess], err, time.Since(e.t0), time.Since(tCmd))
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := extra[k].(type) {
		case float64, int64, string:
			sum += fmt.Sprintf(" ws_%s=%v", k, v)
		}
	}
	fmt.Println(sum)
	e.st.Close()
	if e.keys != nil {
		e.keys.Close()
	}
	if err != nil {
		os.Exit(1)
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// summary is one "SR1SUM k=v ..." line for the e2e script (base sh, no
// jq): per backend op of this command <op>_ms, <op>_<step>_ms and a few
// facts of its Info; per lifecycle fact fact_<name>_ms.
func (e *env) summary(cmd string, r lifecycle.Row, err error, wall, cmdT time.Duration) string {
	kv := []string{"SR1SUM", "cmd=" + cmd, "sess=" + e.o.sess, fmt.Sprintf("ok=%d", map[bool]int{true: 1}[err == nil]),
		"state=" + string(r.State), "phase=" + string(r.Phase), fmt.Sprintf("gen=%d", r.Gen),
		fmt.Sprintf("drift=%d", map[bool]int{true: 1}[r.Drift]), fmt.Sprintf("token=%d", r.Token),
		fmt.Sprintf("wall_ms=%.3f", ms(wall)), fmt.Sprintf("cmd_ms=%.3f", ms(cmdT))}
	e.out.mu.Lock()
	defer e.out.mu.Unlock()
	for _, t := range e.out.timings {
		kv = append(kv, fmt.Sprintf("%s_ms=%.3f", t.Op, t.Ms), fmt.Sprintf("%s_ok=%d", t.Op, map[bool]int{true: 1}[t.OK]))
		for st, v := range t.Steps {
			kv = append(kv, fmt.Sprintf("%s_%s_ms=%.3f", t.Op, st, v))
		}
		for _, k := range []string{"escalated", "drift_bytes", "probes", "procs", "snapshot_written", "restart", "existed", "refused", "force"} {
			if v, ok := t.Info[k]; ok {
				if bv, isb := v.(bool); isb {
					v = map[bool]int{true: 1}[bv]
				}
				kv = append(kv, fmt.Sprintf("%s_%s=%v", t.Op, k, v))
			}
		}
	}
	for _, f := range e.out.facts {
		kv = append(kv, fmt.Sprintf("fact_%s_ms=%d", f.Name, f.DurationMs))
		if f.Bytes > 0 {
			kv = append(kv, fmt.Sprintf("fact_%s_bytes=%d", f.Name, f.Bytes))
		}
	}
	return strings.Join(kv, " ")
}

// ------------------------------------------------------------- commands

func main() {
	if len(os.Args) < 2 {
		die("usage: yard-svc <up|suspend|resume|pause|unpause|probe|status|down|ws-init|ws-base|ws-clone|ws-load|ws-destroy|ws-retire|ws-shred> [flags]")
	}
	if os.Geteuid() != 0 {
		die("must run as root")
	}
	cmd := os.Args[1]
	if cmd == "kek-tpm" {
		kekTPM(os.Args[2:])
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var o opts
	o.flags(fs)
	var sbx, task, specFile, dataset, refquota string
	var gen int64
	var promote bool
	var uid uint
	var auid int64 = -1
	if s := os.Getenv("SUDO_UID"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			auid = v
		}
	}
	if cmd == "up" {
		fs.StringVar(&sbx, "sbx", "", "sandbox id (yard-spawn sbx-create)")
		fs.StringVar(&task, "task", "", "task id (uid from yard-spawn task-begin)")
		fs.UintVar(&uid, "uid", 0, "task uid (instead of -task)")
		fs.StringVar(&specFile, "spec", "", "service spec (JSON)")
		fs.StringVar(&dataset, "dataset", "", "ZFS dataset mounted at the sandbox workspace")
		fs.Int64Var(&auid, "auid", auid, "audit user id (-1 none; default $SUDO_UID)")
	}
	switch cmd {
	case "resume":
		fs.BoolVar(&o.force, "force", false, "resume even if the workspace changed since the suspend snapshot")
	case "probe":
		fs.DurationVar(&o.probeFor, "for", time.Second, "probe this long (or until the session leaves Active/Idle)")
	case "ws-clone":
		fs.Int64Var(&gen, "gen", 0, "base generation (0: the newest)")
		fs.StringVar(&refquota, "refquota", "", "refquota of the clone")
	case "ws-retire":
		fs.Int64Var(&gen, "gen", 0, "base generation")
		fs.BoolVar(&promote, "promote", false, "with live clones, promote the newest instead of deferring the destroy")
	}
	fs.Parse(os.Args[2:])
	if strings.HasPrefix(cmd, "ws-") {
		ws(&o, cmd, gen, refquota, promote)
		return
	}
	if o.sess == "" {
		die("-sess required")
	}
	switch cmd {
	case "up":
		up(&o, sbx, task, uint32(uid), specFile, dataset, auid)
	case "suspend", "resume", "pause", "unpause", "probe":
		transition(&o, cmd)
	case "status":
		status(&o)
	case "down":
		down(&o)
	default:
		die("unknown command %q", cmd)
	}
}

func up(o *opts, sbx, task string, uid uint32, specFile, dataset string, auid int64) {
	tc, err := spawn.LoadTasksConf(o.tasksConf)
	if err != nil {
		die("%v", err)
	}
	if task != "" {
		tk := &spawn.Tasks{Dir: filepath.Join(o.stateDir, "tasks"), Conf: tc, Sys: spawn.HostSys{}}
		if uid, err = tk.Lookup(task); err != nil || uid == 0 {
			die("task %q has no uid (yard-spawn task-begin first): %v", task, err)
		}
	}
	if uid < tc.UIDMin || uid > tc.UIDMax {
		die("uid %d outside the task range %d-%d", uid, tc.UIDMin, tc.UIDMax)
	}
	b, err := os.ReadFile(specFile)
	if err != nil {
		die("%v", err)
	}
	var spec service.Spec
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		die("spec %s: %v", specFile, err)
	}
	e := open(o, "up")
	tCmd := time.Now()
	s := &service.Session{ID: o.sess, Sandbox: sbx, Base: o.base, UID: uid, GID: tc.GID, Class: tc.Class,
		AuditUID: auid, Devfs: tc.Devfs, Dataset: dataset, Spec: spec}
	if o.project != "" {
		if e.b.WS == nil {
			die("-project needs -kek (the workspace key service)")
		}
		s.Project, s.Workspace = o.project, e.b.WS.SessionMnt(o.project, o.sess)
		if s.Dataset == "" {
			s.Dataset = e.b.WS.SessionDS(o.project, o.sess)
		}
	}
	if _, exists := e.m.State().Rows[o.sess]; exists {
		e.finish("up", tCmd, fmt.Errorf("session %s exists in the lifecycle db", o.sess), nil)
	}
	err = e.b.Up(context.Background(), s)
	if err == nil {
		err = e.m.AddSession(o.sess, class, lifecycle.KindService, o.project)
	}
	e.finish("up", tCmd, err, nil)
}

func transition(o *opts, cmd string) {
	e := open(o, cmd)
	tCmd := time.Now()
	row, ok := e.m.State().Rows[o.sess]
	if !ok {
		e.finish(cmd, tCmd, fmt.Errorf("no session %q", o.sess), nil)
	}
	var err error
	switch cmd {
	case "suspend":
		err = e.drive(func(r lifecycle.Row) bool { return r.State == lifecycle.Suspended })
	case "pause":
		err = e.drive(func(r lifecycle.Row) bool { return r.State == lifecycle.Paused && r.Phase == lifecycle.PNone })
	case "resume":
		if row.State != lifecycle.Suspended && row.State != lifecycle.Resuming {
			err = fmt.Errorf("session %s is %s, not suspended", o.sess, row.State)
			break
		}
		if row.State == lifecycle.Suspended {
			if err = e.m.ResumeWith(o.sess, "cli", e.m.Token(o.sess), o.force); err != nil {
				break
			}
		}
		err = e.drive(func(r lifecycle.Row) bool { return r.State == lifecycle.Active || r.State == lifecycle.Suspended })
		if r := e.m.State().Rows[o.sess]; err == nil && r.State == lifecycle.Suspended {
			if r.Drift {
				err = errors.New("resume refused: the workspace changed since the suspend snapshot (session suspended again, new token; resume -force to use it as it is)")
			} else {
				err = errors.New("resume aborted: the restore was observed not done (session suspended again, new token)")
			}
		}
	case "probe":
		if row.State != lifecycle.Active && row.State != lifecycle.Idle {
			err = fmt.Errorf("session %s is %s, not awake", o.sess, row.State)
			break
		}
		deadline := time.Now().Add(o.probeFor)
		for time.Now().Before(deadline) {
			if r := e.m.State().Rows[o.sess]; r.State != lifecycle.Active && r.State != lifecycle.Idle {
				break
			}
			e.m.Poll(context.Background())
			time.Sleep(time.Millisecond)
		}
	case "unpause":
		if row.State != lifecycle.Paused {
			err = fmt.Errorf("session %s is %s, not paused", o.sess, row.State)
			break
		}
		if err = e.m.Message(o.sess); err == nil {
			err = e.drive(func(r lifecycle.Row) bool {
				return (r.State == lifecycle.Active || r.State == lifecycle.Idle) && r.Inbox == 0
			})
		}
	}
	e.finish(cmd, tCmd, err, nil)
}

func status(o *opts) {
	e := open(o, "status")
	tCmd := time.Now()
	row, ok := e.m.State().Rows[o.sess]
	if !ok {
		e.finish("status", tCmd, fmt.Errorf("no session %q", o.sess), nil)
	}
	ctx := context.Background()
	exists, running, err := e.b.Instance(ctx, o.sess, row.Inst)
	_, frozen, _ := e.b.Frozen(ctx, o.sess, row.Inst)
	e.finish("status", tCmd, err, map[string]any{"instance": map[string]any{"name": row.Inst, "exists": exists,
		"running": running, "frozen": frozen}})
}

func down(o *opts) {
	e := open(o, "down")
	tCmd := time.Now()
	ctx := context.Background()
	row, ok := e.m.State().Rows[o.sess]
	var err error
	// Fence/remove the row and settle its own effects first. An externally
	// removed jail can leave nullfs mounts even when Instance says absent;
	// clean those BEFORE waiting for project unmount/key-unload to finish.
	if ok {
		err = (service.RemovalStages{
			Fence: func() error {
				if row.State == lifecycle.Removed {
					return nil
				}
				return e.m.Remove(ctx, o.sess)
			},
			SessionSettled: func() error {
				return e.driveUntil(func(r lifecycle.Row) bool { return r.State == lifecycle.Removed }, lifecycle.SessionOpsSettled)
			},
			Cleanup: func() error { return e.b.CleanupSession(ctx, o.sess, row.Gen) },
			ProjectSettled: func() error {
				if err := e.drive(func(r lifecycle.Row) bool { return r.State == lifecycle.Removed }); err != nil {
					return err
				}
				return e.b.Down(ctx, o.sess, row.Gen)
			},
		}).Run()
	} else {
		err = fmt.Errorf("no session %q", o.sess)
	}
	e.finish("down", tCmd, err, nil)
}

// ws runs a workspace command (no Machine transition; the lifecycle db is
// opened for the key table and the session rows).
func ws(o *opts, cmd string, gen int64, refquota string, promote bool) {
	if o.kek == "" || o.project == "" {
		die("%s needs -kek and -project", cmd)
	}
	e := open(o, cmd)
	tCmd := time.Now()
	ctx := context.Background()
	w := e.b.WS
	p := o.project
	extra := map[string]any{"project": p}
	var err error
	t := func(name string, f func() error) {
		if err != nil {
			return
		}
		t0 := time.Now()
		err = f()
		extra[name+"_ms"] = ms(time.Since(t0))
	}
	needSess := func() {
		if o.sess == "" {
			die("%s needs -sess", cmd)
		}
	}
	switch cmd {
	case "ws-init":
		if _, gerr := w.Z.Zfs(ctx, nil, "list", "-H", "-o", "name", w.ProjectDS(p)); gerr == nil {
			err = fmt.Errorf("%s exists", w.ProjectDS(p))
			break
		}
		var key []byte
		t("key_create", func() (kerr error) {
			key, _, kerr = e.keys.Create(wskey.ConsumerZFS, p, time.Now().UnixMilli())
			if errors.Is(kerr, wskey.ErrExists) { // an interrupted ws-init: the key is there
				key, _, kerr = e.keys.Key(wskey.ConsumerZFS, p)
			}
			return kerr
		})
		t("create", func() error { return w.CreateProject(ctx, p, key) })
		clear(key)
		extra["base_mnt"] = w.BaseMnt(p)
	case "ws-base":
		t("snapshot", func() error {
			g, serr := w.SnapshotBase(ctx, p)
			extra["gen"] = g
			return serr
		})
	case "ws-clone":
		needSess()
		t("clone", func() error { return w.CloneSession(ctx, p, o.sess, gen, refquota) })
		extra["dataset"], extra["mnt"] = w.SessionDS(p, o.sess), w.SessionMnt(p, o.sess)
	case "ws-load":
		needSess()
		t("load", func() error { return w.LoadKey(ctx, nil, p, o.sess) })
	case "ws-destroy":
		needSess()
		t("destroy", func() error { return w.DestroySession(ctx, p, o.sess) })
	case "ws-retire":
		t("retire", func() error {
			what, rerr := w.RetireBase(ctx, p, gen, promote)
			extra["retired"] = what
			return rerr
		})
	case "ws-shred":
		// a session that is still up (its record exists: not `down`) and
		// not suspended, expired or failed holds the project
		for id, r := range e.m.State().Rows {
			if _, rerr := e.b.LoadSession(id); rerr != nil || r.Project != p {
				continue
			}
			if r.State != lifecycle.Suspended && r.State != lifecycle.Expired && r.State != lifecycle.Failed && r.State != lifecycle.Removed {
				err = fmt.Errorf("session %s of %s is %s", id, p, r.State)
			}
			if r.State == lifecycle.Removed && r.Op != 0 && e.m.State().Ops[r.Op].St != lifecycle.Done {
				err = fmt.Errorf("session %s of %s still waits for removal cleanup", id, p)
			}
		}
		t("shred", func() error { return w.ShredProject(ctx, p, e.keys, time.Now().UnixMilli()) })
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	e.finish(cmd, tCmd, err, extra)
}

// kekTPM checks (and with -create makes, with -evict destroys) the key
// service's TPM wrap key: a dedicated persistent RSA key, never one of the
// rotating STS keys. It prints whether the key exists, its public key's
// thumbprint and a fingerprint of the derived KEK (sha256, first 16 hex; the
// KEK itself is never printed). Run as root; no other TPM client may run
// (the tpm20(4) wedge, CONTROL-PLANE.md).
func kekTPM(args []string) {
	fs := flag.NewFlagSet("kek-tpm", flag.ExitOnError)
	handle := fs.String("handle", "0x81010012", "persistent handle of the wrap key")
	dev := fs.String("tpm", "/dev/tpm0", "TPM device")
	create := fs.Bool("create", false, "create the key if it does not exist")
	evict := fs.Bool("evict", false, "evict the key: every key wrapped under it becomes unreadable (crypto-shred)")
	fs.Parse(args)
	h, err := strconv.ParseUint(*handle, 0, 32)
	if err != nil {
		die("-handle: %v", err)
	}
	if uint32(h) == 0x81010010 || uint32(h) == 0x81010011 {
		die("handle %s is an STS signing key slot", *handle)
	}
	d, err := tpmkey.OpenDev(*dev)
	if err != nil {
		die("%v", err)
	}
	defer d.Close()
	st := keyring.TPMStore{T: d}
	hh := keyring.Handle(h)
	exists, err := st.Exists(hh)
	if err != nil {
		die("%v", err)
	}
	res := map[string]any{"handle": hh.String(), "existed": exists}
	switch {
	case *evict:
		if exists {
			if err := st.Evict(hh); err != nil {
				die("evict: %v", err)
			}
		}
		res["evicted"] = exists
		exists = false
	case !exists && *create:
		if _, err := st.Create(hh); err != nil {
			die("create: %v", err)
		}
		res["created"] = true
		exists = true
	}
	res["exists"] = exists
	if exists {
		k, err := st.Open(hh)
		if err != nil {
			die("open: %v", err)
		}
		res["kid"] = sts.Thumbprint(k.Public())
		fp, err := wskey.Fingerprint(k)
		if err != nil {
			die("%v", err)
		}
		res["kek_fingerprint"] = fp
	}
	j, _ := json.Marshal(res)
	fmt.Println(string(j))
}
