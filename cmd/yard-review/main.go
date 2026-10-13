//go:build linux

// yard-review runs one read-only Claude Code review in a Firecracker VM against halo, by hand (AG1;
// design/AGENT-OPERATIONS.md section 9). It is the first task's whole path without yard-ctl:
//
//  1. the input image: the commit's tree plus the change under review (.yard-review/change.diff), built once per
//     (commit, change) and attached read-only;
//  2. an allocation: a fresh id, a directory, the broker route on its own host socket (v.sock_4000) and the
//     control socket (v.sock_5000);
//  3. the VM: Firecracker with the read-only harness image, the input image, vsock, and no network;
//  4. the task: the claude command the driver composes (read and search tools only, no settings, hooks, MCP,
//     CLAUDE.md or subagents, structured output);
//  5. the end: the VM stops (or is killed at the time limit), the route is revoked, unresolved calls are resolved
//     from halo's records while it holds them, and the spend is reported;
//  6. the outcome: the output validated by structure only, and the evidence written beside it.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"yard/internal/agentroute"
	"yard/internal/haloop"
	"yard/internal/jsonshape"
	"yard/internal/ledger"
)

// ReviewSchema is the structure the review must return (Review, with insufficient_information folded in).
const ReviewSchema = `{"type":"object","additionalProperties":false,"required":["verdict","findings"],"properties":{
"verdict":{"type":"string","enum":["pass","fail","insufficient_information"]},
"findings":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,
 "required":["file","line","severity","note"],"properties":{
 "file":{"type":"string","maxLength":300},"line":{"type":"integer","minimum":1},
 "severity":{"type":"string","enum":["info","minor","major","critical"]},"note":{"type":"string","maxLength":4000}}}},
"questions":{"type":"array","maxItems":20,"items":{"type":"string","maxLength":1000}}}}`

// The prompt: stable text first (the rubric), then what varies (the change's location), so reviewers of the same
// change share a prefix in halo's cache.
const rubric = `You are reviewing a proposed change. The repository in the current directory is read-only and already
has the change applied; the change itself, as a diff against the previous version, is in .yard-review/change.diff.
Read the diff, then read whatever parts of the repository you need to judge it. Report concrete defects only: each
finding names a file and line as they are in the current directory, a severity, and a short note saying what is
wrong and why. Do not report style preferences.
verdict is "fail" if any finding is major or critical, otherwise "pass". If you cannot judge the change from what is
here, return verdict "insufficient_information", no findings, and your questions.`

type opts struct {
	repo, commit, change, out, state                   string
	halo, haloKeyFile, model                           string
	fc, kernel, rootfs                                 string
	tokens, charge, seconds, maxOut, vcpu, memMiB, cap int64
	smoke                                              string
}

func main() {
	var o opts
	flag.StringVar(&o.repo, "repo", "", "git repository")
	flag.StringVar(&o.commit, "commit", "HEAD", "commit to review against")
	flag.StringVar(&o.change, "change", "", "file holding the change under review (a diff)")
	flag.StringVar(&o.out, "out", "", "evidence directory (created)")
	flag.StringVar(&o.state, "state", "/work/platform/ag1-state", "ledger, image cache, allocations")
	flag.StringVar(&o.halo, "halo", "http://127.0.0.1:18080", "halo base URL")
	flag.StringVar(&o.haloKeyFile, "halo-key-file", "/work/platform/configs/halo-api-key", "halo API key file")
	flag.StringVar(&o.model, "model", "claude-sonnet-5-5", "model name the harness asks for (halo aliases claude-*)")
	flag.StringVar(&o.fc, "firecracker", "/work/platform/firecracker/bin/firecracker", "firecracker binary")
	flag.StringVar(&o.kernel, "kernel", "/work/platform/firecracker/guest/vmlinux-6.1.155", "guest kernel")
	flag.StringVar(&o.rootfs, "rootfs", "/work/platform/firecracker/images/review-agent.ext4", "harness image")
	flag.Int64Var(&o.tokens, "tokens", 400000, "token limit")
	flag.Int64Var(&o.charge, "charge", 1000000, "charge limit (valuation units)")
	flag.Int64Var(&o.seconds, "seconds", 900, "wall-time limit")
	flag.Int64Var(&o.maxOut, "max-out", 16384, "per-call output cap")
	flag.Int64Var(&o.vcpu, "vcpu", 2, "VM vCPUs")
	flag.Int64Var(&o.memMiB, "mem", 2048, "VM memory (MiB)")
	flag.Int64Var(&o.cap, "output-cap", 64<<20, "bytes of harness output kept")
	flag.StringVar(&o.smoke, "smoke", "", "run this shell command in the VM instead of the harness (bring-up checks)")
	flag.Parse()
	if o.repo == "" || o.change == "" || o.out == "" {
		flag.Usage()
		os.Exit(2)
	}
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/sbin:/sbin") // mkfs.ext4
	if err := runReview(o); err != nil {
		log.Fatal(err)
	}
}

func sha256File(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// inputImage builds (once) the read-only ext4 image of the commit's tree plus the change.
func inputImage(o opts) (path, commit string, err error) {
	c, err := exec.Command("git", "-C", o.repo, "rev-parse", "--verify", o.commit+"^{commit}").Output()
	if err != nil {
		return "", "", fmt.Errorf("commit %s: %w", o.commit, err)
	}
	commit = strings.TrimSpace(string(c))
	change, err := os.ReadFile(o.change)
	if err != nil {
		return "", "", err
	}
	ch := sha256.Sum256(change)
	key := commit[:16] + "-" + hex.EncodeToString(ch[:8]) + "-applied"
	dir := filepath.Join(o.state, "images")
	path = filepath.Join(dir, key+".ext4")
	if _, err := os.Stat(path); err == nil {
		return path, commit, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	tree, err := os.MkdirTemp(dir, "tree-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tree)
	sh := fmt.Sprintf("git -C %q archive %s | tar -x -C %q", o.repo, commit, tree)
	if out, err := exec.Command("sh", "-c", sh).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("archive: %v: %s", err, out)
	}
	// the reviewed tree is the commit with the change applied, so every finding cites a line that exists in it
	ap := exec.Command("git", "apply", "--whitespace=nowarn", "-")
	ap.Dir, ap.Stdin = tree, bytes.NewReader(change)
	if out, err := ap.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("the change does not apply to %s: %v: %s", commit[:12], err, out)
	}
	if err := os.MkdirAll(filepath.Join(tree, ".yard-review"), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(tree, ".yard-review", "change.diff"), change, 0o644); err != nil {
		return "", "", err
	}
	du, _ := exec.Command("du", "-sb", tree).Output()
	var size int64
	fmt.Sscan(string(du), &size)
	size = size*3/2 + 64<<20
	tmp := path + ".tmp"
	if out, err := exec.Command("truncate", "-s", fmt.Sprint(size), tmp).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("truncate: %v %s", err, out)
	}
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-L", "input", "-d", tree, tmp).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("mkfs: %v %s", err, out)
	}
	return path, commit, os.Rename(tmp, path)
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, max uint32, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > max {
		return fmt.Errorf("frame of %d bytes over %d", size, max)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

type guestResult struct {
	Type      string `json:"type"`
	Exit      int    `json:"exit"`
	Signal    string `json:"signal"`
	Stdout    []byte `json:"stdout"`
	Stderr    []byte `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error"`
	StartedMs int64  `json:"started_ms"`
	EndedMs   int64  `json:"ended_ms"`
}

// claudeArgv is the claude driver: a non-interactive run with read and search tools only.
func claudeArgv(o opts, schema string) ([]string, map[string]string) {
	argv := []string{"/usr/local/bin/claude", "-p", rubric,
		// --restricted: no command-running tools, no user/project/local settings files, file tools confined to the
		// working directory. --safe-mode: no CLAUDE.md, skills, plugins, hooks, MCP servers or custom agents.
		// (--bare would also do, but its simple mode keeps only the minimal tool set: no Grep or Glob.)
		"--restricted", "--safe-mode", "--strict-mcp-config", "--disable-slash-commands",
		"--tools", "Read,Grep,Glob",
		"--exclude-dynamic-system-prompt-sections",
		"--output-format", "stream-json", "--verbose",
		"--json-schema", schema,
		"--model", o.model,
		"--no-session-persistence",
	}
	env := map[string]string{
		"ANTHROPIC_BASE_URL":                       "http://127.0.0.1:4000",
		"ANTHROPIC_API_KEY":                        "yard-placeholder", // the broker holds no key for the local route
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
		"DISABLE_AUTOUPDATER":                      "1",
		"DISABLE_TELEMETRY":                        "1",
		"DISABLE_ERROR_REPORTING":                  "1",
		"USE_BUILTIN_RIPGREP":                      "0", // the image's static rg
	}
	return argv, env
}

type callObs struct {
	ID  string    `json:"id"`
	At  time.Time `json:"at"`
	In  int64     `json:"in"`
	Out int64     `json:"out"`
}

type outcome struct {
	Outcome    string            `json:"outcome"`
	Execution  string            `json:"execution"`
	Exhausted  string            `json:"exhausted,omitempty"`
	Value      json.RawMessage   `json:"value,omitempty"`
	Errors     []string          `json:"validation_errors,omitempty"`
	Spend      any               `json:"spend"`
	Unresolved int               `json:"unresolved_left"`
	Timings    map[string]any    `json:"timings"`
	Calls      []callObs         `json:"calls"`
	Evidence   map[string]string `json:"evidence"`
}

func runReview(o opts) error {
	t0 := time.Now()
	timings := map[string]any{}
	mark := func(k string) { timings[k+"_ms"] = time.Since(t0).Milliseconds() }
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	img, commit, err := inputImage(o)
	if err != nil {
		return err
	}
	mark("input_image")
	key, err := os.ReadFile(o.haloKeyFile)
	if err != nil {
		return err
	}
	ab := make([]byte, 16)
	rand.Read(ab)
	alloc := hex.EncodeToString(ab)
	attempt := "review-" + alloc[:12]
	adir := filepath.Join(o.state, "alloc", alloc)
	if err := os.MkdirAll(adir, 0o700); err != nil {
		return err
	}
	l, err := ledger.Open(filepath.Join(o.state, "ledger.db"))
	if err != nil {
		return err
	}
	defer l.Close()
	// the local route's resource valuation: a nominal price, no money
	val := ledger.Valuation{Digest: "ag1-local-v1", Routes: map[string]ledger.Route{
		"local": {Units: ledger.Prices{Input: 1_000_000, CacheRead: 100_000, CacheWrite: 1_000_000, Output: 4_000_000}}}}
	if err := l.Begin(attempt, ledger.Limits{Tokens: o.tokens, Charge: o.charge, Money: 0}, val); err != nil {
		return err
	}
	halo := &haloop.Client{Base: o.halo, Key: strings.TrimSpace(string(key)), Principal: "yard:" + attempt,
		HTTP: nil}
	k, err := halo.Contract(context.Background())
	if err != nil && o.smoke == "" { // a bring-up smoke runs without halo
		return fmt.Errorf("halo contract: %w", err)
	}
	var mu sync.Mutex
	var calls []callObs
	logf, _ := os.Create(filepath.Join(o.out, "route.log"))
	defer logf.Close()
	route := agentroute.New(agentroute.Config{Attempt: attempt, Alloc: alloc[:12], Ledger: l, Halo: halo, Route: "local",
		Mode: k.Inference.Mode, MaxOut: o.maxOut, MinOut: 256, NotAfter: 60 * time.Second,
		Logf: func(f string, a ...any) { fmt.Fprintf(logf, time.Now().Format(time.RFC3339Nano)+" "+f+"\n", a...) },
		OnCall: func(id string, at time.Time, in, out int64) {
			mu.Lock()
			calls = append(calls, callObs{id, at, in, out})
			mu.Unlock()
		}})
	vsock := filepath.Join(adir, "v.sock")
	rl, err := net.Listen("unix", vsock+"_4000")
	if err != nil {
		return err
	}
	go route.Serve(rl)
	cl, err := net.Listen("unix", vsock+"_5000")
	if err != nil {
		return err
	}
	defer cl.Close()

	schema := ReviewSchema
	argv, env := claudeArgv(o, compact(schema))
	if o.smoke != "" {
		argv, env = []string{"/bin/sh", "-c", o.smoke}, map[string]string{}
	}
	cfg := map[string]any{
		"boot-source": map[string]any{"kernel_image_path": o.kernel,
			"boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro quiet i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/sbin/yard-guest"},
		"drives": []map[string]any{
			{"drive_id": "rootfs", "path_on_host": o.rootfs, "is_root_device": true, "is_read_only": true},
			{"drive_id": "input", "path_on_host": img, "is_root_device": false, "is_read_only": true},
		},
		"machine-config": map[string]any{"vcpu_count": o.vcpu, "mem_size_mib": o.memMiB, "smt": false},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": vsock},
	}
	cj, _ := json.MarshalIndent(cfg, "", " ")
	cfgPath := filepath.Join(adir, "vm.json")
	if err := os.WriteFile(cfgPath, cj, 0o600); err != nil {
		return err
	}
	console, _ := os.Create(filepath.Join(o.out, "console.log"))
	defer console.Close()
	fc := exec.Command(o.fc, "--no-api", "--id", alloc[:12], "--level", "Warn", "--config-file", cfgPath)
	fc.Stdout, fc.Stderr = console, console
	if err := fc.Start(); err != nil {
		return err
	}
	mark("vm_started")
	vmDone := make(chan error, 1)
	go func() { vmDone <- fc.Wait() }()

	// the control channel: hello, the task, the result
	resCh := make(chan guestResult, 1)
	go func() {
		c, err := cl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var hello map[string]any
		if err := readFrame(c, 1<<16, &hello); err != nil {
			return
		}
		mu.Lock()
		mark("guest_hello")
		mu.Unlock()
		if err := writeFrame(c, map[string]any{"argv": argv, "env": env, "dir": "/workspace", "output_cap": o.cap}); err != nil {
			return
		}
		var r guestResult
		if err := readFrame(bufio.NewReaderSize(c, 1<<20), uint32(3*o.cap), &r); err == nil {
			resCh <- r
			_ = writeFrame(c, map[string]any{"type": "ack"})
		}
	}()

	timedOut := false
	limit := time.NewTimer(time.Duration(o.seconds) * time.Second)
	select {
	case err := <-vmDone:
		_ = err
	case <-limit.C:
		timedOut = true
		_ = fc.Process.Kill()
		<-vmDone
	}
	mark("vm_exited")
	if ps := fc.ProcessState; ps != nil { // the VM's CPU time: what it took from the host besides memory
		timings["vm_user_cpu_ms"] = ps.UserTime().Milliseconds()
		timings["vm_sys_cpu_ms"] = ps.SystemTime().Milliseconds()
		if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
			timings["vm_maxrss_kib"] = ru.Maxrss
		}
	}
	var res *guestResult
	select {
	case r := <-resCh:
		res = &r
	case <-time.After(2 * time.Second):
	}
	// the end: revoke the scope, resolve, report
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := route.Revoke(ctx); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	left, err := agentroute.Resolve(ctx, l, halo, attempt)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	spend, err := l.Report(ctx, attempt)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	mark("settled")

	out := outcome{Execution: "stopped", Spend: spendWire(spend, time.Since(t0)), Unresolved: left, Timings: timings,
		Exhausted: route.Exhausted(), Evidence: map[string]string{}}
	mu.Lock()
	out.Calls = calls
	if len(calls) > 0 {
		timings["first_call_ms"] = calls[0].At.Sub(t0).Milliseconds()
	}
	mu.Unlock()
	var transcript []byte
	if res != nil {
		transcript = res.Stdout
		os.WriteFile(filepath.Join(o.out, "transcript.jsonl"), res.Stdout, 0o644)
		os.WriteFile(filepath.Join(o.out, "stderr.txt"), res.Stderr, 0o644)
		timings["guest_cmd_started_ms"], timings["guest_cmd_ended_ms"] = res.StartedMs, res.EndedMs
	}
	value, structural := resultValue(transcript)
	switch {
	case timedOut:
		out.Outcome = "timeout"
	case res == nil || res.Type != "result":
		out.Outcome = "worker_failed"
	case out.Exhausted != "":
		out.Outcome = "budget_exhausted"
	case value == nil:
		out.Outcome = "invalid_output"
		out.Errors = []string{structural}
	default:
		s, _ := jsonshape.Parse([]byte(schema))
		if errs := s.Validate(value); len(errs) > 0 {
			out.Outcome, out.Errors = "invalid_output", errs
		} else {
			var v struct {
				Verdict string `json:"verdict"`
			}
			json.Unmarshal(value, &v)
			out.Outcome = "completed"
			if v.Verdict == "insufficient_information" {
				out.Outcome = "insufficient"
			}
		}
		out.Value = value
	}
	for name, p := range map[string]string{"rootfs": o.rootfs, "input_image": img, "kernel": o.kernel, "firecracker": o.fc} {
		out.Evidence[name+"_sha256"] = sha256File(p)
	}
	out.Evidence["commit"] = commit
	out.Evidence["allocation"] = alloc
	out.Evidence["attempt"] = attempt
	out.Evidence["halo_incarnation"] = k.Incarnation
	// the command as run; long arguments (the prompt, the schema) by their digest
	shown := make([]string, len(argv))
	for i, a := range argv {
		shown[i] = a
		if len(a) > 120 {
			h := sha256.Sum256([]byte(a))
			shown[i] = "sha256:" + hex.EncodeToString(h[:])
		}
	}
	aj, _ := json.Marshal(shown)
	out.Evidence["argv"] = string(aj)
	oj, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile(filepath.Join(o.out, "outcome.json"), oj, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s\n", oj)
	return nil
}

func compact(s string) string {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		panic(err)
	}
	return b.String()
}

// resultValue finds the harness's final structured output in its stream-json transcript.
func resultValue(transcript []byte) (json.RawMessage, string) {
	var last map[string]json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(transcript))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if string(ev["type"]) == `"result"` {
			last = ev
		}
	}
	if last == nil {
		return nil, "no result event in the transcript"
	}
	if so, ok := last["structured_output"]; ok && string(so) != "null" {
		return so, ""
	}
	var text string
	if json.Unmarshal(last["result"], &text) == nil && json.Valid([]byte(strings.TrimSpace(text))) {
		return json.RawMessage(strings.TrimSpace(text)), ""
	}
	return nil, "the result event has no structured output"
}

func spendWire(s ledger.Spend, wall time.Duration) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	m["wall_s"] = int64(wall.Seconds())
	return m
}
