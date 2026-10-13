//go:build linux

// yard-guest is PID 1 of an agent VM (design/AGENT-OPERATIONS.md sections 5 and 9). It knows nothing about any
// harness: the host (yard-node, trusted) sends it the command to run. It:
//
//  1. mounts the minimal filesystems: proc, sys, devtmpfs, a tmpfs /tmp and /home/agent, and the task's input
//     image read-only at /workspace (nodev, nosuid, noexec);
//  2. asks the host for its task over vsock (port 5000, length-framed JSON);
//  3. forwards 127.0.0.1:4000 in the guest to vsock port 4000, the host socket the broker serves for this
//     allocation alone (the VM has no network);
//  4. runs the task's command as the unprivileged user `agent`, capturing stdout and stderr (capped), and reaps
//     every orphan, as PID 1 must;
//  5. sends the result frame and restarts, which ends the Firecracker process.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	hostCID     = 2
	controlPort = 5000
	modelPort   = 4000
	agentUID    = 1000
)

// Task is what the host sends.
type Task struct {
	Argv      []string          `json:"argv"`
	Env       map[string]string `json:"env"`
	Dir       string            `json:"dir"`
	OutputCap int               `json:"output_cap"` // bytes kept of stdout (and of stderr)
}

// Result is what the guest sends back.
type Result struct {
	Type      string `json:"type"` // "result" or "error"
	Exit      int    `json:"exit"`
	Signal    string `json:"signal,omitempty"`
	Stdout    []byte `json:"stdout"`
	Stderr    []byte `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
	StartedMs int64  `json:"started_ms"` // guest monotonic ms since init, when the command started
	EndedMs   int64  `json:"ended_ms"`
}

var t0 = time.Now()

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "yard-guest %6dms: "+format+"\n", append([]any{time.Since(t0).Milliseconds()}, args...)...)
}

func must(what string, err error) {
	if err != nil {
		logf("%s: %v", what, err)
		halt()
	}
}

func halt() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART) // reboot=k: Firecracker exits
	select {}
}

func mounts() {
	for _, m := range []struct {
		src, dst, fs, data string
		flags              uintptr
	}{
		{"proc", "/proc", "proc", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"sysfs", "/sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777,size=512m", unix.MS_NOSUID | unix.MS_NODEV},
		{"tmpfs", "/run", "tmpfs", "mode=0755,size=16m", unix.MS_NOSUID | unix.MS_NODEV},
		{"tmpfs", "/home/agent", "tmpfs", fmt.Sprintf("mode=0700,uid=%d,gid=%d,size=512m", agentUID, agentUID), unix.MS_NOSUID | unix.MS_NODEV},
	} {
		err := unix.Mount(m.src, m.dst, m.fs, m.flags, m.data)
		if err == unix.EBUSY && m.dst == "/dev" { // the kernel mounted devtmpfs itself (DEVTMPFS_MOUNT)
			continue
		}
		must("mount "+m.dst, err)
	}
	// the task's input: the second drive, read-only, as data only
	must("mount /workspace", unix.Mount("/dev/vdb", "/workspace", "ext4",
		unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "noload"))
}

// vsockDial connects to the host. net.FileConn does not know AF_VSOCK, so the socket is a plain (blocking) file.
// loopbackUp brings lo up: the forwarder listens on 127.0.0.1, and a VM without network has nothing else.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func vsockDial(port uint32) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: hostCID, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d", port)), nil
}

// frames: 4-byte big-endian length, then JSON (vsock half-close resets the connection, so messages are framed)
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

func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > 1<<20 {
		return fmt.Errorf("frame of %d bytes", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// forward serves 127.0.0.1:4000 in the guest, each connection piped to vsock port 4000 on the host.
func forward() {
	ln, err := net.Listen("tcp", "127.0.0.1:4000")
	must("listen 4000", err)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			h, err := vsockDial(modelPort)
			if err != nil {
				logf("vsock %d: %v", modelPort, err)
				return
			}
			defer h.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(h, c); done <- struct{}{} }()
			go func() { io.Copy(c, h); done <- struct{}{} }()
			<-done // either side finished: close both (no half-close over vsock)
		}()
	}
}

// capped keeps the first n bytes written to it.
type capped struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	n         int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.n - c.buf.Len(); room < len(p) {
		c.truncated = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// run starts the command as the agent user and reaps every child (PID 1), returning the command's own status.
func run(t Task) Result {
	res := Result{Type: "result"}
	if len(t.Argv) == 0 {
		return Result{Type: "error", Error: "empty argv"}
	}
	if t.OutputCap <= 0 {
		t.OutputCap = 64 << 20
	}
	stdout, stderr := &capped{n: t.OutputCap}, &capped{n: t.OutputCap}
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	var copies sync.WaitGroup
	copies.Add(2)
	go func() { io.Copy(stdout, outR); copies.Done() }()
	go func() { io.Copy(stderr, errR); copies.Done() }()
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/agent", "USER=agent", "LANG=C.UTF-8", "TMPDIR=/tmp"}
	for k, v := range t.Env {
		env = append(env, k+"="+v)
	}
	dir := t.Dir
	if dir == "" {
		dir = "/workspace"
	}
	devnull, _ := os.Open("/dev/null")
	attr := &syscall.ProcAttr{Dir: dir, Env: env, Files: []uintptr{devnull.Fd(), outW.Fd(), errW.Fd()},
		Sys: &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: agentUID, Gid: agentUID}}}
	res.StartedMs = time.Since(t0).Milliseconds()
	pid, err := syscall.ForkExec(t.Argv[0], t.Argv, attr)
	outW.Close()
	errW.Close()
	devnull.Close()
	if err != nil {
		return Result{Type: "error", Error: "exec: " + err.Error()}
	}
	logf("started %s (pid %d)", t.Argv[0], pid)
	for {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(-1, &ws, 0, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			break
		}
		if wpid == pid {
			if ws.Signaled() {
				res.Exit, res.Signal = 128+int(ws.Signal()), ws.Signal().String()
			} else {
				res.Exit = ws.ExitStatus()
			}
			break
		}
	}
	res.EndedMs = time.Since(t0).Milliseconds()
	// the command's own pipe writers may live on in orphans; give them a moment, then stop waiting
	done := make(chan struct{})
	go func() { copies.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = unix.Kill(-pid, unix.SIGKILL)
	}
	stdout.mu.Lock()
	stderr.mu.Lock()
	res.Stdout, res.Stderr = stdout.buf.Bytes(), stderr.buf.Bytes()
	res.Truncated = stdout.truncated || stderr.truncated
	stdout.mu.Unlock()
	stderr.mu.Unlock()
	return res
}

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "yard-guest runs as PID 1 of an agent VM")
		os.Exit(2)
	}
	signal.Ignore(unix.SIGPIPE)
	mounts()
	must("lo", loopbackUp())
	logf("mounted, lo up")
	go forward()
	ctl, err := vsockDial(controlPort)
	must("control", err)
	must("hello", writeFrame(ctl, map[string]any{"type": "hello", "ms": time.Since(t0).Milliseconds()}))
	var t Task
	must("task", readFrame(ctl, &t))
	logf("task: %s", strings.Join(t.Argv[:min(1, len(t.Argv))], " "))
	res := run(t)
	logf("exit %d %s (%d bytes out)", res.Exit, res.Signal, len(res.Stdout))
	// the result frame may exceed readFrame's cap on the guest side; the host reads it with its own cap
	if err := writeFrame(ctl, res); err != nil {
		logf("result: %v", err)
	}
	// a write returns once queued, not delivered: wait for the host's ack (bounded) before powering off
	acked := make(chan error, 1)
	go func() { var a map[string]any; acked <- readFrame(ctl, &a) }()
	select {
	case err := <-acked:
		if err != nil {
			logf("ack: %v", err)
		}
	case <-time.After(10 * time.Second):
		logf("ack: timed out")
	}
	ctl.Close()
	halt()
}
