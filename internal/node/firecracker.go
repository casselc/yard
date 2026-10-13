//go:build linux

package node

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Firecracker launches each allocation as a firecracker process (no API socket), with the parent-death signal set
// so the VM never outlives the node, and serves its control channel (v.sock_5000): the task out, the result in
// (written durably before the guest is acknowledged).
type Firecracker struct {
	Bin       string
	OutputCap int64 // the result frame's cap
	Logf      func(string, ...any)
}

type fcVM struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	ln   net.Listener
}

func (v *fcVM) Wait() error { <-v.done; return v.err }
func (v *fcVM) Kill() error { return v.cmd.Process.Kill() }
func (v *fcVM) CPU() (user, sys time.Duration, rss int64) {
	ps := v.cmd.ProcessState
	if ps == nil {
		return 0, 0, 0
	}
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
		rss = ru.Maxrss
	}
	return ps.UserTime(), ps.SystemTime(), rss
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

func readFrameRaw(r io.Reader, max uint32) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > max {
		return nil, fmt.Errorf("frame of %d bytes over %d", size, max)
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFileSync(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, p)
}

func (fc *Firecracker) Launch(id, dir string, s Spec) (VM, error) {
	logf := fc.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	vsock := filepath.Join(dir, "v.sock")
	os.Remove(vsock + "_5000")
	ln, err := net.Listen("unix", vsock+"_5000")
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"boot-source": map[string]any{"kernel_image_path": s.Kernel,
			"boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro quiet i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/sbin/yard-guest"},
		"drives": []map[string]any{
			{"drive_id": "rootfs", "path_on_host": s.Rootfs, "is_root_device": true, "is_read_only": true},
			{"drive_id": "input", "path_on_host": s.Input, "is_root_device": false, "is_read_only": true},
		},
		"machine-config": map[string]any{"vcpu_count": s.VCPU, "mem_size_mib": s.MemMiB, "smt": false},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": vsock},
	}
	cj, _ := json.MarshalIndent(cfg, "", " ")
	cfgPath := filepath.Join(dir, "vm.json")
	if err := os.WriteFile(cfgPath, cj, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	console, err := os.Create(filepath.Join(dir, "console.log"))
	if err != nil {
		ln.Close()
		return nil, err
	}
	cmd := exec.Command(fc.Bin, "--no-api", "--id", id[:min(len(id), 32)], "--level", "Warn", "--config-file", cfgPath)
	cmd.Stdout, cmd.Stderr = console, console
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if err := cmd.Start(); err != nil {
		ln.Close()
		console.Close()
		return nil, err
	}
	v := &fcVM{cmd: cmd, done: make(chan struct{}), ln: ln}
	go func() {
		v.err = cmd.Wait()
		console.Close()
		ln.Close()
		close(v.done)
	}()
	capBytes := fc.OutputCap
	if capBytes <= 0 {
		capBytes = 64 << 20
	}
	go func() { // the control channel: one connection per VM
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReaderSize(c, 1<<20)
		if _, err := readFrameRaw(br, 1<<16); err != nil { // hello
			logf("%s: hello: %v", id, err)
			return
		}
		if err := writeFrame(c, s.Task); err != nil {
			logf("%s: task: %v", id, err)
			return
		}
		res, err := readFrameRaw(br, uint32(3*capBytes))
		if err != nil {
			logf("%s: result: %v", id, err)
			return
		}
		if err := writeFileSync(filepath.Join(dir, "result.json"), res); err != nil {
			logf("%s: store result: %v", id, err)
			return
		}
		writeFrame(c, map[string]string{"type": "ack"}) // only after the result is durable
	}()
	return v, nil
}
