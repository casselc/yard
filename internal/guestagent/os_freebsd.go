//go:build freebsd

package guestagent

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SysClock steps the wall clock with settimeofday(2) (root).
type SysClock struct{}

func (SysClock) Now() time.Time { return time.Now() }

func (SysClock) Step(d time.Duration) error {
	tv := unix.NsecToTimeval(time.Now().Add(d).UnixNano())
	return unix.Settimeofday(&tv)
}

// SysctlGen reads dev.vmgenc.0.guid: the kernel's CACHED generation ID, updated only when vmgenc(4)
// handles the ACPI notify (sys/dev/vmgenc/vmgenc_acpi.c). "" when the guest has no vmgenc.
type SysctlGen struct{ Name string }

func (s SysctlGen) ReadGen() (Gen, error) {
	n := s.Name
	if n == "" {
		n = "dev.vmgenc.0.guid"
	}
	b, err := unix.SysctlRaw(n)
	if err != nil {
		if err == unix.ENOENT {
			return "", nil
		}
		return "", err
	}
	return Gen(hex.EncodeToString(b)), nil
}

// DevRandom writes host bytes to /dev/random and reads kr from it; Params reads the reseed rule's
// sysctls. The write path and the rule are documented at ReseedPlan (resume.go): writes reach Fortuna
// synchronously, but only a later reseed (a read's pre_read: pool 0 >= minpoolsize, > 100 ms since the
// last reseed) puts them into the generator. vmgenc(4)'s mix of the generation ID (2 events, 24 bytes of
// pool-0 accounting) waits for that same reseed.
type DevRandom struct{ Path string }

func (d DevRandom) path() string {
	if d.Path == "" {
		return "/dev/random"
	}
	return d.Path
}

func (DevRandom) Params() (EntropyParams, error) {
	mp, err := unix.SysctlUint32("kern.random.fortuna.minpoolsize")
	if err != nil {
		return EntropyParams{}, fmt.Errorf("sysctl kern.random.fortuna.minpoolsize: %w (not Fortuna?)", err)
	}
	hz, err := unix.SysctlUint32("kern.hz")
	if err != nil || hz == 0 {
		return EntropyParams{}, fmt.Errorf("sysctl kern.hz: %v (%d)", err, hz)
	}
	return EntropyParams{MinPoolSize: int(mp), Tick: time.Second / time.Duration(hz)}, nil
}

func (d DevRandom) Add(b []byte, passes int) (int, error) {
	f, err := os.OpenFile(d.path(), os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for i := 0; i < passes; i++ {
		if _, err := f.Write(b); err != nil {
			return i, fmt.Errorf("write %d: %w", i, err)
		}
	}
	return passes, nil
}

func (d DevRandom) Read8() (string, error) {
	f, err := os.Open(d.path())
	if err != nil {
		return "", err
	}
	defer f.Close()
	b := make([]byte, 8)
	if _, err := f.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RcServices runs `service NAME restart|status` (rc.subr: status prints "NAME is running as pid N.").
type RcServices struct{}

var pidRe = regexp.MustCompile(`pid ([0-9]+)`)

func (RcServices) Pid(ctx context.Context, name string) (int, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/service", name, "status").CombinedOutput()
	m := pidRe.FindSubmatch(out)
	if m == nil {
		if err != nil {
			return 0, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return 0, fmt.Errorf("no pid in %q", strings.TrimSpace(string(out)))
	}
	return strconv.Atoi(string(m[1]))
}

func (RcServices) Restart(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "/usr/sbin/service", name, "restart")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) } // the rc script and its children
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (RcServices) Kill(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

// WatchDevd reads devd(8)'s event socket (one event per seqpacket) and calls on for every ACPI
// VMGenerationCounter notification ("!system=ACPI subsystem=VMGenerationCounter type=... notify=0x00",
// acpi_UserNotify in sys/dev/acpica/acpi.c). Reconnects every second while devd is not there. Clients of
// the socket need no devd.conf change.
func WatchDevd(ctx context.Context, path string, on func(), logf func(string, ...any)) {
	if path == "" {
		path = "/var/run/devd.seqpacket.pipe"
	}
	fails := 0
	for ctx.Err() == nil {
		c, err := net.Dial("unixpacket", path)
		if err != nil {
			if fails++; fails == 1 || fails%60 == 0 {
				logf("devd: %v (retrying every 1 s)", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		fails = 0
		go func() { <-ctx.Done(); c.Close() }()
		buf := make([]byte, 8192)
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			ev := string(buf[:n])
			if strings.Contains(ev, "system=ACPI") && strings.Contains(ev, "subsystem=VMGenerationCounter") {
				on()
			}
		}
		c.Close()
	}
}
