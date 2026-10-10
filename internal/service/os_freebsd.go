//go:build freebsd

package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"yard/internal/spawn"
)

// HostOS is the FreeBSD OS.
type HostOS struct{ spawn.HostSys }

// Procs reads every process's jail id, pid and state with ps(1) (one -o per
// keyword: in "-o jid=,pid=" the header of jid would be ",pid=") and keeps
// those of jid. `ps -J` is not used: it refuses the id of a dying jail,
// whose processes may still be exiting.
func (HostOS) Procs(jid int) ([]Proc, error) {
	out, err := exec.Command("/bin/ps", "-ax", "-o", "jid=", "-o", "pid=", "-o", "stat=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var ps []Proc
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		j, err1 := strconv.Atoi(f[0])
		pid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil || j != jid || strings.HasPrefix(f[2], "Z") {
			continue
		}
		ps = append(ps, Proc{PID: pid, Stopped: strings.HasPrefix(f[2], "T")})
	}
	return ps, nil
}

func (h HostOS) Zfs(ctx context.Context, lock *os.File, args ...string) (string, error) {
	return h.ZfsIn(ctx, lock, nil, args...)
}

// ZpoolSync is `zpool sync POOL`.
func (HostOS) ZpoolSync(ctx context.Context, pool string) error {
	if out, err := exec.CommandContext(ctx, "/sbin/zpool", "sync", pool).CombinedOutput(); err != nil {
		return fmt.Errorf("zpool sync %s: %v: %s", pool, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ZfsIn runs zfs(8) with stdin (a raw key never touches a file or argv).
func (HostOS) ZfsIn(ctx context.Context, lock *os.File, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/sbin/zfs", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin"}
	if lock != nil {
		cmd.ExtraFiles = []*os.File{lock}
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("zfs %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}
