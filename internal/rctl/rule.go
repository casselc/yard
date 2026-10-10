// Package rctl builds and applies RCTL rules with rctl_add_rule(2) and
// rctl_remove_rule(2) (no rctl(8) fork: Phase 0 measured 0.8 ms per CLI call).
//
// Phase 0 finding (spike 22): rules on a jail do NOT cover its child jails.
// yard therefore caps a task with user:<uid> rules (they aggregate across
// jails) and puts per-call memory caps on each child jail.
package rctl

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	resources = map[string]bool{"cputime": true, "datasize": true, "stacksize": true, "coredumpsize": true,
		"memoryuse": true, "memorylocked": true, "maxproc": true, "openfiles": true, "vmemoryuse": true,
		"pseudoterminals": true, "swapuse": true, "nthr": true, "msgqqueued": true, "msgqsize": true,
		"nmsgq": true, "nsem": true, "nsemop": true, "nshm": true, "shmsize": true, "wallclock": true,
		"pcpu": true, "readbps": true, "writebps": true, "readiops": true, "writeiops": true}
	actions = map[string]bool{"deny": true, "log": true, "devctl": true, "throttle": true, "sigterm": true, "sigkill": true, "sigxcpu": true}
	amount  = regexp.MustCompile(`^[0-9]{1,15}[kmgtpeKMGTPE]?$`)
	jname   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
)

// Limit is "<resource>:<action>=<amount>", e.g. "vmemoryuse:deny=64m".
type Limit string

// kernel returns the limit with its amount in plain digits. The kernel parses
// the amount with strtoul and rejects any suffix (EINVAL); rctl(8) expands
// k/m/g/... with expand_number(3) before the syscall, and so do we (powers of
// 1024, as expand_number does).
func (l Limit) kernel() (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	ra, amt, _ := strings.Cut(string(l), "=")
	n, err := expand(amt)
	if err != nil {
		return "", fmt.Errorf("rctl limit %q: %w", l, err)
	}
	return ra + "=" + strconv.FormatInt(n, 10), nil
}

func expand(s string) (int64, error) {
	shift := uint(0)
	if c := s[len(s)-1]; c < '0' || c > '9' {
		shift = 10 * uint(1+strings.IndexByte("kmgtpe", c|0x20))
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > (1<<63-1)>>shift {
		return 0, fmt.Errorf("amount out of range")
	}
	return n << shift, nil
}

// Validate parses the limit strictly (no commas, no per-process suffix).
func (l Limit) Validate() error {
	ra, amt, ok := strings.Cut(string(l), "=")
	if !ok {
		return fmt.Errorf("rctl limit %q: want resource:action=amount", l)
	}
	res, act, ok := strings.Cut(ra, ":")
	if !ok || !resources[res] || !actions[act] || !amount.MatchString(amt) {
		return fmt.Errorf("rctl limit %q: bad resource, action or amount", l)
	}
	return nil
}

// Amount validates a size like "64m".
func Amount(s string) error {
	if !amount.MatchString(s) {
		return fmt.Errorf("rctl amount %q: want digits with optional k/m/g/t suffix", s)
	}
	return nil
}

// UserRule is user:<uid>:<limit>, amount in plain digits.
func UserRule(uid uint32, l Limit) (string, error) {
	k, err := l.kernel()
	if err != nil {
		return "", err
	}
	return "user:" + strconv.FormatUint(uint64(uid), 10) + ":" + k, nil
}

// JailRule is jail:<name>:<limit>, amount in plain digits.
func JailRule(name string, l Limit) (string, error) {
	if !jname.MatchString(name) {
		return "", fmt.Errorf("rctl jail name %q", name)
	}
	k, err := l.kernel()
	if err != nil {
		return "", err
	}
	return "jail:" + name + ":" + k, nil
}

// UserFilter / JailFilter select every rule of a subject (for removal).
func UserFilter(uid uint32) string { return "user:" + strconv.FormatUint(uint64(uid), 10) }

func JailFilter(name string) (string, error) {
	if !jname.MatchString(name) {
		return "", fmt.Errorf("rctl jail name %q", name)
	}
	return "jail:" + name, nil
}
