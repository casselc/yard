// Package jail creates and removes FreeBSD jails with jail_set(2),
// jail_get(2) and jail_remove(2), without cgo. Attaching a process to a jail
// is done by the C exec shim (shim/yard-exec-shim.c) with jail_attach(jid):
// attach-by-jid works on release hosts, where jail_attach_jd() leaks a
// prison reference (fixed in stable/15 by 3584cde63e; HARNESS.md).
package jail

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// Flags for jail_set(2) / jail_get(2).
const (
	Create = 0x01
	Update = 0x02
	Attach = 0x04
)

// jailsys values for ip4/ip6/vnet.
const (
	SysDisable = 0
	SysNew     = 1
	SysInherit = 2
)

// Param is one jail parameter. Val nil means a boolean "true" (or, with a
// "no" prefix in the name, "false"), as jail(2) expects.
type Param struct {
	Name string
	Val  []byte
}

// Str is a string parameter (NUL-terminated).
func Str(name, v string) Param { return Param{name, append([]byte(v), 0)} }

// Int is a C int parameter (little-endian, 4 bytes, amd64/arm64).
func Int(name string, v int32) Param {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return Param{name, b}
}

// Bool is a boolean parameter: Bool("persist") or Bool("allow.noset_hostname").
func Bool(name string) Param { return Param{name, nil} }

// Encode returns the name/value byte slices in jail(2) iovec order.
func Encode(ps []Param) [][]byte {
	out := make([][]byte, 0, 2*len(ps))
	for _, p := range ps {
		out = append(out, append([]byte(p.Name), 0), p.Val)
	}
	return out
}

var compRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidComponent checks one component of a hierarchical jail name. Dots
// separate levels, and an all-digit name would be read as a jid.
func ValidComponent(s string) error {
	if !compRe.MatchString(s) {
		return fmt.Errorf("jail name component %q: want [A-Za-z0-9_-]{1,64}", s)
	}
	if strings.Trim(s, "0123456789") == "" {
		return fmt.Errorf("jail name component %q is all digits", s)
	}
	return nil
}

// Hardened returns the parameters every yard jail gets: no allow.* (the
// two that default to on are turned off explicitly), enforce_statfs=2.
func Hardened() []Param {
	return []Param{
		Bool("allow.noset_hostname"),
		Bool("allow.noreserved_ports"),
		Int("enforce_statfs", 2),
	}
}
