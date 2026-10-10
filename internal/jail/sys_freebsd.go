//go:build freebsd

package jail

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysJailGet    = 506
	sysJailSet    = 507
	sysJailRemove = 508
)

func iovecs(ps []Param, errbuf []byte) ([]unix.Iovec, [][]byte) {
	parts := Encode(append(ps, Param{"errmsg", errbuf}))
	iov := make([]unix.Iovec, len(parts))
	for i, b := range parts {
		if len(b) > 0 {
			iov[i].Base = &b[0]
			iov[i].SetLen(len(b))
		}
	}
	return iov, parts
}

func call(trap uintptr, ps []Param, flags int) (int, error) {
	errbuf := make([]byte, 1024)
	iov, keep := iovecs(ps, errbuf)
	r, _, e := syscall.Syscall(trap, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags))
	runtime.KeepAlive(keep)
	runtime.KeepAlive(iov)
	if e != 0 {
		if i := bytes.IndexByte(errbuf, 0); i > 0 {
			return -1, fmt.Errorf("%w: %s", e, errbuf[:i])
		}
		return -1, e
	}
	return int(r), nil
}

// Set calls jail_set(2) and returns the jid.
func Set(ps []Param, flags int) (int, error) { return call(sysJailSet, ps, flags) }

// JID looks a jail up by (hierarchical) name.
func JID(name string) (int, error) { return call(sysJailGet, []Param{Str("name", name)}, 0) }

// Remove calls jail_remove(2): it kills every process in the jail and its
// descendants and removes them.
func Remove(jid int) error {
	_, _, e := syscall.Syscall(sysJailRemove, uintptr(jid), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
