//go:build freebsd

package rctl

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysAdd    = 528
	sysRemove = 529
)

func call(trap uintptr, s string) error {
	b := append([]byte(s), 0)
	_, _, e := syscall.Syscall6(trap, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0, 0, 0)
	runtime.KeepAlive(b)
	if e != 0 {
		return e
	}
	return nil
}

// Add adds one rule. ENOSYS means kern.racct.enable=0.
func Add(rule string) error { return call(sysAdd, rule) }

// Remove removes every rule matching filter. ESRCH (nothing matched) is not an error.
func Remove(filter string) error {
	err := call(sysRemove, filter)
	if err == unix.ESRCH {
		return nil
	}
	return err
}
