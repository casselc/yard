//go:build freebsd

package mount

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysNmount = 378
	mntRdonly = 0x1
	mntNosuid = 0x8
	mntForce  = 0x80000
)

// Mount performs s with nmount(2). Every yard mount is nosuid.
func Mount(s Spec) error {
	opts, err := s.Options()
	if err != nil {
		return err
	}
	errbuf := make([]byte, 255)
	var parts [][]byte
	for _, kv := range opts {
		parts = append(parts, append([]byte(kv[0]), 0), append([]byte(kv[1]), 0))
	}
	parts = append(parts, []byte("errmsg\x00"), errbuf)
	iov := make([]unix.Iovec, len(parts))
	for i, b := range parts {
		iov[i].Base = &b[0]
		iov[i].SetLen(len(b))
	}
	flags := mntNosuid
	if s.RO {
		flags |= mntRdonly
	}
	_, _, e := syscall.Syscall(sysNmount, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags))
	runtime.KeepAlive(parts)
	runtime.KeepAlive(iov)
	if e != 0 {
		if i := bytes.IndexByte(errbuf, 0); i > 0 {
			return fmt.Errorf("nmount %s: %w: %s", s, e, errbuf[:i])
		}
		return fmt.Errorf("nmount %s: %w", s, e)
	}
	return nil
}

// Unmount unmounts target, forcibly if force.
func Unmount(target string, force bool) error {
	f := 0
	if force {
		f = mntForce
	}
	return unix.Unmount(target, f)
}

// List returns every current mountpoint.
func List() ([]string, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n+16)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for _, s := range buf[:n] {
		b := s.Mntonname[:]
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		out = append(out, string(b))
	}
	return out, nil
}
