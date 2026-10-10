//go:build linux

package frontend

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the uid of the connected peer (SO_PEERCRED).
func PeerUID(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		var u *unix.Ucred
		u, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if gerr == nil {
			uid = u.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, gerr
}
