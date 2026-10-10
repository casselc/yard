//go:build freebsd

package frontend

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the effective uid of the connected peer (LOCAL_PEERCRED).
// Needs CAP_GETSOCKOPT on the accepted socket in capability mode.
func PeerUID(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		var x *unix.Xucred
		x, gerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if gerr == nil {
			uid = x.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, gerr
}
