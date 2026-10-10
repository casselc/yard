//go:build unix

package tpmkey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Dev is a TPM character device (/dev/tpm0 on FreeBSD) accessed with plain
// blocking read(2)/write(2) on a raw fd: no Go netpoller/kqueue involvement,
// and the fd can be rights-limited to CAP_READ|CAP_WRITE|CAP_EVENT|CAP_FSTAT.
//
// FreeBSD's tpm20(4) only lets the thread that wrote a command read its
// response (owner_tid; any other thread gets EPERM). Worse, that EPERM read
// cancels the driver's discard callout, so the unread response wedges the
// device: every later write blocks uninterruptibly until reboot. Go may move a
// goroutine to another OS thread between write and read, so all transactions
// run on one goroutine locked to its OS thread (Send), never via Read/Write
// from arbitrary goroutines.
type Dev struct {
	fd  int
	req chan devReq
}

type devReq struct {
	cmd  []byte
	resp chan devResp
}

type devResp struct {
	b   []byte
	err error
}

// OpenDev opens the device read-write and starts its thread-locked worker.
func OpenDev(path string) (*Dev, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	d := &Dev{fd: fd, req: make(chan devReq)}
	go d.loop()
	return d, nil
}

func (d *Dev) loop() {
	runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
	for r := range d.req {
		b, err := d.transact(r.cmd)
		r.resp <- devResp{b, err}
	}
}

// transact writes one command and reads its whole response on the calling (locked) thread.
func (d *Dev) transact(cmd []byte) ([]byte, error) {
	for {
		n, err := unix.Write(d.fd, cmd)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tpm write: %w", err)
		}
		if n != len(cmd) {
			return nil, fmt.Errorf("tpm write: short write %d of %d", n, len(cmd))
		}
		break
	}
	buf := make([]byte, 4096) // TPM_BUFSIZE
	got := 0
	for {
		n, err := unix.Read(d.fd, buf[got:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tpm read: %w", err)
		}
		if n == 0 {
			return nil, errors.New("tpm read: no data")
		}
		got += n
		if got >= 10 {
			size := int(binary.BigEndian.Uint32(buf[2:6]))
			if size < 10 || size > len(buf) {
				return nil, fmt.Errorf("tpm read: bad response size %d", size)
			}
			if got >= size {
				return buf[:size], nil
			}
		}
	}
}

// Send implements go-tpm's transport.TPM: one command, one response, on the locked thread.
func (d *Dev) Send(cmd []byte) ([]byte, error) {
	r := devReq{cmd: cmd, resp: make(chan devResp, 1)}
	d.req <- r
	out := <-r.resp
	return out.b, out.err
}

// Fd returns the raw descriptor.
func (d *Dev) Fd() uintptr { return uintptr(d.fd) }

// Close stops the worker and closes the fd.
func (d *Dev) Close() error {
	close(d.req)
	return unix.Close(d.fd)
}
