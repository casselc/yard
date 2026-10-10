package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openTTY opens a serial device raw (8N1, no echo, CLOCAL so a missing peer is not a hangup).
func openTTY(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: TIOCGETA: %w", path, err)
	}
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB | unix.CRTSCTS
	t.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	t.Ispeed, t.Ospeed = unix.B115200, unix.B115200
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, t); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: TIOCSETA: %w", path, err)
	}
	return f, nil
}
