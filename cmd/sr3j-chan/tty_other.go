//go:build !freebsd

package main

import (
	"errors"
	"os"
)

// openTTY: serial transport is FreeBSD-only (the guest and the NUC); other builds are for unit tests.
func openTTY(path string) (*os.File, error) { return nil, errors.New("tty transport: FreeBSD only") }
