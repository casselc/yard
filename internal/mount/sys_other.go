//go:build !freebsd

package mount

import "errors"

var ErrUnsupported = errors.New("mount: FreeBSD only")

func Mount(Spec) error           { return ErrUnsupported }
func Unmount(string, bool) error { return ErrUnsupported }
func List() ([]string, error)    { return nil, ErrUnsupported }
