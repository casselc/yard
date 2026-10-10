//go:build !freebsd

package jail

import "errors"

// ErrUnsupported is returned off FreeBSD.
var ErrUnsupported = errors.New("jail: FreeBSD only")

func Set([]Param, int) (int, error) { return -1, ErrUnsupported }
func JID(string) (int, error)       { return -1, ErrUnsupported }
func Remove(int) error              { return ErrUnsupported }
