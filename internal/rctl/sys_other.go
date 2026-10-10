//go:build !freebsd

package rctl

import "errors"

var ErrUnsupported = errors.New("rctl: FreeBSD only")

func Add(string) error    { return ErrUnsupported }
func Remove(string) error { return ErrUnsupported }
