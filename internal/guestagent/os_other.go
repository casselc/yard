//go:build !freebsd

package guestagent

import (
	"context"
	"errors"
	"time"
)

// The adapters are FreeBSD-only (the guest); other builds are for unit tests, which use fakes.

var errNotFreeBSD = errors.New("guestagent: FreeBSD only")

type SysClock struct{}

func (SysClock) Now() time.Time             { return time.Now() }
func (SysClock) Step(d time.Duration) error { return errNotFreeBSD }

type SysctlGen struct{ Name string }

func (SysctlGen) ReadGen() (Gen, error) { return "", nil }

type DevRandom struct{ Path string }

func (DevRandom) Params() (EntropyParams, error)        { return EntropyParams{}, errNotFreeBSD }
func (DevRandom) Add(b []byte, passes int) (int, error) { return 0, errNotFreeBSD }
func (DevRandom) Read8() (string, error)                { return "", errNotFreeBSD }

type RcServices struct{}

func (RcServices) Pid(ctx context.Context, name string) (int, error) { return 0, errNotFreeBSD }
func (RcServices) Restart(ctx context.Context, name string) error    { return errNotFreeBSD }
func (RcServices) Kill(pid int) error                                { return errNotFreeBSD }

func WatchDevd(ctx context.Context, path string, on func(), logf func(string, ...any)) { <-ctx.Done() }
