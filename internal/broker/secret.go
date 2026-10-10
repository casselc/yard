package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// Secret holds a credential value. Every way of printing it (fmt verbs,
// JSON) yields "[redacted]"; only the broker's injection code reads the
// bytes, through value().
type Secret struct{ b []byte }

const redacted = "[redacted]"

// NewSecret wraps a value (tests and minters).
func NewSecret(v string) Secret { return Secret{b: []byte(v)} }

func (s Secret) value() string                { return string(s.b) }
func (s Secret) Empty() bool                  { return len(s.b) == 0 }
func (s Secret) String() string               { return redacted }
func (s Secret) GoString() string             { return redacted }
func (s Secret) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// SecretSource yields named secrets (cloud API keys, halo's key). The
// sandbox never sees them: the broker injects them on the upstream side.
type SecretSource interface {
	Secret(ctx context.Context, name string) (Secret, error)
}

// ErrNoSecret: the source has no secret of that name.
var ErrNoSecret = errors.New("no such secret")

// ErrSecretPolicy: the secret exists but fails the source's checks
// (owner, mode, type, size, format).
var ErrSecretPolicy = errors.New("secret fails policy")

var secretNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// FileSource reads one secret per file from Dir. Every ancestor of Dir must
// be owned by root or the broker's uid and not group/world-writable unless
// sticky; Dir itself is opened once (O_DIRECTORY|O_NOFOLLOW), checked by
// descriptor (owner = broker uid, not group/world-writable), and the secret
// is opened relative to that descriptor (O_NOFOLLOW|O_NONBLOCK, so a FIFO
// cannot block) and checked by descriptor (regular file, owner, 0600/0400).
// Errors wrap ErrNoSecret or ErrSecretPolicy and never carry content.
type FileSource struct {
	Dir string
	// MaxSize bounds a secret file (default 64 KiB).
	MaxSize int64
	// stopAt ends the ancestor walk at this directory (tests: the test
	// runner's temp root is not ours to vouch for).
	stopAt string
}

func policy(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrSecretPolicy}, a...)...)
}

// checkAncestors refuses a path any of whose parents another user could
// replace.
func checkAncestors(dir, stopAt string, uid int) error {
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		if stopAt != "" && p == stopAt {
			return nil
		}
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return policy("ancestor %s: %v", p, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return policy("ancestor %s is not a directory", p)
		}
		if int(st.Uid) != 0 && int(st.Uid) != uid {
			return policy("ancestor %s owned by uid %d", p, st.Uid)
		}
		if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 { // MUTANT:ancestorsUnchecked
			return policy("ancestor %s is group/world-writable", p)
		}
		if p == "/" {
			return nil
		}
	}
}

func (f FileSource) Secret(_ context.Context, name string) (Secret, error) {
	if !secretNameRe.MatchString(name) {
		return Secret{}, policy("secret name %q: want [a-z0-9][a-z0-9._-]{0,63}", name)
	}
	if !filepath.IsAbs(f.Dir) || filepath.Clean(f.Dir) != f.Dir {
		return Secret{}, policy("secret dir %q must be absolute and clean", f.Dir)
	}
	uid := os.Geteuid()
	if err := checkAncestors(f.Dir, f.stopAt, uid); err != nil {
		return Secret{}, err
	}
	dfd, err := unix.Open(f.Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Secret{}, policy("secret dir: open: %v", err)
	}
	defer unix.Close(dfd)
	var dst unix.Stat_t
	if err := unix.Fstat(dfd, &dst); err != nil {
		return Secret{}, policy("secret dir: fstat: %v", err)
	}
	if dst.Mode&0o022 != 0 {
		return Secret{}, policy("secret dir %s is group/world-writable (%#o)", f.Dir, dst.Mode&0o777)
	}
	if int(dst.Uid) != uid {
		return Secret{}, policy("secret dir %s not owned by uid %d", f.Dir, uid)
	}
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return Secret{}, fmt.Errorf("secret %s: %w", name, ErrNoSecret)
		}
		return Secret{}, policy("secret %s: open: %v", name, err)
	}
	fh := os.NewFile(uintptr(fd), name)
	defer fh.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return Secret{}, policy("secret %s: fstat: %v", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG { // MUTANT:secretNotRegular
		return Secret{}, policy("secret %s is not a regular file", name)
	}
	if st.Mode&0o077 != 0 {
		return Secret{}, policy("secret %s has mode %#o; want 0600 or 0400", name, st.Mode&0o777)
	}
	if int(st.Uid) != uid {
		return Secret{}, policy("secret %s not owned by uid %d", name, uid)
	}
	max := f.MaxSize
	if max <= 0 {
		max = 64 << 10
	}
	if st.Size > max {
		return Secret{}, policy("secret %s larger than %d bytes", name, max)
	}
	b, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil || int64(len(b)) > max {
		return Secret{}, policy("secret %s: read failed or too large", name)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" || strings.ContainsAny(v, "\r\n\x00") {
		return Secret{}, policy("secret %s: empty, or more than one line", name)
	}
	return Secret{b: []byte(v)}, nil
}

// MapSource is an in-memory SecretSource (tests).
type MapSource map[string]string

func (m MapSource) Secret(_ context.Context, name string) (Secret, error) {
	v, ok := m[name]
	if !ok {
		return Secret{}, fmt.Errorf("secret %s: %w", name, ErrNoSecret)
	}
	return NewSecret(v), nil
}
