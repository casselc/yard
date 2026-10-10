package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrOwned: another yard-ctl owns the database (assumption A3 of
// spec/sr0/README.md, enforced).
var ErrOwned = errors.New("lifecycle: database is owned by another yard-ctl")

// OpenOwned opens the store as its only owner: an exclusive flock on
// <path>.lock, taken without waiting, held until Close. yard-ctl uses this;
// OpenStore (no lock) is for secondary handles such as a read-only CLI.
func OpenOwned(path string) (*Store, error) {
	lp := path + ".lock"
	f, err := os.OpenFile(lp, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := "unknown pid"
		if b, rerr := os.ReadFile(lp); rerr == nil && len(strings.TrimSpace(string(b))) > 0 {
			holder = "pid " + strings.TrimSpace(string(b))
		}
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s holds %s; stop it first (one yard-ctl per database)", ErrOwned, holder, lp)
		}
		return nil, fmt.Errorf("lifecycle: lock %s: %w", lp, err)
	}
	if err := f.Truncate(0); err == nil {
		f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	st, err := OpenStore(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	st.lock = f
	return st, nil
}
