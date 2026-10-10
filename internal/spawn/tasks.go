package spawn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"yard/internal/rctl"
)

// TasksConf is /usr/local/etc/yard/tasks.conf (written by ops/n0-30-tasks.sh).
type TasksConf struct {
	UIDMin, UIDMax uint32
	GID            uint32
	Class          string
	Rctl           []rctl.Limit // applied as user:<uid>:<limit>
	Devfs          int
}

// DefaultTasksConf matches what n0-30-tasks.sh installs.
var DefaultTasksConf = TasksConf{UIDMin: 2000000, UIDMax: 2099999, GID: 2000000, Class: "yard_task",
	Rctl: []rctl.Limit{"maxproc:deny=512", "openfiles:deny=16384", "vmemoryuse:deny=8g", "pcpu:deny=200"}, Devfs: 10}

// ParseTasksConf reads key=value lines; unknown keys are errors.
func ParseTasksConf(r io.Reader) (TasksConf, error) {
	c := DefaultTasksConf
	sc := bufio.NewScanner(r)
	n := 0
	u32 := func(v string) (uint32, error) {
		x, err := strconv.ParseUint(v, 10, 32)
		return uint32(x), err
	}
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("tasks.conf line %d: no '='", n)
		}
		var err error
		switch k {
		case "task_uid_min":
			c.UIDMin, err = u32(v)
		case "task_uid_max":
			c.UIDMax, err = u32(v)
		case "task_gid":
			c.GID, err = u32(v)
		case "task_login_class":
			c.Class = v
		case "task_rctl":
			c.Rctl = nil
			for _, f := range strings.Fields(v) {
				l := rctl.Limit(f)
				if err = l.Validate(); err != nil {
					break
				}
				c.Rctl = append(c.Rctl, l)
			}
		case "devfs_ruleset":
			var x uint32
			x, err = u32(v)
			c.Devfs = int(x)
		default:
			return c, fmt.Errorf("tasks.conf line %d: unknown key %q", n, k)
		}
		if err != nil {
			return c, fmt.Errorf("tasks.conf line %d: %w", n, err)
		}
	}
	if c.UIDMin < 1000 || c.UIDMax < c.UIDMin || c.GID == 0 {
		return c, fmt.Errorf("tasks.conf: bad uid range %d-%d or gid %d", c.UIDMin, c.UIDMax, c.GID)
	}
	return c, sc.Err()
}

// LoadTasksConf reads path; a missing file gives the defaults.
func LoadTasksConf(path string) (TasksConf, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultTasksConf, nil
	}
	if err != nil {
		return TasksConf{}, err
	}
	defer f.Close()
	return ParseTasksConf(f)
}

var taskRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Tasks allocates per-task uids. Allocation is a file per uid in Dir,
// created with O_EXCL (so two spawners cannot hand out the same uid), whose
// content is the task id.
type Tasks struct {
	Dir  string
	Conf TasksConf
	Sys  Sys
}

func (t *Tasks) file(uid uint32) string {
	return filepath.Join(t.Dir, strconv.FormatUint(uint64(uid), 10))
}

// Lookup returns the uid allocated to task, or 0.
func (t *Tasks) Lookup(task string) (uint32, error) {
	ents, err := os.ReadDir(t.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	for _, e := range ents {
		uid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(t.Dir, e.Name()))
		if err == nil && strings.TrimSpace(string(b)) == task {
			return uint32(uid), nil
		}
	}
	return 0, nil
}

// Begin allocates a uid for task (idempotent) and installs its rctl user: rules.
func (t *Tasks) Begin(task string) (uint32, error) {
	if !taskRe.MatchString(task) {
		return 0, fmt.Errorf("task id %q: want [a-z0-9][a-z0-9-]{0,62}", task)
	}
	if err := os.MkdirAll(t.Dir, 0o700); err != nil {
		return 0, err
	}
	uid, err := t.Lookup(task)
	if err != nil {
		return 0, err
	}
	if uid == 0 {
		for u := t.Conf.UIDMin; ; u++ {
			f, err := os.OpenFile(t.file(u), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err == nil {
				_, werr := f.WriteString(task + "\n")
				cerr := f.Close()
				if werr != nil || cerr != nil {
					os.Remove(t.file(u))
					return 0, fmt.Errorf("allocate uid %d: %v %v", u, werr, cerr)
				}
				uid = u
				break
			}
			if !errors.Is(err, os.ErrExist) {
				return 0, err
			}
			if u == t.Conf.UIDMax {
				return 0, fmt.Errorf("task uid range %d-%d exhausted", t.Conf.UIDMin, t.Conf.UIDMax)
			}
		}
	}
	// (re)install the rules: remove first so Begin is idempotent
	if err := t.Sys.RemoveRules(rctl.UserFilter(uid)); err != nil {
		return 0, fmt.Errorf("rctl remove user:%d: %w", uid, err)
	}
	for _, l := range t.Conf.Rctl {
		r, err := rctl.UserRule(uid, l)
		if err != nil {
			return 0, err
		}
		if err := t.Sys.AddRule(r); err != nil {
			return 0, fmt.Errorf("rctl add %s: %w", r, err)
		}
	}
	return uid, nil
}

// End removes the task's rules and frees its uid.
func (t *Tasks) End(task string) (uint32, error) {
	uid, err := t.Lookup(task)
	if err != nil || uid == 0 {
		return 0, err
	}
	if err := t.Sys.RemoveRules(rctl.UserFilter(uid)); err != nil {
		return uid, fmt.Errorf("rctl remove user:%d: %w", uid, err)
	}
	return uid, os.Remove(t.file(uid))
}
