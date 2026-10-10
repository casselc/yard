// Package mount does the per-jail mounts with nmount(2): nullfs (template
// and workspace), tmpfs (size-capped scratch) and devfs (with a ruleset).
package mount

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Spec is one mount.
type Spec struct {
	Type    string // nullfs | tmpfs | devfs
	Source  string // nullfs only
	Target  string
	RO      bool
	Size    string // tmpfs size, e.g. "64m"
	Mode    uint32 // tmpfs root mode (0 = default)
	Ruleset int    // devfs ruleset (0 = none)
}

func (s Spec) String() string {
	ro := ""
	if s.RO {
		ro = ",ro"
	}
	switch s.Type {
	case "nullfs":
		return fmt.Sprintf("nullfs %s -> %s%s", s.Source, s.Target, ro)
	case "tmpfs":
		return fmt.Sprintf("tmpfs size=%s -> %s%s", s.Size, s.Target, ro)
	default:
		return fmt.Sprintf("%s ruleset=%d -> %s%s", s.Type, s.Ruleset, s.Target, ro)
	}
}

// Options returns the nmount(2) name/value pairs (values without NUL).
func (s Spec) Options() ([][2]string, error) {
	if !strings.HasPrefix(s.Target, "/") {
		return nil, fmt.Errorf("mount target %q not absolute", s.Target)
	}
	o := [][2]string{{"fstype", s.Type}, {"fspath", s.Target}}
	switch s.Type {
	case "nullfs":
		if !strings.HasPrefix(s.Source, "/") {
			return nil, fmt.Errorf("nullfs source %q not absolute", s.Source)
		}
		o = append(o, [2]string{"target", s.Source})
	case "tmpfs":
		if s.Size != "" {
			o = append(o, [2]string{"size", s.Size})
		}
		if s.Mode != 0 {
			o = append(o, [2]string{"mode", "0" + strconv.FormatUint(uint64(s.Mode), 8)})
		}
	case "devfs":
		if s.Ruleset > 0 {
			o = append(o, [2]string{"ruleset", strconv.Itoa(s.Ruleset)})
		}
	default:
		return nil, fmt.Errorf("mount type %q", s.Type)
	}
	return o, nil
}

// Under returns the mountpoints in mps that are prefix or below it,
// deepest first (the order to unmount them in).
func Under(mps []string, prefix string) []string {
	prefix = strings.TrimRight(prefix, "/")
	var out []string
	for _, m := range mps {
		if m == prefix || strings.HasPrefix(m, prefix+"/") {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.Count(out[i], "/") > strings.Count(out[j], "/") })
	return out
}
