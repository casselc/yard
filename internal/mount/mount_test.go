package mount

import (
	"reflect"
	"testing"
)

func TestOptions(t *testing.T) {
	o, err := Spec{Type: "nullfs", Source: "/t", Target: "/r", RO: true}.Options()
	if err != nil || !reflect.DeepEqual(o, [][2]string{{"fstype", "nullfs"}, {"fspath", "/r"}, {"target", "/t"}}) {
		t.Fatal(o, err)
	}
	o, _ = Spec{Type: "tmpfs", Target: "/r/tmp", Size: "64m", Mode: 0o1777}.Options()
	if !reflect.DeepEqual(o, [][2]string{{"fstype", "tmpfs"}, {"fspath", "/r/tmp"}, {"size", "64m"}, {"mode", "01777"}}) {
		t.Fatal(o)
	}
	o, _ = Spec{Type: "devfs", Target: "/r/dev", Ruleset: 10}.Options()
	if !reflect.DeepEqual(o, [][2]string{{"fstype", "devfs"}, {"fspath", "/r/dev"}, {"ruleset", "10"}}) {
		t.Fatal(o)
	}
	for _, bad := range []Spec{{Type: "nullfs", Source: "rel", Target: "/r"}, {Type: "zfs", Target: "/r"}, {Type: "tmpfs", Target: "r"}} {
		if _, err := bad.Options(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestUnder(t *testing.T) {
	got := Under([]string{"/", "/a/root", "/a/root/dev", "/a/rootx", "/a/root/.yard", "/a/root/.yard/calls/c1", "/b"}, "/a/root/")
	want := []string{"/a/root/.yard/calls/c1", "/a/root/dev", "/a/root/.yard", "/a/root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}
