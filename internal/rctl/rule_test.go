package rctl

import "testing"

func TestRules(t *testing.T) {
	r, err := UserRule(2000001, "vmemoryuse:deny=8g")
	if err != nil || r != "user:2000001:vmemoryuse:deny=8589934592" {
		t.Fatal(r, err)
	}
	r, err = JailRule("ysbx_a.c1", "vmemoryuse:deny=64m")
	if err != nil || r != "jail:ysbx_a.c1:vmemoryuse:deny=67108864" {
		t.Fatal(r, err)
	}
	for _, bad := range []Limit{"vmemoryuse:deny=64m,user:0:maxproc:deny=1", "vmemoryuse:deny=64m/process", "nope:deny=1",
		"maxproc:explode=1", "maxproc=1", "maxproc:deny=-1", "maxproc:deny="} {
		if bad.Validate() == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for in, want := range map[Limit]string{"maxproc:deny=512": "maxproc:deny=512", "pcpu:deny=200": "pcpu:deny=200",
		"openfiles:deny=1K": "openfiles:deny=1024", "swapuse:deny=7E": "swapuse:deny=8070450532247928832"} {
		if got, err := in.kernel(); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := Limit("swapuse:deny=8E").kernel(); err == nil {
		t.Error("8E (overflows int64) accepted")
	}
	if _, err := JailRule("a:b", "maxproc:deny=1"); err == nil {
		t.Error("colon in jail name accepted")
	}
	if f := UserFilter(7); f != "user:7" {
		t.Fatal(f)
	}
}
