package jail

import (
	"bytes"
	"testing"
)

func TestEncode(t *testing.T) {
	parts := Encode([]Param{Str("name", "a.b"), Int("ip4", SysInherit), Bool("persist"), Int("children.max", -1)})
	want := [][]byte{[]byte("name\x00"), []byte("a.b\x00"), []byte("ip4\x00"), {2, 0, 0, 0}, []byte("persist\x00"), nil,
		[]byte("children.max\x00"), {0xff, 0xff, 0xff, 0xff}}
	if len(parts) != len(want) {
		t.Fatalf("%d parts", len(parts))
	}
	for i := range want {
		if !bytes.Equal(parts[i], want[i]) || (want[i] == nil) != (parts[i] == nil) {
			t.Fatalf("part %d = %q, want %q", i, parts[i], want[i])
		}
	}
}

func TestValidComponent(t *testing.T) {
	for _, ok := range []string{"ysbx_a1", "c0042", "a-b"} {
		if ValidComponent(ok) != nil {
			t.Errorf("rejected %s", ok)
		}
	}
	for _, bad := range []string{"", "a.b", "1234", "a b", "x/y"} {
		if ValidComponent(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
