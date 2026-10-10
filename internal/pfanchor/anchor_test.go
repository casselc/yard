package pfanchor

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	s := Spec{ID: "s1", Iface: "epair3a", Jail: netip.MustParseAddr("10.77.3.2"), Broker: netip.MustParseAddr("10.77.3.1"), BrokerPort: 8099}
	got, err := s.Render()
	if err != nil {
		t.Fatal(err)
	}
	want := "# yard/sbx-s1 (yard-spawn)\n" +
		"rdr pass on epair3a inet proto tcp from 10.77.3.2 to { 169.254.169.254, 169.254.170.2 } port 80 -> 10.77.3.1 port 8099\n" +
		"block drop in log quick on epair3a all\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	s.Broker = netip.MustParseAddr("127.0.0.1")
	if _, err := s.Render(); err == nil {
		t.Fatal("loopback broker accepted (Phase 0 S4: no reply comes back)")
	}
	s.Broker = netip.MustParseAddr("10.77.3.1")
	s.Iface = "epair3a; pass all"
	if _, err := s.Render(); err == nil {
		t.Fatal("interface injection accepted")
	}
}

func TestRenderExpose(t *testing.T) {
	s := Spec{ID: "s1", Iface: "epair3a", Jail: netip.MustParseAddr("10.77.3.2"), Broker: netip.MustParseAddr("10.77.3.1"),
		BrokerPort: 8099, Expose: []uint16{8080, 9000}}
	got, err := s.Render()
	if err != nil {
		t.Fatal(err)
	}
	want := "pass out quick on epair3a inet proto tcp from 10.77.3.1 to 10.77.3.2 port { 8080, 9000 } keep state\n"
	if !strings.Contains(got, want) {
		t.Fatalf("got:\n%s\nwant line:\n%s", got, want)
	}
	if strings.Index(got, want) > strings.Index(got, "block drop in") {
		t.Fatal("expose rule after the quick block")
	}
	s.Expose = []uint16{0}
	if _, err := s.Render(); err == nil {
		t.Fatal("port 0 accepted")
	}
}
