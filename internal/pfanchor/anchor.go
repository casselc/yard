// Package pfanchor renders and loads the per-sandbox pf anchor
// yard/sbx-<id>: metadata endpoints redirected to the broker on the HOST
// side of the sandbox's epair (a non-loopback address -- Phase 0 S4: a
// loopback rdr target got the request through but no reply back), and
// everything else from the sandbox blocked and logged.
package pfanchor

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

// Metadata endpoints redirected to the broker: EC2 IMDS and ECS credentials.
var Metadata = []string{"169.254.169.254", "169.254.170.2"}

// Spec describes one sandbox's network policy.
type Spec struct {
	ID         string     // sandbox id; anchor is yard/sbx-<id>
	Iface      string     // host side of the epair
	Jail       netip.Addr // sandbox address
	Broker     netip.Addr // broker address (host side of the epair)
	BrokerPort uint16
	// Allow lists extra host:port the sandbox may reach (e.g. the egress proxy).
	Allow []netip.AddrPort
}

var (
	idRe    = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	ifaceRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,14}$`)
)

// Name returns the anchor path.
func (s Spec) Name() string { return "yard/sbx-" + s.ID }

// Render returns the anchor ruleset.
func (s Spec) Render() (string, error) {
	if !idRe.MatchString(s.ID) {
		return "", fmt.Errorf("sandbox id %q", s.ID)
	}
	if !ifaceRe.MatchString(s.Iface) {
		return "", fmt.Errorf("interface %q", s.Iface)
	}
	if !s.Jail.Is4() || !s.Broker.Is4() || s.Broker.IsLoopback() || s.BrokerPort == 0 {
		return "", fmt.Errorf("need IPv4 jail and non-loopback broker addresses and a broker port")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s (yard-spawn)\n", s.Name())
	fmt.Fprintf(&b, "rdr pass on %s inet proto tcp from %s to { %s } port 80 -> %s port %d\n",
		s.Iface, s.Jail, strings.Join(Metadata, ", "), s.Broker, s.BrokerPort)
	for _, a := range s.Allow {
		fmt.Fprintf(&b, "pass in quick on %s inet proto tcp from %s to %s port %d keep state\n", s.Iface, s.Jail, a.Addr(), a.Port())
	}
	fmt.Fprintf(&b, "block drop in log quick on %s all\n", s.Iface)
	return b.String(), nil
}

// Load replaces the anchor's rules with pfctl(8).
func Load(s Spec) error {
	rules, err := s.Render()
	if err != nil {
		return err
	}
	cmd := exec.Command("/sbin/pfctl", "-q", "-a", s.Name(), "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %v: %s", s.Name(), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Flush removes every rule in the anchor.
func Flush(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("sandbox id %q", id)
	}
	// an empty load, not -F all (see spawn.flushAnchor)
	out, err := exec.Command("/sbin/pfctl", "-q", "-a", "yard/sbx-"+id, "-f", "/dev/null").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl flush: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Enabled reports whether pf is loaded and enabled.
func Enabled() bool {
	out, err := exec.Command("/sbin/pfctl", "-s", "info").Output()
	return err == nil && bytes.Contains(out, []byte("Status: Enabled"))
}
