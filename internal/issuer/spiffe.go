// Package issuer turns a mint request into a SPIFFE-shaped JWT signed by the
// keyring's active key (IDENTITY.md "Identity flow" and decision 6).
//
// Two token kinds:
//
//   - External federation tokens (AWS, Azure, Anthropic, ...): sub is the
//     agent's policy class, spiffe://<td>/harness/<h>/policy/<class>, so cloud
//     trust rules key on sub alone (Azure FIC needs an exact match, at most
//     20 per identity). The full workload id, the user and AWS session tags
//     travel as extra claims.
//   - Internal tokens (yard, MCP, scope): RFC 8693 shape, sub = the user,
//     act = {"sub": full workload SPIFFE id}.
package issuer

import (
	"fmt"
	"regexp"
	"strings"
)

var segRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// WorkloadID is the authorizing-parts-first SPIFFE path of a sandbox run.
type WorkloadID struct {
	Harness string `json:"harness"`
	Policy  string `json:"policy"`
	Node    string `json:"node"`
	Sandbox string `json:"sandbox"`
	Run     string `json:"run"`
}

// Validate checks every segment against [a-z0-9-]{1,63}.
func (w WorkloadID) Validate() error {
	for _, kv := range [][2]string{{"harness", w.Harness}, {"policy", w.Policy}, {"node", w.Node}, {"sandbox", w.Sandbox}, {"run", w.Run}} {
		if !segRe.MatchString(kv[1]) {
			return fmt.Errorf("workload %s %q: want [a-z0-9-]{1,63}", kv[0], kv[1])
		}
	}
	return nil
}

// SPIFFE returns spiffe://<td>/harness/<h>/policy/<p>/node/<n>/sandbox/<s>/run/<r>.
func (w WorkloadID) SPIFFE(td string) string {
	return fmt.Sprintf("spiffe://%s/harness/%s/policy/%s/node/%s/sandbox/%s/run/%s", td, w.Harness, w.Policy, w.Node, w.Sandbox, w.Run)
}

// PolicySubject is the prefix of SPIFFE that names the policy class.
func (w WorkloadID) PolicySubject(td string) string {
	return fmt.Sprintf("spiffe://%s/harness/%s/policy/%s", td, w.Harness, w.Policy)
}

// ParseSPIFFE is the inverse of SPIFFE.
func ParseSPIFFE(td, id string) (WorkloadID, error) {
	pre := "spiffe://" + td + "/"
	if !strings.HasPrefix(id, pre) {
		return WorkloadID{}, fmt.Errorf("spiffe id %q not in trust domain %s", id, td)
	}
	p := strings.Split(strings.TrimPrefix(id, pre), "/")
	if len(p) != 10 || p[0] != "harness" || p[2] != "policy" || p[4] != "node" || p[6] != "sandbox" || p[8] != "run" {
		return WorkloadID{}, fmt.Errorf("spiffe id %q: want harness/<h>/policy/<p>/node/<n>/sandbox/<s>/run/<r>", id)
	}
	w := WorkloadID{Harness: p[1], Policy: p[3], Node: p[5], Sandbox: p[7], Run: p[9]}
	return w, w.Validate()
}

var tdRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// ValidTrustDomain checks a SPIFFE trust domain name.
func ValidTrustDomain(td string) bool { return tdRe.MatchString(td) && !strings.Contains(td, "..") }
