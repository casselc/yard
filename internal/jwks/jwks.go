// Package jwks publishes the issuer's public keys: an OpenID discovery
// document plus a JWKS, written atomically to a directory (for static
// hosting on the user's domain, IDENTITY.md decision 1) and served over HTTP.
package jwks

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"yard/internal/keyring"
	"yard/internal/sts"
)

const (
	JWKSPath      = "/.well-known/jwks.json"
	DiscoveryPath = "/.well-known/openid-configuration"
)

// Discovery is the subset of OpenID Provider Metadata that AWS IAM OIDC and
// Entra federated credentials read.
type Discovery struct {
	Issuer          string   `json:"issuer"`
	JWKSURI         string   `json:"jwks_uri"`
	ResponseTypes   []string `json:"response_types_supported"`
	SubjectTypes    []string `json:"subject_types_supported"`
	SigningAlgs     []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported []string `json:"claims_supported"`
	ScopesSupported []string `json:"scopes_supported,omitempty"`
}

// NewDiscovery builds the discovery document for issuer.
func NewDiscovery(issuer string) Discovery {
	return Discovery{
		Issuer:          issuer,
		JWKSURI:         strings.TrimRight(issuer, "/") + JWKSPath,
		ResponseTypes:   []string{"id_token"},
		SubjectTypes:    []string{"public"},
		SigningAlgs:     []string{"RS256"},
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "act", "apv", "yard_wid", "yard_user", "yard_kind", "yard_seq"},
	}
}

// Publisher renders and publishes the documents. Publish is idempotent:
// files are rewritten only when their content changes.
type Publisher struct {
	Dir    string // optional: output directory (.well-known/ is created under it)
	Issuer string

	mu   sync.RWMutex
	jwks []byte
	disc []byte
}

func marshal(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

// Publish renders set and writes it (and the discovery document) to Dir.
func (p *Publisher) Publish(set sts.JWKS) (changed bool, err error) {
	j := marshal(set)
	d := marshal(NewDiscovery(p.Issuer))
	p.mu.Lock()
	changed = !bytes.Equal(j, p.jwks)
	p.jwks, p.disc = j, d
	p.mu.Unlock()
	if p.Dir == "" {
		return changed, nil
	}
	wk := filepath.Join(p.Dir, ".well-known")
	if err := os.MkdirAll(wk, 0o755); err != nil {
		return changed, err
	}
	for name, b := range map[string][]byte{"jwks.json": j, "openid-configuration": d} {
		path := filepath.Join(wk, name)
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
			continue
		}
		if err := keyring.WriteFileAtomic(path, b, 0o644); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// ServeHTTP serves the two documents.
func (p *Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.RLock()
	var b []byte
	switch r.URL.Path {
	case JWKSPath:
		b = p.jwks
	case DiscoveryPath:
		b = p.disc
	}
	p.mu.RUnlock()
	if b == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(b)
}
