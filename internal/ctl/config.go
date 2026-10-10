package ctl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"yard/internal/frontend"
	"yard/internal/issuer"
	"yard/internal/keyring"
)

// Duration is a JSON duration string ("24h").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Config is yard-ctl's configuration file.
type Config struct {
	Issuer            string   `json:"issuer"`
	TrustDomain       string   `json:"trust_domain"`
	ExternalAudiences []string `json:"external_audiences"`
	InternalAudiences []string `json:"internal_audiences"`
	MaxTTL            Duration `json:"max_ttl"`
	DefaultTTL        Duration `json:"default_ttl"`
	RatePerSecond     float64  `json:"rate_per_s"`
	Burst             int      `json:"burst"`
	AWSSessionTags    bool     `json:"aws_session_tags"`

	KeyStore struct {
		Kind    string `json:"kind"` // "tpm" | "dir"
		TPMPath string `json:"tpm_path"`
		Dir     string `json:"dir"`
	} `json:"keystore"`
	ActiveHandle  string   `json:"active_handle"`
	StandbyHandle string   `json:"standby_handle"`
	KeyringState  string   `json:"keyring_state"`
	PublishDelay  Duration `json:"publish_delay"`
	RetireGrace   Duration `json:"retire_grace"`

	SeqLog  string `json:"seq_log"`
	JWKSDir string `json:"jwks_dir"`

	Frontend struct {
		Kind  string            `json:"kind"` // "unix" | "tsnet"
		Path  string            `json:"path"`
		Mode  string            `json:"mode"`  // octal, e.g. "0660"
		Users map[string]Caller `json:"users"` // uid -> caller
	} `json:"frontend"`
}

// Caller in the config file.
type Caller struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// LoadConfig reads a config file strictly.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// IssuerConfig maps to issuer.Config.
func (c *Config) IssuerConfig() issuer.Config {
	return issuer.Config{Issuer: c.Issuer, TrustDomain: c.TrustDomain,
		ExternalAudiences: c.ExternalAudiences, InternalAudiences: c.InternalAudiences,
		MaxTTL: time.Duration(c.MaxTTL), DefaultTTL: time.Duration(c.DefaultTTL),
		RatePerSecond: c.RatePerSecond, Burst: c.Burst, AWSSessionTags: c.AWSSessionTags}
}

// RingConfig maps to keyring.Config (defaults when unset).
func (c *Config) RingConfig() keyring.Config {
	rc := keyring.DefaultConfig
	if c.PublishDelay > 0 {
		rc.PublishDelay = time.Duration(c.PublishDelay)
	}
	if c.RetireGrace > 0 {
		rc.RetireGrace = time.Duration(c.RetireGrace)
	}
	return rc
}

// Handles parses the active and standby handles.
func (c *Config) Handles() (keyring.Handle, keyring.Handle, error) {
	a, err := ParseHandle(c.ActiveHandle)
	if err != nil {
		return 0, 0, err
	}
	s, err := ParseHandle(c.StandbyHandle)
	return a, s, err
}

// ParseHandle parses "0x81010010".
func ParseHandle(s string) (keyring.Handle, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("handle %q: %w", s, err)
	}
	return keyring.Handle(v), nil
}

// Frontend builds the configured frontend.
func (c *Config) BuildFrontend() (frontend.Frontend, error) {
	switch c.Frontend.Kind {
	case "unix", "":
		u := &frontend.Unix{Path: c.Frontend.Path, Users: map[uint32]frontend.Caller{}}
		if c.Frontend.Mode != "" {
			m, err := strconv.ParseUint(c.Frontend.Mode, 8, 32)
			if err != nil {
				return nil, fmt.Errorf("frontend mode %q: %w", c.Frontend.Mode, err)
			}
			u.Mode = os.FileMode(m)
		}
		for k, v := range c.Frontend.Users {
			uid, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("frontend user key %q: want a numeric uid", k)
			}
			u.Users[uint32(uid)] = frontend.Caller{Name: v.Name, Roles: v.Roles}
		}
		if u.Path == "" {
			return nil, fmt.Errorf("frontend: unix path required")
		}
		return u, nil
	case "tsnet":
		return &frontend.Tsnet{}, nil
	}
	return nil, fmt.Errorf("frontend kind %q", c.Frontend.Kind)
}
