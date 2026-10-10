// Package service is SR1: long-running services (dev servers, watchers,
// REPLs) in jails, suspended and resumed by the SR0 lifecycle
// (internal/lifecycle). HARNESS.md "SR1: jails on the NUC/jailhost".
//
// A service is declared as a Spec (command, env, cwd, ports, readiness
// probe). Backend implements lifecycle.Backend, lifecycle.Pauser and
// lifecycle.ArtifactStore for the kind "service":
//
//	Quiesce     SIGTERM every process in the instance's jail (SIGCONT to
//	            stopped ones), SIGKILL after the grace period, and verify that
//	            none is left. The jail stays (the checkpoint needs it).
//	Checkpoint  ZFS snapshot of the workspace dataset, named by session,
//	            generation and checkpoint op (ysr1-<sess>-g<gen>-c<ckpt>), plus
//	            the artifact: the spec and the snapshot name, digested, written
//	            create-only on the encrypted artifact dataset.
//	Destroy     jail_remove, wait until no process of the jail is left, unmount
//	            and remove its root (closing a jail descriptor would not kill).
//	Restore     recreate instance <gen> from the artifact's spec on the same
//	            workspace, through yard-spawn's own setup path (spawn.Start), and
//	            wait for readiness; on a timeout remove what it started.
//	Unquiesce   (abort path) SIGCONT what is still there, or start the service
//	            again in its jail.
//	Pause       SIGSTOP every process (the optional pause tier); Unpause SIGCONT.
//
// Every outcome is done / not done / unknown: a step that runs out of time
// returns an error, and the lifecycle resolves it by observation (Instance,
// Frozen, CheckpointOK, Exists) once InFlight says nothing can still land.
// FreeBSD has no process checkpoint: live process state is never kept.
package service

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"yard/internal/rctl"
	"yard/internal/spawn"
)

// Duration is a time.Duration written as "5s" in JSON.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Probe is a readiness probe. Every attempt has its own timeout, and the
// whole wait is bounded by Spec.StartTimeout.
type Probe struct {
	Kind     string   `json:"kind"`               // tcp | http | cmd
	Port     uint16   `json:"port,omitempty"`     // tcp, http: a port of Spec.Ports, exposed by the sandbox
	Path     string   `json:"path,omitempty"`     // http: GET path (default /); ready on 2xx/3xx
	Argv     []string `json:"argv,omitempty"`     // cmd: run in the service's jail as its uid; ready on exit 0
	Interval Duration `json:"interval,omitempty"` // between attempts (default 20ms)
	Timeout  Duration `json:"timeout,omitempty"`  // one attempt (default 1s)
}

// Spec declares a service.
type Spec struct {
	Name         string   `json:"name"`
	Argv         []string `json:"argv"`
	Env          []string `json:"env,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`   // in the jail; default /workspace
	Ports        []uint16 `json:"ports,omitempty"` // TCP ports it listens on
	Ready        Probe    `json:"ready"`
	StartTimeout Duration `json:"start_timeout,omitempty"` // start to ready (default 30s)
	StopGrace    Duration `json:"stop_grace,omitempty"`    // SIGTERM to SIGKILL (default 5s)
	KillWait     Duration `json:"kill_wait,omitempty"`     // SIGKILL / jail_remove to no process left (default 2s)
	PauseWait    Duration `json:"pause_wait,omitempty"`    // SIGSTOP / SIGCONT to observed (default 1s)
	Mem          string   `json:"mem,omitempty"`           // vmemoryuse deny on the instance's jail
	TmpSize      string   `json:"tmp,omitempty"`           // its /tmp tmpfs (default 64m)
}

// Defaults fills unset durations and the cwd.
func (s *Spec) Defaults() {
	def := func(d *Duration, v time.Duration) {
		if *d == 0 {
			*d = Duration(v)
		}
	}
	def(&s.StartTimeout, 30*time.Second)
	def(&s.StopGrace, 5*time.Second)
	def(&s.KillWait, 2*time.Second)
	def(&s.PauseWait, time.Second)
	def(&s.Ready.Interval, 20*time.Millisecond)
	def(&s.Ready.Timeout, time.Second)
	if s.Cwd == "" {
		s.Cwd = "/workspace"
	}
	if s.Ready.Kind == "http" && s.Ready.Path == "" {
		s.Ready.Path = "/"
	}
}

var (
	nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	envRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}=`)
)

// Validate checks the spec (after Defaults) against the sandbox it runs in.
func (s *Spec) Validate(sbx *spawn.Sandbox) error {
	if !nameRe.MatchString(s.Name) {
		return fmt.Errorf("service name %q: want [a-z][a-z0-9-]{0,31}", s.Name)
	}
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return errors.New("service: empty argv")
	}
	for _, a := range append(append([]string{s.Cwd, s.Ready.Path}, s.Argv...), s.Env...) {
		if strings.ContainsRune(a, 0) {
			return errors.New("service: NUL in argv, env or path")
		}
	}
	for _, e := range s.Env {
		if !envRe.MatchString(e) {
			return fmt.Errorf("service env %q: want KEY=VALUE", e)
		}
	}
	if !strings.HasPrefix(s.Cwd, "/") {
		return fmt.Errorf("service cwd %q not absolute", s.Cwd)
	}
	if len(s.Ports) > 16 {
		return errors.New("service: more than 16 ports")
	}
	for i, p := range s.Ports {
		if p == 0 || slices.Contains(s.Ports[:i], p) {
			return fmt.Errorf("service port %d: zero or repeated", p)
		}
	}
	for _, d := range []struct {
		name string
		v    Duration
		max  time.Duration
	}{{"start_timeout", s.StartTimeout, 10 * time.Minute}, {"stop_grace", s.StopGrace, 5 * time.Minute},
		{"kill_wait", s.KillWait, time.Minute}, {"pause_wait", s.PauseWait, time.Minute},
		{"ready.interval", s.Ready.Interval, time.Minute}, {"ready.timeout", s.Ready.Timeout, time.Minute}} {
		if d.v <= 0 || d.v.D() > d.max {
			return fmt.Errorf("service %s %s: want (0, %s]", d.name, d.v.D(), d.max)
		}
	}
	switch s.Ready.Kind {
	case "tcp", "http":
		if !slices.Contains(s.Ports, s.Ready.Port) {
			return fmt.Errorf("service probe port %d is not one of its ports", s.Ready.Port)
		}
		if sbx.Net != spawn.SbxBroker || !slices.Contains(sbx.Expose, s.Ready.Port) {
			return fmt.Errorf("service probe port %d: the sandbox %s does not expose it to the host (broker sandbox, -expose)",
				s.Ready.Port, sbx.ID)
		}
		if s.Ready.Kind == "http" && !strings.HasPrefix(s.Ready.Path, "/") {
			return fmt.Errorf("service probe path %q", s.Ready.Path)
		}
	case "cmd":
		if len(s.Ready.Argv) == 0 {
			return errors.New("service probe: cmd needs argv")
		}
	default:
		return fmt.Errorf("service probe kind %q (tcp|http|cmd)", s.Ready.Kind)
	}
	for _, a := range []string{s.Mem, s.TmpSize} {
		if a != "" {
			if err := rctl.Amount(a); err != nil {
				return err
			}
		}
	}
	return nil
}
