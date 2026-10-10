// Package lifecycle is the SR0 session suspend/resume lifecycle of yard-ctl.
//
// The Quint model spec/sr0/lifecycle.qnt is the ground truth. Every
// controller action there has a method of the same name on *Ctl
// (transitions.go) with the same guard and the same update; the replay test
// drives Ctl through ITF traces of the model and compares the state after
// every step. Change the model first, re-run it, then change this package.
//
// Ctl is pure: no I/O, no clock, no randomness. Machine (machine.go) wraps it
// with the SQLite store, the backends, the clock and the fact sink.
package lifecycle

import (
	"maps"
	"slices"
)

// State is a session's lifecycle state (Quint State).
type State string

const (
	Active     State = "Active"
	Idle       State = "Idle"
	Paused     State = "Paused" // SR1 pause tier: the instance's processes are SIGSTOPped
	Suspending State = "Suspending"
	Suspended  State = "Suspended"
	Resuming   State = "Resuming"
	Expired    State = "Expired"
	Failed     State = "Failed"
	Removed    State = "Removed" // `yard-svc down`: terminal; holds no token, blocks no key unload
)

// Phase is the step within Suspending or Resuming (Quint Phase).
type Phase string

const (
	PNone       Phase = "PNone"
	PQuiesce    Phase = "PQuiesce"
	PCheckpoint Phase = "PCheckpoint"
	PDestroy    Phase = "PDestroy"
	PAbort      Phase = "PAbort"
	PRestore    Phase = "PRestore"
	PMint       Phase = "PMint"
	PPause      Phase = "PPause"
	PUnpause    Phase = "PUnpause"
	PKey        Phase = "PKey" // SR1: load the project key; restore checks drift before mounting
)

// OpKind is the kind of an external call (Quint OpKind).
type OpKind string

const (
	OQuiesce    OpKind = "OQuiesce"    // stop the instance: jail_remove + wait for exit, FC/bhyve pause, KV freeze
	OCheckpoint OpKind = "OCheckpoint" // ZFS snapshot + memory/spec/KV artifact (its op id names the artifact)
	ODestroy    OpKind = "ODestroy"    // remove the original instance (frees RAM)
	OUnquiesce  OpKind = "OUnquiesce"  // undo a quiesce (abort path)
	ORestore    OpKind = "ORestore"    // start instance <gen> from checkpoint <arg>; the name is create-only
	OMint       OpKind = "OMint"       // STS credential for epoch <arg>
	ODelete     OpKind = "ODelete"     // delete checkpoint <arg>'s artifacts
	OPause      OpKind = "OPause"      // SR1 pause tier: SIGSTOP every process of instance <arg>
	OUnpause    OpKind = "OUnpause"    // SIGCONT them
	// SR1 workspace keys (layout D). OLoadKey is a session op: `zfs load-key`
	// of the session's project root from stdin, without mounting its clone.
	// ORestore checks drift, mounts, then starts. OUnmount/OUnloadKey are project ops (Op.Sess is the project):
	// unmount every dataset of the project, then `zfs unload-key` its root.
	OLoadKey   OpKind = "OLoadKey"
	OUnmount   OpKind = "OUnmount"
	OUnloadKey OpKind = "OUnloadKey"
)

// projOp reports whether k is a project op (Op.Sess names the project).
func projOp(k OpKind) bool { return k == OUnmount || k == OUnloadKey }

// OpSt is what yard-ctl knows of an op's outcome (Quint OpSt).
type OpSt string

const (
	Pending OpSt = "Pending" // sent; no answer yet
	Unknown OpSt = "Unknown" // timed out, failed with an error, or orphaned by a restart
	Done    OpSt = "Done"
	NotDone OpSt = "NotDone"
	// Refused is a definite answer "refused, nothing done": SR1 decision 2,
	// a restore refuses a workspace changed since the suspend snapshot.
	Refused OpSt = "Refused"
)

// Outcome is an op copy's answer as the Machine hears it.
type Outcome int

const (
	AnsError   Outcome = iota // failed, timed out, killed: unknown
	AnsDone                   // exited 0: the effect holds
	AnsRefused                // refused before doing anything (ErrRefused)
)

// Kinds of backend (Quint Kind, a string there too).
const (
	KindJail    = "jail"
	KindService = "service"
	KindFC      = "fc"
	KindBhyve   = "bhyve"
	KindKV      = "kv"
)

// Row is the durable sessions row (Quint Row).
type Row struct {
	ID          string
	Class       string // run class: selects the Policy (Go only; the model has POLICY per session)
	State       State
	Kind        string
	Gen         int64
	Phase       Phase
	Inst        int64 // name of the current instance (the generation it was restored from)
	Ckpt        int64 // current checkpoint op id, 0 none
	Op          int64 // the op the current phase waits on, 0 none
	Token       int64 // one-shot resume token, 0 none
	CredEpoch   int64
	DecidedAt   int64
	DecidedSeq  int64
	QuiescedAt  int64
	SuspendedAt int64
	Resumes     int64
	Inbox       int64
	Force       bool   // the current resume carries the override (resume on a changed workspace)
	Drift       bool   // outcome: the last resume was refused, the workspace changed since the snapshot
	ConsumedAt  int64  // Go only (facts): when the resume token was consumed
	Project     string // Go only (the model's PROJECT const): the workspace key's project, "" none
}

// Op is a durable op row (Quint Op).
type Op struct {
	ID       int64
	Kind     OpKind
	Sess     string
	Gen      int64
	Arg      int64
	St       OpSt
	SentAt   int64
	Attempts int64
	Inc      int64
	Force    bool  // a restore with the override
	Bytes    int64 // reported by a successful answer (facts only; not in the model)
}

// KPhase is a project key's unload step (Quint KPhase).
type KPhase string

const (
	KNone    KPhase = "KNone"
	KUnmount KPhase = "KUnmount"
	KUnload  KPhase = "KUnload"
)

// Proj is the durable record of a project's workspace key (Quint Proj):
// Loaded is yard-ctl's belief that the key is loaded.
type Proj struct {
	Phase  KPhase
	Op     int64
	Loaded bool
}

// Probe is a liveness probe of an awake session's instance (Quint Probe,
// volatile): asked for instance Inst of generation Gen at ReqAt; Answered
// with Alive, or still Pending.
type Probe struct {
	Pending  bool
	ReqAt    int64
	Inst     int64
	Gen      int64
	Answered bool
	Alive    bool
}

// Obs is yard-ctl's volatile view of a session's activity (Quint Obs).
type Obs struct {
	Pending  bool
	ReqAt    int64
	Seq      int64
	SeenAt   int64
	AnsReqAt int64
}

func freshObs() Obs { return Obs{Seq: -1, AnsReqAt: -1} }

// Policy is the per-run-class policy (HARNESS.md SR0). Durations are in the
// Ctl clock's unit (milliseconds in production, ticks in the replay).
type Policy struct {
	KeepWarm  bool  // never suspend (a service that may not be recreated)
	IdleAfter int64 // IDLE_TIMEOUT
	MaxAge    int64 // maximum suspended age (TTL); artifacts are deleted at expiry
	// Pause turns on the SR1 pause tier: an idle session is SIGSTOPped
	// first (its backend must implement Pauser), and suspended only after
	// IdleAfter + SuspendHold of no activity.
	Pause       bool
	SuspendHold int64
}

// Config holds the model's constants that are not per class.
type Config struct {
	OpTimeout   int64
	MaxAttempts int64 // per retryable op; 0 = unbounded
	Clients     []string
	Policies    map[string]Policy
	// Optional per-session policy overrides, equivalent to the model's
	// POLICY(session). Manual commands must not change every peer's policy.
	SessionPolicies map[string]Policy
	// Model bounds (the replay sets them; production leaves them 0 = none).
	MaxGen, MaxOps, MaxTokens int64
	// ProbeEvery (Go only, Machine): how often an awake session's instance
	// is probed for liveness (SR1 decision 3), in clock units; 0: never.
	ProbeEvery int64
}

// Driver names (Quint IDLER, RECOVERY); clients are the resume triggers.
const (
	Idler    = "idler"
	Recovery = "recovery"
)

// Ctl is the controller state (Quint Sys minus the environment). Rows and
// Ops are durable (SQLite); Drivers and Obs are memory, lost on a crash.
type Ctl struct {
	Cfg       Config
	Clock     int64
	Up        bool
	Inc       int64
	Rows      map[string]Row
	Ops       map[int64]Op
	Drivers   map[string]map[string]bool
	Obs       map[string]Obs
	Projects  map[string]Proj  // durable (SR1 workspace keys)
	Probes    map[string]Probe // volatile (SR1 liveness)
	NextOp    int64
	NextToken int64
	// TokenOf maps the token sequence number to the token value stored in
	// the row (production: random, see machine.go; the replay: identity).
	TokenOf func(n int64) int64
}

// NewCtl returns an empty controller (no sessions) at incarnation 1.
func NewCtl(cfg Config) *Ctl {
	return &Ctl{Cfg: cfg, Up: true, Inc: 1, Rows: map[string]Row{}, Ops: map[int64]Op{},
		Drivers: map[string]map[string]bool{}, Obs: map[string]Obs{}, Projects: map[string]Proj{},
		Probes: map[string]Probe{}, NextOp: 1, NextToken: 1, TokenOf: func(n int64) int64 { return n }}
}

// AddSession registers a new Active session (Quint init: instance 0 running,
// credential epoch 1). project, if not "", is its workspace key's project;
// a new project starts with its key loaded (the session is active).
func (c *Ctl) AddSession(id, class, kind, project string) {
	c.Rows[id] = Row{ID: id, Class: class, State: Active, Kind: kind, Phase: PNone, CredEpoch: 1, Project: project}
	c.Drivers[id] = map[string]bool{}
	c.Obs[id] = freshObs()
	c.Probes[id] = Probe{}
	if _, ok := c.Projects[project]; project != "" && !ok {
		c.Projects[project] = Proj{Phase: KNone, Loaded: true}
	}
}

// Clone deep-copies the controller.
func (c *Ctl) Clone() *Ctl {
	n := *c
	n.Rows = maps.Clone(c.Rows)
	n.Ops = maps.Clone(c.Ops)
	n.Obs = maps.Clone(c.Obs)
	n.Projects = maps.Clone(c.Projects)
	n.Probes = maps.Clone(c.Probes)
	n.Drivers = make(map[string]map[string]bool, len(c.Drivers))
	for k, v := range c.Drivers {
		n.Drivers[k] = maps.Clone(v)
	}
	n.Cfg.Clients = slices.Clone(c.Cfg.Clients)
	return &n
}

func (c *Ctl) policy(s string) Policy {
	if p, ok := c.Cfg.SessionPolicies[s]; ok {
		return p
	}
	return c.Cfg.Policies[c.Rows[s].Class]
}

// DriverSet returns the sorted driver names of a session.
func (c *Ctl) DriverSet(s string) []string {
	return slices.Sorted(maps.Keys(c.Drivers[s]))
}
