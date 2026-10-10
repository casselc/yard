# SR0: the session suspend/resume lifecycle

The Quint model of yard-ctl's session lifecycle (HARNESS.md, "Milestones:
suspend and resume", SR0), and how `internal/lifecycle` is driven by it.

| File | What it is |
|---|---|
| `lifecycle.qnt` | the model; instances `design`, `design2` and 12 mutants |
| `lifecycle_test.qnt` | scripted runs: design paths, each mutant's counterexample (`*BreaksTest`) and the step the design blocks (`*DesignTest`) |
| `run_models.sh` | runs every instance with `quint run` at a fixed seed, then every scripted run |
| `gen_traces.sh` | writes the ITF traces the Go replay test uses (`internal/lifecycle/testdata/traces`) |

Quint 0.32: `quint typecheck`, `quint run`, `quint test`. Nothing here uses
`quint verify`: every result below is sampled, not exhaustive.

## Scope

**Modelled.** Sessions (one in `design`, two in `design2`: a service and
a keep-warm KV session) through the states active, idle, suspending,
suspended, resuming, expired, failed. The sessions row (SQLite) is the
durable record: kind, generation, phase, current instance, current
checkpoint, the op the phase waits on, the one-shot resume token, the
credential epoch, the decision time and activity sequence, the inbox of
held messages. Seven kinds of external call, each an *op*, are modelled as
request, effect and answer (next section). Also modelled:
- an abstract clock (`Tick`), op timeouts, idle detection, and TTL;
- a slow activity observation;
- tool-call workspace writes in flight;
- the broker's credentials;
- a yard-ctl crash and restart at any step;
- instance crashes;
- concurrent resume triggers (`msg`, `timer`).

**Assumptions** (each an environment rule in the model):
- **A1. The settle bound is observable.** Every op runs as a process (VMM,
  bhyvectl, jail teardown, engine spill, STS call, rm). yard-ctl can tell
  whether a process for an op still runs, including one started by an
  earlier incarnation (pidfile, jail name, VMM API socket).
  `Backend.InFlight` is that observation. The model's `settled(id)`: no
  copy of the op is in flight.
- **A2. Effects are observable after settle.** Each observation reads the
  effect itself:
  - the instance's state by name (`jls`, VMM state);
  - the artifact's digest and size against the record;
  - the broker's credential list;
  - the artifact directory.
- **A3. One yard-ctl process owns the database.** Op ids come from its
  counter. The conditional UPDATEs (consume, expire) and the compare-and-swap
  commits defend against concurrent handlers and against a second handle
  (a CLI, a stray process); they do not make two yard-ctl processes safe
  to run.
- **A4. Answers reach only their sender.** An answer to a copy sent by an
  earlier incarnation is lost; that op is `Unknown` after restart.
- **A5. Each external call is one op row**, inserted in the same
  transaction as the row change that needs it.
  - A crash between commit and send leaves a Pending op with no copy.
  - Recovery makes that op Unknown. It is already settled, so the next
    step observes it NotDone and retries it.
- **A6. The workspace dataset survives suspend.** Restore makes the
  workspace the checkpoint's ZFS snapshot (clone-and-switch), because VM
  memory and disk must match.

**Not modelled.**
- **Message delivery to the harness** (`Deliver`) is atomic. The payload
  queue belongs to the broker and SR5. This row is open in the register.
- **Instance loss outside suspend/resume.** An Active session whose
  instance dies stays Active. That is a liveness gap for SR1/SR2 health
  checks, not part of SR0.
- **Key management and dataset encryption.** `enc` is an attribute of
  artifacts; the Machine refuses to start on an unencrypted dataset.
- **Live process state.** SR1 recreates services from their spec.
- **Byzantine backends.**
- **Liveness.** Quint runs check safety on finite runs. Each liveness
  hazard is checked as the state property that is its mechanism (I4, I5,
  I7), plus a scripted run.

**Bounds** (state space only): `MAX_GEN` 2 suspends per session, 16 ops,
4 tokens, 2 attempts per retry, 3 environment faults per trace (lost or
answer-lost copies, partial writes, instance or yard-ctl crashes), 1
message, 3 activities, clock to 24.

## The model in one picture

```
Active --GoIdle--> Idle --SuspendBegin--> Suspending
                                          PQuiesce --(quiesce Done)--> PCheckpoint --(ckpt Done)--> PDestroy
                                             |  any phase, step resolved: SuspendAbort -> PAbort    |
                                             v                                                     | destroy Done,
                         Idle <--SuspendAbortDone-- PAbort --SuspendFail--> Failed                  | activity re-read
                                                                                                    v
Active <--ResumeComplete-- Resuming(PMint) <--ResumeMint-- Resuming(PRestore) <--ResumeConsume-- Suspended --Expire--> Expired
                                        ResumeAbort (restore NotDone) -> Suspended; ResumeFail -> Failed
```

Every op: `newOp` (row Pending plus a copy) -> `OpLand` / `OpLandAnswerLost`
/ `OpLandPartial` / `OpLose` (environment) -> the answer (`Done` only for a
success exit to the sender) or `OpTimeout` (`Unknown`) -> `OpResolve` once
settled (Done/NotDone by observation) -> `OpRetry` (retryable kinds only).
`CtlCrash` drops drivers and observations. `CtlRestart` starts a new
incarnation. `RecoverOps` marks the old incarnation's Pending ops Unknown,
and `Adopt` gives a suspending or resuming row a recovery driver, which
continues through the same actions.

## Invariants

| # | Invariant | Quint |
|---|---|---|
| I1 | A snapshot is resumed at most once: each token claimed once, each checkpoint started once, at most one live instance per session | `resumedAtMostOnce` = `tokenClaimedOnce`, `restoredOnce`, `oneInstance` |
| I2 | No acknowledged workspace write is lost across suspend (a suspended session's snapshot holds every acked write; otherwise the live workspace does) | `noAckedWriteLost` |
| I3 | A resumed session holds no credential the broker honours that was requested before it suspended | `noPreSuspendCredential` |
| I4 | Artifacts are only on encrypted storage, and each belongs to the current suspend record or has a delete owed (an op row not yet done): so after resume or TTL they are gone or being deleted | `artifactsAccounted` |
| I5 | A resume holding the token finds its artifact until the restore is done | `resumeKeepsArtifacts` |
| I6 | A session is suspended only after IDLE_TIMEOUT with no activity | `suspendedOnlyIdle` |
| I7 | TTL expiry never drops a held message | `noMessageLost` |

## Register of external calls

Format of casselc/observability otel-chdb AMBIGUITY.md, "Rules":
- every unknown outcome has a settle bound, a resolving observation and a
  caller rule (wait, verify, fence or idempotent retry);
- the unsafe rule is a named mutant (casselc/observability
  otel-chdb/model/TEMPLATE.md).

"Atomic" marks a call the model does in one step.

| # | Call | Outcomes: done / not done / unknown | Settle bound | Resolving observation | Caller rule | Quint actions | Mutant (breaks) |
|---|---|---|---|---|---|---|---|
| X1 | **Quiesce**: SR1 `jail_remove` and wait for every process to exit (closing a jail descriptor does not kill, and a dying jail takes time); SR2 FC pause; SR3 bhyve pause; SR4 engine freeze | **done:** exit 0. **unknown:** timeout, error, restart | the teardown/pause process exits (A1) | instance by name is not running | **wait** for done (observed) before the checkpoint: the fence against late workspace writes; **idempotent retry** if not done | `SuspendBegin` (send), `OpLand*`, `OpLose`, `OpTimeout`, `OpResolve`, `OpRetry`; effect `OQuiesce` drops in-flight writes | `snapshotBeforeQuiesce` (I2) |
| X2 | **Checkpoint**: ZFS snapshot plus `bhyvectl --suspend`, FC snapshot, or engine KV spill; create-only artifact path named by the op id | **done:** exit 0 and the artifact verifies. **not done:** after settle, the artifact is missing or partial. **unknown:** timeout (may still complete), error after writing, killed mid-write (partial), restart | the VMM/engine process exits or the op's own completion (A1) | artifact digest and size against the suspend record (`CheckpointOK`) | **wait** to settle, then **verify**. Not done: delete it (owed) and take a new checkpoint under a new id. Never retried blindly | `SuspendCheckpoint`, `SuspendCheckpointRetry`, `OpLandPartial`, `OpTimeout`, `OpResolve` | `checkpointTimeoutNotDone` (I4); `recoverAssumesNotDone` (I4) |
| X3 | **Destroy** the original instance after the checkpoint (frees RAM) | done: exit 0. unknown: timeout, error | process exits | instance by name is gone | **wait** for done before commit. A paused original that lingers beside a restored copy is two instances | `SuspendDestroy`, `OpRetry` | `commitBeforeDestroy` (I1) |
| X4 | **Unquiesce** (abort path) | done: exit 0. unknown | process exits | instance running | idempotent retry. If observed not done and the instance is gone, the session fails | `SuspendAbort`, `SuspendAbortDone`, `SuspendFail` | — (liveness only) |
| X5 | **Restore**: FC load, `bhyve -r`, service start from its spec, KV restore; instance name (session, gen) is create-only | **done:** exit 0, or the name exists. **not done:** after settle, no instance by that name. **unknown:** error with the VM started (lost answer), a late start, restart | the restore process exits (A1) | instance (session, gen) exists | **fence** (create-only name) and **verify**. Only a restore observed not done goes back to Suspended with a fresh token. A restart never assumes not done | `ResumeConsume` (send), `ResumeMint`, `ResumeAbort`, `ResumeFail`, `OpTimeout`, `OpResolve`, `RecoverOps`, `Adopt` | `blindRestoreRetry` (I1) |
| X6 | **STS mint** of a session credential (broker refresh, and the re-mint at resume) | done: the broker holds a credential of the epoch. unknown: timeout, error, late answer | the STS call returns | the broker's credential list holds the epoch | **fence**: the epoch is bumped at commit. The STS mints only the row's epoch and the broker honours only it, so a mint requested before the suspend that answers after the resume is refused or dead. **Idempotent retry** for the current epoch | `CredRefresh`, `ResumeMint`, `ResumeComplete`, `OpRetry` | `noCredEpoch` (I3) |
| X7 | **Artifact delete** (after resume, abort, failure, and at TTL) by checkpoint id | done: exit 0 and gone. unknown: lost, late | the rm process exits | the artifact is absent | **idempotent retry** until observed. The delete is an op row inserted with the row change that owes it (A5). Paths are per checkpoint, so a late delete cannot hit a newer suspend | `issueDelete` in `SuspendCheckpointRetry`, `SuspendAbort`, `ResumeComplete`, `ResumeFail`, `Expire`; `OpRetry` | `fireAndForgetDelete` (I4); `gcByAge` (I5, the gcReopens shape: GC by age while a resume holds the token) |
| X8 | **Activity observation** (the broker's count of model and tool calls) | an observation, never "not done": slow, answered later | none: freshness is the answer time | the sequence number, dated **at the answer** when it changed | **verify after the fence**: the commit re-reads activity requested after the quiesce was known done, and requires the sequence unchanged and no held messages, else abort | `ObsReq`, `ObsAnswer`, `GoIdle`, `SuspendBegin`, `SuspendCommit`, `SuspendAbort` | `observeAtRequest` (I6); `ignoreActivityDuringSuspend` (I6) |
| X9 | **Workspace write** by a tool call (not yard-ctl's call, but the late effect quiesce fences) | acked when it lands; may land with the ack lost; dies with the quiesce | the quiesce | — | fenced by X1 | `WriteIssue`, `WriteLand`, `WriteLandAckLost` | `snapshotBeforeQuiesce` (I2) |
| X10 | **Token consume**: local SQLite, one conditional `UPDATE sessions SET state='Resuming' … WHERE id=? AND state='Suspended' AND token=?` plus the restore op row in one transaction | done: one row changed. not done: none (`ResumeReject`) | the transaction | — | atomic (local) | `ResumeConsume`, `ResumeReject` | `nonAtomicConsume` (I1) |
| X11 | **Expire**: local conditional `UPDATE … WHERE state='Suspended' AND token=? AND inbox=0` plus the owed delete; races X10, one wins | as X10 | the transaction | — | atomic (local) | `Expire` | `expireDropsInbox` (I7) |
| X12 | **Message delivery** to the harness | — | — | — | **atomic in the model (open)** | `Deliver` | — |

Every op row has a metric source: Fact records (below) carry the outcome,
and the op table holds Unknown/NotDone counts per kind. A production
counter per unknown class is open (rule 5).

## Design rules and mutants: results

Every run uses `quint run lifecycle.qnt --main <instance> --invariant
<inv> --max-steps 100 --max-samples 3000 --seed 0x5eed`, then scripted
`quint test` (`sh run_models.sh`). Run on 2026-10-07 with the committed
model. These are sampled runs, not proofs.

| Instance | Invariant | Expected | `quint run` (seed 0x5eed) | Scripted `*BreaksTest` |
|---|---|---|---|---|
| `design` | all (I1–I7) | holds | holds (~2930 traces) | — |
| `design2 (2 sessions, one keep-warm)` | all | holds | holds (~2920) | — |
| `nonAtomicConsume` | I1 | breaks | **breaks** (~850 traces to the first) | breaks |
| `blindRestoreRetry` | I1 | breaks | held at 3000 and 20000 | **breaks** |
| `commitBeforeDestroy` | I1 | breaks | **breaks** (~870) | breaks |
| `snapshotBeforeQuiesce` | I2 | breaks | held at 3000 and 20000 | **breaks** |
| `noCredEpoch` | I3 | breaks | held at 3000 and 20000 | **breaks** |
| `checkpointTimeoutNotDone` | I4 | breaks | **breaks** (~650) | breaks |
| `fireAndForgetDelete` | I4 | breaks | **breaks** (~40) | breaks |
| `recoverAssumesNotDone` | I4 | breaks | held at 3000 and 20000 | **breaks** |
| `gcByAge` | I5 | breaks | **breaks** (~520) | breaks |
| `observeAtRequest` | I6 | breaks | **breaks** (~180) | breaks |
| `ignoreActivityDuringSuspend` | I6 | breaks | **breaks** (~390) | breaks |
| `expireDropsInbox` | I7 | breaks | held at 3000 and 20000 | **breaks** |

**Focused instances** (`<m>Focus` / `<m>FocusDesign`, same environment and step; `--step` as listed; 3000 samples x 100 steps, seed 0x5eed). Each step is a restriction of `step`, so every focused trace is a trace of the full model:
- `stepQuiet`: Tick, OpLand, ObsAnswer and the controller;
- `stepWrites`: `stepQuiet` plus tool-call writes;
- `stepCrash`: `stepQuiet` plus yard-ctl crash and restart;
- `stepInbox`: `stepQuiet` plus messages arriving only while suspended.

The environment is narrowed with no faults, no activity, and 1 tick timeouts / a 100-tick credential TTL / a 1-tick TTL where listed.

| Mutant | Step, environment | Mutant (traces to the first counterexample) | Design under the same instance |
|---|---|---|---|
| `blindRestoreRetry` | `stepQuiet`, OP_TIMEOUT 1 | **breaks** I1 (~32) | holds (~3000) |
| `snapshotBeforeQuiesce` | `stepWrites`, 4 writes | **breaks** I2 (~240) | holds (~3000) |
| `noCredEpoch` | `stepQuiet`, CRED_TTL 100 | **breaks** I3 (~13) | holds (~2900) |
| `recoverAssumesNotDone` | `stepCrash`, 1 crash | **breaks** I4 (~570) | holds (~3100) |
| `expireDropsInbox` | `stepInbox`, maxAge 1, 2 messages | **breaks** I7 (~30) | holds (~2900) |

So all 12 mutants now break in random simulation (7 under `step`, 5 under a focused step).

Scripted: `lifecycle_test` 11/11 design paths, `designScripts` 23/23 (12 DesignTests, 11 PrefixTests), each mutant's BreaksTest 1/1. 0 rows off expectation.

Where random simulation "held", it did not reach the counterexample at
3000 samples x 100 steps, nor at 20000 samples x 120 steps (seed 0x5eed):
each needs a narrow interleaving (a write between two specific landings, a
resume inside the credential TTL, a message during the suspended window, a
crash with a checkpoint in flight). The `*BreaksTest` replays it, and the matching `*DesignTest`
shows the design disables the step the counterexample needs (with a
`*PrefixTest` showing that the prefix itself runs on the design, so the
`.fail()` is not vacuous).

### Design witnesses

`quint run --main design --invariant allInvariants --witnesses … --max-steps 100 --max-samples 3000 --seed 0x5eed`:

| Witness | Traces (of 3000) |
|---|---|
| `wIdle` | 1044 (34.8%) |
| `wSuspending` | 985 (32.8%) |
| `wSuspended` | 24 (0.8%) |
| `wResuming` | 21 (0.7%) |
| `wActive` (after a resume) | 16 (0.53%) |
| `wResumedWithWrites` | 11 (0.37%) |
| `wExpired` / `wExpiredClean` (artifacts gone) | 2 / 2 (0.07%) |
| `wFailed` | 788 (26.3%) |
| `wRaceRejected` (a second trigger rejected while resuming) | 21 (0.7%) |
| `wAbortedToIdle` | 206 (6.9%) |
| `wAdoptSuspending` (restart mid-suspend, recovery driver) | 151 (5.0%) |
| `wRecoveredResume` (resume completed after a restart) | 16 (0.53%) |
| `wResolvedUnknown` (an unknown op resolved by observation) | 2215 (73.8%) |
| `wLateLand` (a copy landed after its op went unknown) | 953 (31.8%) |
| `wPartialRetried` (partial checkpoint deleted and retaken) | 175 (5.8%) |
| `wResumeAborted` | **0** — reached by `resumeAbortDesignTest` |
| `wAdoptResuming` (restart mid-resume) | **0** — reached by `crashResumeDesignTest` |
| `wHeldMessage` (message held while suspended) | **0** — reached by `heldMessageDeliveredDesignTest`, `expireDropsInbox` prefix |

The three 0% witnesses need three or more specific steps in a row deep in
a trace; each is reached by a scripted design run, and those runs are in
the replay set.

### The broken variant: `nonAtomicConsume`

The resume token checked by one statement and claimed by another (a
`SELECT` then an unconditional `UPDATE`), with two triggers (a message and
a timer) racing. Counterexample (`nonAtomicConsumeBreaksTest`; random
simulation finds the same shape, see the table):

| Step | Action | State | Token | Drivers | Claims of token 1 |
|---|---|---|---|---|---|
| 0–13 | idle, `SuspendBegin`, quiesce/checkpoint/destroy land, activity re-read | Suspending | 0 | idler | – |
| 14 | `SuspendCommit` | Suspended | 1 | – | – |
| 15 | `ResumeCheck(msg, 1)`: the token matches | Suspended | 1 | – | – |
| 16 | `ResumeCheck(timer, 1)`: still matches | Suspended | 1 | – | – |
| 17 | `ResumeClaim(msg)`: restore op 4 sent | Resuming | 0 | msg | 1 |
| 18 | `ResumeClaim(timer)`: restore op 5 sent | Resuming | 0 | msg, timer | **2** (`tokenClaimedOnce` fails) |

Two restores of one checkpoint are now in flight. The restore name fence
(X5) still lets only one instance start. Without that fence
(`blindRestoreRetry` shape) both copies start, and the two VMs share RNG
state and identity tokens. The design and the Go store use the single
conditional UPDATE. `TestStoreConsumeRaceAcrossHandles` races 16 store
handles plus an expiry on one token: one winner.
`TestMachineDoubleResumeRace` races 32 Resume calls through the Machine:
one winner, 31 `ErrTokenRejected`.

### Other counterexamples (scripted, `lifecycle_test.qnt`)

- **snapshotBeforeQuiesce.** The checkpoint is sent while the quiesce is in
  flight, and the checkpoint lands. A tool-call write then lands and is
  acked. Commit leaves the write out of the snapshot (I2), so a resume would
  roll it back.
- **checkpointTimeoutNotDone.** A checkpoint times out and is taken as not
  done. The abort deletes it, the session goes Idle, and the late
  checkpoint then writes its artifact. That artifact is owed by nothing
  (I4).
- **recoverAssumesNotDone.** yard-ctl restarts with a checkpoint in flight
  and takes it as not done. It deletes it and takes another, and the first
  copy then lands (I4). A restore in flight is protected by the name fence.
- **commitBeforeDestroy.** The destroy request is lost and commit goes
  ahead. A resume starts instance 1 beside the paused original (I1,
  `oneInstance`).
- **blindRestoreRetry.** The restore times out and is resent at once with
  no name fence. Both copies start (I1, `restoredOnce`).
- **noCredEpoch.** A refresh requested before the suspend lands after the
  resume. With no epoch, the STS mints it and the broker honours it for its
  TTL (I3). The original credential had already expired by TTL, so this is
  the late-mint path alone.
- **gcByAge.** A sweeper deletes the artifact of a session whose resume
  holds the token (I5).
- **observeAtRequest.** Activity happens between the observation request
  and its answer. Dated at the request, the session looks idle one tick
  early, and it is suspended with activity inside the window (I6).
- **ignoreActivityDuringSuspend.** Activity happens after the decision,
  before the quiesce lands, and the commit does not re-read it (I6).
- **expireDropsInbox.** A message is held for a suspended session, and TTL
  expiry drops it (I7).
- **fireAndForgetDelete.** The delete after a resume is lost, and nothing
  owes it (I4).

## Mapping: Quint action -> Go

`internal/lifecycle`.
- `Ctl` (types.go, transitions.go) is pure. Each method's guard and update
  are the action's `can<Name>` and `apply<Name>`.
- Arguments the model reads from the environment are parameters, filled by
  `Machine` from the backends and by the replay from the trace:
  - `settled` and `observedDone` (op resolution);
  - instance existence or running;
  - the activity sequence.

| Quint action | Go | Durable write |
|---|---|---|
| `Tick` | `Ctl.Tick` / `SetClock` | – |
| `OpLand` (answer part) | `Ctl.OpAnswer(id, inc, ok, bytes)` from `Machine.runCopy` | ops row |
| `OpLandAnswerLost`, `OpLandPartial`, `OpLose` | (environment: no yard-ctl action) | – |
| `OpTimeout` | `Ctl.OpTimeout` (`Machine.pollOps`) | ops row |
| `OpResolve` | `Ctl.OpResolve(id, settled, observedDone)` (`Executor.Settled`, `Executor.Observe`) | ops row |
| `OpRetry` | `Ctl.OpRetry` | ops row |
| `RecoverOps` | `Ctl.RecoverOps` (`Start`) | ops rows |
| `Adopt` | `Ctl.Adopt` (`Start`) | – (memory) |
| `CtlCrash` / `CtlRestart` | process death / `Start` (`Ctl.CtlRestart`, incarnation in `meta`) | meta |
| `ObsReq` / `ObsAnswer` | `Ctl.ObsReq` / `Ctl.ObsAnswer(s, seq)` (`Machine.observe`, `ActivitySource`) | – (memory) |
| `GoIdle`, `Touch`, `Deliver` | `Ctl.GoIdle`, `Ctl.Touch`, `Ctl.Deliver(s, instUp)` | sessions row |
| `MessageArrive` | `Ctl.MessageArrive` (`Machine.Message`) | sessions row |
| `CredRefresh` | `Ctl.CredRefresh` | ops row |
| `SuspendBegin` | `Ctl.SuspendBegin` | row + quiesce op, one tx |
| `SuspendCheckpoint` | `Ctl.SuspendCheckpoint` | row + checkpoint op |
| `SuspendCheckpointRetry` | `Ctl.SuspendCheckpointRetry` | row + delete op + checkpoint op |
| `SuspendDestroy` | `Ctl.SuspendDestroy` | row + destroy op |
| `SuspendCommit` | `Ctl.SuspendCommit` (fact `suspend`) | row (CAS) |
| `SuspendAbort` / `SuspendAbortDone` / `SuspendFail` | `Ctl.SuspendAbort` / `SuspendAbortDone` / `SuspendFail(s, instExists)` | row + delete op + unquiesce op / row / row |
| `ResumeConsume` / `ResumeReject` | `Ctl.ResumeConsume` -> `ErrTokenRejected`; durable: `Store.ConsumeToken` (the conditional UPDATE) via `Machine.Resume` | row + restore op, one tx |
| `ResumeMint` / `ResumeComplete` | `Ctl.ResumeMint(s, d, instUp)` / `Ctl.ResumeComplete(s, d, instUp)` (fact `resume`) | row + mint op / row + delete op |
| `ResumeAbort` / `ResumeFail` | `Ctl.ResumeAbort` / `Ctl.ResumeFail(s, d, instUp)` | row / row + delete op |
| `Expire` | `Ctl.Expire`; durable: `Store.Expire` (conditional UPDATE racing the consume) | row + delete op, one tx |
| `ResumeCheck`, `ResumeClaim`, `RestoreBlindRetry`, `GcSweep` | none: mutant-only actions | – |

Op rows are the request/answer split: `ops(id, kind, sess, gen, arg, st
Pending|Unknown|Done|NotDone, sent_at, attempts, inc)`. Recovery resolves
them by observation (`Start` -> `RecoverOps`, then `pollOps` -> `OpResolve`
once `Executor.Settled`).

**"Driven by the same transitions."** `internal/lifecycle/replay_test.go`
reads the ITF traces from `gen_traces.sh`:
- the scripted design runs;
- a greedy cover of random `--mbt` design runs (traces that add an action,
  or an action pair).

For each step it applies the same action with the same picks to `Ctl`,
commits it to a SQLite `Store` (reloading from it at every `CtlCrash`), and
compares the full controller state with the model's. The checked state is
the rows, ops, drivers, observations, clock, incarnation and counters.

Result: 189 traces (34 scripted, 155 random), 16051 steps, every design action exercised, Go equal to the model after every step.

Positive controls, each injected into the Go code and reverted:
- no epoch bump at commit: 22 traces fail;
- `ResumeAbort` disabled: 1 fails;
- the expiry TTL off by one: 3 fail.

## What SR1–SR5 must provide

- **SR1 (jails, services)** implements `Backend` for kinds `jail` and
  `service`:
  - `Quiesce` is `jail_remove` and a wait for every process to exit, with an
    explicit kill: closing the jail descriptor does not.
  - `Checkpoint` takes the ZFS snapshot and writes the service spec as the
    artifact.
  - `Restore` recreates the service jail from the spec under the
    create-only name `(session, gen)` and waits for readiness.
  - `InFlight` reports from jail names, dying jails and the spawner's
    process descriptors.
  - `Instance` comes from `jls`.
- **SR2 (Firecracker)** implements `fc`:
  - `Quiesce` pauses the VM.
  - `Checkpoint` takes the snapshot into the artifact path on the
    encrypted dataset and returns its bytes.
  - `Restore` loads the snapshot under a unique VM id `(session, gen)` and
    resumes it; a second load with that id fails.
  - `InFlight` uses the jailer pidfile.
  - The guest agent's resume epoch is the row's generation.
  - The broker treats the vsock reset as retryable.
  - Policy: suspend at turn boundaries.
- **SR3 (bhyve)** implements `bhyve`:
  - `Checkpoint` is `bhyvectl --suspend`; `Restore` is `bhyve -r`.
  - `CheckpointOK` checks the files' sizes and digest.
  - If the spike fails, the kind falls back to `service` (cold boot plus
    spec).
- **SR4 (engine KV)** implements `kv`:
  - `Checkpoint` spills paged KV and the recurrent state.
  - `Restore` restores it, or reports not done so that resume
    re-prefills.
  - `Instance` is the engine session id.
- **SR5 (scheduler)**:
  - Calls `Machine.Resume` with `Machine.Token` for internal triggers.
  - Owns the message payload queue: `Deliver` is atomic in this model, and
    that row is open.
  - Picks which sessions to suspend under memory pressure. Today
    `SuspendBegin` fires on idle alone; SR5 adds an LRU or pressure policy
    on top of the same guard.
  - Wires `Machine.Poll` to a timer.
- **The broker and STS:**
  - `Minter.Mint` must refuse an epoch other than the row's current one.
  - The broker must honour only the current epoch (I3 depends on both).
  - `ActivitySource` is the broker's count of model and tool calls per
    session.
- **Facts.** `FactSink` takes `yard.fact/v1` records:
  - `yard.fact.type=tool_outcome`, `gen_ai.evaluation.name=yard.lifecycle.<name>@v1`,
    source EXECUTOR;
  - names: suspend (decision to commit in ms, checkpoint bytes), resume
    (token consume to complete in ms, suspended ms), suspend_abort,
    resume_abort, fail, expire.
  - The OTel exporter is not built here.

## Decisions (user, 2026-10-07)

1. **The message queue is owned by yard-ctl**, beside the lifecycle store
   (same encrypted dataset, its own table). Today the row's `inbox` count is
   all that exists.
   - SR5 modelling item: delivery to the harness (X12, atomic here) becomes
     request / effect / answer.
   - Its effect is the harness acknowledging the message; a lost answer
     means redelivery, so messages need ids and the harness must dedupe.
   - A message may be removed from the queue only after the answer is
     Done.
2. **Credential epoch, enforced now** (`internal/issuer/epoch.go`).
   - Session tokens carry `yard_sess` and `yard_epoch`. The epoch is the
     row's `CredEpoch`, bumped by `SuspendCommit`; `lifecycle.Machine`
     implements `issuer.EpochSource`.
   - The issuer refuses to mint for any other epoch (`ErrStaleEpoch`).
   - `issuer.VerifyEpoch` is the broker-side check (the warden model's
     broker-side epoch check uses the same rule): it rejects a token whose
     epoch is not the session's current one.
   - The verifier also closes a race: a mint checked just before the bump
     and signed just after carries the old epoch, so it is rejected.
   - `TestI3NoEpochMutantBreaks` is the Go counterpart of `noCredEpoch`:
     without both checks, a refresh requested before the suspend and
     answered after the resume is honoured.
3. **One yard-ctl per database, enforced.** `lifecycle.OpenOwned` takes an
   exclusive non-blocking `flock` on `<db>.lock`. It fails fast with
   `ErrOwned`, naming the holder's pid and the lock path. `OpenStore` stays
   for secondary handles. This makes assumption A3 a check.
4. **SR1/SR2 requirement: dead-instance detection while Active.** Each
   backend runs a health check (SR1: `jls` / process descriptor exit; SR2:
   VMM process and API socket). A dead instance of an Active or Idle
   session is a lifecycle event: today it would be Failed, or restarted
   from the service spec for SR1 kinds. Model it in Quint (an Active-state
   counterpart of `InstanceCrash` with a controller reaction) before coding
   it.
5. **Production metrics per unknown-outcome class** (AMBIGUITY.md rule 5).
   - The hook exists: a `FactSink` that also implements
     `lifecycle.OutcomeCounter` gets `CountOutcome(kind, class)` for
     answer_done, answer_error, answer_ignored, timeout, restart_unknown,
     resolved_done, resolved_not_done and retry.
   - Requirement for when the backends are real: export these as OTel
     counters per kind and class, and alert on resolved_not_done and
     restart_unknown rates.

## When to update

Change `lifecycle.qnt` first and re-run `run_models.sh`. Then change
`internal/lifecycle` to match, regenerate traces with `gen_traces.sh`, and
run `go test ./internal/lifecycle/`. Never edit the model to match the code.
