# Agent operations: Cordis delegating to coding agents through yard (draft, revision 2, 2026-10-13)

Status: **draft**. Yard's half of cordis RFC 0008 (`casselc/jolt-sim`, `docs/cordis/rfc/0008-agent-runs.md`), which
extends cordis RFC 0007 ("Boundaries, and the inference operation contract") from inference to coding agents.
- The sandbox choice is `design/SANDBOX-LINUX.md`.
- The model is `spec/agentop/`, whose results are evidence **under the assumptions listed in section 15**, not
  proofs of this revision's protocol.
- The private notes this draws on (HARNESS, IDENTITY, WARDEN, A2A-MCP, TRAINING-DATA) are cited by name.

## 0. Decisions

User, 2026-10-12 (kept):
1. **Models:** the local Halo model first (Claude Code against halo-flash's `/v1/messages` through the broker),
   then the brokered Anthropic API. Keys stay in the broker.
2. **Applying an agent's change always needs the user's approval** until a cordis approval harness exists and is
   tested; automated approval can then be enabled cell by cell.
3. **Sandboxes: Firecracker**, no bwrap or Landlock stopgap. Agent tasks run in Firecracker microVMs on the Halo
   (yard-node; HARNESS SR2, P0-2 spike done). NUC jails stay a second backend behind the same executor interface.

User, 2026-10-13 (this revision): the architecture is unchanged (Yard executes agents in Firecracker; the per-agent
outbox manages durable operations; Cordis coordinates workflows; Halo supplies local inference). The scope is
narrowed and the contract corrected:

4. **The first deliverable is one read-only Claude review task against Halo** (section 1), reliable in authority,
   recovery and accounting. Writers, approved apply, cloud routes, interactive continuation, native delegation,
   and other harnesses come after it, each when its own state, budget and cancellation semantics are written
   (section 12).
5. **Status is separate from accounting certainty** (section 4); the broker's accounting is conservative and
   durable (section 6); valuation is the operator's (section 5); the executor's recovery is staged and fenced
   (section 7); artifacts have their own leases (section 8).

## 1. What this is, and the first milestone

A cordis cell hands work to a coding agent as a typed, budgeted, recoverable **operation**, as it hands a
completion to halo. The workflow sees a typed outcome and a cost, never a process, a socket or a credential.

```
cordis cell ── effect agent.run ──► outbox (operation envelope + yard adapter) ── RFC 0007 verbs, api "agent" ──► yard-ctl
                                                                                                  │ durable task
                                       yard-node (Halo) ◄── start / stop / observe ───────────────┘
                                       └ Firecracker VM: harness driver (claude)
                                           └ vsock ─► broker ─► halo /v1/messages
                                       workspace: immutable base snapshot, mounted read-only
```

**Milestone Y1 (the one thing to deliver first).** One noninteractive Claude Code review task against Halo, with:
- an **immutable workspace** (a base snapshot, attached read-only; nothing in the VM can change it);
- **read and search tools only** (Read, Grep, Glob); no shell, no network, **no native subagents**;
- **structured findings** (a typed output, validated by structure only; section 9);
- **bounded resources**: token, monetary and wall-clock limits enforced independently, plus VM memory, CPU,
  process and output limits;
- **retained evidence**: the transcript, the meter rows, the stage log, the outcome, all under artifact leases;
- **cancellation** at any stage;
- **recovery** from yard-ctl, broker and yard-node restarts and from a lost worker, with the fault tests of
  section 16.

It is connected to Cordis (a `claude_review` cell in a review loop) only after it passes alone.

## 2. Owners

| Owner | Authoritative for | Not |
|---|---|---|
| **cordis** (workflow) | The cell's intent; whether a returned value **satisfies the task** (acceptance); which outcomes it applied | Credentials, sandboxes, routing, prices |
| **outbox** (per agent) | The operation envelope: attempt identity, the exact submission, polling, durable capture, acknowledgement; the yard adapter's reading of outcomes | What the agent did inside; valuation |
| **yard-ctl** | The task row and its stages, durably; fencing; artifact leases; the contract and its valuation | The workflow's meaning of the result |
| **yard-node** (Halo) | The Firecracker VM allocation: start, stop, its incarnation; the volumes | Policy |
| **broker** | Model routing, credential injection, **reservations and metering**, scope activation and revocation | Task outcomes |
| **operator** | The price table (valuation), permitted agents and routes, budget ceilings, who may use `ReadWrite` | |
| **the user** (approval page), later a **cordis approval harness** | Approval of a candidate (deferred, section 12) | |

## 3. The cordis side

Noninteractive. A task states its inputs and gets one outcome.

```
type Workspace   = { repo: str, version: str }          // a yard workspace version; immutable
type AgentBudget = { tokens: int, micro_usd: int, seconds: int }   // three independent limits
type AgentTask<T> = {
  agent: Agent, model: ModelRoute,                       // a permitted route, never a key
  workspace: Workspace, mode: ReadOnly,                  // ReadWrite is deferred (section 12)
  instructions: [str],
  output: Type<T>,                                       // validated by structure
  budget: AgentBudget,                                   // at or below the operator's ceiling
  valuation: Digest,                                     // the price table the outbox priced its reservation with
}
type AgentResult<T> =
  | Completed{ value: T, usage: Usage, artifacts: [Artifact] }
  | Incomplete{ reason: Timeout | BudgetExhausted | Cancelled | InvalidOutput | WorkerFailed | Insufficient,
                usage: Usage, spend: Spend, artifacts: [Artifact] }
```

`Insufficient` is how a noninteractive agent says it cannot proceed without more information; the cell decides what
to do (emit a new task with more, or ask a person). A **refusal** is reserved for a submission that was **not
executed** (section 4). An `Incomplete` is a *result*: it cost something, it has a usage, and it may have partial
artifacts.

## 4. The agent operation: terminal outcome, execution, spend

The wire is RFC 0007's: submit with incarnation, `not_after` and digest; status, fetch, cancel, ack; retention
until ack; the record ceiling; refusals that close only their copy. `api: "agent"` adds a body, not verbs.

A terminal answer carries three independent facts:

| Fact | Values | Meaning |
|---|---|---|
| **outcome** | `completed`, `invalid_output`, `insufficient`, `budget_exhausted`, `timeout`, `cancelled`, `worker_failed` | what the task did. All are `done` operations with a usage. |
| **execution** | `stopped`, `unconfirmed` | whether yard **proved the worker stopped**. `unconfirmed` means the worker was unreachable; nothing is claimed about what it did, only about what it can still do: once the scope is revoked it can make no model call, and the VM has no other egress. |
| **spend** | `exact`, `bounded` | `exact`: every model call was answered with a usage. `bounded`: at least one call has no answer and is charged at its reserved maximum. `charge` is the integer sum in monetary units, never below the confirmed usage. |

A task is **terminal** only when its broker scope is revoked and every in-flight call is either answered or charged
conservatively. If yard cannot reach the broker to revoke, the operation stays `running` (marked `degraded`) and its
reservation holds; at the operation's deadline the attempt is `unknown` and settled at the whole reservation.

The earlier claim that uncertainty occurs only after yard-ctl's store is lost is withdrawn. The uncertain things are:
- **spend** of an unanswered model call (bounded, never exact), resolved if the route can say (halo's operation
  records can; Anthropic's cannot);
- **execution** of an unreachable worker (unconfirmed);
- **everything**, if yard-ctl's or the broker's store is lost (the `unknown` of RFC 0007, settled at R).

**Admission refusal is not execution failure.** `refused` (HTTP 4xx/503: not permitted, over the ceiling, valuation
changed, record ceiling) and `closed`, `never_accepted`, `cancelled_before_accept` (RFC 0007) mean **not executed,
nothing spent**. Everything else that ends a task is a typed outcome above, with a usage and whatever partial
artifacts were captured.

Guarantees in the contract (`GET /v1/yard/contract`, the shape of halo's):

| Guarantee | Agent operations |
|---|---|
| External effects | none outside the VM, except model calls through the broker (reserved and metered) |
| Repeating | spends again and may differ; a new attempt is a new VM |
| Deduplication | per attempt, durable in yard-ctl; a store loss is `unknown` |
| Cancel | revokes the scope, stops the VM; the outcome is `cancelled` with usage to that point |
| Cost | the broker's, in integer monetary units at the pinned valuation (section 5); never the harness's report |
| Retention | the operation record until acknowledged; artifacts by their own leases (section 8) |
| Valuation | the digest of the price table; pinned per attempt |

## 5. Valuation and budgets

- **Operator-controlled.** The price table (price per million tokens by route and direction, a nominal price for
  local inference per route, a price per second of VM time if the operator charges it) is the operator's. Its
  digest is the **valuation**. An agent or a cell may choose permitted routes, smaller budgets and retry strategies;
  it cannot change a price, and no price is derived from anything the graph holds.
- **Pinned per attempt.** At accept, yard-ctl records the valuation in force. A submit carries the valuation the
  outbox read from the contract; if it differs, the submit is refused (`409 valuation_changed`, not executed) and
  the outbox re-reads. The attempt's reservation, the broker's enforcement and the settlement all use the pinned
  table, however long the task runs.
- **Three independent limits**, each enforced alone, none derived from another:
  - tokens (input plus output, per route as the broker counts them),
  - money (integer **micro-dollars**),
  - time (seconds of wall clock, by yard-ctl against the VM allocation).

  The first reached ends the task with that outcome. A task with any of the three missing is refused.
- **Integers only.** Prices are integer micro-dollars per million tokens; a call's cost rounds **up** to the next
  micro-dollar. Cordis's budget unit is the micro-dollar; the conversion is done by yard, once.

## 6. Broker accounting: reserve, send, settle, recover

The broker's meter is a durable table, one row per model call: `{call, task, route, state, reserved, confirmed}`.

1. **Reserve before sending.** A call's maximum cost is computed at the pinned valuation from an upper bound on its
   input (the measured request) and the output limit the broker **imposes** on the request (`max_tokens` clamped to
   what the remaining budget can pay for). The row is committed (`reserved`) **before** the request leaves. A call
   whose maximum plus every other open reservation and all settled spend would pass the task's token or monetary
   limit is answered `429` and never sent. This holds for **concurrent** calls: the check and the insert are one
   transaction against the task's totals.
2. **Send.** The row becomes `sent`.
3. **Settle.**
   - An answer with usage: the row becomes `settled` at the confirmed cost (≤ reserved); the difference is released
     to the task's budget.
   - A refusal by the provider before any generation (a 4xx the route documents as not-executed): `released`.
   - Any other end (timeout, connection loss, no usage in the answer, a broker crash): the row becomes
     `unresolved` and **keeps its reservation as the charge**. It is never released by the broker's own say-so.
4. **Resolve, when the route can.** For halo, the broker asks the operation record for the call's usage by its
   operation id and settles at it; for a route that cannot say, the charge stays at the reserved maximum.
5. **Recovery.** On start the broker reads its table. `reserved` rows (a crash between commit and send): the send
   may or may not have happened; they become `unresolved`. `sent` rows: `unresolved`. Reservations are only ever
   released by an answer or a route's own record, never by recovery. A lost table is the `unknown` of section 4.

The task's `spend` is `exact` iff no row is `unresolved`, else `bounded`, and its `charge` is the sum of `settled`
and `unresolved` reservations.

## 7. The executor's internal protocol: stages, observations, fencing

Acceptance, worker start, scope activation, result capture, worker termination and scope revocation are **not** one
transaction. Each is a durable stage in the task row, entered by a request whose effect and answer may each be lost,
duplicated or late, and left only on a **resolving observation**.

| Stage | Entered by (durable first) | Resolving observation | If unknown on recovery |
|---|---|---|---|
| `accepted` | one transaction: task row, digest, deadline, reservation, **pinned valuation**, the allocation record `{alloc_id, incarnation}` minted but unused | the row | none; this is the commit |
| `scope_created` | broker scope created **inactive**, bound to `(task, alloc_id, incarnation, route, caps)` | broker scope table | create again (idempotent by task) |
| `worker_starting` | the start request to yard-node, naming `(alloc_id, incarnation)` | yard-node's VM table by `alloc_id` | verify; **never start a second allocation for the attempt** |
| `scope_active` | broker activates the scope for the VM's `(vsock CID, tap, incarnation)` reported by yard-node | broker scope table | re-ask |
| `running` | the driver's first event, or the node's ready | node VM table, the stream | adopt a live allocation; a gone one goes to `capturing` with `worker_failed` |
| `capturing` | outcome known (driver result, cap, timeout, cancel, loss) | the artifact store's content hashes | capture again from the node if reachable, else `artifacts: unavailable` |
| `stopping` | stop request to yard-node | VM table: absent | retry; on a lease expiry the node's own watchdog stops the VM; mark `execution: unconfirmed` if the node stays unreachable past the stop bound |
| `revoking` | broker revokes the scope; in-flight calls drained or marked `unresolved` | broker scope table: revoked | retry; non-terminal until done |
| `settled` | the task's `spend` computed from the meter | the meter | recompute |
| `done` | outcome, execution, spend, artifact leases, in one transaction | the row | none |

**Fencing.** The broker identifies a caller by `(vsock CID, tap)`, but both are reusable. Therefore:
- yard-ctl mints a monotonic **allocation incarnation** and records it before it asks yard-node to start;
- yard-node refuses a start whose incarnation is not newer than the last it saw for that CID, and attests
  `(CID, tap, alloc_id, incarnation)` to the broker on the VM's behalf;
- the broker admits a call only if the connection's attested tuple equals the **active scope's**; a scope is
  activated for exactly one tuple and revoked at its end, so a later VM on the same CID and tap, an old VM that
  outlived its scope, and a stale activation all fail the same comparison;
- a node that cannot reach yard-ctl stops its VM at the allocation's **lease expiry** (a watchdog in the node),
  which bounds a lost worker's life even if nothing else is reachable;
- scope revocation does not wait for the worker: it is how a possibly-running worker is made harmless.

Cancellation enters at any stage: it sets the task's `cancel` flag in the row, and the stages after the current one
proceed to `capturing` with outcome `cancelled`. A cancel before `accepted` commits is `cancelled_before_accept`.

## 8. Artifacts: retention separate from acknowledgement

Acknowledging an operation releases **the operation's record and its receipt capture**. It does not release an
artifact. Artifacts are `{id, digest, size, kind, lease}` where `kind` is `transcript`, `findings`, `invalid_output`,
`partial`, `meter`, `stage_log`, or (deferred) `candidate_workspace`.

- Each artifact has an **explicit lease** (`expires_at`, in yard-ctl's clock) and **holders**. Capture sets a default
  lease from the operator's retention policy.
- A holder (an approval record, an open review, a cell) extends or releases its hold with `artifact.lease(id,
  until)`. An artifact lives until its last hold and lease have both ended.
- **Unavailable is an explicit failure.** Fetching an artifact whose lease ended or whose bytes are lost answers
  `410 artifact_unavailable` with the digest it should have had. A consumer that needed it (an approval, an audit)
  fails; it is never given an empty or substitute value.
- Retention is quota-bounded per owner; a refusal to extend a lease is a typed error, not an eviction.

## 9. Completion is not acceptance

- **Yard validates structure**: the final output parses and matches the declared output schema.
- It **preserves** an output that does not as an `invalid_output` artifact and ends the task with that outcome.
  There is **no automatic retry**, no hidden second model call inside validation.
- **Repair is explicit**: a repair is a *new attempt* a cell emits (with the invalid output and the error as its
  input), under its own reservation and metering. Yard offers no in-VM repair loop.
- **Cordis evaluates acceptance**: whether findings cite files and lines that exist in the reviewed version,
  whether a zero-finding review read anything, whether the verdict is consistent. Yard never decides that a
  result is good.

## 10. Harness drivers and routes

The first driver is `claude` (Claude Code, print mode, JSON output) against halo's `/v1/messages` through the
broker. A driver turns `{instructions, output schema, tools, route}` into the harness's non-interactive run.
- **Tools: Read, Grep, Glob only.** No shell, no write, no web, **no native subagents** (the harness's Task tool is
  disabled in the driver's configuration, and the VM has nothing a subagent could add).
- Flag names and output formats are verified per harness version (AG1); the driver pins the version and flags and
  records them in the stage log.
- The harness's own sandbox stays on as an inner layer; the VM is the boundary.
- Metering is the broker's. Halo answers carry usage and `engine_ms`; Anthropic answers (later) are priced from the
  price-fact table at the pinned valuation.

## 11. Workspaces (the immutable base, and diffs)

- **Base.** A workspace version is an immutable ZFS snapshot plus a registry row `{repo, version, base, produced_by}`.
  Many tasks may attach the **same snapshot read-only** (no clone per task for a read-only task; a clone only when a
  task writes, which is deferred). Nothing writes a version in place.
- **Diffs are computed by a trusted tool over the actual trees**, not with `zfs diff`. `zfs diff` reports changed
  blocks and paths of a ZFS *filesystem*; a zvol holds a guest filesystem, so it exposes nothing about files. The
  comparison is made as follows, and is needed from the first writer on:
  - a **diff worker**: a separate, minimal Firecracker VM with the base and result volumes attached read-only (the
    host never mounts a guest-written filesystem), running a vetted tool that walks both trees without following
    symlinks;
  - the tool emits a **canonical manifest**: for every path in either tree, its type (file, directory, symlink,
    special), mode, owner policy, size, content hash, and, for a symlink, its target string; deletions and type
    changes are entries; renames are not inferred;
  - the **tree digest** is a Merkle hash of the manifest; the **diff digest** is the hash of the sorted manifest
    delta; the text diff shown to a person is derived from the same walk, for regular text files, and says "binary"
    with the hash otherwise;
  - an approval binds to `(base tree digest, result tree digest, diff digest)`; apply recomputes the result tree
    digest.

## 12. Deferred, and what must be written first

None of these is in the first milestone. Each needs its own state, budget and cancellation semantics.

| Deferred | Must specify before it is built |
|---|---|
| **`ReadWrite` tasks and candidate workspaces** | the clone's lifecycle and lease; the writer's quota; the trusted diff (section 11); artifact kind `candidate_workspace` |
| **Approval and apply** | **Approval is a durable record**, produced by a person or an approval harness and bound to `(candidate digest, expected base, diff digest, expiry)`; it is not an open operation. **Apply is a short compare-and-set operation** that carries the approval id and validates: the caller's authority, the approval's expiry, the candidate's digest and lease, the target head equal to the expected base. Waiting for a human is never an operation's `running` |
| **Interactive continuation (`needs_input`)** | whether a VM is held suspended or a new attempt carries the answer; budget and lease for the wait; cancellation. Until then a task returns `insufficient` |
| **A2A child delegation** | the child's budget drawn from the parent's reservation and metered into its spend; cancellation propagation; the chain limits; the ambiguity register's rows for it (A2A-MCP R5, R9, R12, R15). Until then Cordis coordinates top-level fan-out |
| **Anthropic route** | price facts at the valuation; the USD limit; unresolvable unanswered calls charged at their maxima (section 6) |
| **Codex, opencode, yard-agent drivers** | each driver's pinned flags, output format and event stream; metering parity |

## 13. Identity

- The task runs as a yard session: an STS token with `sub` = the user and `act` = the sandbox session, and inside
  that the cordis principal that submitted the operation (IDENTITY's RFC 8693 shape).
- The broker scope is minted for the task, bound to the allocation tuple, and revoked at its end.
- The VM holds no credential.

## 14. Observability

Every task is a run (TRAINING-DATA): a trace with spans for model calls (through the broker, with the reservation
and settlement), the stage transitions, the driver's validation, and the artifacts. The cordis verdict and whether
a review was later overturned are recorded as score facts. Content capture follows the run class.

## 15. Models

`spec/agentop/` (quint 0.32, seed 0x5eed, 10,000 samples × 40 steps, and the deep runs) is **evidence under these
assumptions, which are narrower than this revision's protocol**:
- every model call is **atomic, answered, and of known cost**: it either does not happen or happens once with an
  exact usage;
- calls are **not concurrent** within a task's accounting step;
- the **worker stop is reliable** and observed, and revocation is **instantaneous** with the task's end;
- there are **no broker crashes** and no lost usage answers; the broker's table is never behind the provider;
- a VM's identity is not reusable (no CID reuse, no stale activation);
- artifacts are not modelled; apply and approval are (and are deferred in this revision).

What it does show, under those assumptions: the cap, meter-not-report, restart adoption, revocation at the end,
approval before apply, and compare-and-set apply each hold, and each mutant breaks its property.

**To model before Y1's recovery is built** (`spec/agentop/accounting.qnt` and `spec/agentop/stages.qnt`, with
gate rows, mutants and witnesses):

| Extension | Properties | Mutants |
|---|---|---|
| Concurrent reservations | `reservedBeforeSend`; `withinCap` over reserved plus settled across concurrent calls | `reserveAfterSend`, `checkThenInsert` (the cap check not in the insert's transaction) |
| Lost usage answers | `neverUndercharged`: charge ≥ real spend; `unresolvedKeepsCharge` | `releaseOnTimeout`, `chargeZeroOnLoss` |
| Broker crashes | recovery never releases a reservation; `spendBounded` after a crash between reserve and send | `recoverReleases`, `recoverTrustsHarness` |
| Ambiguous worker start and stop | `runsOnce`; `noSecondAllocation`; a lost stop answer resolves by observation | `rerunOnRestart` (existing), `startWithoutIncarnation` |
| Delayed revocation | `noCallAfterRevoke` over the window between a worker's death and the revoke; stale incarnation never admitted | `scopeNotRevoked` (existing), `cidReuse`, `activateWithoutAttestation` |
| Artifacts | `noReleaseWhileHeld`; `unavailableIsExplicit` | `ackReleasesArtifact`, `substituteEmpty` |

Witnesses: an unanswered call charged at its maximum; a broker crash with a `sent` row; a worker lost with its
node unreachable (`execution: unconfirmed`, spend `bounded`); a stale-incarnation call refused; an artifact fetched
after its lease with an explicit failure.

## 16. Milestones

| # | Work | Exit |
|---|---|---|
| **Y0** | This revision; the extended models of section 15 with their gate rows | The design holds under the stated assumptions; each mutant breaks its property; each witness is reached |
| **Y1a** | The review VM alone: Firecracker image with the claude driver, read-only base attach, broker with the reservation table, yard-ctl stages, artifacts and leases; operations served for `api: "agent"` | one review task against halo with limits, evidence, cancellation; the **fault set**: yard-ctl restart at every stage, broker crash between reserve and send, lost usage answer, killed VM, unreachable node (lease expiry), stale activation, cancel at every stage, lease expiry; halo's `tools/op_fault_probe.py` adapted to agent tasks |
| **Y1b** | Cordis connection: the outbox's yard adapter and a `claude_review` cell | a cordis review loop ships through the milestone's faults, with the evidence manifest |
| **Y2** | Measured optimisations (section 17) | each reported with its measurement |
| **Later** | The deferred list of section 12, each when its semantics are written | |

## 17. What to measure, not guess

VM boot (126 ms, P0-2) is small against a task of minutes, and is not a target. The candidates, each measured before
it is optimised:
- **Immutable workspace sharing**: one read-only snapshot attached to N concurrent reviewers versus a clone each:
  attach time, page-cache sharing, storage.
- **Stable prompt prefixes**: the instruction text ordered so the shared part (rules, tool descriptions) is a prefix
  and halo's prefix cache hits across reviewers: cache hit rate, time to first token.
- **Harness startup**: Claude Code process start to first model call, with the image's node and caches.
- **Interference with halo_serve**: CPU, memory and storage I/O from N VMs in `yard.slice` against halo's
  throughput and latency (the GPU is shared through halo's scheduler, where an agent's calls are ordinary requests
  under the task's principal).

## 18. Open questions

1. The monetary value of **local inference** (a nominal price per token or per engine second): the operator's
   choice, but needed so a local review has a comparable budget.
2. The **stop bound** and the **lease length** for an allocation: how long a lost worker may live.
3. Whether halo's operation records give the broker enough to **resolve** an unanswered call's usage exactly.
4. The default **artifact lease** and per-owner quota.
5. Where the **diff worker** runs (its own VM image, its own slice).
6. Where workspace versions live when the VM is on the Halo (the Halo's pool, with `zfs send` for retention) —
   unchanged from revision 1.

## History

- Revision 1 (2026-10-12): first draft.
- Revision 2 (2026-10-13): after review. Status separated from accounting certainty; broker reserve/settle/recover
  protocol; operator valuation pinned per attempt, three independent limits, integer micro-dollars; typed terminal
  outcomes; staged recovery and fencing by allocation incarnation; artifact leases; trusted tree comparison replaces
  `zfs diff`; structural validation only, explicit repair; approval separated from apply; `needs_input` and A2A
  delegation deferred; models restated as evidence under assumptions with the extensions named; one read-only
  review task first; measured optimisation.
