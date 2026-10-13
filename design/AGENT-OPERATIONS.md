# Agent operations: Cordis delegating to Claude Code, Codex and opencode through yard (draft, 2026-10-12)

Status: **draft**. Yard's half of what cordis would call RFC 0008. It extends cordis RFC 0007 ("Boundaries, and
the inference operation contract") from inference to coding agents.
- The sandbox choice is `design/SANDBOX-LINUX.md`.
- The model is `spec/agentop/`.
- The private notes this draws on (HARNESS, IDENTITY, WARDEN, A2A-MCP, TRAINING-DATA) are cited by name.

## 0. Decisions (user, 2026-10-12)

1. **Models:** the local Halo model first (Claude Code against halo-flash's `/v1/messages` through the broker),
   then the **brokered Anthropic API**. Keys stay in the broker.
2. **Applying an agent's change always needs the user's approval.** That holds until a cordis approval harness
   exists and is tested. Automated approval can then be enabled and configured **cell by cell**.
3. **Sandboxes: Firecracker, with no bwrap or Landlock stopgap.**
   - Agent tasks run in Firecracker microVMs on the Halo (yard-node; HARNESS SR2, P0-2 spike done). That is the
     first backend and the default.
   - **NUC jails stay on the roadmap** as a second backend behind the same executor interface: capacity, and
     distance from the GPU box (`design/SANDBOX-LINUX.md`, option E).

## 1. What this is

A cordis cell can hand work to a coding agent as a typed, budgeted, recoverable **operation**, as it hands a
completion to halo:
- "Review this diff against the repo and give me a verdict and findings."
- "Implement this change and give me a branch."

The workflow sees a typed result and a cost, never a process, a socket or a credential.

```
cordis cell ── effect agent.run ──► outbox (operation service) ── RFC 0007 verbs, api "agent" ──► yard-ctl
                                                                                                  │ durable task
                                       yard-node (Halo) ◄── start / cancel / observe ─────────────┘
                                       └ Firecracker VM: harness driver (claude | codex | opencode | yard-agent)
                                           └ vsock ─► broker ─► halo /v1/messages  (then Anthropic, key injected)
                                       workspace: ZFS version → zvol clone (ro or rw) → result version
```

## 2. Owners

| Owner | Authoritative for | Not |
|---|---|---|
| **cordis** (workflow) | The cell's intent, its typed result, which receipts it applied, which workspace version the workflow is on | Credentials, sandboxes, model routing |
| **outbox** (operation service, per agent) | Attempts, reservations and settlement, receipts, the commit-before-ack handoff; the same adapter as for halo, with `api: "agent"` | What the agent did inside |
| **yard-ctl** (executor) | The task record, durably: accepted, running, finished; the VM and workspace it used; the metered usage; the result held until acknowledged | The workflow's meaning of the result |
| **yard-node** (Halo) | The Firecracker VM's lifecycle, the zvol clone, the vsock channel to the guest | Policy |
| **broker** | Model routing, credential injection, **metering**, the per-task budget cap and scope | Task outcomes |
| **workspace registry** (yard-ctl) | Workspace versions and which task produced each; `apply` | |
| **the user** (approval page), later a **cordis approval harness** | Whether a result version may be applied | |

## 3. The cordis side

An effect and types (cordis graph language; the names are a proposal for the cordis agent):

```
type Workspace = { repo: str, version: str };            // a yard workspace version
type AgentBudget = { tokens: int, usd: float, minutes: int };
type AgentTask<T> = {
  agent: Agent,                 // Claude | Codex | Opencode | YardAgent
  model: ModelRoute,            // Local (halo) | Anthropic   (the route, never a key)
  workspace: Workspace, mode: ReadOnly | ReadWrite,
  instructions: [str],
  output: Type<T>,              // validated by yard-ctl; a schema miss is retried once, then an error
  budget: AgentBudget,
};
type AgentOutcome<T> = { value: T, result_version: Workspace | null, usage: Usage, transcript: Ref };

effect agent.run<T>(AgentTask<T>) : AgentOutcome<T>;
effect workspace.apply(Workspace /* result */, Workspace /* expected base */) : Workspace;   // needs approval
```

A review cell:

```
type Finding = { file: str, line: int, severity: Severity, note: str };
type Review  = { verdict: Pass | Fail, findings: [Finding] };

cell claude_review(diff : Diff, ws : Workspace) : Review ! { agent.run } = {
  use r = agent.run(AgentTask{ agent: Claude, model: Local, workspace: ws, mode: ReadOnly,
                               instructions: ['Review the change below. ...', diff.patch], output: Review,
                               budget: { tokens: 400000, usd: 0, minutes: 15 } });
  r.value
}
```

**Authority is the runner's configuration, never the graph's** (RFC 0007, `observe.qnt`'s `misclassify`). The
runner config grants, per cell:
- which agents and model routes it may use, and the maximum budget;
- `ReadWrite`;
- whether `workspace.apply` may be approved automatically.

Until the approval harness exists, the last is always "no": every apply raises a card for the user.

## 4. The agent operation type

The wire is RFC 0007's, unchanged:
- submit with incarnation, not-after and digest;
- status, fetch, observe, cancel, ack;
- retention until ack, the record ceiling, refusals that close only their copy.

The type declares its guarantees in yard's contract (`GET /v1/yard/contract`, the same shape as halo's):

| Guarantee | Agent operations |
|---|---|
| External effects | none outside the VM, except model calls through the broker (metered). A `ReadWrite` task produces a **new workspace version**; it never changes the version it started from |
| Repeating | spends again and may differ; a new attempt is a new VM and a new branch |
| Deduplication | per attempt, durable in yard-ctl (not per incarnation: yard-ctl's store survives restarts) |
| Cancel | stops the VM; the attempt ends `cancelled` with the usage metered until then |
| Cost | **metered by the broker** (tokens per route; USD for Anthropic from its usage and a price table; engine_ms for halo); never the harness's own report |
| Retention | the result, the transcript reference and the result version until acknowledged; the VM is gone at the end |
| Unknown outcomes | only if yard-ctl's disk is lost. A VM or yard-node crash is a known `failed`, settled at its metered usage |

**Status answers** are halo's, plus one:
- `running`;
- `done`, with `value`, `result_version`, usage and finish (`stop`, `budget`, `timeout`, `cancelled`, `error`);
- `released`, `expired`, `closed`, `never_accepted`, `unknown`;
- **`needs_input`** (proposed): the harness asked a question it may not answer itself. The cordis cell routes
  it, then submits a new attempt with the answer.

**Incarnation:** yard-ctl's durable epoch. It changes only on a store loss, which is the case "unknown" exists for.

## 5. The executor: yard-ctl and yard-node

1. **Accept** (durable, one transaction):
   - the task row with its digest, deadline and reservation;
   - a broker scope (`task id`, route, cap);
   - the workspace snapshot it reads.
2. **Prepare (yard-node):**
   - a zvol clone of the workspace version, read-only for `ReadOnly`;
   - a Firecracker VM from the harness image: rootfs read-only, the zvol as `/workspace`, a tmpfs home, vsock only.
   - P0-2 measured 126 ms to boot; the harness's own start comes on top.
3. **Run:**
   - The guest agent starts the harness driver.
   - Model calls leave only through vsock to the broker, which routes, injects, meters and enforces the cap; past
     the cap it answers 429, and the driver ends with finish `budget`.
   - The observation stream carries the harness's events (messages, tool calls); they are observations, never
     receipts.
4. **Finish:**
   - The driver writes the final result.
   - yard-ctl validates it against `output`; on a miss it retries once, in the same VM, with the validation error.
   - For `ReadWrite`, yard-node snapshots the zvol, and the registry records it as a new version with its base
     and `zfs diff` summary.
   - The VM stops, the broker scope is revoked, and the record turns `done` with the metered usage.
5. **Restart recovery:**
   - yard-ctl recovers its rows.
   - A row that was running is checked with yard-node. A live VM is re-adopted; a gone one ends `failed` at the
     metered usage.
   - A redelivered submit for an accepted attempt is a duplicate. It **never** boots a second VM (`runsOnce`).
6. **Placement:**
   - Firecracker on the Halo, in `yard.slice`, capped below halo_serve. NUC jails are a later backend (AG8); yard-ctl
     picks the backend from the task's placement class, and the contract is the same.
   - No GPU device in the VM.
   - The workspace dataset lives on the Halo's ZFS pool for the VM's lifetime (open question 2).

## 6. Harness drivers and model routes

A driver is a small program in the image. It turns `{instructions, output schema, tools, model route}` into the
harness's non-interactive run, and collects its final answer and event stream.

| Driver | Run | Local route (first) | Anthropic route (second) |
|---|---|---|---|
| claude | Claude Code, print mode with JSON or stream-JSON output and a tool allow-list | `ANTHROPIC_BASE_URL` → broker `inference.yard` → halo `/v1/messages` | broker → Anthropic, key injected |
| codex | Codex non-interactive exec with JSON events | broker → halo `/v1/responses` (Codex's Responses gaps, G6, apply) | — (or a brokered OpenAI route later) |
| opencode | opencode run, JSON output | broker → halo (OpenAI-compatible) | broker → Anthropic |
| yard-agent | yard's own loop (HARNESS J4) | broker → halo `/v1/responses` | broker → Anthropic |

- **Flag names and output formats are verified per harness version in AG1.** The table names the modes, not
  exact flags.
- The harnesses' own sandboxes stay on inside the VM as an inner layer. The VM is the boundary.
- **The broker meters both routes:**
  - Halo answers carry usage and `engine_ms`, and operations carry their own records.
  - Anthropic answers carry usage, priced from the price-fact table (bitemporal, as halo-scope's).

## 7. Workspaces and apply

- **Versions:** a version is a ZFS snapshot plus a registry row `{repo, version, base, produced_by, diff summary}`.
  A task reads one version and, if `ReadWrite`, returns one new version. Nothing writes a version in place.
- **Apply** is an operation of its own: `workspace.apply(result, expected_base)`.
  - It succeeds only if the target branch is still at `expected_base`. Otherwise it is `conflict`: the workflow
    rebases with a new task or asks.
  - It needs an **approval** bound to `(result version, expected base, diff digest)`:
    - a card on the approval page, showing the diff from the registry and never the agent's description of it;
    - the passkey for anything the policy marks sensitive;
    - an expiry, after which the apply is refused, never run on a late approval (WARDEN, A2A R11).
- **Automated approval, later:**
  - A cordis approval harness is a cordis workflow: critics, tests in their own agent task, deciders. It approves
    a result by a recorded, scored decision.
  - Once it exists and passes its own test suite (an evaluation set of good and bad diffs with known answers),
    the runner config may enable it for a named cell, with that cell's limits.
  - The card path stays for every other cell, and for anything the policy marks sensitive.

## 8. Identity

- **The task runs as a yard session:** an STS token with `sub` = the user and `act` = the sandbox session, and
  inside that the cordis principal that submitted the operation (IDENTITY's RFC 8693 shape).
- **The broker scope is minted for the task** and revoked at its end. A model call after the end is refused
  (`noCallsAfterEnd`).
- The VM holds no credential; the broker identifies it by its vsock CID and tap.

## 9. Agent operations and A2A-MCP

A2A-MCP.md designs **east-west** calls: one sandbox calling another, through `yard-relay`, as A2A tasks or MCP
calls, with suspension, wakes, chain limits and an ambiguity register (R1–R17). This draft is **north-bound**: a
workflow delegating to yard. They meet, and they must not become two state machines for one call.

- **The contract cordis sees is RFC 0007's,** because cordis's outbox already implements it (journal, receipts,
  commit-before-ack), and the halo milestone proved it end to end.
- **Inside yard, a task whose agent is an A2A server** (yard-agent, or a harness behind an A2A wrapper) is driven
  as an A2A task through the relay. The operation's attempt id is the A2A `messageId`, its idempotency key. The
  relay's ambiguity register (R5, R9, R12, R15) applies inside yard, and the operation status is derived from it:

| A2A task / relay | Operation status |
|---|---|
| SUBMITTED, WORKING | `running` |
| COMPLETED (stored at the relay) | `done` |
| INPUT_REQUIRED | `needs_input` |
| CANCELED | `done` with finish `cancelled` |
| FAILED, REJECTED | `done` with finish `error` |
| unknown (R5, R12, R15) | `failed` with metered usage when the VM is known gone; `unknown` only if yard-ctl's store was lost |

- **CLI harnesses** (Claude Code, Codex, opencode) are driven directly by their driver in the VM; there is no A2A
  server to talk to.
- **An agent that delegates further** (Claude in a task calling Codex) does so as an **A2A edge through the
  relay**:
  - the edge policy, cards and chain limits (D6, D10) apply;
  - the chain's budget is drawn from the parent task's reservation;
  - the child is metered into the parent's usage.

  It is never a nested cordis operation the agent can submit itself. Agents get no outbox.

## 10. Observability and training data

Every agent task is a run (TRAINING-DATA):
- one trace, with spans for model calls (through the broker), tool calls (with snapshot ids), the driver's
  validation and the apply;
- content capture by run class (`own-code` on; anything web- or secret-touching digest-only).

The signals:
- the cordis verdict (did the review match the eventual outcome);
- the approval decision on the apply card, and the user's edit of the agent's diff before applying (a preference
  pair);
- for reviews, whether the critic's verdict was overturned.

All are recorded as score facts with supersede and retract.

## 11. Ambiguity register (agent-specific; the wire's are RFC 0007's, the relay's A2A-MCP's)

| # | Call | done / not done / unknown | Settle bound | Resolving observation | Rule | Mutant |
|---|---|---|---|---|---|---|
| G1 | yard-ctl → yard-node: start the VM | done: the VM reports ready. Not done: refused (capacity). Unknown: lost answer | the boot bound (~1 s) + the harness start | yard-node's VM table by task id | verify, never start a second one for the attempt | `rerunOnRestart` |
| G2 | broker model call | done: answered and metered. Not done: refused (cap, scope). Unknown: lost answer | the call timeout | the broker's meter row | **charge what the meter says**; the harness's report is advisory | `meterFromHarness` |
| G3 | the task's end → scope revoke | done: revoked | immediate (same transaction as `done`) | the broker's scope table | revoke before the record turns done | `scopeNotRevoked` |
| G4 | apply | done: the branch moved to the result. Not done: conflict, denied, expired. Unknown: lost answer | the apply's own bound | the branch head | verify the head; apply is a compare-and-set on `expected_base` | `applyStaleBase` |
| G5 | approval | done: approved (hash-bound). Not done: denied, expired | the card expiry | the card | wait, then refused; a late approval never releases it | `applyWithoutApproval`, `autoApproveUnconfigured` |

## 12. The model (`spec/agentop/`)

**Scope:** what agents add beyond RFC 0007's wire, whose models (halo `spec/operation`, cordis `operation.qnt`,
`capture.qnt`, `expiry.qnt`) already cover delivery, identity, deadlines and the handoff. The actors:
- a durable executor that restarts;
- VMs that crash;
- a broker that meters, caps and revokes;
- a harness that makes model calls and reports its own usage, possibly wrong;
- workspace versions and `apply`;
- an approver: the user, or a cell's automated approval when it is enabled and its harness is tested.

**Properties:**
- `accounted`: real model spend ≤ settled + reserved;
- `withinCap`: no task spends past its budget;
- `runsOnce`: one VM per attempt;
- `noApplyWithoutApproval`;
- `noLostUpdate`: the main line only moves by an apply from its current head;
- `appliedOnce`;
- `noCallsAfterEnd`.

**Mutants, one per rule:**
- `brokerNoCap`;
- `meterFromHarness`;
- `rerunOnRestart`;
- `scopeNotRevoked`;
- `applyWithoutApproval`;
- `autoApproveUnconfigured` (auto-approval on a cell whose harness is not tested, or not enabled for it);
- `applyStaleBase`.

**Results** (`spec/agentop/run.sh`, quint 0.32, seed 0x5eed, 10,000 samples × 40 steps):
- **The design holds** in all three approval configurations:
  - today's (`design`: automated approval enabled nowhere);
  - `enabledUntested` (a cell enables it before its harness passed: still the user only);
  - `autoConfigured` (enabled and tested).

  Both `design` and `autoConfigured` also hold at 100,000 × 80.
- **Each mutant breaks its property:** `brokerNoCap` withinCap; `meterFromHarness` accounted; `rerunOnRestart`
  runsOnce; `scopeNotRevoked` noCallsAfterEnd; `applyWithoutApproval` noApplyWithoutApproval;
  `autoApproveUnconfigured` noAutoUnlessConfigured; `applyStaleBase` noLostUpdate.
- **Every witness is reached:**
  - an applied result and a settled review;
  - a cap hit, and a crashed task settled at its meter;
  - a restart that re-adopted a running task;
  - an apply conflict, and a denial;
  - an automated apply on the configured cell.

Details are in `spec/agentop/results.txt`.

## 13. Milestones

| # | Work | Exit |
|---|---|---|
| **AG0** | This draft and `spec/agentop` | The design holds; each mutant breaks its property; every witness is reached |
| **AG1** | Firecracker harness image: the P0-2 guest plus node, Claude Code, ripgrep, git; the guest agent's exec and vsock broker forward; the claude driver | `claude` in print mode, in the VM, reviews a fixture repo against halo `/v1/messages` through the broker. Measured: boot to first model call; the review's wall time vs the same outside the VM |
| **AG2** | yard-ctl serves `/v1/operations` for `api: "agent"`: durable rows, zvol clones, scopes, recovery | halo's `tools/op_fault_probe.py`, adapted to agent tasks, passes, including a yard-ctl restart mid-task and a killed VM |
| **AG3** | cordis `agent.run` through the outbox adapter (one adapter, two executors); the `claude_review` cell | A cordis review loop with `claude_review` against the local model ships through the milestone's faults |
| **AG4** | `ReadWrite` tasks, versions, `workspace.apply` with approval cards | An implement-then-review workflow produces a branch; the apply raises a card; approve applies it; deny and expire refuse; a moved base conflicts |
| **AG5** | The brokered Anthropic route; price facts; the USD cap | The same review on the Anthropic route, metered in USD; the cap stops a runaway task |
| **AG6** | Codex and opencode drivers (and yard-agent when J4 lands) | The review cell runs on each, through the same contract |
| **AG8** | The NUC jail backend (Linux compatibility, SANDBOX-LINUX option E): its harness spikes, then the same AG2 tests on it | The review cell runs on either backend through the same contract; placement is a per-task class |
| **AG7** | The cordis approval harness and its evaluation set; per-cell enablement in the runner config | The harness scores at least the agreed bar on held-out diffs; enabling it for one cell auto-applies there and nowhere else |

## 14. Open questions

1. `needs_input`: route a harness's question to the cell (a new attempt with the answer), or hold the VM
   suspended for an answer (SR2 snapshot)? The draft proposes a new attempt, which keeps VMs short-lived.
2. Where workspace versions live when the VM is on the Halo:
   - the Halo's pool, with `zfs send` to the NUC for retention and other nodes;
   - or the NUC's, with the zvol sent to the Halo per task.

   The draft proposes the Halo's, since the VM and the zvol must be co-located.
3. A deadline for `ReadWrite` results: an approval card's expiry vs the result's retention. The draft proposes
   retention until acknowledged, as for every operation, with the card expiring sooner.
4. Concurrency on the Halo: how many agent VMs beside halo_serve. Each VM costs 1-2 GiB and CPU in `yard.slice`;
   the GPU is shared through halo's scheduler, where an agent's model calls are ordinary requests under the task's
   principal (G3 fairness applies).
