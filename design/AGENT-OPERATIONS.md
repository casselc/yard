# Agent operations: Cordis delegating to coding agents through yard (draft, revision 2.2, 2026-10-13)

Status: **draft, revision 2.2**. This is yard's half; Cordis RFC 0008 (revision 3, `casselc/jolt-sim`) is Cordis's
half, and the two use one vocabulary. It extends Cordis RFC 0007
("Boundaries, and the inference operation contract") from inference to coding agents.
- The sandbox choice is `design/SANDBOX-LINUX.md`.
- The models are `spec/agentop/`.
- The private notes this draws on (HARNESS, IDENTITY, WARDEN, A2A-MCP, TRAINING-DATA) are cited by name.

**The goal of the first milestone is one reliable review operation**, with clear authority, recovery and
accounting. It is not a general agent platform. Writers, approved apply, cloud routes, other harnesses and
delegation come after it, in that order (section 16).

Revision 2 answers a review of revision 1; section 18 lists what changed. The architecture is unchanged:
- Yard executes agents in Firecracker.
- Each agent's outbox manages durable operations.
- Cordis coordinates workflows.
- Halo supplies local inference.

## 0. Decisions (user, 2026-10-12)

1. **Models:** the local Halo model first (Claude Code against halo-flash's `/v1/messages` through the broker),
   then the **brokered Anthropic API**. Keys stay in the broker.
2. **Applying an agent's change always needs the user's approval.** That holds until a Cordis approval harness
   exists and is tested. Automated approval can then be enabled and configured **cell by cell**.
3. **Sandboxes: Firecracker, with no bwrap or Landlock stopgap.**
   - Agent tasks run in Firecracker microVMs on the Halo (yard-node; HARNESS SR2, P0-2 spike done). That is the
     first backend and the default.
   - **NUC jails stay on the roadmap** as a second backend behind the same executor interface: capacity, and
     distance from the GPU box (`design/SANDBOX-LINUX.md`, option E).

## 1. What this is

A Cordis cell hands work to a coding agent as a typed, budgeted, recoverable **operation**, as it hands a
completion to Halo. The first is "review this change against this commit and return structured findings". The
workflow sees a typed outcome, its cost and how certain that cost is, and references to the evidence. It never
sees a process, a socket or a credential.

```
cordis cell ── effect agent.run ──► outbox ── RFC 0007 envelope, api "agent" ──► yard-ctl (durable stages)
                                                                                   │ allocation a (never reused)
                                     yard-node (Halo) ◄── start / stop / observe ──┘
                                     └ Firecracker VM a: harness driver (claude first)
                                         └ vsock ─► host socket for a ─► broker (scope bound to a)
                                                                           ├─► halo /v1/operations (local)
                                                                           └─► Anthropic (later, key injected)
                                     input: read-only image of a commit; writers (later): a clone → a candidate
```

## 2. Owners

| Owner | Authoritative for | Not |
|---|---|---|
| **Cordis** (workflow) | The cell's intent; whether an outcome satisfies the task (acceptance); which artifacts the workflow still needs; which approved candidates to apply | Credentials, sandboxes, model routing, prices |
| **outbox** (per agent) | The shared envelope: attempts, exact submission, polling, durable capture, commit before ack. The yard adapter interprets agent outcomes | What the agent did inside |
| **yard-ctl** (executor) | The attempt's durable stages and their resolution; allocations and their fencing; structural validation of the output; the terminal outcome | The workflow's meaning of the result |
| **yard-node** (Halo) | The VM table by allocation id; starting, stopping, reaping; tombstones | Policy |
| **broker** | Routing, credential injection, the **reservation ledger**, the per-attempt limits, scopes bound to allocations | Task outcomes |
| **artifact store** (yard) | Artifacts by digest, their leases and retention, explicit unavailability | |
| **approvals** (yard, WARDEN's page) | Approval records bound to a candidate's digest and base, with expiry | Applying |
| **the operator** (runner configuration) | Which agents, routes and limits a cell may use; **valuations (prices)**; write access; automated approval per cell | |

## 3. The operation envelope and the executor adapters

**Shared** with Halo's operations (RFC 0007, unchanged):
- identity: owner (the principal), operation id, attempt;
- exact submission: the digest of the submit body's bytes, the deadline, the incarnation;
- polling: status and result by identity;
- durable capture: the outbox commits the receipt before it acknowledges;
- acknowledgement: the executor releases the operation record after the ack.

**Not shared.** Each executor has an adapter, on both sides, for:
- status interpretation: the executor-specific outcome is carried inside `done`, not as new envelope statuses;
- charging: Halo's usage is exact tokens and engine time; an agent attempt's is per-dimension, with a certainty;
- result decoding: Halo returns an API's final object; yard returns an outcome with artifact references;
- artifact handling: Halo has none beyond the body; yard's artifacts outlive the operation (section 8).

Revision 1 added `failed` and `needs_input` to the envelope's statuses. Revision 2 adds none:
- a lost worker is an outcome inside `done`;
- `needs_input` is deferred (section 12).

**Yard's contract** is `GET /v1/yard/contract`, in the same shape as Halo's. It gives:
- the incarnation;
- the record limits;
- the valuations currently offered (id and digest);
- the agents and routes the asking principal may use, and its ceilings.

**The incarnation.** It is yard-ctl's durable store epoch. A yard-ctl restart keeps it. Losing the store changes
it, and then RFC 0007's `unknown` applies.

**Yard-Time, the deadline clock.** Halo's deadlines are in its monotonic clock, which resets only together with
its incarnation, so a reset clock always comes with an incarnation that refuses every old copy. Yard keeps its
incarnation across a restart, so it cannot use the process clock. Deadlines (`not_after`) and every `Yard-Time`
header are in a **persistent logical clock** instead:
- **It never repeats or goes backwards.** yard-ctl persists a **ceiling**, durably, ahead of the times it hands
  out (10 s ahead), and advances it before Yard-Time would pass it.
- **After a restart it resumes at the ceiling.** Real time that passed since the ceiling was written (by the wall
  clock) is added when that is positive, and never subtracted. A clock that steps backwards only pauses Yard-Time,
  which delays expiry and never brings it early.
- **Tombstones stay safe.** A record or tombstone is pruned only when Yard-Time is past its `not_after` and its
  outcome is acknowledged. Since Yard-Time never returns to a time it handed out, a late copy of a pruned attempt is
  always refused as late. It is never accepted again.

`spec/agentop/clock.qnt` models this, with a restart close to the deadline. AG2 tests a restart just before a
deadline, and just after it.

That is **not the only uncertainty**. Uncertain cost (section 6) and uncertain execution (section 5) are
reported inside known outcomes.

## 4. Submission and outcomes

**Refusal is reserved for submissions that were not executed.** A refused submit costs nothing and closes only
its copy (RFC 0007). The reasons:
- `capacity`, with a retry-after;
- `not_permitted`: the cell, agent, route or limits exceed the runner configuration;
- `invalid_task`;
- `valuation_changed` (409);
- `limits_missing`: tokens, charge, money and seconds are each required;
- `input_unavailable`.

A refusal closes **that copy**, not the attempt. `never_accepted` means "not accepted yet": a delayed copy of the
submit may still arrive and be accepted before the deadline. Only an authoritative terminal answer releases the
attempt's identity and its reservation:
- `done`;
- `cancelled_before_accept`, an acknowledged cancellation;
- `closed`, the deadline passed in Yard-Time.

**An accepted attempt ends in a typed terminal outcome.** Every one of them can have cost something:

| Outcome | Meaning |
|---|---|
| `completed` | The harness finished and its output **passed structural validation** against the task's schema. The value (the findings) is carried in the receipt itself, so guards that examine only the findings do not depend on artifact leases. Acceptance that checks the transcript or other evidence needs those artifacts held (section 8) |
| `insufficient` | The harness finished and said it cannot do the task with what it has; its questions are data (no resumption, section 12) |
| `invalid_output` | The harness finished; its output failed structural validation. **The raw output and the errors are kept** |
| `budget_exhausted` | The broker refused a call at a limit (`tokens` or `money`), and the harness stopped |
| `timeout` | The task's wall-time limit passed; yard-ctl stopped the worker |
| `cancelled` | The cancel verb; yard-ctl stopped the worker |
| `worker_failed` | The VM died, yard-node became unreachable and the worker was fenced, or a capture step failed (the artifacts it could not capture are listed as unavailable) |

Every terminal outcome carries the same three fields:
- **`execution`:**
  - `stopped` means yard-node confirmed that the worker's process is gone.
  - `unconfirmed` means the worker could not be confirmed stopped (it was fenced, section 5). Its broker access is
    revoked and its result is not captured. If yard-node later confirms that the worker stopped, yard appends an
    **execution correction** (below). The receipt itself never changes.
- **`spend`:** the one charge representation (wire fields below).
  - `exact`: every model call's usage was confirmed, by its answer or by halo's record.
  - `bounded`: at least one call is unresolved. It is charged at its reserved maximum, so the true cost is at most
    the charge.

**The spend object**, the one representation the adapter reads. Every amount is an integer, and every pair is
`{ "confirmed": n, "unresolved_max": n }`, whose sum is what is charged:

```
"spend": {
  "valuation":   "<price table digest>",
  "certainty":   "exact" | "bounded",
  "charge":      { "confirmed": n, "unresolved_max": n },   // valuation units: what Cordis settles
  "money_micro_usd": { "confirmed": n, "unresolved_max": n }, // actual financial cost (provider routes only)
  "tokens": {
    "input":       { ... },   // prompt tokens not read from a cache
    "cache_read":  { ... },   // prompt tokens served from a cache (halo's prefix cache, the provider's cache)
    "cache_write": { ... },   // prompt tokens written to a provider cache
    "output":      { ... }
  },
  "engine_ms":   n,           // halo engine time, reported for observability, not charged
  "wall_s":      n
}
```

**What is counted:**
- **The token limit** counts all four classes. A cached token is processed context too, and it bounds the work.
- **`charge`** is each call's tokens times its class price under the pinned valuation, rounded up per call, then
  summed.
- **Engine time is not charged** in this revision. A valuation that later prices it must add it to `charge` and to
  the reservation's maximum together.
- **`money_micro_usd`** is non-zero only for provider routes.

**Execution corrections.** A receipt, once captured and acknowledged, is immutable. Later evidence about an attempt
is **appended** instead:
- `GET /v1/yard/corrections?after=<seq>` is an append-only log, with a sequence number per entry and retention
  like a record's;
- an entry is `{ seq, owner, operation_id, attempt, kind, evidence, at }`;
- the kind is `execution_stopped` for now. A later spend reconciliation (open question 2) would be another kind.

Cordis reads the log after its last sequence number and records each entry as a fact beside the receipt. It never
rewrites the receipt.

**The outcome is final, and `done` is reported, only after** the worker is stopped or fenced, the broker has
confirmed the scope revoked, and each unresolved local call has either been resolved from halo's record or found
unresolvable (section 6). The report never waits for exactness. If the broker
cannot be reached to revoke, the operation stays `running`, marked `degraded`, and its reservation holds. At the
operation's deadline it is `unknown`, settled at the whole reservation.

**Partial artifacts come with every outcome that has them:**
- the transcript;
- the raw final output;
- the candidate (writers only, and only from a stopped worker);
- the evidence bundle: broker ledger rows, the VM console, the input commit, the image and harness version.

**Completion is not acceptance.** Yard validates **structure**: the output parses and matches the schema. Whether
the result satisfies the task is Cordis's decision. For example, Cordis can require that every finding cites a
file and line that exist in the reviewed commit.

Yard does not retry inside validation. The harness may correct itself during its own run, and those tokens are
metered like any others. A **repair** is an explicit new attempt, submitted by Cordis with the invalid output and
the validation errors, under its own budget.

## 5. Yard-ctl's recovery protocol

Several steps are not one transaction, because each has its own party:
- accepting the task;
- starting the worker;
- activating the scope;
- capturing the result;
- stopping the worker;
- revoking the scope.

yard-ctl keeps **a durable stage per attempt** (SQLite, WAL, synchronous). Each step is written before it is
attempted, and each is resolved by an observation, never by assumption.

**Allocations.** Every start of a worker has an **allocation id**: 128 random bits, written before anything
external happens, never reused. Everything about that worker is keyed by it:
- the broker scope;
- the host-side vsock socket;
- the zvol clone and snapshot names;
- yard-node's VM table row;
- the console log.

| Stage | Written before | Resolving observation | After a yard-ctl restart |
|---|---|---|---|
| `accepted` | The row: digest, deadline, limits, pinned valuation, the input artifact's lease | — | continue |
| `allocating` | The allocation id; then the broker scope bound to it; then the start request | yard-node's VM table by allocation: `running`, `exited(reason)` or `absent` (yard-node keeps exit records until yard-ctl clears them) | query; resolve as below |
| `started` | — (the observation moves it here) | the VM table; the guest's finish message (to yard-node, which records it) | query; re-adopt if running |
| `capturing` | The capture intent | Stop is confirmed (yard-node reaped the Firecracker process via its pidfd); the snapshot exists (named by allocation); artifact rows with digests | redo idempotently: each step checks its named result first |
| `ending` | The revocation request; the outcome | the broker's scope table (revoked); the ledger has no `sent` row for the attempt | resend the revocation; resolve local calls |
| `ended` | — | — | report `done` |

**Fencing rules:**
- **F1.** Allocation ids are never reused, and every resource is named by one.
- **F2. The broker scope is bound to the allocation, not to the vsock CID.** Firecracker's vsock is a per-VM
  device backed by a host Unix socket, and a guest CID identifies nothing on the host: every VM may use CID 3.
  yard-node creates a host socket per allocation, and the broker's forwarder on that socket serves that allocation
  only. A call is charged to the attempt the allocation belongs to. When the allocation ends, the socket is
  unlinked and the scope revoked.
- **F3.** Before an attempt allocates again (a start that is `absent` past the start bound), its old allocation is
  **tombstoned** at yard-node, so a late start request for it is refused, and its scope is revoked. Tombstones are
  durable at yard-node: it reloads them before it serves a start after its own restart. An attempt
  allocates again at most once. A worker that never started has spent nothing.
- **F4. An unreachable worker is not a stopped worker.** If yard-node is unreachable past the bound:
  - yard-ctl revokes the allocation's scope and owes yard-node a tombstone;
  - the attempt ends `worker_failed` with execution `unconfirmed`;
  - the VM's memory and CPU stay counted against capacity until yard-node confirms it gone. On reconnect, yard-node
    kills it, and yard appends an `execution_stopped` correction (section 4). The receipt is unchanged.
- **F5.** Nothing is captured from a worker that is not confirmed stopped, or from an allocation that is not the
  attempt's current one. A late finish message from a fenced allocation is kept as evidence and never becomes the
  result.
- **F6.** The accounting is final only after the broker confirms the revocation (section 4).
- **F7.** yard-node reconciles on start and on reconnect: it kills any VM whose allocation yard-ctl does not list
  as current.
- **F8. A watchdog bounds a lost worker's life.** Each allocation has a lease that yard-ctl renews. If the lease
  expires (yard-ctl cannot reach the node), yard-node stops the VM itself. This holds even while nothing reaches the
  node.

**Cancel and the time limit.** yard-ctl stops the worker (stop, then reap), then captures and ends. A worker that
cannot be stopped because its node is unreachable is fenced (F4), and the watchdog (F8) stops it.

## 6. The broker: valuation, limits and reservations

**Valuation is the operator's.** A valuation is a versioned price table, in integer **valuation units** per token
class per route:
- On a provider route, one unit is one µUSD of actual cost. The charge equals the money spent.
- On the local route, the price is a **resource valuation**: a nominal charge for the Halo's capacity, set by the
  operator. It is not financial spending, and `money_micro_usd` stays 0. It lives in the runner configuration with
the broker, outside the graph and the mutation protocol.

The agent (through its graph) can choose among the routes it is permitted, set limits **at or below** its
ceilings, and choose retry strategies. It cannot create or change a valuation.

The valuation is identified by the digest of its price table, published in yard's contract. The outbox reads it
and sends it with the submit; the cell never names it. yard-ctl **pins** it for the attempt. A submit made with a
stale valuation is refused with `409 valuation_changed` (not executed), and the outbox re-reads the contract. Every
reservation and every settlement of that attempt uses the pinned valuation. A price change applies to later attempts
only.

**Cordis budgets in valuation units.** It reserves the task's `charge` limit, and settles at `spend.charge`.
Because every route has a non-zero price, a local review consumes the workflow's budget like any other.

**Four limits, each enforced on its own, each with a mandatory operator ceiling:**
- **`tokens`:** all four classes, counted by the broker;
- **`charge`:** valuation units under the pinned valuation, counted by the broker. This is Cordis's reservation;
- **`money_micro_usd`:** actual financial spend on provider routes, counted by the broker. It is a separate cap,
  so a cheap-looking valuation can never authorise real spending past it;
- **`seconds`:** wall time, enforced by yard-ctl.

`broker.qnt`'s money dimension stands for any priced dimension: `charge` and `money_micro_usd` are both enforced as
it is.

**Reserve, send, settle.** The ledger is SQLite (WAL, synchronous=FULL), one row per model call.

1. **Reserve.** In one immediate transaction:
   - compute the call's **maximum cost**:
     - an input bound;
     - the output cap: the broker sets `max_tokens` to what fits, or refuses;
     - the most expensive input class (a cache write costs more than plain input);
     - all of it priced under the pinned valuation, rounded up;
   - check that everything already held for the attempt, plus this maximum, fits **each** limit. "Everything held"
     is confirmed usage, unresolved maxima and open reservations;
   - insert the row as `reserved`.

   Concurrent calls of one attempt serialize on this transaction, so together they cannot pass a limit.
2. **Send** only after that commit. The row becomes `sent`.
3. **Settle** on the answer. Confirmed usage is priced under the pinned valuation, and the rest of the reservation
   is released.
4. **No answer:** a timeout, a dropped connection or a provider error without usage. The row becomes
   `unresolved`, **charged at its maximum**. The broker never resends a call; a retry by the harness is a new call
   with a new reservation.
5. **A broker crash.** On restart, every `reserved` or `sent` row is `unresolved`, because its connection is gone.
   - A `reserved` row was never sent, but the broker cannot know that across the crash, so it is charged too.
   - The broker serves no call for an attempt until its rows are recovered.

**Input bounds:**
- **Local route:** the exact count from Halo's `POST /v1/messages/count_tokens`, which accepts Claude Code's full
  request body and agrees with the generation's prompt count (`design/AG1.md`).
- **Provider route:** the provider's count endpoint where one exists. Otherwise the request's byte length, which
  bounds the token count for a byte-level tokenizer. AG6 verifies that bound against the provider's counts before
  any money limit relies on it.

**The local route resolves its lost answers, while Halo keeps them.** The broker submits each local call to Halo as
an **RFC 0007 operation**, with the call's ledger id as the operation id. It relays the operation's observation
stream to the harness as the Messages stream. After a lost connection or a broker crash, Halo's status and result
answer it: Halo keeps the usage until the broker acknowledges, which it does after committing the settlement.

**Halo's records are not durable.** They live as long as its incarnation, so a lost local call is unresolvable when:
- Halo restarted before the broker captured the usage (a new incarnation: the old operation is `unknown`);
- the operation's deadline passed;
- Halo says `never_accepted` and the deadline has passed.

The call then **keeps its reserved maximum**, as a provider call does, and the attempt is `bounded`. A local review
can therefore end `bounded`. The broker never waits for exactness: once nothing is in flight, the attempt reports
with what it has (`broker.qnt`'s `neverStuck`; mutant `awaitExactLocal`).

A provider call that lost its answer stays `unresolved`, and the attempt is `bounded`. Reconciling against the
provider's usage reports later is open question 2.

**Certainty** is reported, never assumed. `exact` is reported only when no row of the attempt is `unresolved`.

## 7. Workspaces, candidates, approval and apply (writers; after the first milestone)

**Inputs are commits.** Yard's repository registry is bare git repositories on the Halo's ZFS pool.

A task names a commit. A trusted builder turns the commit's tree into an **ext4 input image**, once per commit,
and caches it under its id. Readers attach it read-only. A writer gets a zvol clone of the image's snapshot.

**The diff is not `zfs diff`.** The guest filesystem lives inside a zvol, a block device, so ZFS sees changed
blocks, not files. Mounting a guest-written filesystem on the host kernel would also expose the host to a crafted
filesystem image. The trusted comparison runs in a **differ VM**, which is:
- built from yard's image: read-only rootfs, no network, no broker;
- given the base image read-only, and a throwaway clone of the result snapshot, so a dirty journal can be
  recovered without touching the snapshot.

It walks both trees with `lstat` and never follows a link. It emits a sorted **manifest** for each tree: path,
kind, mode, size, SHA-256, link target. From the manifests it emits:
- the **diff**: additions, deletions, mode changes, symlink changes, content changes with text diffs, binary
  changes marked;
- the **candidate commit**: the result tree as a git commit whose parent is the base commit, exported as a pack.

The policy refuses (as an explicit difference in the diff) device nodes, FIFOs, sockets, hard links, `.git`
changes, and mode bits git cannot represent (setuid, or anything but 644, 755 and links). yard-ctl verifies the
pack with git's strict object checks and stores the candidate in the artifact store.

**Approval waits outside any operation:**
1. `agent.run` (a writer) ends `completed` with a candidate: commit id, base commit, diff digest.
2. **`approval.request`** is short and keyed. It creates a durable **approval record**, bound to:
   - the candidate commit and the base commit;
   - the diff digest;
   - the target ref and the cell;
   - an expiry.

   The record holds a lease on the candidate's artifacts. The card shows the differ's diff, never the agent's
   description of it.
3. The decision reaches the workflow as an input, like any outside event. It can also be read from the approval's
   status (`pending`, `approved`, `denied`, `expired`, `revoked`). No operation is running while a person decides.
4. **`workspace.apply(approval)`** is a short compare-and-set operation. **When it runs**, it checks that:
   - the approval is approved, unexpired and not revoked;
   - the cell still has the authority to apply to the target, from the runner configuration at that moment;
   - the candidate's artifacts are available;
   - the target ref is still at the base.

   It then moves the ref to the candidate commit (a fast-forward).

   Its outcomes are `applied`, `conflict`, `refused` (with the reason) and `artifact_unavailable`. A repeat of an
   applied approval answers `applied`.

**Automated approval, later (AG8).** A Cordis approval harness is a Cordis workflow (critics, tests in their own
agent tasks, deciders) whose decision is a recorded fact. Once it passes its evaluation set, the runner
configuration may enable it for a named cell, within that cell's limits. Every other cell, and anything the policy
marks sensitive, keeps the card.

## 8. Artifacts and retention

**Acknowledging an operation releases the operation's record, not its artifacts.**

An artifact has these fields:
- a digest;
- a kind: input image, transcript, raw output, candidate, evidence bundle;
- who produced it;
- a retention floor;
- **leases**.

A lease is (holder, until). The holders are:
- the operation attempt, until it is acknowledged;
- the workflow that received the receipt, which renews and releases its lease explicitly;
- an approval record, until it is decided and either applied or expired;
- the training-data store, when the run class captures it.

Leases are managed with `POST /v1/artifacts/{id}/leases` and `DELETE /v1/artifacts/{id}/leases/{holder}`. Retention
removes an artifact only when no lease holds it and its floor has passed. What remains is a tombstone: digest,
kind and deletion time.

**Unavailability is explicit.** Fetching a removed artifact answers `410 artifact_unavailable` with its tombstone.
An apply or a review step that needs it fails with `artifact_unavailable`, and never proceeds as if it were empty.

## 9. The first task: a read-only Claude review against Halo

| | |
|---|---|
| Input | One commit's tree **with the change applied**, as a read-only input image (`is_read_only` drive, mounted `ro,nodev,nosuid,noexec`), with the diff beside it in `.yard-review/change.diff`, so every finding cites a line that exists in the reviewed tree |
| Harness | Claude Code in print mode with stream-JSON output, as an unprivileged user in the guest |
| Tools | Read, Grep and Glob only (`--tools`). `--restricted` removes command-running tools and ignores user, project and local settings files. `--safe-mode` disables CLAUDE.md, skills, hooks, MCP servers and custom agents. No Task tool is offered, so no **native subagent** can run. `--bare` is not used: its simple mode drops Grep and Glob (AG1) |
| Output | `--json-schema` with `Review = { verdict, findings[{file, line, severity, note}] }` or `InsufficientInformation = { questions }` |
| Route | Broker → Halo `/v1/operations` with `api: "messages"` (section 6) |
| Limits | tokens, money (0 on the local route, still enforced), wall time. VM: 2 vCPU, 2 GiB, tmpfs home, the vsock socket only |
| Evidence | transcript, raw output, validation result, ledger rows, console, input commit, image and harness digests, all leased |
| Cancel, recovery | sections 4 and 5; the fault probe of AG2 |

Cordis connects to this task (AG3) before anything else is added.

## 10. Performance: what to measure first

VM boot is 126 ms (P0-2), which is small next to a review's minutes, so it is not a target. AG1 measures:
1. **Sharing immutable inputs.** One image per commit for every reviewer, so the host page cache is shared. Measure
   the build time per commit and the memory per extra reviewer.
2. **Stable prompt prefixes.** Halo's prefix cache serves repeated prefixes, so order what the model reads from
   stable to variable:
   - the harness's system prompt and tool definitions (fixed per version);
   - the review rubric;
   - the change;
   - the reviewer's role.

   Measure `cached_tokens` per call, and time to first token, for one reviewer and for a fan-out of three.
3. **Harness startup.** The interval from the VM being ready to the first model call: Node and Claude Code's own
   start. A Firecracker snapshot of a warmed guest is the remedy if it dominates, and only then.
4. **Interference with Halo.** Run halo-flash's decode and prefill benchmarks with 0, 1, 2 and 4 review VMs active.
   Report tok/s, TTFT, CPU contention and memory.
   - The VMs draw on the same 128 GB unified memory as the weights. `yard.slice`'s memory and CPU caps, and the VM
     count, come from these numbers.
   - The ZFS ARC competes with page cache, and the n-gram reads live on `/data`, so storage is measured too.

## 11. Identity

- **The attempt runs as a yard session:** an STS token with `sub` = the user and `act` = the sandbox session, and
  the submitting Cordis principal inside it (IDENTITY's RFC 8693 shape).
- **The broker scope is minted per allocation** and revoked at the attempt's end (F2, F6).
- **The VM holds no credential.** It is identified by the host socket it reached the broker through.

## 12. Deferred: interactive continuation and native delegation

The first milestones run **non-interactive** tasks. A harness that needs more ends `insufficient`
with its questions, and Cordis decides what to do: answer them in a new attempt, or ask a person.

**Fan-out is Cordis's.** Several reviewers, a quorum, escalation and cross-review are cells and manifests
(RFC 0008). Inside the VM, the harness's own subagents are disabled.

These come later, each only with all of its semantics specified:
- **`needs_input` resumption:**
  - where the waiting state lives: a suspended VM or a new attempt;
  - what the wait costs against the limits;
  - how a cancel during the wait ends it;
  - how the answer is bound to the question.
- **Native delegation** (an agent calling another through `yard-relay` as an A2A edge, A2A-MCP):
  - the child's limits are carved durably from the parent's reservation;
  - the parent's cancel propagates to the child;
  - the child's artifacts are leased to the parent;
  - the child's outcome is reported into the parent's evidence;
  - the relay's ambiguity rows (R5, R9, R12, R15) map onto the outcomes of section 4.

## 13. Observability and training data

Every attempt is a run (TRAINING-DATA). It has one trace, with spans for:
- the stages;
- model calls, with their ledger ids;
- tool calls;
- validation;
- capture.

Content capture follows the run class.

The signals:
- Cordis's acceptance decision;
- for reviews, whether the verdict held up later;
- for writers (later), the approval decision and any edit before applying.

All are score facts, with supersede and retract.

## 14. Ambiguity register (agent-specific; the envelope's are RFC 0007's)

| # | Call | done / not done / unknown | Bound | Resolving observation | Rule | Mutant (model) |
|---|---|---|---|---|---|---|
| G1 | yard-ctl → yard-node: start allocation a | running / absent, exited / lost answer, late request | start bound | VM table by a | tombstone before allocating again (F3) | `restartStartsAgain` (executor) |
| G2 | broker → model: a call | answered / refused / no answer | call timeout | the ledger; Halo's operation status (local) | reserve the maximum durably first; hold it unanswered | `checkConfirmedOnly`, `volatileReserve`, `dropUnanswered` (broker) |
| G3 | yard-ctl → broker: revoke a's scope | revoked / — / not yet confirmed | resend until confirmed | the scope table | final only after confirmation (F6) | `endBeforeRevoke` (executor) |
| G4 | yard-ctl → yard-node: stop a | reaped / — / node unreachable | stop bound | VM table; pidfd | unreachable is `unconfirmed`, not `stopped` (F4, F8) | `unreachableIsStopped` (executor) |
| G5 | capture a's result | snapshot named a exists / — / partial | capture bound | the snapshot and artifact rows | only from a stopped, current allocation (F5) | `captureFromUnstopped` (executor) |
| G6 | approval | approved / denied, expired, revoked / pending | expiry | the approval record | checked again when apply runs | `expiryAtApproval`, `authorityAtRequest` (apply) |
| G7 | apply | ref moved / conflict, refused, unavailable / lost answer | apply bound | the target ref | compare-and-set on the approved base, the approved digest | `applyStaleBase`, `approvalByName` (apply) |
| G8 | artifact release | removed / held / — | — | lease rows | only with no lease; ack drops only its own | `ackReleasesArtifacts` (apply) |

## 15. The models (`spec/agentop/`)

**Scope:** what agents add beyond RFC 0007's envelope, whose models already cover delivery, identity, deadlines
and the handoff:
- halo `spec/operation`;
- Cordis `operation.qnt`, `capture.qnt` and `expiry.qnt`.

The models are sampled with `quint run` (`spec/agentop/run.sh`), never model-checked. Their results are
**evidence under each model's stated assumptions**, not proofs.

**`broker.qnt`: one attempt's accounting.**
- **Modelled:**
  - three concurrent calls;
  - token and money limits;
  - local and provider routes;
  - a provider that serves a call whether or not its answer returns;
  - lost answers;
  - two broker crashes;
  - local calls resolved from Halo's operation record;
  - Halo restarting during the broker's reconciliation, which loses those records.
- **Properties:**
  - `accounted`: real spend ≤ what the ledger holds, per dimension;
  - `withinTokens` and `withinMoney`: real spend within each limit, on its own;
  - `exactIsExact`;
  - `neverStuck`: an ended attempt with nothing in flight can always report.
- **Mutants:**
  - `checkConfirmedOnly`: admission ignores open reservations;
  - `volatileReserve`: the reservation is not durable before the send;
  - `dropUnanswered`;
  - `valuationFromGraph`: the agent zeroed the price;
  - `moneyOnly`: no separate token limit;
  - `claimExact`;
  - `awaitExactLocal`: the report waits for local calls to become exact, and stays stuck once Halo has lost them.
- **Assumes:** a call's real cost never exceeds its reserved maximum, which is the input bound's correctness.
  AG6 verifies that for the provider.

**`executor.qnt`: yard-ctl's recovery for two attempts.**
- **Modelled:**
  - delayed start requests;
  - starts observed as absent;
  - yard-node partitions with VMs still running;
  - delayed revocation;
  - workers that write after they finish;
  - every VM on CID 3;
  - yard-node's watchdog stopping a VM whose lease lapsed;
  - yard-node restarting: its VMs die with it, and start requests already in flight can still arrive.
- **Properties:**
  - `oneLive`;
  - `attributed`: a call is charged to its worker's attempt;
  - `noSpendAfterFinal`;
  - `stoppedIsStopped`;
  - `candidateStable`.
- **Mutants:**
  - `restartStartsAgain`: no tombstone;
  - `bindByCid`;
  - `unreachableIsStopped`;
  - `endBeforeRevoke`;
  - `captureFromUnstopped`;
  - `tombstoneVolatile`: yard-node's tombstones do not survive its restart. Added after yard-node's hegel-go test
    found exactly this in the code (a tombstone written under an id its recovery did not reload).
- **Assumes:** yard-ctl's store survives, so its restart is a stutter, and the broker applies revocations it
  receives (its crashes are `broker.qnt`'s).

**`clock.qnt`: Yard-Time across yard-ctl restarts.**
- **Modelled:**
  - one attempt with a deadline;
  - copies of its submit arriving at any time, late ones included;
  - its record pruned once past the deadline and acknowledged;
  - two restarts that keep the incarnation, one of them close to the deadline.
- **Properties:**
  - `runsOnce`;
  - `monotone`: Yard-Time never goes back below a time it handed out.
- **Mutants:**
  - `processClock`: a restart resumes at the process clock's zero;
  - `ceilingBehind`: the persisted ceiling lags the times handed out.

**`apply.qnt`: candidates, leases, approvals and apply.**
- **Modelled:**
  - two candidates, whose names can be repointed;
  - acknowledgement and workflow leases;
  - approvals with expiry;
  - the operator withdrawing authority;
  - three approval configurations: none enabled (today), enabled but untested, enabled and tested.
- **Properties:**
  - `approvedApplied`: approved, unexpired, authorised, that content;
  - `noLostUpdate`;
  - `appliedOnce`;
  - `noAutoUnlessConfigured`;
  - `neededPresent`.
- **Mutants:**
  - `applyWithoutApproval`;
  - `expiryAtApproval`;
  - `authorityAtRequest`;
  - `approvalByName`;
  - `applyStaleBase`;
  - `autoApproveUnconfigured`;
  - `ackReleasesArtifacts`;
  - `substituteEmpty`: a released candidate applied as empty content (with the ack releasing artifacts).

**`agentop.qnt`: revision 1's model, kept.** It holds under its own assumptions:
- atomic calls of known cost;
- a VM whose liveness yard-node always knows;
- a broker that never crashes;
- approval inside the apply.

Revision 2 does not rely on it.

**Results** (quint 0.32, seed 0x5eed, 10,000 samples × 40 steps; `spec/agentop/results.txt`):
- **The designs hold:** `bdesign`, `edesign`, and `adesign` in all three approval configurations. Revision 1's
  model holds in its three as well.
- **Each mutant breaks the property it names:** 7 in the broker, 6 in the executor, 2 in the clock, 8 in apply, and revision 1's 7.
- **Every witness is reached:**
  - concurrent calls in flight;
  - a bounded report and an exact one;
  - a local call resolved after a lost answer, and a local review ending `bounded` after a Halo restart;
  - a yard-ctl restart near the deadline, and a pruned attempt's late copy refused;
  - a provider serving after a broker crash;
  - a limit refusal;
  - a lost worker confirmed stopped;
  - a fenced worker still running whose calls are refused;
  - a fenced worker later confirmed stopped;
  - a re-allocation that completed;
  - a pending revocation;
  - a watchdog stopping a fenced worker;
  - apply, conflict, expired and unauthorised refusals, apply after acknowledgement, and an automated apply on the
    configured cell.

Deep runs and a second seed are in `results.txt`.

## 16. Milestones

| # | Work | Exit |
|---|---|---|
| **AG0** | This revision and the models | The designs hold; each mutant breaks its property; every witness is reached |
| **AG1** (Y1a) | The review task by hand on the Halo: the harness image (the P0-2 guest plus Node, Claude Code, ripgrep, git); the claude driver; input images per commit; the broker's ledger with reservations and the local route through Halo operations | The section 9 review runs in a VM against a fixture repository and returns a valid `Review`. Section 10's measurements are recorded. Disallowed tools are refused (verified in the transcript) |
| **AG2** (Y1a) | yard-ctl serves the envelope for `api: "agent"`: stages, allocations, fencing, outcomes with certainty, artifacts with leases | The fault probe passes at every stage: a lost start answer; a late start (a stale allocation); yard-node unreachable (SIGSTOP), then back; the watchdog's lease expiry; a killed VM; a yard-ctl restart at every stage; a cancel at every stage; a broker crash between reserve and send, and mid-call; a lost model answer; a Halo restart while the broker reconciles (the attempt ends `bounded`, never stuck); a yard-ctl restart just before and just after a deadline; a delayed revocation; an artifact read after its lease. Every outcome's certainty is true to the injected fault |
| **AG3** (Y1b) | Cordis: the envelope with a yard adapter; `agent.run` and the review cell (RFC 0008) | **The first deliverable:** a Cordis review workflow with the review cell, through the milestone's faults, with the evidence manifest |
| **AG4** | Writers: read-write clones, the differ VM, candidates | An implementer task returns a candidate whose diff shows modes, symlinks and deletions; the policy refusals fire on crafted trees |
| **AG5** | Approvals and apply | Approve then apply; deny, expire, withdrawn authority and a moved base each refuse; apply after the operation's acknowledgement still finds the candidate |
| **AG6** | The brokered Anthropic route: valuations in µUSD, the input bound verified against the provider's counts | The review on the Anthropic route, metered in µUSD; the money limit stops a runaway task; a lost answer is reported `bounded` |
| **AG7** | Codex and opencode drivers | The review runs on each through the same contract |
| **AG8** | The Cordis approval harness, its evaluation set, per-cell enablement | It scores at least the agreed bar on held-out diffs; enabling it for one cell auto-applies there and nowhere else |
| **AG9** | The NUC jail backend (SANDBOX-LINUX option E): its harness spikes, then AG2's probe on it | The review runs on either backend; placement is a per-task class |
| later | `needs_input` resumption; native delegation | With the semantics listed in section 12 |

## 17. Open questions

1. **The local route's resource valuation rates** per token class, which the operator sets (section 6).
2. **Reconciling bounded provider charges.** The provider's usage reports could later lower a `bounded` charge, as
   an explicit correction fact. Or the bound stands. The draft proposes that the bound stands until AG6 shows how
   often answers are lost.
3. **Where input images and candidates live.** The draft proposes the Halo's pool, with `zfs send` to the NUC for
   retention.
4. **Retention floors** per artifact kind and run class.
5. **VM concurrency beside `halo_serve`**, decided from AG1's measurements.
6. **The allocation lease and the stop bound:** how long a lost worker may live (F4, F8).

## 18. History

- **Revision 1 (2026-10-12):** first draft, with `agentop.qnt`.
- **Revision 2 (2026-10-13)** answers the review:
  1. Task status is separated from accounting certainty: `execution` and `accounting` on every outcome; fenced is
     not stopped; uncertainty is not limited to a store loss (sections 4, 5, 6).
  2. The broker reserves each call's maximum durably before sending it, serializes concurrent calls, holds
     unanswered calls at their maximum, and recovers from crashes. Local calls are resolved through Halo's
     operations (section 6).
  3. Valuation is the operator's, pinned per attempt. Tokens, money (integer µUSD) and time are enforced
     independently (section 6).
  4. Refusal is only for submissions that were not executed. Typed terminal outcomes carry usage and partial
     artifacts (section 4).
  5. yard-ctl has durable stages, resolving observations and fencing rules F1–F7. Scopes are bound to the
     allocation, not the CID (section 5).
  6. Artifacts have leases and retention, separate from the acknowledgement, and unavailability is explicit
     (section 8).
  7. The diff comes from a trusted differ VM over the actual trees, not `zfs diff` (section 7).
  8. Yard validates structure only. Cordis decides acceptance. A repair is an explicit, metered attempt (section 4).
  9. Approval waits outside any operation. Apply is a short compare-and-set that checks approval, expiry and
     authority when it runs (section 7).
  10. `needs_input` and native delegation are deferred, and `insufficient_information` is added (section 12).
  11. Only the envelope is shared. Status interpretation, charging, decoding and artifacts are adapters' (section 3).
  12. The models are extended, and revision 1's results are restated under their assumptions (section 15).
  13. The first milestone is one read-only Claude review against Halo, connected to Cordis (sections 9, 16).
  14. The performance work targets measured bottlenecks, not boot time (section 10).
- **Revision 2.1 (2026-10-13)** reconciles with the Cordis agent's yard draft (branch `design/agent-operations-r2`)
  and RFC 0008 revision 3:
  - It adopts their outcome vocabulary (`insufficient`, `timeout`, `worker_failed`, execution `unconfirmed`,
    `spend { certainty, charge }`).
  - It adopts these additions of theirs:
    - the valuation digest sent by the outbox, refused with `409 valuation_changed`;
    - µUSD as Cordis's unit;
    - findings carried in the receipt;
    - `degraded`, then `unknown` at the deadline, when revocation cannot be confirmed;
    - the node watchdog (F8);
    - the approval decision arriving as an input;
    - their fault list.
  - It keeps the per-allocation host socket in place of CID and tap attestation, and stop-before-capture.
- **Revision 2.2 (2026-10-13)** answers the second review:
  1. **Halo's records die with its incarnation.** A local call becomes unresolvable when Halo restarts before the
     broker captured it. It keeps its maximum, so a local review can end `bounded`, and the report never waits for
     exactness. `broker.qnt` models the Halo restart (mutant `awaitExactLocal`).
  2. **Refusals and `never_accepted` don't release the attempt.** A refusal closes only its copy, and
     `never_accepted` is not terminal. Only `done`, an acknowledged cancellation or `closed` releases the
     attempt's identity and reservation (section 4).
  3. **Yard-Time is a persistent logical clock** with a durable ceiling. It never goes backwards across a restart
     that keeps the incarnation, so tombstones are never pruned early or re-accepted. `clock.qnt` models it.
  4. **Pricing:**
     - charges are in valuation units, with a resource valuation for the local route (not financial spend);
     - there are four limits, `tokens`, `charge`, `money_micro_usd` and `seconds`;
     - Cordis reserves `charge`.
  5. **One spend object** on the wire, with token classes, how cached tokens count, and engine time reported but
     not charged.
  6. **Corrections:** the receipt is immutable. Later execution evidence is appended to a corrections log that Cordis
     reads.
  7. **Acceptance and leases:** acceptance that needs the transcript or other evidence depends on those artifacts'
     leases.
