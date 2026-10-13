# AG2: yard-agentd serves the envelope for api "agent" (results, 2026-10-13)

This is milestone AG2 of `design/AGENT-OPERATIONS.md`: the executor and the node, with durable stages, allocations,
fencing, outcomes with certainty, and artifacts under leases. It is shown against Halo and real Claude Code reviews
under every fault on the AG2 list. The code is on branch `ag1`.

## What runs

```
caller (the probe; later Cordis's outbox) ── envelope: Yard-Incarnation / Yard-Not-After / Yard-Digest ──► yard-agentd
yard-agentd: store (exec.db: records, artifacts, leases, corrections, Yard-Time), ledger.db, a broker route per
             allocation (in-process for now), stages accepted → allocating → started → capturing → ending → ended
   └ yard-node (Unix socket): VMs by allocation id; exit records and tombstones on disk; leases and a watchdog
        └ Firecracker VM: yard-guest → Claude Code (the AG1 review) → 127.0.0.1:4000 → the allocation's route
                                                                             └ halo /v1/operations (via its fault proxy)
```

**Components:**

| Component | What it is |
|---|---|
| `internal/agentexec` | the executor |
| `cmd/yard-agentd` | the executor's process |
| `internal/node` and `cmd/yard-node` | the node |
| `internal/yardtime` | Yard-Time |
| `internal/driver` | the Claude driver |
| `internal/fakehalo` | a fake Halo, for the tests |
| `tools/agent_fault_probe.py` | the live probe |
| `streams/AG/ag2_session.sh` | its session script (private) |

## Live results (`streams/AG/ag2/results.jsonl`)

| Scenario | Fault | Outcome | Execution | Spend | Notes |
|---|---|---|---|---|---|
| baseline | none | completed | stopped | exact | 126 s |
| agentd_crash | yard-agentd SIGKILLed while the worker runs, restarted | completed | stopped | exact | after the fix below; first run: invalid_output |
| node_outage | yard-node SIGSTOPped 20 s (unreachable bound 10 s), then SIGCONT | worker_failed | **unconfirmed** | exact | then an `execution_stopped` correction (the lease watchdog had stopped it); after the fix below |
| vm_killed | the VM's firecracker killed | worker_failed | stopped | exact | |
| cancel | the cancel verb | cancelled | stopped | exact | |
| timeout | a 45 s wall-time limit | timeout | stopped | exact | |
| halo_lost | one model call's answer lost at halo's proxy | completed | stopped | exact | the call resolved from halo's record |
| halo_restart | halo restarted (new incarnation) mid-review | completed | stopped | **bounded** | the lost call kept its maximum; nothing waited for exactness |

Every attempt was acknowledged, and the ack released its record. Acknowledged records past their deadline were pruned,
and their artifacts outlived them.

## Defects found, and fixed

**Found by the tests:**
- **yard-node lost a tombstone across a restart** (hegel-go stateful test). Recovery reloaded only ids of a
  valid shape, but the API accepted any id, so a late start ran after the restart. Ids are now validated where state
  is written.
  - The model never restarted the node, so it had assumed tombstones were durable. `executor.qnt` now restarts the
    node, with the mutant `tombstoneVolatile`.
- **Yard-Time jumped forward by its ceiling's lead on every restart** (executor property). A 2 s task limit was spent
  by one restart with a 10 s lead. The lead is now 1 s.

**Found live:**
- **`agentd_crash`: call ids collided after a broker restart.**
  - The restarted route counted calls from 1 again, and the ids collided with the ledger's rows.
  - The route answered the harness 403. Claude Code read that as an authentication failure and stopped.
  - The fix: call ids carry a per-route epoch, and yard's own errors answer 529 (retryable).
  - The probe had accepted `invalid_output` here and so passed the failure. It now requires `completed`.
- **`node_outage`: a frozen node went unnoticed.**
  - A frozen node hangs calls instead of refusing them, and the node client's 40 s timeout outlasted the 10 s bound,
    so the executor never fenced.
  - Every node call now has its own deadline inside the bound.
  - The test fake now hangs while unreachable, which reproduced the defect before the fix.

## Tests and mutants

**Tests:**
- **`internal/agentexec`:** an envelope test, plus a hegel-go property over a fake yard-node whose workers call the
  model through their allocation's socket. The faults: an executor crash, a node outage (hanging), lost and late
  starts, and cancels.
  - The property's checks:
    - every attempt ends;
    - one live worker per attempt;
    - a replaced allocation never runs;
    - no spend after done;
    - stopped means stopped;
    - outcomes match their workers;
    - spend is accounted, and exact when the report says so;
    - fenced workers are corrected.
  - Also `TestNodeOutageFences`.
- **`internal/node`:** a stateful test (start, possibly late; finish; stop; tombstone; leases; crash).
- **`internal/yardtime`:** a stateful test (elapse, wall-clock steps either way, restarts after downtime).

**Mutants**, through `tools/mutants.py`:
- agentexec: 12 of 12;
- node: 6 of 6;
- yardtime: 4 of 4;
- route: 6 of 6 plus 2 of 2;
- ledger: 8 of 8.

The tables explain the equivalent mutants.

## Not done in AG2

- **The broker route is in-process.** Its revocation is synchronous, and a crash of the executor is a crash of the
  broker. Folding it into yard-broker (B0) gives the separate-process revocation the model's `revoking` set
  describes.
- **yard-agentd is not yet yard-ctl.** Authentication is a single bearer key, and the principal header is trusted.
- **Node reconciliation (F7) is in the code but not exercised live.**
- **The workflow's lease renewal, and Cordis's side (AG3).**
