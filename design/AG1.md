# AG1: the read-only review against Halo, by hand (results, 2026-10-13)

This is milestone AG1 of `design/AGENT-OPERATIONS.md`: section 9's review task run in a Firecracker VM against a
local `halo_serve`, through the broker's ledger, without yard-ctl. The code is on branch `ag1`:
- `internal/ledger`, `internal/haloop`, `internal/agentroute`;
- `internal/jsonshape`;
- `cmd/yard-guest`, `cmd/yard-review`;
- `ops/agent-image/build.sh`.

## What runs

```
yard-review (host)
  input image: the commit's tree with the change applied, plus .yard-review/change.diff  (ext4, read-only, cached)
  allocation a: v.sock_4000 -> agentroute (Messages endpoint for a alone) -> halo /v1/operations, api "messages"
                v.sock_5000 -> control: hello, task, result, ack
  firecracker --no-api: vmlinux 6.1, review-agent.ext4 (read-only root), the input image (read-only), vsock, no net
    yard-guest (PID 1): mounts, lo up, 127.0.0.1:4000 -> vsock 4000, runs the task as `agent`, result over vsock 5000
      claude -p <rubric> --restricted --safe-mode --strict-mcp-config --disable-slash-commands --tools Read,Grep,Glob
             --exclude-dynamic-system-prompt-sections --output-format stream-json --verbose --json-schema <Review>
             --model claude-sonnet-5-5 --no-session-persistence
  after the VM stops: revoke the route, resolve unresolved calls from halo's records, report the spend,
  validate the structured output (structure only), write the evidence
```

**What each call goes through:**
1. Halo's `count_tokens` gives the exact input bound.
2. The output is clamped to the per-call cap (16,384) and to what the limits leave.
3. The maximum is reserved in the ledger.
4. The call goes to Halo as one operation, and its observation stream is relayed.
5. It is settled at Halo's usage, then acknowledged.

## Results

| Run | Outcome | Spend | Calls | Wall | Notes |
|---|---|---|---|---|---|
| run-1 | completed | exact, 17,490 tokens (10,432 cache read) | 7 | 127 s | `--bare`: only Read was offered (see below) |
| run-2 | completed | exact, 34,025 tokens (24,896 cache read) | 7 | 128 s | `--safe-mode`: Glob, Grep, Read offered; used Read 6, Glob 2, Grep 1 |
| fan-out ×3 | completed ×3 | exact each: 45,757 / 37,195 / 36,744 tokens, 68–85% cache read | 9 / 7 / 8 | 286 / 286 / 224 s | three reviewers of one change at once |
| run-3 | completed | exact | 6 | 120 s | the change applied in the input (below); citations at 13 and 18 now exist in the reviewed tree |

**Findings.** Every run found the planted defects in the change:
- the inverted `clamp` (critical);
- the `last_n` off-by-one (major).

Every run also flagged the pre-existing `mean` defect (minor or info) and labelled it not introduced by the diff.

The harness's own usage report agreed with the broker's meter: 17,490 tokens in run-1. Its "cost" ($0.04, priced
as a cloud model) is meaningless for the local route, which is why settlement never reads it.

**Timings** (run-2; the others agree within 50 ms):

| Interval | ms |
|---|---|
| VM start → guest hello (boot, mounts, control) | 200 |
| guest hello → first model call (harness startup) | 720 |
| first model call → result | ~127,000 |
| VM exit → spend reported (revoke, resolve, report) | 2 |

So the VM boot (≈0.2 s) and the harness start (≈0.7 s) are under 1% of the review. The model is the wall time.

**VM cost** (fan-out): 2.2–2.4 s user plus 0.8 s system CPU per review, and 355–359 MiB peak RSS per VM. At that
CPU rate, P0-2's interference model puts the effect on decode near zero: about 0.48% per GB/s of CPU memory traffic,
and a review VM barely touches memory bandwidth.

**The interference to watch is host memory.** With the model loaded at a 128K context and three VMs running,
available memory fell to 26.5 GB, and 3.1 GB of swap was in use. VM count and `yard.slice`'s memory cap should be set
from this.

**Fan-out.**
- **Prediction:** each review takes 1.3–1.6× the single run's wall time, and the cache-read share stays near 70%.
- **Measured:** 1.75–2.2× per review (224–286 s against 128 s), and 68–85% read from the cache.
- **Aggregate:** three reviews in 286 s, against 384 s run one after another, which is 1.34× the throughput.

The wall-time prediction missed: Halo serves three concurrent sessions of this shape worse than assumed. Not
diagnosed yet.

## What AG1 changed in the design

- **`--bare` is not usable for the review.** Its simple mode keeps only the minimal tool set (Read, not Grep or
  Glob). The driver uses `--restricted` with `--safe-mode`:
  - **`--restricted`:** no command-running tools; no user, project or local settings files; file tools confined
    to the working directory.
  - **`--safe-mode`:** no CLAUDE.md, skills, hooks, MCP servers or custom agents.

  The offered tools are exactly Glob, Grep and Read (plus StructuredOutput). There is no Task tool, so no subagent can
  run.

  Two built-in plugins still load, one of which reads AGENTS.md. For a read-only review that is a prompt-injection
  surface inside the VM, not a way out of it.
- **Review the change applied.** With the base commit as the input, a defect in added code has no line to cite: in
  the fan-out, reviewers cited post-change lines that did not exist in their tree. The input image is now the
  commit with the change applied, and the diff is alongside it. So a Cordis acceptance guard can check every
  citation against the reviewed tree.
- **Halo already serves `POST /v1/messages/count_tokens`.** It accepts Claude Code's full request body and agrees
  with the generation's prompt count (321 and 321 in the probe).
- **Halo's `prompt_tokens` includes `cached_tokens`.** Its OPERATIONS.md called them disjoint; it is corrected in
  halo-flash 9cfe03b. The broker settles input = prompt − cached, cache read = cached. Cordis's halo adapter
  (prompt + completion) was already right.
- **Halo's `messages` operation streams Anthropic SSE frames** whatever `stream` the request carries. The result is
  the final Message, and the stream answers 410 after the ack.

## Tests and mutants

**Tests:**
- **`internal/ledger`:**
  - a hegel-go stateful test against a model: reserve, send, answer, lose, late serving, resolve, crash and
    recover, end, report, across two attempts and two routes;
  - a concurrent-reservation property;
  - rounding and pinning.

  Run under `-race`.
- **`internal/agentroute`:** a fake Halo with faults (a lost submit answer, a refused copy, a broken stream, a
  restart that loses the records, full-length output, the harness leaving) under a hegel-go property:
  - accounted;
  - within the token limit;
  - never stuck;
  - an exact report is exact;
  - every call resolves without a restart.

  Also: a budget refusal is not retryable, a refused copy settles at zero at once, and nothing runs after revoke.
- **`internal/jsonshape`:** valid reviews pass; each structural break is reported.

**Mutants:**
- `tools/ledger-mutants.sh`, 8 of 8 caught:
  - `checkConfirmedOnly`, `noRecover`, `dropUnanswered`, `moneyOnly`, `claimExact`;
  - `reserveCheapInput`: it first survived because the oracle shared the code's input pricing; the oracle now has
    its own;
  - `noRoundUp`, `reportInFlight`.
- `tools/route-mutants.sh`, 6 of 6 caught:
  - `lostIsFree`, `resolveUnknownFree`, `cachedTwice`;
  - `noCancelOnRefusal`: it first survived because the test's 2 s acceptance window closed the operation anyway; a
    60 s test now catches it;
  - `exhaustRetryable`;
  - `noClamp`: it first survived because nothing checked the token limit; that check is now part of the property.
  - Not listed: `revokeKeepsServing`, which is equivalent because Close cuts every connection and the ledger
    refuses an ended attempt.

## Not done in AG1

- yard-ctl's stages, allocations, fencing and the envelope (AG2).
- The fault probe through a real VM: a killed VM, an unreachable node, a broker crash mid-call. The route's faults are
  tested against the fake Halo only.
- A Halo restart during a real review (unit-tested only).
- The interference benchmark proper: Halo's decode and prefill benchmarks with 0, 1, 2 and 4 VMs, beyond the CPU and
  memory figures above.
- Diagnosing why the fan-out ran slower than predicted.
