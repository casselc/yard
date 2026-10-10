# Guest resume duties (guest-resume branch, 2026-10-07)

What the in-guest agent does after its VM is restored from a snapshot, before the guest is safe to
use. This continues HARNESS.md "Milestones: suspend and resume": the SR2 guest agent "reconnects ...
using a resume epoch; steps the guest clock on resume". The code is `internal/guestagent`, used now by
the `sr3j-chan` agent role and later by yard-agent. The design was modelled first in
`spec/guestresume` (Quint).

## Facts it rests on

- With bhyve patch 0002 (in the bhyve that restores: SR3J's own build since 2026-10-08) and vmm patch
  0003 (the loaded module, variant p4), every restore writes a new VM generation ID
  and raises the ACPI notify. FreeBSD's vmgenc(4) (`sys/dev/vmgenc/vmgenc_acpi.c`) handles it in a
  taskqueue. It copies the ID into a **cached** guid (`sysctl dev.vmgenc.0.guid` reads that copy), mixes
  it into Fortuna pool 0 (`random_harvest_direct`, `RANDOM_PURE_VMGENID`, pool forced to 0 in
  `fortuna.c`), and sends devd `!system=ACPI subsystem=VMGenerationCounter`. If the notify is lost (a
  vmm without 0003), the sysctl keeps the old ID. Polling the sysctl therefore recovers a lost devd
  event, but not a lost notify.
- The kernel RNG gets the ID. Userland arc4random state in long-running processes is never reseeded,
  so a process that holds keys or nonce state from before the snapshot must be restarted or rekeyed.
- A restored guest's clock loses about 1.3 s per restore and does not advance across the downtime.
- On FreeBSD 15, each `write(2)` to `/dev/random` (`randomdev.c` `randomdev_accumulate`) is hashed, with
  two cycle counts, into 32 bytes. Those go **synchronously** (not through the harvest queue) as four
  8-byte events into the next four Fortuna pools, chosen by a static counter; each adds 12 bytes of
  accounting. Pool 0 is used at every reseed, pool k only at every 2^k-th. Nothing written reaches the
  generator until a reseed, and only a read reseeds: `random_fortuna_pre_read` (`fortuna.c`) runs at the
  start of every read and getrandom and reseeds iff pool 0 holds >= `kern.random.fortuna.minpoolsize`
  (64) bytes and more than 100 ms of `getsbinuptime()` passed since the last reseed. That clock is
  tick-granular (a FreeBSD VM guest runs at hz 100: `subr_param.c` HZ_VM). There is no reseed counter
  (only an SDT probe) and no "reseed now" path (`randomdev_ioctl` takes FIOASYNC/FIONBIO only).
  vmgenc's ID is 2 events, 24 bytes, in pool 0: it also waits for a reseed that needs 40 more bytes.
- Hence `ReseedPlan` (`resume.go`): 8(2T-1) writes with T = ceil(minpool/12) (88 for 64) put exactly
  2T-1 events in pool 0, and whatever other readers do, at least T of them are hashed into the
  generator by the time a read that starts more than 100 ms + 2 ticks after the last write (120 ms at
  hz 100) returns. If a reseed fell inside the writes, the events before it are in; if T or more came
  after it, pool 0 is full enough and that read (or an earlier reader's) takes them.
  `TestReseedPlanCoversInterleavings` checks this over every counter phase, pool-0 pre-fill and up to
  two foreign reseeds, and that 8 writes fewer would not be enough. Assumption: no other process writes
  `/dev/random` meanwhile (only `rc.d/random`, at boot and shutdown).

## Design

**Signals.** Two signals say "restored". Each crosses a boundary, so each can be lost, late or
duplicated (the modelling rule of observability `TEMPLATE.md`).

| Signal | Path | Lost | Late | Duplicated |
|---|---|---|---|---|
| VM generation | ACPI notify → vmgenc → devd socket (`WatchDevd`); 1 s sysctl poll; SIGUSR1; the exec gate's own sysctl read | the notify (no 0003): the sysctl never changes; a devd event: the poll catches it | taskqueue delay, ms | every poll, every gate read, SIGUSR1 |
| Host epoch | yard-ctl bumps it before resuming (SR0); every HELLO carries it | no host connects | the first HELLO arrives ~0.55 s after the restore starts | every stream reconnects with it; also **stale**: a HELLO queued in the snapshot's socket buffer arrives with the old epoch |

**Rule.** A run is keyed by (generation, epoch). A signal that equals the last run's key does nothing.
An epoch lower than the done epoch is stale and is ignored. Either signal alone starts a run:

| Arrives | What happens |
|---|---|
| generation first (the usual order) | The run starts at once and uses the first live host connection. Later HELLOs with the new epoch are no-ops: the host's answer reported that epoch, and it became part of the key. |
| epoch first | The run waits up to `Settle` (1 s) for the generation signal, then keys by whatever the sysctl says. |
| only the epoch (notify lost) | After `Settle`, the run is keyed (old generation, new epoch). The host bytes make the RNG fresh. The kernel's vmgenid mix did not happen. |
| only the generation (a clone made without yard-ctl, or a host that did not bump) | The run is keyed (new generation, same epoch). The exec gate reads the sysctl itself, so an exec that overtakes the devd event is still refused. |
| neither | Undetectable. The model shows this as finding `notifyLostOnClone`. Assumption A1: a restore without an epoch bump happens only on a vmm whose notify is reliable (p4). |
| no host ever connects | The agent stays `resuming` and waits. Privileged work only comes over a host connection, so nothing is accepted. Key-holding services keep running until a host appears (see decisions below). |

**A run** (`Resumer.runOnce`). Each step has a timeout and a recorded outcome: `done`, `notdone`,
`unknown` (it timed out and may still land) or `skip`.

0. Read the generation (sysctl), then read 8 bytes of `/dev/random` (`kr_pre`).
1. Exchange with a live host connection. TCP is tried before the UART, newest first.
   `RESUMEREQ{gen, seq}` gets `RESUMEANS{host rx/tx time, host epoch, 64 random bytes}`, answered by
   every host-side reader. An answer whose nonce does not match is dropped and counted as `stale`. The
   agent takes 4 samples and keeps the lowest-RTT one. A dead connection is skipped after 1 s.
2. (a) **Clock**: NTP offset θ = ((T1−t0)+(T2−t3))/2. The agent steps by θ with `settimeofday`; the error
   bound is RTT/2. (b) **Entropy**: at least 64 host bytes are written `ReseedPlan` times (88), then,
   more than 120 ms (the plan's gap, measured on the monotonic clock) after the last write returned,
   the verifying read `kr_post`. `done` only then; `notdone` (too few bytes, no reseed rule, a write
   failed) or `unknown` (the writes timed out, or the read failed). A run whose entropy is not `done`
   restarts nothing, completes no key, keeps the gate shut and is retried after `HostWait` (1 s).
   This is in addition to vmgenc's mix, not instead of it. Cost: ~10 ms more than the old 110 ms wait. (c) **Services**:
   `service X restart` for each name in `-resume-restart` (default none), each with a timeout (30 s). On
   timeout the agent kills the pid it recorded before the restart, and the outcome is `unknown`. `done`
   requires a new pid. (d) **Record** (`n`, generations, epochs, trigger, `kr_pre`/`kr_post`, the clock
   step/bound/RTT, entropy bytes/writes, each service's outcome and old/new pid, stale answers): sent to
   every live host connection (`RESUMEREC`) and included in every later WELCOME. The stream clients log
   each `n` once.
3. **Recheck.** The done key becomes the run's key: the generation read in step 0 and the epoch **from
   the host's answer**. The agent then re-reads the generation and compares the epochs seen during the
   run. Anything not covered starts the next run at once (trigger `recheck`).

**Gate.** `Allow()` reads the generation first, then refuses (`ErrResuming`; `sr3j-chan` EXEC rc 75)
unless the phase is `ready`. The phase becomes `ready` only when a run ends with nothing left to do.
Pings report the phase (WELCOME `state`, `resumes`, `resume`).

**The agent's own crypto state.** `sr3j-chan` has none: its tick `token` is an identity, and the e2e
checks that it survives. Go's `crypto/rand` calls `getrandom(2)` each time. `Config.SelfRekey` is the
hook for yard-agent's own keys and runs after the entropy step.

**Changed behaviour.** Until now `-stepclock` set the clock to the HELLO's `host_ns` on any HELLO more
than 1 s off. A HELLO from a restored socket buffer carries an old `host_ns`. `-stepclock` now enables
step (a) of the run instead.

## The Quint model (`spec/guestresume`)

`guestresume.qnt` holds the model and the scripted runs; `guestresumeTest.qnt` holds the design and one
instance per mutant; `run.sh` writes `results.txt`. The model uses quint 0.32 `run`/`test` only. It
includes the guest's memory being rewound by a restore (agent, services, RNG, cached guid), repeated
restores of one snapshot, stale HELLOs and answers, the request → effect → answer of the exchange and of
`service restart` (lost, late, duplicate), the Settle and service timeouts, and Fortuna: vmgenc's ID and
the host bytes wait in pool 0 until a reseed, any reader may reseed (`KernelReseed`) but not within
`RESEED_GAP` of the last one, the writes can fail or time out and land late (`EntLateEffect`), and the
agent's verifying read (`EntVerify`) comes `RESEED_GAP` after the writes.

Properties: **noStaleWork** (no exec accepted while the clock, the kernel RNG or a key-holding service
predates the restore), **atMostOncePerKey** (per VM instance), **recordHonest** (a record says `done`
only if the restart happened), **entropyHonest** (a record says entropy `done` only if the generator then
held the host bytes).

| Instance | Property | 20000 samples × 200 steps, seed 0x5eed |
|---|---|---|
| design | noStaleWork / atMostOncePerKey / recordHonest / entropyHonest | ok ×4; 13 witnesses each reached (0.1–100 %) |
| actOnlyOnEpoch (ignores the generation) | noStaleWork | VIOLATED (a clone) |
| actOnlyOnGen (ignores the epoch) | noStaleWork | VIOLATED (a lost notify) |
| epochNotMonotonic (any epoch ≠ done) | atMostOncePerKey | VIOLATED (a stale HELLO) |
| noDedupe | atMostOncePerKey | VIOLATED (a duplicate notify) |
| acceptWhileResuming | noStaleWork | VIOLATED |
| skipEntropy | noStaleWork | VIOLATED (with a lost notify) |
| servicesBeforeEntropy | noStaleWork | VIOLATED |
| staleReply (no nonce check) | noStaleWork | VIOLATED |
| clearOnComplete (end marks everything seen as done) | noStaleWork | VIOLATED |
| timeoutIgnored (old pid left running) | noStaleWork | VIOLATED |
| timeoutCountsDone | recordHonest | VIOLATED |
| keyFromSeen (key epoch = newest seen) | noStaleWork | VIOLATED (finding 2) |
| notifyLostOnClone (assumption A1 off) | noStaleWork | VIOLATED (the documented limit) |
| entropyDoneEarly (done right after the writes) | entropyHonest / noStaleWork | VIOLATED / VIOLATED (another reader had just reseeded) |
| entropyFailOpen (failed writes count as done) | noStaleWork | VIOLATED |

80 steps (until 2026-10-08) no longer found epochNotMonotonic: every run now needs a tick between the
writes and the verifying read, and the time bound (MAX_TIME 12, was 6) and trace length had to grow.

Scripted runs: 20 `*DesignTest` pass on the design, and each mutant's `*BreaksTest` passes on its own
instance (`run.sh` prints `failures: 0`).

The model produced two findings:

1. A snapshot taken during a run makes every clone finish that run again under its old key. The
   agent's memory is rewound and it cannot know. So "at most once per key" holds per VM instance, the
   recheck then runs the clone's own key, and the host sees the old key's record again and dedupes by
   `n`.
2. The first design keyed a run by the newest epoch seen. An answer from before a restore whose notify
   was lost then absorbed the new epoch and skipped the recheck, so a stale clock was accepted (20000 ×
   40). The key's epoch now comes from the host's answer (mutant `keyFromSeen`).

| Quint action | Go |
|---|---|
| `onGen` (DevdEvent, Poll) | `Resumer.ObserveGen` (`WatchDevd`, `-genpoll`, SIGUSR1, `Allow`) |
| `onEpoch` (Hello) | `Resumer.ObserveEpoch` (agent `serve`, HELLO) |
| `Work` | `Resumer.Allow` / `AllowEpoch` (agent `serve`, EXEC) |
| `RunStart` | `runOnce`: settle loop, `ReadGen`, `kr_pre`, nonce |
| `HostAnswer` | `conn.answerResume` (host reader) |
| `RunAnswer` | `runOnce`: `exchange` (nonce check, best RTT), clock, `entropy` writes |
| `EntVerify` | `entropy`: the gap wait and the verifying read; the gate on its outcome |
| `SvcEffect` / `SvcDone` / `SvcTimeout` | `restartAll` (`within`, `Services.Kill`) |
| `RunReport` | `runOnce`: done key, `report`, recheck |
| consts | the `rules` struct (`design` = all true) |

## Tests

- `internal/guestagent` uses fakes for the clock, sysctl, services and host, and a small Fortuna for the
  entropy (the write path and the reseed rule above; pool 0 starts full, so `kr_pre` reseeds and a read
  right after the writes cannot). Eleven scenarios (generation first plus duplicates, epoch first, lost
  notify, clone, stale HELLO, gate and order, stale answer, change during a run, answer epoch older, a
  failing write and its retry, service hang), the clock bound, host failover and short entropy (notdone,
  retried), waiting for a host, 16 concurrent signallers giving one run, `ReseedPlan`'s numbers and its
  interleaving check. `TestMutantsCaught` plants the model's 14 agent-side mutants through `rules`;
  each one fails at least one scenario (a service seeded before the reseed fails `fresh`). The suite is
  clean under `-race`.
- `cmd/sr3j-chan` `TestResumeOverUART` runs over the bounded-pipe UART with the credit window. It
  checks the exchange through the host reader, exec refused (rc 75) while resuming, the record frame,
  the clock within 0.1 s, and that duplicates start no run.
- `ops/sr3j/sr3j-20-e2e.sh` checks each restore and runs section 5b (repeated restores of one
  snapshot). The predictions are in its header (PREDICT "resume duties", "same snapshot").

## Run 20261008T012430Z (vmnet, p4 module): GATE FAIL, 13 resume mismatches, and why

- **No generation change on any restore** (10 rows: trigger epoch, gen 21aed969 → 21aed969 ×5): the e2e
  restored with `$SNAP/bhyve` = `/usr/local/yard/bhyve-snap/bhyve` for tap/vmnet/ngd
  (`sr3j-20-e2e.sh` NET case, `sr3j-lib.sh` SNAP). That bhyve has no 0002, so nothing wrote a new ID or
  raised the notify; SR3J's own bhyve had only the netgraph patch. Fixed: `sr3j-00-build.sh` applies SR3
  0001+0002 before its own patch, the e2e uses `$INST/bhyve` for every NET, refuses a BUILDINFO without
  the three patches, and refuses the base vmm when it restores.
- **Section 5b, epoch 5 → 6, gen/kr_pre/kr_post equal on 3 clones**: no clone ran at all. Without 0002
  the generation stayed, and 5b does not bump the epoch, so the agent stayed `ready`; the ping took the
  WELCOME's last record, which was restore 5's (n 5, epoch 5 → 6, its kr values), three times. A harness
  bug (it did not check that the record came from the clone), not an epoch bump, and the identical
  `kr_post` says nothing about random(4). Fixed: `client ping -resume-after N` waits for a record newer
  than N; 5b checks n = runs + 1, gen changed, epoch old = new = the epoch file, entropy done.
- The random(4) reading still changed the agent: the old 64 writes + 110 ms was right for the common
  case, but nothing checked the reseed rule's inputs (minpoolsize, hz) or the gap, and a failed entropy
  step still opened the gate. See ReseedPlan above.
- `start_to_tick` 0.550 vs 0.6..2: the tick is once a second, the range is now 0.5..2.

## Run (the user, on the NUC; the vmm must be the p4 module)

```sh
# Halo (after any SR1 deploy-nuc.sh: that copies all of ops/ from its worktree, including ops/sr3j):
tools/deploy-sr3j.sh
# NUC as chuck: rebuilds bhyve with SR3 0001+0002 + the netgraph patch (BUILDINFO patches=sr3/0001.. sr3/0002.. sr3j/0001..)
sh ~/yard/ops/sr3j/sr3j-00-build.sh
# NUC as root:
cd ~/yard/ops/sr3j && sudo sh sr3j-10-install.sh
kldstat -v | grep vmm.ko      # must be .../bhyve-snap-p4/vmm.ko (else: sudo env SR3_VARIANT=p4 sh ../sr3/sr3-20-vmm.sh)
sudo sh sr3j-20-e2e.sh        # vmnet, N=5, SR3J_SAME_K=3; re-bakes the guest image (agent2-*)
```

## Open, for the user to decide

- **Which services to restart by default.** The default is none. Candidates in a yard guest: sshd (it
  holds host keys and per-connection state, and restarting it drops sessions), ntpd if it runs (the
  clock step already covers time), and any harness daemon with long-lived TLS or session keys.
- **No host after a restore.** Should key-holding services be restarted after a grace period without
  the host bytes (kernel vmgenid mix only)? The agent does not do this now, because a restart before
  the bytes may seed from the cloned kernel RNG if pool 0 has not reseeded.
- **Clones outside yard-ctl on a vmm that loses notifies are undetectable** (assumption A1). Every
  platform restore must bump the epoch.
- A crash of the agent mid-run (daemon -r restarts it) has boot semantics: it adopts the current
  (generation, epoch) without a run. Persisting the done key would need a store that survives a restore
  correctly. The disk does not: it is not part of the snapshot.
