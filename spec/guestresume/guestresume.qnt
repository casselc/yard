// Guest resume duties: what the in-guest agent must do after its VM was restored from a snapshot,
// and when it may accept privileged work from the host again.
//
// The Go code is internal/guestagent (Resumer): every agent-side action below has a method or a step
// of Resumer.runOnce of the same name (docs/guest-resume.md has the mapping table).
//
// Two signals say "this guest was restored", and both cross a boundary that can lose, delay or
// duplicate them (casselc/observability otel-chdb/model/TEMPLATE.md):
//   - the VM generation: bhyve (patch 0002) writes a new ID and raises an ACPI notify. vmgenc(4)
//     processes it in a taskqueue: it updates the CACHED guid (sysctl dev.vmgenc.0.guid), mixes the ID
//     into Fortuna pool 0 (used only at the next reseed) and sends devd "VMGenerationCounter". A lost notify (vmm without patch 0003:
//     the SCI's Remote IRR stuck after the first one) leaves the sysctl at the old value -- polling it
//     cannot recover a lost notify, only a lost devd event (sys/dev/vmgenc/vmgenc_acpi.c).
//   - the resume epoch: yard-ctl bumps it before it resumes (SR0) and every HELLO carries it. HELLOs
//     can be lost, late, duplicated (every stream reconnects), and STALE: a HELLO queued in the
//     snapshot's socket buffers arrives after the restore with the old epoch.
// The actions need host inputs (time, entropy); the agent fetches them with a request/answer
// exchange (nonce = (generation, counter)) that has the same four failure modes, and restarts
// key-holding services with `service X restart`, a local call whose effect can land after its timeout.
//
// The kernel RNG (FreeBSD 15 Fortuna, sys/dev/random): bytes written to /dev/random and vmgenc's ID go
// into pool 0 at once, but reach the generator only at a reseed, which a read performs iff pool 0 is
// big enough and more than RESEED_GAP passed since the last reseed (random_fortuna_pre_read). The agent
// writes enough that pool 0 is big enough (internal/guestagent ReseedPlan), so only the time rule is
// modelled: any reader may reseed (KernelReseed); the agent's verifying read comes RESEED_GAP after its
// writes (VERIFY_RESEED). The writes can fail (notdone) or time out and land later (unknown).
//
// A restore rewinds everything in guest memory (the agent, the services, the kernel RNG, the cached
// guid) to the snapshot; the same snapshot can be restored many times (clones). Messages in flight and
// the host side are not rewound.
//
// Each design rule is a const; its unsafe choice is a named mutant instance in guestresumeTest.qnt.
module guestresume {
  // ------------------------------------------------------------------ rules (consts)
  const ACT_ON_GEN: bool           // a new VM generation starts a resume       (mutant actOnlyOnEpoch)
  const ACT_ON_EPOCH: bool         // a newer host epoch starts a resume         (mutant actOnlyOnGen)
  const EPOCH_MONOTONIC: bool      // only epoch > done counts; lower = stale    (mutant epochNotMonotonic)
  const DEDUPE: bool               // a signal equal to the done key is a no-op  (mutant noDedupe)
  const GATE_WORK: bool            // exec refused unless Ready                  (mutant acceptWhileResuming)
  const ADD_ENTROPY: bool          // host bytes written to /dev/random          (mutant skipEntropy)
  const ENTROPY_FIRST: bool        // entropy before the service restarts        (mutant servicesBeforeEntropy)
  const NONCE_CHECK: bool          // an answer must echo this run's nonce       (mutant staleReply)
  const RECHECK_AT_END: bool       // after a run, re-read gen/epoch; run again  (mutant clearOnComplete)
  const KILL_ON_TIMEOUT: bool      // a restart that times out: kill the old pid (mutant timeoutIgnored)
  const TIMEOUT_UNKNOWN: bool      // ...and record "unknown", not "done"        (mutant timeoutCountsDone)
  const KEY_FROM_ANSWER: bool      // the run's epoch = the host answer's epoch  (mutant keyFromSeen)
  const VERIFY_RESEED: bool        // "done" only after the verifying read, >= RESEED_GAP after the writes (mutant entropyDoneEarly)
  const ENTROPY_GATE: bool         // entropy not done: no restarts, no done key, retry (mutant entropyFailOpen)
  // environment assumption A1: a restore WITHOUT an epoch bump (a clone made outside yard-ctl) only
  // happens on a vmm whose notify is not lost (p4). false in the design; true = finding notifyLostOnClone.
  const CLONE_NOTIFY_LOSABLE: bool
  // bounds
  const MAX_GEN: int               // restores
  const MAX_EPOCH: int
  const MAX_TIME: int
  const SETTLE: int                // epoch-first: wait this long for the generation signal
  const SVC_TIMEOUT: int
  const RESEED_GAP: int            // Fortuna: no reseed within this long of the previous one

  // ------------------------------------------------------------------ types
  type Phase = Ready | Resuming
  type Step = SIdle | SSettle | SExchange | SEntropy | SServices | SReport
  type Nonce = { g: int, n: int }
  // a host answer: madeAt = the VM generation when the host drew its time and random bytes (ghost)
  type Resp = { nonce: Nonce, epoch: int, madeAt: int }
  type SvcOp = { nonce: Nonce, oldPid: int }
  type Svc = { pid: int, alive: bool, seed: int }   // seed: the RNG lineage it seeded from
  type Agent = {
    phase: Phase, step: Step,
    doneGen: int, doneEpoch: int,       // the key of the last completed run
    seenGen: int, seenEpoch: int,
    runGen: int, runEpoch: int, nonce: Nonce, nextNonce: int,
    settleUntil: int, svcSentAt: int, oldPid: int, outcome: str,
    // the entropy step: written at entAt, bytes drawn in VM generation entMade (ghost); entOutcome:
    // "" | "written" | "done" | "notdone" | "unknown" | "skip"; entReseeded (ghost): the generator holds them
    entAt: int, entMade: int, entOutcome: str, entReseeded: bool,
  }
  // guest memory: what a snapshot holds and a restore brings back. rng: the newest VM generation whose
  // fresh material the generator holds; pool: the newest one waiting in pool 0; lastReseed: when the
  // last reseed happened; entLate: a write that timed out and may still land (-1: none)
  type Guest = {
    ag: Agent, svc: Svc, rng: int, pool: int, lastReseed: int, entLate: int, kernelGen: int, clockOk: bool,
    svcOps: Set[SvcOp], svcAns: Set[Nonce], devd: int,
  }
  type Run = { gen: int, epoch: int, vm: int }   // vm: the VM generation the run completed in (ghost)
  type Record = { outcome: str, restarted: bool, entropy: str, reseeded: bool }

  // ------------------------------------------------------------------ state
  var time: int
  var vmGen: int                 // truth: the VM generation (0 = boot; one per restore, unique)
  var g: Guest                   // the running guest's memory
  var snap: Guest                // the snapshot (taken by Snapshot)
  var hasSnap: bool
  var notifyPending: bool        // bhyve raised the notify for the current generation, not yet handled
  var lastClone: bool            // the last restore came without an epoch bump
  var hostEpoch: int
  var hellos: Set[int]           // HELLO epochs in flight (also stale ones from before a restore)
  var reqs: Set[Nonce]           // agent requests in flight
  var resps: Set[Resp]           // host answers in flight
  var nextPid: int
  // ghost
  var runs: List[Run]
  var recs: List[Record]
  var badWork: bool              // privileged work was accepted on a stale guest
  var notifyLost: int            // generation whose notify was lost (0 none)
  var w: { dupIgnored: bool, staleRejected: bool, refused: bool, workAfterRun: bool, recheckRun: bool,
           cloneRun: bool, lostNotifyRun: bool, svcTimeout: bool, twoClones: int, entRetry: bool, otherReseed: bool }

  pure def max(a: int, b: int): int = if (a > b) a else b

  // ------------------------------------------------------------------ agent logic (pure)
  // a change starts a run, or (a run active) leaves the phase Resuming for the end-of-run recheck
  pure def trigger(a: Agent, now: int, settle: bool): Agent =
    if (a.step == SIdle) { ...a, phase: Resuming, step: SSettle, settleUntil: if (settle) now + SETTLE else now }
    else { ...a, phase: Resuming }

  // ObserveGen: devd event, poll, SIGUSR1, or the read in Allow()
  pure def onGen(a: Agent, gen: int, now: int): Agent =
    if (not(ACT_ON_GEN)) a
    else {
      val a1 = { ...a, seenGen: gen }
      if (gen != a.doneGen or not(DEDUPE)) trigger(a1, now, false) else a1
    }

  // ObserveEpoch: a HELLO's epoch
  pure def onEpoch(a: Agent, e: int, now: int): Agent =
    if (not(ACT_ON_EPOCH)) a
    else {
      val newer = if (EPOCH_MONOTONIC) e > a.doneEpoch else e != a.doneEpoch
      val a1 = { ...a, seenEpoch: if (EPOCH_MONOTONIC) max(a.seenEpoch, e) else e }
      // epoch first and the generation unchanged: give the notify SETTLE to arrive
      if (newer or not(DEDUPE)) trigger(a1, now, a1.seenGen == a1.doneGen) else a1
    }

  pure def fresh(gs: Guest, vg: int): bool =
    and { gs.clockOk, gs.rng == vg, not(gs.svc.alive) or gs.svc.seed == vg }

  // ------------------------------------------------------------------ init
  pure val agent0: Agent = { phase: Ready, step: SIdle, doneGen: 0, doneEpoch: 1, seenGen: 0, seenEpoch: 1,
    runGen: 0, runEpoch: 0, nonce: { g: 0, n: 0 }, nextNonce: 1, settleUntil: 0, svcSentAt: 0, oldPid: 0, outcome: "",
    entAt: 0, entMade: 0, entOutcome: "", entReseeded: false }
  pure val guest0: Guest = { ag: agent0, svc: { pid: 1, alive: true, seed: 0 }, rng: 0, pool: 0, lastReseed: 0, entLate: -1,
    kernelGen: 0, clockOk: true, svcOps: Set(), svcAns: Set(), devd: 0 }

  action init = all {
    time' = 0, vmGen' = 0, g' = guest0, snap' = guest0, hasSnap' = false, notifyPending' = false, lastClone' = false,
    hostEpoch' = 1, hellos' = Set(), reqs' = Set(), resps' = Set(), nextPid' = 2,
    runs' = List(), recs' = List(), badWork' = false, notifyLost' = 0,
    w' = { dupIgnored: false, staleRejected: false, refused: false, workAfterRun: false, recheckRun: false,
           cloneRun: false, lostNotifyRun: false, svcTimeout: false, twoClones: 0, entRetry: false, otherReseed: false },
  }

  // ------------------------------------------------------------------ environment: VM and host
  action Tick = all { time < MAX_TIME, time' = time + 1,
    vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending, lastClone' = lastClone,
    hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  action Snapshot = all { snap' = g, hasSnap' = true, w' = { ...w, twoClones: 0 },
    time' = time, vmGen' = vmGen, g' = g, notifyPending' = notifyPending, lastClone' = lastClone,
    hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // Restore(bump): yard-ctl bumps the epoch first (bump) or a clone is made outside it (not bump).
  // bhyve writes a fresh generation ID and raises the notify; the guest's clock lost the downtime.
  action Restore(bump: bool): bool = all { hasSnap, vmGen < MAX_GEN, not(bump) or hostEpoch < MAX_EPOCH,
    vmGen' = vmGen + 1, g' = { ...snap, clockOk: false }, notifyPending' = true, lastClone' = not(bump),
    hostEpoch' = if (bump) hostEpoch + 1 else hostEpoch,
    w' = { ...w, twoClones: w.twoClones + 1 },
    time' = time, snap' = snap, hasSnap' = hasSnap, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // the host bumps the epoch without a restore (an aborted suspend): a spurious resume, safe
  action HostBump = all { hostEpoch < MAX_EPOCH, hostEpoch' = hostEpoch + 1,
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hellos' = hellos, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // vmgenc_status_changed: cached guid := the page, Fortuna pool 0 gets the ID (the generator only at the
  // next reseed), devd event queued
  action KernelNotify = all { notifyPending, notifyPending' = false,
    g' = { ...g, kernelGen: vmGen, pool: max(g.pool, vmGen), devd: g.devd + 1 },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, lastClone' = lastClone,
    hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // the notify is lost (vmm without patch 0003); on a clone only if the assumption is off
  action LoseNotify = all { notifyPending, not(lastClone) or CLONE_NOTIFY_LOSABLE, notifyPending' = false,
    notifyLost' = vmGen,
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, lastClone' = lastClone,
    hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, w' = w }

  // a read by any process in the guest reseeds Fortuna (pool size assumed; the time rule modelled)
  action KernelReseed = all { time >= g.lastReseed + RESEED_GAP,
    g' = { ...g, rng: max(g.rng, g.pool), pool: 0, lastReseed: time },
    w' = { ...w, otherReseed: w.otherReseed or g.ag.step == SEntropy },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // a write to /dev/random that the agent gave up on (timeout) lands late
  action EntLateEffect = all { g.entLate >= 0,
    g' = { ...g, pool: max(g.pool, g.entLate), entLate: -1 },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  action HostHello = all { hellos' = hellos.union(Set(hostEpoch)),
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, reqs' = reqs, resps' = resps, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // the host answers a request: its current time and epoch, fresh random bytes (request -> effect)
  action HostAnswer(n: Nonce, keep: bool): bool = all { reqs.contains(n),
    resps' = resps.union(Set({ nonce: n, epoch: hostEpoch, madeAt: vmGen })),
    reqs' = if (keep) reqs else reqs.exclude(Set(n)),
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  action LoseMsg(which: int, n: Nonce, r: Resp, e: int): bool = all {
    if (which == 0) reqs.contains(n) else if (which == 1) resps.contains(r) else hellos.contains(e),
    reqs' = if (which == 0) reqs.exclude(Set(n)) else reqs,
    resps' = if (which == 1) resps.exclude(Set(r)) else resps,
    hellos' = if (which == 2) hellos.exclude(Set(e)) else hellos,
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, nextPid' = nextPid,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // ------------------------------------------------------------------ agent: signals
  // keep = the event stays deliverable (duplicate)
  action DevdEvent(keep: bool): bool = all { g.devd > 0,
    val a1 = onGen(g.ag, g.kernelGen, time)
    all {
      g' = { ...g, ag: a1, devd: if (keep) g.devd else g.devd - 1 },
      w' = { ...w, dupIgnored: w.dupIgnored or (g.ag.phase == Ready and a1 == { ...g.ag, seenGen: g.kernelGen }) },
    },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // the 1 s sysctl poll (and SIGUSR1): reads the cached guid
  action Poll = all {
    g' = { ...g, ag: onGen(g.ag, g.kernelGen, time) },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  action Hello(e: int, keep: bool): bool = all { hellos.contains(e),
    val a1 = onEpoch(g.ag, e, time)
    all {
      g' = { ...g, ag: a1 },
      w' = { ...w, dupIgnored: w.dupIgnored or (g.ag.phase == Ready and e == g.ag.doneEpoch and a1.phase == Ready) },
    },
    hellos' = if (keep) hellos else hellos.exclude(Set(e)),
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // Work: the host's HELLO (its current epoch) and an EXEC on the same connection. The gate (Allow)
  // reads the generation first. Assumption: after a clone the host's first work does not overtake
  // the guest's handling of the notify (milliseconds after the vCPUs start vs a reconnect of >= 0.5 s).
  action Work = all { not(notifyPending and lastClone),
    val a1 = onEpoch(onGen(g.ag, g.kernelGen, time), hostEpoch, time)
    val accept = not(GATE_WORK) or a1.phase == Ready
    all {
      g' = { ...g, ag: a1 },
      badWork' = (badWork or (accept and not(fresh(g, vmGen)))),
      w' = { ...w, refused: w.refused or not(accept), workAfterRun: w.workAfterRun or (accept and vmGen > 0 and runs.length() > 0) },
    },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, notifyLost' = notifyLost }

  // ------------------------------------------------------------------ agent: the run (Resumer.runOnce)
  // RunStart: the settle is over (or the generation already changed): read the generation, send the
  // request for host time + entropy.
  action RunStart = all { g.ag.step == SSettle, time >= g.ag.settleUntil or g.kernelGen != g.ag.doneGen,
    val rg = if (ACT_ON_GEN) g.kernelGen else g.ag.seenGen
    val n = { g: rg, n: g.ag.nextNonce }
    all {
      g' = { ...g, ag: { ...g.ag, step: SExchange, seenGen: rg, runGen: rg, nonce: n, nextNonce: g.ag.nextNonce + 1 } },
      reqs' = reqs.union(Set(n)),
    },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // RunResend: no answer yet: send another request (exchange timeout)
  action RunResend = all { g.ag.step == SExchange, reqs.contains(g.ag.nonce) == false,
    reqs' = reqs.union(Set(g.ag.nonce)),
    time' = time, vmGen' = vmGen, g' = g, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // a: step the clock from the host time; b: write the host bytes to /dev/random (wr: the writes' outcome:
  // "done", "notdone" = a write failed, "unknown" = timed out, may land later). The services follow in
  // EntVerify (ENTROPY_FIRST; the mutant restarts them here, before the bytes are in).
  // The run's key is what its inputs prove: the generation read at RunStart and the epoch the host
  // reported in THIS answer. Keying it by the newest epoch seen (keyFromSeen) let an answer from before
  // a restore (same lineage, so its nonce matches) absorb the restore's epoch and skip the recheck:
  // stale clock accepted (found by this model at seed 0x5eed, 20000 x 40).
  action RunAnswer(r: Resp, keep: bool, wr: str): bool = all { g.ag.step == SExchange, resps.contains(r),
    val ok = not(NONCE_CHECK) or r.nonce == g.ag.nonce
    val freshBytes = r.madeAt == vmGen   // drawn by the host after this restore
    val wo = if (not(ADD_ENTROPY)) "skip" else if (wr == "done") "written" else wr
    val a1 = { ...g.ag, step: SEntropy, runEpoch: if (KEY_FROM_ANSWER) r.epoch else max(g.ag.seenEpoch, r.epoch),
               seenEpoch: max(g.ag.seenEpoch, r.epoch), entAt: time, entMade: r.madeAt, entOutcome: wo, entReseeded: false,
               svcSentAt: time, oldPid: g.svc.pid }
    val g1 = { ...g, clockOk: freshBytes, ag: a1,
               pool: if (wo == "written") max(g.pool, r.madeAt) else g.pool,
               entLate: if (wo == "unknown") r.madeAt else g.entLate }
    if (ok) all {
      g' = if (ENTROPY_FIRST) g1
           else { ...g1, svc: { pid: nextPid, alive: true, seed: g.rng }, svcAns: g.svcAns.union(Set(g.ag.nonce)) },
      nextPid' = if (ENTROPY_FIRST) nextPid else nextPid + 1,
      w' = w,
    } else all {
      // an answer to another request (a stale one from before the restore, or a duplicate): dropped
      g' = g, nextPid' = nextPid, w' = { ...w, staleRejected: true },
    },
    resps' = if (keep) resps else resps.exclude(Set(r)),
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // the verifying read (kr_post), RESEED_GAP after the writes: its pre_read reseeds unless another
  // reader did after the writes, so the generator then holds the bytes; "done", and the service
  // restarts are requested. The mutant (entropyDoneEarly) reads at once and says "done" anyway.
  // Writes not done: nothing is restarted and the run goes to its report (an incomplete run).
  action EntVerify = all { g.ag.step == SEntropy,
    val a = g.ag
    val written = a.entOutcome == "written"
    val waited = not(written) or not(VERIFY_RESEED) or time >= a.entAt + RESEED_GAP
    val rs = written and time >= g.lastReseed + RESEED_GAP
    val rng1 = if (rs) max(g.rng, g.pool) else g.rng
    val proceed = written or a.entOutcome == "skip" or not(ENTROPY_GATE)
    val op = { nonce: a.nonce, oldPid: g.svc.pid }
    all {
      waited,
      g' = { ...g, rng: rng1, pool: if (rs) 0 else g.pool, lastReseed: if (rs) time else g.lastReseed,
             svcOps: if (proceed and ENTROPY_FIRST) g.svcOps.union(Set(op)) else g.svcOps,
             ag: { ...a, step: if (proceed) SServices else SReport,
                   entOutcome: if (written) "done" else a.entOutcome,
                   entReseeded: written and rng1 >= a.entMade,
                   svcSentAt: if (ENTROPY_FIRST) time else a.svcSentAt,
                   oldPid: if (ENTROPY_FIRST) g.svc.pid else a.oldPid,
                   outcome: if (proceed) a.outcome else "skip" } },
    },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // the restart's effect (stop + start: a new pid seeded from the RNG as it is now) and its answer;
  // it may land after the agent's timeout
  action SvcEffect(op: SvcOp): bool = all { g.svcOps.contains(op),
    g' = { ...g, svc: { pid: nextPid, alive: true, seed: g.rng }, svcOps: g.svcOps.exclude(Set(op)),
           svcAns: g.svcAns.union(Set(op.nonce)) },
    nextPid' = nextPid + 1,
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // the `service` command hangs after its effect (lost answer)
  action SvcLoseAnswer(n: Nonce): bool = all { g.svcAns.contains(n), g' = { ...g, svcAns: g.svcAns.exclude(Set(n)) },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  action SvcDone = all { g.ag.step == SServices, g.svcAns.contains(g.ag.nonce),
    g' = { ...g, svcAns: g.svcAns.exclude(Set(g.ag.nonce)), ag: { ...g.ag, step: SReport, outcome: "done" } },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost, w' = w }

  // the restart did not answer in time: kill the pid recorded before it (a new process, if the
  // restart did land, was seeded after the entropy), record "unknown"
  action SvcTimeout = all { g.ag.step == SServices, time >= g.ag.svcSentAt + SVC_TIMEOUT,
    g' = { ...g,
      svc: if (KILL_ON_TIMEOUT and g.svc.pid == g.ag.oldPid) { ...g.svc, alive: false } else g.svc,
      ag: { ...g.ag, step: SReport, outcome: if (TIMEOUT_UNKNOWN) "unknown" else "done" } },
    w' = { ...w, svcTimeout: true },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, runs' = runs, recs' = recs, badWork' = badWork, notifyLost' = notifyLost }

  // d: the resume record goes to the host; the done key := the run's key; RECHECK_AT_END: a generation
  // or epoch seen during the run that the run did not cover starts the next run at once. The mutant
  // (clearOnComplete) marks everything seen as done and goes Ready.
  // ENTROPY_GATE: a run whose entropy is not done completes nothing: the done key stays, the phase stays
  // Resuming and the run is retried (after a tick: Go's HostWait).
  action RunReport = all { g.ag.step == SReport,
    val a = g.ag
    val complete = not(ENTROPY_GATE) or a.entOutcome == "done" or a.entOutcome == "skip"
    val again = RECHECK_AT_END and (g.kernelGen != a.runGen or a.seenGen != a.runGen or a.seenEpoch > a.runEpoch)
    all {
      g' = { ...g, ag: if (complete) { ...a,
                         doneGen: if (RECHECK_AT_END) a.runGen else a.seenGen,
                         doneEpoch: if (RECHECK_AT_END) a.runEpoch else max(a.seenEpoch, a.runEpoch),
                         phase: if (again) Resuming else Ready, step: if (again) SSettle else SIdle, settleUntil: time }
                       else { ...a, phase: Resuming, step: SSettle, settleUntil: time + 1 } },
      runs' = if (complete) runs.append({ gen: a.runGen, epoch: a.runEpoch, vm: vmGen }) else runs,
      recs' = recs.append({ outcome: a.outcome, restarted: g.svc.pid != a.oldPid, entropy: a.entOutcome, reseeded: a.entReseeded }),
      w' = { ...w, recheckRun: w.recheckRun or (complete and again), entRetry: w.entRetry or not(complete),
                   cloneRun: w.cloneRun or (complete and a.runEpoch == a.doneEpoch and a.runGen != a.doneGen),
                   lostNotifyRun: w.lostNotifyRun or (complete and notifyLost == vmGen and vmGen > 0 and a.runEpoch > a.doneEpoch) },
    },
    time' = time, vmGen' = vmGen, snap' = snap, hasSnap' = hasSnap, notifyPending' = notifyPending,
    lastClone' = lastClone, hostEpoch' = hostEpoch, hellos' = hellos, reqs' = reqs, resps' = resps,
    nextPid' = nextPid, badWork' = badWork, notifyLost' = notifyLost }

  // ------------------------------------------------------------------ step
  pure val gens = 0.to(MAX_GEN)
  pure val epochs = 1.to(MAX_EPOCH)
  action step = {
    nondet keep = Set(true, false).oneOf()
    nondet bump = Set(true, false).oneOf()
    nondet which = Set(0, 1, 2).oneOf()
    nondet n = reqs.union(Set({ g: 0, n: 0 })).oneOf()
    nondet r = resps.union(Set({ nonce: { g: 0, n: 0 }, epoch: 0, madeAt: 0 })).oneOf()
    nondet e = hellos.union(Set(0)).oneOf()
    nondet op = g.svcOps.union(Set({ nonce: { g: 0, n: 0 }, oldPid: 0 })).oneOf()
    nondet an = g.svcAns.union(Set({ g: 0, n: 0 })).oneOf()
    nondet wk = 0.to(5).oneOf()   // the writes: mostly done, 1 in 6 notdone, 1 in 6 unknown
    val wr = if (wk == 0) "notdone" else if (wk == 1) "unknown" else "done"
    any {
      Tick, Snapshot, Restore(bump), HostBump, KernelNotify, LoseNotify, HostHello, KernelReseed, EntLateEffect,
      HostAnswer(n, keep), LoseMsg(which, n, r, e),
      DevdEvent(keep), Poll, Hello(e, keep), Work,
      RunStart, RunResend, RunAnswer(r, keep, wr), EntVerify, SvcEffect(op), SvcLoseAnswer(an), SvcDone, SvcTimeout, RunReport,
    }
  }

  // ------------------------------------------------------------------ properties
  // I1: no privileged work on a guest whose clock, kernel RNG or key-holding services predate the restore
  val noStaleWork = not(badWork)
  // I2: the resume actions run at most once per (generation, epoch) in one VM instance. Across a
  // restore the guest's memory is rewound: a snapshot taken during a run makes every clone finish that
  // run's remaining steps again under the old key (the agent cannot know; first found by this model,
  // seed 0x5eed), and the end-of-run recheck then runs the clone's own key.
  val atMostOncePerKey = runs.indices().forall(i => runs.indices().forall(j => i < j implies runs[i] != runs[j]))
  // I3: a record that says "done" means the service was restarted in that run
  val recordHonest = recs.indices().forall(i => recs[i].outcome == "done" implies recs[i].restarted)
  // I4: a record that says entropy "done" means the generator held the host bytes when it said so
  val entropyHonest = recs.indices().forall(i => recs[i].entropy == "done" implies recs[i].reseeded)
  val safety = and { noStaleWork, atMostOncePerKey, recordHonest, entropyHonest }

  // witnesses (`quint run --witnesses`: the share of traces in which each becomes true)
  val wRun = runs.length() > 0                               // a run completes
  val wHostRestoreRun = runs.select(x => x.epoch > 1 and x.vm > 0).length() > 0
  val wCloneRun = w.cloneRun                                 // generation only (no epoch bump)
  val wLostNotifyRun = w.lostNotifyRun                       // epoch only (the notify was lost)
  val wDupIgnored = w.dupIgnored                             // a duplicate signal changed nothing
  val wStaleRejected = w.staleRejected                       // an answer to another request dropped
  val wRefused = w.refused                                   // exec refused while resuming
  val wWorkAfterRun = w.workAfterRun                         // exec accepted after a run
  val wRecheckRun = w.recheckRun                             // a change during a run starts another
  val wSvcTimeout = w.svcTimeout                             // a restart timed out; old pid killed
  val wTwoClones = w.twoClones >= 2 and runs.select(x => x.vm >= 2).length() > 0   // same snapshot twice, both handled
  val wEntRetry = w.entRetry                                 // entropy not done: the run is retried
  val wOtherReseed = w.otherReseed                           // another reader reseeded during the entropy wait

  // ------------------------------------------------------------------ scripted runs (quint test)
  // Parametric in the rules: `*DesignTest` runs pass on the design; `<mutant>BreaksTest` replays the
  // shortest schedule we know that breaks the mutant's property (run it in the mutant's instance).
  pure def runKeys(l: List[Run]): List[{ gen: int, epoch: int }] = l.foldl(List(), (acc, x) => acc.append({ gen: x.gen, epoch: x.epoch }))
  pure def nn(gen: int, n: int): Nonce = { g: gen, n: n }
  pure def rr(gen: int, n: int, e: int, at: int): Resp = { nonce: nn(gen, n), epoch: e, madeAt: at }
  pure def oo(gen: int, n: int, pid: int): SvcOp = { nonce: nn(gen, n), oldPid: pid }

  // the host's answer is used: clock stepped, bytes written; RESEED_GAP later the verifying read
  run answer(r: Resp): bool = RunAnswer(r, false, "done").then(Tick).then(EntVerify)

  // the run after a restore whose generation the agent already saw: gen 1, epoch e, nonce n, old pid
  run finishRun(gen: int, n: int, e: int, pid: int): bool =
    RunStart.then(HostAnswer(nn(gen, n), false)).then(answer(rr(gen, n, e, vmGen)))
      .then(SvcEffect(oo(gen, n, pid))).then(SvcDone).then(RunReport)

  // gen first (the usual order): notify, devd event, run; then the HELLOs with the new epoch are no-ops
  run genFirstDesignTest = init.then(HostHello).then(Snapshot).then(Restore(true)).then(KernelNotify).then(DevdEvent(true))
    .then(RunStart).then(HostAnswer(nn(1, 1), false)).then(answer(rr(1, 1, 2, 1)))
    .then(SvcEffect(oo(1, 1, 1))).then(SvcDone).then(RunReport)
    .then(HostHello).then(Hello(2, true)).then(Hello(2, false)).then(DevdEvent(false)).then(Poll).then(Work)
    .expect(and { safety, runKeys(runs) == List({ gen: 1, epoch: 2 }), g.ag.phase == Ready, w.dupIgnored, w.workAfterRun })

  // epoch first: the HELLO starts the run, which waits SETTLE for the notify; the late devd event is a no-op
  run epochFirstDesignTest = init.then(Snapshot).then(Restore(true)).then(HostHello).then(Hello(2, false))
    .then(KernelNotify).then(RunStart).then(HostAnswer(nn(1, 1), false)).then(answer(rr(1, 1, 2, 1)))
    .then(SvcEffect(oo(1, 1, 1))).then(SvcDone).then(RunReport).then(DevdEvent(false)).then(Work)
    .expect(and { safety, runKeys(runs) == List({ gen: 1, epoch: 2 }), g.ag.phase == Ready })

  // only the epoch (notify lost): run keyed (old gen, new epoch); the host's bytes make the RNG fresh
  run lostNotifyPrefix = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Hello(2, false))
    .then(Tick).then(RunStart).then(HostAnswer(nn(0, 1), false)).then(answer(rr(0, 1, 2, 1)))
  run lostNotifyDesignTest = lostNotifyPrefix.then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, runKeys(runs) == List({ gen: 0, epoch: 2 }), g.rng == 1, w.lostNotifyRun })
  run skipEntropyBreaksTest = lostNotifyPrefix.then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(not(noStaleWork))
  // services before entropy: the restart happens inside RunAnswer, seeded from the stale RNG
  run servicesBeforeEntropyBreaksTest = lostNotifyPrefix.then(SvcDone).then(RunReport).then(Work).expect(not(noStaleWork))
  run actOnlyOnGenBreaksTest = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Work)
    .expect(not(noStaleWork))
  run actOnlyOnGenDesignTest = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Work)
    .expect(and { safety, w.refused, g.ag.phase == Resuming })

  // the verifying read: another reader reseeded just before the writes, so a read right after them does
  // not reseed (Fortuna's 100 ms rule); the design reads RESEED_GAP later
  run reseedPrefix = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Hello(2, false))
    .then(Tick).then(KernelReseed).then(RunStart).then(HostAnswer(nn(0, 1), false)).then(RunAnswer(rr(0, 1, 2, 1), false, "done"))
  run entropyEarlyDesignTest = reseedPrefix.then(EntVerify).fail()
  run entropyWaitDesignTest = reseedPrefix.then(Tick).then(EntVerify).then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, g.rng == 1, recs == List({ outcome: "done", restarted: true, entropy: "done", reseeded: true }) })
  run entropyDoneEarlyBreaksTest = reseedPrefix.then(EntVerify).then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport)
    .expect(and { not(entropyHonest), recs[0].entropy == "done", g.rng == 0 })

  // the writes fail: nothing restarted, no key, the gate stays shut; the retry completes. The mutant
  // (entropyFailOpen) restarts from the stale RNG and opens the gate.
  run entFailPrefix = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Hello(2, false))
    .then(Tick).then(RunStart).then(HostAnswer(nn(0, 1), false)).then(RunAnswer(rr(0, 1, 2, 1), false, "notdone")).then(EntVerify)
  run entropyRetryDesignTest = entFailPrefix.then(RunReport).then(Work).then(Tick).then(RunStart).then(HostAnswer(nn(0, 2), false))
    .then(answer(rr(0, 2, 2, 1))).then(SvcEffect(oo(0, 2, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, w.entRetry, w.refused, w.workAfterRun, runKeys(runs) == List({ gen: 0, epoch: 2 }),
                  recs.length() == 2, recs[0].entropy == "notdone", recs[1].entropy == "done" })
  run entropyFailOpenBreaksTest = entFailPrefix.then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(not(noStaleWork))
  // the writes time out (unknown) and land later: still no key until a run's verifying read
  run entropyLateDesignTest = init.then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello).then(Hello(2, false))
    .then(Tick).then(RunStart).then(HostAnswer(nn(0, 1), false)).then(RunAnswer(rr(0, 1, 2, 1), false, "unknown")).then(EntVerify)
    .then(RunReport).then(EntLateEffect).then(Work)
    .expect(and { safety, g.pool == 1, g.ag.phase == Resuming, runs.length() == 0, recs[0].entropy == "unknown" })

  // only the generation (a clone, no epoch bump): run keyed (new gen, same epoch)
  run cloneDesignTest = init.then(Snapshot).then(Restore(false)).then(KernelNotify).then(DevdEvent(false))
    .then(finishRun(1, 1, 1, 1)).then(Work)
    .expect(and { safety, runKeys(runs) == List({ gen: 1, epoch: 1 }), w.cloneRun, w.workAfterRun })
  run actOnlyOnEpochBreaksTest = init.then(Snapshot).then(Restore(false)).then(KernelNotify).then(Work).expect(not(noStaleWork))
  run actOnlyOnEpochDesignTest = init.then(Snapshot).then(Restore(false)).then(KernelNotify).then(Work)
    .expect(and { safety, w.refused })
  run acceptWhileResumingBreaksTest = init.then(Snapshot).then(Restore(true)).then(KernelNotify).then(Work).expect(not(noStaleWork))
  run acceptWhileResumingDesignTest = init.then(Snapshot).then(Restore(true)).then(KernelNotify).then(Work)
    .expect(and { safety, w.refused })

  // the same snapshot restored twice: both clones run, with distinct keys
  run twoClonesDesignTest = init.then(Snapshot).then(Restore(false)).then(KernelNotify).then(DevdEvent(false))
    .then(finishRun(1, 1, 1, 1)).then(Restore(false)).then(KernelNotify).then(DevdEvent(false))
    .then(RunStart).then(HostAnswer(nn(2, 1), false)).then(answer(rr(2, 1, 1, 2)))
    .then(SvcEffect(oo(2, 1, 1))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, runKeys(runs) == List({ gen: 1, epoch: 1 }, { gen: 2, epoch: 1 }), w.twoClones == 2 })

  // a duplicate devd event after the run: the design ignores it, noDedupe runs again with the same key
  run dupPrefix = init.then(Snapshot).then(Restore(false)).then(KernelNotify).then(DevdEvent(true))
    .then(finishRun(1, 1, 1, 1)).then(DevdEvent(false))
  run noDedupeBreaksTest = dupPrefix.then(RunStart).then(HostAnswer(nn(1, 2), false)).then(answer(rr(1, 2, 1, 1)))
    .then(SvcEffect(oo(1, 2, 2))).then(SvcDone).then(RunReport).expect(not(atMostOncePerKey))
  run noDedupeDesignTest = dupPrefix.expect(and { safety, g.ag.phase == Ready, g.ag.step == SIdle, w.dupIgnored })

  // a stale HELLO (old epoch, from before the restore) after the run
  run staleHelloPrefix = init.then(HostHello).then(Snapshot).then(Restore(true)).then(KernelNotify).then(DevdEvent(false))
    .then(finishRun(1, 1, 2, 1)).then(Hello(1, false))
  run epochNotMonotonicBreaksTest = staleHelloPrefix.then(Tick).then(RunStart).then(HostAnswer(nn(1, 2), false))
    .then(answer(rr(1, 2, 2, 1))).then(SvcEffect(oo(1, 2, 2))).then(SvcDone).then(RunReport)
    .expect(not(atMostOncePerKey))
  run epochNotMonotonicDesignTest = staleHelloPrefix.expect(and { safety, g.ag.phase == Ready, g.ag.step == SIdle })

  // an answer to an earlier request (duplicated in flight across the snapshot) reaches a clone's run
  run staleReplyPrefix = init.then(HostBump).then(HostHello).then(Hello(2, false)).then(Tick).then(RunStart)
    .then(HostAnswer(nn(0, 1), false)).then(RunAnswer(rr(0, 1, 2, 0), true, "done")).then(Tick).then(EntVerify).then(SvcEffect(oo(0, 1, 1)))
    .then(SvcDone).then(RunReport).then(Snapshot).then(Restore(false)).then(KernelNotify).then(DevdEvent(false))
    .then(RunStart).then(RunAnswer(rr(0, 1, 2, 0), false, "done"))
  run staleReplyBreaksTest = staleReplyPrefix.then(Tick).then(EntVerify).then(SvcEffect(oo(1, 2, 2))).then(SvcDone).then(RunReport).then(Work)
    .expect(not(noStaleWork))
  run staleReplyDesignTest = staleReplyPrefix.then(HostAnswer(nn(1, 2), false)).then(answer(rr(1, 2, 2, 1)))
    .then(SvcEffect(oo(1, 2, 2))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, w.staleRejected, runKeys(runs) == List({ gen: 0, epoch: 2 }, { gen: 1, epoch: 2 }) })

  // a snapshot taken mid-run; the clone finishes the old run with the old answer, having seen its new generation
  run midRunPrefix = init.then(HostBump).then(HostHello).then(Hello(2, false)).then(Tick).then(RunStart)
    .then(HostAnswer(nn(0, 1), false)).then(Snapshot).then(Restore(false)).then(KernelNotify).then(DevdEvent(false))
    .then(answer(rr(0, 1, 2, 0))).then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport)
  run clearOnCompleteBreaksTest = midRunPrefix.then(Work).expect(not(noStaleWork))
  run clearOnCompleteDesignTest = midRunPrefix.then(Work).then(RunStart).then(HostAnswer(nn(1, 2), false))
    .then(answer(rr(1, 2, 2, 1))).then(SvcEffect(oo(1, 2, 2))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, w.recheckRun, w.refused, g.ag.phase == Ready })

  // the restart hangs: after SVC_TIMEOUT the old pid is killed and the record says "unknown"
  run svcHangPrefix = lostNotifyPrefix.then(Tick).then(Tick).then(SvcTimeout).then(RunReport)
  run timeoutIgnoredBreaksTest = svcHangPrefix.then(Work).expect(not(noStaleWork))
  run timeoutCountsDoneBreaksTest = svcHangPrefix.expect(not(recordHonest))
  run svcHangDesignTest = svcHangPrefix.then(Work)
    .expect(and { safety, not(g.svc.alive), recs == List({ outcome: "unknown", restarted: false, entropy: "done", reseeded: true }) })
  // ...and the restart lands late: a new process seeded after the entropy
  run svcLateDesignTest = svcHangPrefix.then(SvcEffect(oo(0, 1, 1))).then(Work)
    .expect(and { safety, g.svc.alive, g.svc.seed == 1 })

  // the finding behind assumption A1: a clone whose notify is lost is invisible to the guest
  run notifyLostOnCloneBreaksTest = init.then(Snapshot).then(Restore(false)).then(LoseNotify).then(Work).expect(not(noStaleWork))
  run notifyLostOnCloneDesignTest = init.then(Snapshot).then(Restore(false)).then(LoseNotify).fail()

  // an answer from before a host restore whose notify was lost, delivered after the new epoch was seen
  run keyPrefix = init.then(HostBump).then(HostHello).then(Hello(2, false)).then(Tick).then(RunStart)
    .then(HostAnswer(nn(0, 1), false)).then(Snapshot).then(Restore(true)).then(LoseNotify).then(HostHello)
    .then(Hello(3, false)).then(answer(rr(0, 1, 2, 0))).then(SvcEffect(oo(0, 1, 1))).then(SvcDone).then(RunReport)
  run keyFromSeenBreaksTest = keyPrefix.then(Work).expect(not(noStaleWork))
  run keyFromSeenDesignTest = keyPrefix.then(Work).then(RunStart).then(HostAnswer(nn(0, 2), false))
    .then(answer(rr(0, 2, 3, 1))).then(SvcEffect(oo(0, 2, 2))).then(SvcDone).then(RunReport).then(Work)
    .expect(and { safety, w.refused, w.recheckRun, runKeys(runs) == List({ gen: 0, epoch: 2 }, { gen: 0, epoch: 3 }) })
}
