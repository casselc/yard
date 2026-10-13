// -*- mode: Bluespec; -*-
// executor.qnt: yard-ctl's recovery protocol for an attempt (design/AGENT-OPERATIONS.md section 5).
//
// Accepting a task, starting its worker, activating its broker scope, capturing its result, stopping the worker
// and revoking the scope are separate steps against separate parties, not one transaction. yard-ctl keeps a
// durable stage per attempt and resolves each step by an observation (yard-node's VM table by allocation id,
// the broker's scope table). A start request can be delayed or its answer lost; yard-node can be unreachable
// while its VMs keep running; a revocation reaches the broker late. Every VM uses guest CID 3 (Firecracker's
// vsock does not make CIDs unique across VMs), so the allocation, not the CID, is what identifies a worker.
// yard-ctl's decisions read only its durable rows and these observations, so its own restart is a stutter here.
//
// Rules (RULES; one mutant each in executor_modes.qnt):
//  fence     an allocation that did not start is tombstoned at yard-node before the attempt allocates again
//  alloc     the broker scope is bound to the allocation (a per-allocation host socket), not to the guest CID
//  stopped   an unreachable worker is recorded fenced, not stopped, until yard-node confirms it is gone
//  revoke    the attempt's accounting is final only after the broker confirmed the scope revoked
//  capture   the result is captured only after the worker is confirmed stopped
module executor {
  type Rules = { fence: bool, alloc: bool, stopped: bool, revoke: bool, capture: bool }
  const RULES: Rules

  pure val NA = 2
  pure val ATTEMPTS = 0.to(NA - 1)
  pure val NAL = 4                 // allocation ids 0..3 (never reused)
  pure val ALLOCS = 0.to(NAL - 1)
  pure val CID = 3
  pure val MAXW = 2                // writes a worker makes to its workspace

  type Stage = Unused | Accepted | Allocating | Started | Capturing | Ending | Ended
  type Exec = Unknown | Stopped | Fenced
  type Out = NoOutcome | Completed | WorkerLost
  type Att = { stage: Stage, al: int, exec: Exec, out: Out, candidate: int }
  // yard-node's VM table, by allocation id (truth: alive is whether the VM runs)
  type Vm = { attempt: int, used: bool, requested: bool, alive: bool, finished: bool, tomb: bool, writes: int }
  type S = {
    att: int -> Att,
    vms: int -> Vm,
    nextAl: int,
    scopes: int -> int,           // the broker's scope table: key -> attempt (-1: none)
    revoking: Set[int],           // revocations sent, not yet applied at the broker
    fenceOwed: Set[int],          // tombstones yard-ctl owes yard-node (durable), delivered when reachable
    reachable: bool, partitions: int,
    // ghosts
    misattributed: bool, spentAfterFinal: bool, reallocs: int, refusedCalls: int, upgraded: int, watchdogs: int,
  }
  var s: S

  pure val A0: Att = { stage: Unused, al: -1, exec: Unknown, out: NoOutcome, candidate: -1 }
  pure val V0: Vm = { attempt: -1, used: false, requested: false, alive: false, finished: false, tomb: false, writes: 0 }
  pure def key(al: int): int = if (RULES.alloc) al else CID
  pure val KEYS = 0.to(NAL - 1)   // CID 3 is among them

  action init = s' = {
    att: ATTEMPTS.mapBy(_ => A0), vms: ALLOCS.mapBy(_ => V0), nextAl: 0,
    scopes: KEYS.mapBy(_ => -1), revoking: Set(), fenceOwed: Set(), reachable: true, partitions: 0,
    misattributed: false, spentAfterFinal: false, reallocs: 0, refusedCalls: 0, upgraded: 0, watchdogs: 0,
  }

  def A(a: int): Att = s.att.get(a)
  def V(al: int): Vm = s.vms.get(al)
  pure def setA(st: S, a: int, x: Att): S = { ...st, att: st.att.set(a, x) }
  pure def setV(st: S, al: int, v: Vm): S = { ...st, vms: st.vms.set(al, v) }
  // end an attempt's run: the outcome is recorded and its scope's revocation sent
  pure def ending(st: S, a: int, x: Att): S = { ...setA(st, a, { ...x, stage: Ending }), revoking: st.revoking.union(Set(key(x.al))) }

  // ---- yard-ctl ---------------------------------------------------------------------------------------------
  action accept: bool = {
    nondet a = ATTEMPTS.oneOf()
    all { A(a).stage == Unused, s' = setA(s, a, { ...A(a), stage: Accepted }) }
  }

  // write the allocation durably, activate its scope, and ask yard-node to start it
  action allocate: bool = {
    nondet a = ATTEMPTS.oneOf()
    val al = s.nextAl
    all {
      A(a).stage == Accepted, al < NAL,
      s' = { ...setV(setA(s, a, { ...A(a), stage: Allocating, al: al }), al, { ...V0, attempt: a, used: true, requested: true }),
             nextAl: al + 1, scopes: s.scopes.set(key(al), a) },
    }
  }

  // the start is observed (its answer, or yard-node's table by allocation id)
  action observeStarted: bool = {
    nondet a = ATTEMPTS.oneOf()
    all { A(a).stage == Allocating, s.reachable, V(A(a).al).alive,
          s' = setA(s, a, { ...A(a), stage: Started }) }
  }

  // yard-node says the allocation is not running (the request may still be in flight): tombstone it there, revoke
  // its scope, and allocate again. The mutant allocates again without the tombstone
  action observeAbsent: bool = {
    nondet a = ATTEMPTS.oneOf()
    val al = A(a).al
    val st1 = if (RULES.fence) setV(s, al, { ...V(al), tomb: true }) else s
    all {
      A(a).stage == Allocating, s.reachable, not(V(al).alive), not(V(al).finished),
      s' = { ...setA(st1, a, { ...A(a), stage: Accepted }), revoking: s.revoking.union(Set(key(al))),
             reallocs: s.reallocs + 1 },
    }
  }

  // the worker reported it finished: stop it, then snapshot. The mutant snapshots the running worker
  action beginCapture: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    all {
      x.stage == Started, s.reachable, V(x.al).finished,
      if (RULES.capture) s' = setV(setA(s, a, { ...x, stage: Capturing }), x.al, { ...V(x.al), alive: false })
      else s' = ending(s, a, { ...x, out: Completed, exec: Stopped, candidate: V(x.al).writes }),
    }
  }

  action snapshot: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    all { x.stage == Capturing, s.reachable, not(V(x.al).alive),
          s' = ending(s, a, { ...x, out: Completed, exec: Stopped, candidate: V(x.al).writes }) }
  }

  // yard-node reports the worker gone without finishing: a lost worker, confirmed stopped
  action observeLost: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    all { x.stage == Started, s.reachable, not(V(x.al).alive), not(V(x.al).finished),
          s' = ending(s, a, { ...x, out: WorkerLost, exec: Stopped }) }
  }

  // yard-node is unreachable past the bound: fence the worker (revoke its scope; owe yard-node a tombstone) and
  // end the attempt as a lost worker. Its execution is "fenced", not "stopped"; the mutant says "stopped"
  action fenceUnreachable: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    all { (x.stage == Allocating or x.stage == Started), not(s.reachable),
          s' = { ...ending(s, a, { ...x, out: WorkerLost, exec: if (RULES.stopped) Fenced else Stopped }),
                 fenceOwed: s.fenceOwed.union(Set(x.al)) } }
  }

  // yard-node is reachable again and has applied the tombstones: a fenced attempt's execution becomes stopped
  action confirmStopped: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    all { x.exec == Fenced, s.reachable, not(V(x.al).alive), not(s.fenceOwed.contains(x.al)),
          s' = { ...setA(s, a, { ...x, exec: Stopped }), upgraded: s.upgraded + 1 } }
  }

  // the accounting is final once the broker confirmed the revocation; the mutant does not wait
  action finalise: bool = {
    nondet a = ATTEMPTS.oneOf()
    val x = A(a)
    val revoked = s.scopes.get(key(x.al)) != a
    all { x.stage == Ending, if (RULES.revoke) revoked else true, s' = setA(s, a, { ...x, stage: Ended }) }
  }

  // ---- the broker -------------------------------------------------------------------------------------------
  action revokeApply: bool = {
    nondet k = KEYS.oneOf()
    all { s.revoking.contains(k),
          s' = { ...s, revoking: s.revoking.exclude(Set(k)), scopes: s.scopes.set(k, -1) } }
  }

  // ---- yard-node and its VMs --------------------------------------------------------------------------------
  // a start request arrives (it may be late); a tombstoned allocation is not started
  action nodeStart: bool = {
    nondet al = ALLOCS.oneOf()
    val v = V(al)
    all { v.requested, not(v.tomb),
          s' = setV(s, al, { ...v, requested: false, alive: true }) }
  }

  action nodeDrop: bool = {
    nondet al = ALLOCS.oneOf()
    val v = V(al)
    all { v.requested, v.tomb, s' = setV(s, al, { ...v, requested: false }) }
  }

  // yard-node applies the tombstones it is owed: kills those VMs, refuses their starts
  action nodeFence: bool = {
    nondet al = ALLOCS.oneOf()
    all { s.fenceOwed.contains(al), s.reachable,
          s' = { ...setV(s, al, { ...V(al), tomb: true, alive: false }), fenceOwed: s.fenceOwed.exclude(Set(al)) } }
  }

  // a worker calls a model through its allocation's socket: the broker charges the attempt its key maps to
  action vmCall: bool = {
    nondet al = ALLOCS.oneOf()
    val v = V(al)
    val owner = s.scopes.get(key(al))
    all {
      v.alive,
      if (owner < 0) s' = { ...s, refusedCalls: s.refusedCalls + 1 }
      else s' = { ...s, misattributed: s.misattributed or owner != v.attempt,
                  spentAfterFinal: s.spentAfterFinal or A(owner).stage == Ended },
    }
  }

  action vmWrite: bool = {
    nondet al = ALLOCS.oneOf()
    val v = V(al)
    all { v.alive, v.writes < MAXW, s' = setV(s, al, { ...v, writes: v.writes + 1 }) }
  }

  action vmFinish: bool = {
    nondet al = ALLOCS.oneOf()
    val v = V(al)
    all { v.alive, not(v.finished), s' = setV(s, al, { ...v, finished: true }) }
  }

  // the VM stops: it crashed, or the mutant's late stop after a capture
  action vmCrash: bool = {
    nondet al = ALLOCS.oneOf()
    all { V(al).alive, s' = setV(s, al, { ...V(al), alive: false }) }
  }

  // yard-node's watchdog: an allocation whose lease yard-ctl stopped renewing (yard-ctl unreachable) is stopped by
  // the node itself, which bounds a lost worker's life even while nothing reaches it
  action watchdog: bool = {
    nondet al = ALLOCS.oneOf()
    all { not(s.reachable), V(al).alive, s' = { ...setV(s, al, { ...V(al), alive: false }), watchdogs: s.watchdogs + 1 } }
  }

  action partition: bool = all { s.reachable, s.partitions < 2,
                                 s' = { ...s, reachable: false, partitions: s.partitions + 1 } }
  action heal: bool = all { not(s.reachable), s' = { ...s, reachable: true } }

  action step = any {
    accept, allocate, observeStarted, observeAbsent, beginCapture, snapshot, observeLost, fenceUnreachable,
    confirmStopped, finalise, revokeApply, nodeStart, nodeDrop, nodeFence, vmCall, vmWrite, vmFinish, vmCrash,
    watchdog, partition, heal,
  }

  // ---- properties -------------------------------------------------------------------------------------------
  // at most one live worker per attempt
  val oneLive: bool = ATTEMPTS.forall(a => ALLOCS.filter(al => V(al).alive and V(al).attempt == a).size() <= 1)
  // a call is charged to the attempt whose worker made it
  val attributed: bool = not(s.misattributed)
  // nothing is charged to an attempt after its accounting is final
  val noSpendAfterFinal: bool = not(s.spentAfterFinal)
  // "stopped" means stopped
  val stoppedIsStopped: bool = ATTEMPTS.forall(a => A(a).exec == Stopped implies not(V(A(a).al).alive))
  // a captured result is the worker's final workspace
  val candidateStable: bool = ATTEMPTS.forall(a => {
    val x = A(a)
    (x.candidate >= 0 and not(V(x.al).alive)) implies x.candidate == V(x.al).writes
  })
  val safety: bool = and { oneLive, attributed, noSpendAfterFinal, stoppedIsStopped, candidateStable }

  // witnesses
  val wCompleted: bool = ATTEMPTS.exists(a => A(a).stage == Ended and A(a).out == Completed)
  val wLost: bool = ATTEMPTS.exists(a => A(a).stage == Ended and A(a).out == WorkerLost and A(a).exec == Stopped)
  val wFencedAlive: bool = ATTEMPTS.exists(a => A(a).exec == Fenced and V(A(a).al).alive)
  val wFencedRefused: bool = ATTEMPTS.exists(a => A(a).exec == Fenced) and s.refusedCalls > 0
  val wUpgraded: bool = s.upgraded > 0
  val wRealloc: bool = s.reallocs > 0 and ATTEMPTS.exists(a => A(a).stage == Ended and A(a).out == Completed)
  val wWatchdog: bool = s.watchdogs > 0 and ATTEMPTS.exists(a => A(a).exec == Fenced)
  val wRevokePending: bool = ATTEMPTS.exists(a => A(a).stage == Ending and s.revoking.contains(key(A(a).al)))
}
