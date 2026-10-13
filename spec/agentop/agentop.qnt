// -*- mode: Bluespec; -*-
// agentop.qnt: agent operations (design/AGENT-OPERATIONS.md), what agents add to the operation contract.
//
// The wire (identity, delivery, deadlines, the commit-before-ack handoff) is cordis RFC 0007's and is modelled
// there (cordis operation/capture/expiry.qnt, halo-flash spec/operation). This model takes an accepted attempt
// and adds: a durable executor (yard-ctl) that restarts, Firecracker VMs that crash, a broker that meters every
// model call, caps the task's budget and revokes its scope at the end, a harness that reports its own usage
// (possibly short), workspace versions and an apply that needs an approval, given by the user or, on a cell
// configured for it, by a tested cordis approval harness.
//
// Rules (RULES; one mutant each in agentop_modes.qnt):
//  cap        the broker refuses a call that would pass the task's budget
//  meter      settlement is the broker's meter, never the harness's report
//  adopt      after a yard-ctl restart a running task is re-adopted from yard-node, never started again
//  revoke     the broker scope is revoked when the task ends (no model call after it)
//  approval   an apply needs an approval of that result
//  autoGate   automated approval only on a cell where it is enabled and its harness is tested
//  cas        an apply is a compare-and-set on the result's base
module agentop {
  type Rules = { cap: bool, meter: bool, adopt: bool, revoke: bool, approval: bool, autoGate: bool, cas: bool }
  const RULES: Rules
  const AUTO_ENABLED: bool    // the cell's runner config enables automated approval
  const HARNESS_TESTED: bool  // the cordis approval harness passed its evaluation set

  pure val NT = 3             // tasks
  pure val CAP = 3            // a task's budget (tokens, abstract): its reservation
  pure val TASKS = 0.to(NT - 1)

  type TSt = Unused | Accepted | Running | Done | Failed | Cancelled
  type Task = {
    st: TSt, ro: bool, base: int, result: int,   // result: the version it produced (-1: none)
    metered: int, reported: int, vms: int,       // vms: VMs booted for it (ghost)
    scope: bool, vm: bool,                       // the broker scope, a live VM (yard-node's, volatile)
    settled: bool, approved: bool, auto: bool, applied: int,
  }
  type S = {
    tasks: int -> Task,
    main: int, nextVer: int,                     // the main line's head; version ids
    reserved: int, settled: int, real: int,      // the ledger; real: what the models actually served (ghost)
    // ghosts for the properties
    callAfterEnd: bool, lostUpdate: bool, appliedUnapproved: bool, autoUnconfigured: bool,
    restarts: int, crashes: int, capHits: int, conflicts: int, denied: int,
  }
  var s: S

  pure val T0: Task = { st: Unused, ro: true, base: 0, result: -1, metered: 0, reported: 0, vms: 0, scope: false,
                        vm: false, settled: false, approved: false, auto: false, applied: 0 }

  action init = s' = {
    tasks: TASKS.mapBy(_ => T0), main: 0, nextVer: 1, reserved: 0, settled: 0, real: 0,
    callAfterEnd: false, lostUpdate: false, appliedUnapproved: false, autoUnconfigured: false,
    restarts: 0, crashes: 0, capHits: 0, conflicts: 0, denied: 0,
  }

  pure def ended(t: Task): bool = t.st == Done or t.st == Failed or t.st == Cancelled
  pure def upd(st: S, i: int, t: Task): S = { ...st, tasks: st.tasks.set(i, t) }

  // ---- cordis / outbox --------------------------------------------------------------------------------------
  // an accepted attempt, read-only or read-write, on the main line's head, under a reservation of CAP
  action submit: bool = {
    nondet i = TASKS.oneOf()
    nondet ro = Set(true, false).oneOf()
    val t = s.tasks.get(i)
    all { t.st == Unused,
          s' = { ...upd(s, i, { ...t, st: Accepted, ro: ro, base: s.main }), reserved: s.reserved + CAP } }
  }

  // settle an ended task: the meter (or, the meter mutant, the harness's own report)
  action settle: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    all { ended(t), not(t.settled),
          s' = { ...upd(s, i, { ...t, settled: true }), reserved: s.reserved - CAP,
                 settled: s.settled + (if (RULES.meter) t.metered else t.reported) } }
  }

  // ---- yard-ctl and yard-node -------------------------------------------------------------------------------
  // start the task's VM and its broker scope (yard-ctl's durable row says Accepted)
  action boot: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    all { t.st == Accepted, s' = upd(s, i, { ...t, st: Running, vm: true, scope: true, vms: t.vms + 1 }) }
  }

  // yard-ctl restarts. With `adopt`, running rows are checked with yard-node: a live VM is re-adopted, a gone one
  // fails. The mutant takes every running row as never started, and boots it again
  action restart: bool = all {
    s.restarts < 2,
    s' = { ...s, restarts: s.restarts + 1,
           tasks: TASKS.mapBy(i => {
             val t = s.tasks.get(i)
             if (t.st != Running) t
             else if (not(RULES.adopt)) { ...t, st: Accepted }
             else if (t.vm) t
             else { ...t, st: Failed, scope: false } }) },
  }

  // the harness makes a model call through the broker, costing c
  action modelCall: bool = {
    nondet i = TASKS.oneOf()
    nondet c = 1.to(2).oneOf()
    val t = s.tasks.get(i)
    val open = t.scope and t.vm
    val over = t.metered + c > CAP
    all {
      open,
      if (RULES.cap and over) s' = { ...s, capHits: s.capHits + 1 }  // refused: 429, the driver ends with "budget"
      else s' = { ...upd(s, i, { ...t, metered: t.metered + c }), real: s.real + c,
                  callAfterEnd: s.callAfterEnd or ended(t) },
    }
  }

  // the harness finishes: it reports its usage (possibly short) and, read-write, a new version
  action finish: bool = {
    nondet i = TASKS.oneOf()
    nondet short = Set(0, 1).oneOf()
    val t = s.tasks.get(i)
    val ver = if (t.ro) -1 else s.nextVer
    all {
      t.st == Running, t.vm,
      s' = { ...upd(s, i, { ...t, st: Done, result: ver, reported: if (t.metered >= short) t.metered - short else 0,
                            vm: not(RULES.revoke), scope: not(RULES.revoke) }),
             nextVer: if (t.ro) s.nextVer else s.nextVer + 1 },
    }
  }

  // the VM crashes (or yard-node with it): a known failure, settled at what was metered
  action crash: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    all { t.st == Running, t.vm,
          s' = { ...upd(s, i, { ...t, st: Failed, vm: false, scope: not(RULES.revoke) }), crashes: s.crashes + 1 } }
  }

  action cancel: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    all { t.st == Running, s' = upd(s, i, { ...t, st: Cancelled, vm: not(RULES.revoke), scope: not(RULES.revoke) }) }
  }

  // ---- approval and apply -----------------------------------------------------------------------------------
  // the user approves (or denies) a result on its card
  action userDecides: bool = {
    nondet i = TASKS.oneOf()
    nondet yes = Set(true, false).oneOf()
    val t = s.tasks.get(i)
    all { t.st == Done, not(t.ro), not(t.approved),
          if (yes) s' = upd(s, i, { ...t, approved: true }) else s' = { ...s, denied: s.denied + 1 } }
  }

  // the cordis approval harness approves, where the cell's config allows it
  action autoApprove: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    val configured = AUTO_ENABLED and HARNESS_TESTED
    all { t.st == Done, not(t.ro), not(t.approved),
          if (RULES.autoGate) configured else true,
          s' = { ...upd(s, i, { ...t, approved: true, auto: true }),
                 autoUnconfigured: s.autoUnconfigured or not(configured) } }
  }

  // apply a result to the main line: needs its approval and (cas) the main line still at its base
  action apply: bool = {
    nondet i = TASKS.oneOf()
    val t = s.tasks.get(i)
    all {
      t.st == Done, not(t.ro), t.result >= 0, t.applied == 0,
      if (RULES.approval) t.approved else true,
      if (RULES.cas and s.main != t.base) s' = { ...s, conflicts: s.conflicts + 1, tasks: s.tasks.set(i, { ...t, applied: -1 }) }
      else s' = { ...upd(s, i, { ...t, applied: t.applied + 1 }), main: t.result,
                  lostUpdate: s.lostUpdate or s.main != t.base,
                  appliedUnapproved: s.appliedUnapproved or not(t.approved) },
    }
  }

  action step = any { submit, settle, boot, restart, modelCall, finish, crash, cancel, userDecides, autoApprove, apply }

  // ---- properties -------------------------------------------------------------------------------------------
  val accounted: bool = s.real <= s.settled + s.reserved
  val withinCap: bool = TASKS.forall(i => s.tasks.get(i).metered <= CAP)
  val runsOnce: bool = TASKS.forall(i => s.tasks.get(i).vms <= 1)
  val noCallsAfterEnd: bool = not(s.callAfterEnd)
  val noApplyWithoutApproval: bool = not(s.appliedUnapproved)
  val noAutoUnlessConfigured: bool = not(s.autoUnconfigured)
  val noLostUpdate: bool = not(s.lostUpdate)
  val appliedOnce: bool = TASKS.forall(i => s.tasks.get(i).applied <= 1)
  val safety: bool = and { accounted, withinCap, runsOnce, noCallsAfterEnd, noApplyWithoutApproval,
                           noAutoUnlessConfigured, noLostUpdate, appliedOnce }

  // witnesses
  val wApplied: bool = TASKS.exists(i => s.tasks.get(i).applied == 1)
  val wReviewSettled: bool = TASKS.exists(i => s.tasks.get(i).ro and s.tasks.get(i).st == Done and s.tasks.get(i).settled)
  val wCapHit: bool = s.capHits > 0
  val wCrashSettled: bool = TASKS.exists(i => s.tasks.get(i).st == Failed and s.tasks.get(i).settled and s.crashes > 0)
  val wRestartAdopted: bool = s.restarts > 0 and TASKS.exists(i => s.tasks.get(i).st == Done and s.tasks.get(i).settled)
  val wConflict: bool = s.conflicts > 0
  val wDenied: bool = s.denied > 0
  val wAutoApplied: bool = TASKS.exists(i => s.tasks.get(i).auto and s.tasks.get(i).applied == 1)
}
