// -*- mode: Bluespec; -*-
// apply.qnt: candidates, approvals and apply (design/AGENT-OPERATIONS.md section 7).
//
// A writer attempt produces a candidate: an immutable commit on its base, held in the artifact store under
// leases (the operation's, until it is acknowledged; the workflow's; an approval's). Acknowledging the operation
// drops only the operation's lease. An approval is a durable record bound to the candidate's digest and base,
// with an expiry; waiting for it occupies no operation. Apply is a short compare-and-set operation that checks,
// when it runs, that the approval is granted and unexpired, that the cell still has the authority to apply,
// that the approved content is what it applies, that the artifact is available, and that the target is still
// at the base. A candidate's name can be pointed at new content by a later run (a branch name, say), which is
// why the approval binds the digest and not the name.
//
// Rules (RULES; one mutant each in apply_modes.qnt):
//  approval  apply needs a granted approval
//  expiry    the approval's expiry is checked when the apply runs
//  authority the cell's authority to apply is checked when the apply runs, not only when approval was asked
//  bound     the content applied is the digest that was approved, not whatever the name holds now
//  cas       apply is a compare-and-set on the approved base
//  autoGate  automated approval only on a cell where it is enabled and its harness is tested
//  explicit  an unavailable artifact fails the apply explicitly; it is never applied as empty content
//  lease     acknowledging the operation drops only its own lease; an artifact goes only when no lease holds it
module apply {
  type Rules = { approval: bool, expiry: bool, authority: bool, bound: bool, cas: bool, autoGate: bool, lease: bool, explicit: bool }
  const RULES: Rules
  const AUTO_ENABLED: bool
  const HARNESS_TESTED: bool

  pure val NCAND = 2
  pure val CANDS = 0.to(NCAND - 1)
  pure val TTL = 2               // an approval's lifetime, in ticks
  pure val MAXCLOCK = 5

  type CSt = NoCand | Held | Released
  type Cand = { st: CSt, digest: int, base: int, opLease: bool, wfLease: bool }
  type ASt = NoAppr | Pending | Approved | Denied | Expired | Applied
  type Appr = { st: ASt, digest: int, base: int, expiry: int, auto: bool }
  type Out = { applied: int, conflicts: int, refused: int, unavailable: int }
  type S = {
    cands: int -> Cand, apprs: int -> Appr,
    head: int, nextDigest: int, clock: int, authority: bool,
    out: Out,
    appliedBad: bool, lostUpdate: bool, autoUnconfigured: bool, appliedCount: int -> int,
  }
  var s: S

  pure val C0: Cand = { st: NoCand, digest: -1, base: -1, opLease: false, wfLease: false }
  pure val P0: Appr = { st: NoAppr, digest: -1, base: -1, expiry: 0, auto: false }

  action init = s' = {
    cands: CANDS.mapBy(_ => C0), apprs: CANDS.mapBy(_ => P0), head: 0, nextDigest: 1, clock: 0, authority: true,
    out: { applied: 0, conflicts: 0, refused: 0, unavailable: 0 },
    appliedBad: false, lostUpdate: false, autoUnconfigured: false, appliedCount: CANDS.mapBy(_ => 0),
  }

  def C(c: int): Cand = s.cands.get(c)
  def P(c: int): Appr = s.apprs.get(c)
  pure def setC(st: S, c: int, x: Cand): S = { ...st, cands: st.cands.set(c, x) }
  pure def setP(st: S, c: int, x: Appr): S = { ...st, apprs: st.apprs.set(c, x) }
  pure def live(p: Appr): bool = p.st == Pending or p.st == Approved

  // ---- the writer attempt and the operation -----------------------------------------------------------------
  action produce: bool = {
    nondet c = CANDS.oneOf()
    all { C(c).st == NoCand,
          s' = { ...setC(s, c, { st: Held, digest: s.nextDigest, base: s.head, opLease: true, wfLease: true }),
                 nextDigest: s.nextDigest + 1 } }
  }

  // a later run writes new content under the same candidate name
  action repoint: bool = {
    nondet c = CANDS.oneOf()
    all { C(c).st == Held, s.nextDigest < 5,
          s' = { ...setC(s, c, { ...C(c), digest: s.nextDigest }), nextDigest: s.nextDigest + 1 } }
  }

  // the operation is acknowledged: its lease goes (the mutant releases the artifact with it)
  action ack: bool = {
    nondet c = CANDS.oneOf()
    all { C(c).opLease,
          s' = setC(s, c, if (RULES.lease) { ...C(c), opLease: false } else { ...C(c), opLease: false, st: Released }) }
  }

  action wfRelease: bool = {
    nondet c = CANDS.oneOf()
    all { C(c).wfLease, s' = setC(s, c, { ...C(c), wfLease: false }) }
  }

  // retention: an artifact no lease holds may go
  action gc: bool = {
    nondet c = CANDS.oneOf()
    val x = C(c)
    all { x.st == Held, not(x.opLease), not(x.wfLease), not(live(P(c))), s' = setC(s, c, { ...x, st: Released }) }
  }

  // ---- approvals ----------------------------------------------------------------------------------------------
  action request: bool = {
    nondet c = CANDS.oneOf()
    all { C(c).st == Held, P(c).st == NoAppr,
          s' = setP(s, c, { st: Pending, digest: C(c).digest, base: C(c).base, expiry: s.clock + TTL, auto: false }) }
  }

  action userDecides: bool = {
    nondet c = CANDS.oneOf()
    nondet yes = Set(true, false).oneOf()
    all { P(c).st == Pending, s.clock < P(c).expiry, s' = setP(s, c, { ...P(c), st: if (yes) Approved else Denied }) }
  }

  action autoApprove: bool = {
    nondet c = CANDS.oneOf()
    val configured = AUTO_ENABLED and HARNESS_TESTED
    all { P(c).st == Pending, s.clock < P(c).expiry, if (RULES.autoGate) configured else true,
          s' = { ...setP(s, c, { ...P(c), st: Approved, auto: true }),
                 autoUnconfigured: s.autoUnconfigured or not(configured) } }
  }

  action expire: bool = {
    nondet c = CANDS.oneOf()
    all { live(P(c)), s.clock >= P(c).expiry, s' = setP(s, c, { ...P(c), st: Expired }) }
  }

  action tick: bool = all { s.clock < MAXCLOCK, s' = { ...s, clock: s.clock + 1 } }

  // the operator withdraws the cell's authority to apply
  action revokeAuthority: bool = all { s.authority, s.clock >= MAXCLOCK - 1, s' = { ...s, authority: false } }

  // ---- apply ----------------------------------------------------------------------------------------------------
  action apply: bool = {
    nondet c = CANDS.oneOf()
    val x = C(c)
    val p = P(c)
    val granted = p.st == Approved
    val unexpired = s.clock < p.expiry
    // what it applies, and on which base: the approval's (bound), or the name's current content
    val content = if (RULES.bound and p.st != NoAppr) p.digest else x.digest
    val base = if (p.st != NoAppr) p.base else x.base
    val ok = and {
      if (RULES.approval) granted else true,
      if (RULES.expiry) unexpired else true,
      if (RULES.authority) s.authority else true,
      if (RULES.bound) x.digest == content else true,
    }
    all {
      x.st != NoCand, p.st != Applied, s.appliedCount.get(c) == 0,
      if (not(ok)) s' = { ...s, out: { ...s.out, refused: s.out.refused + 1 } }
      else if (x.st != Held and RULES.explicit) s' = { ...s, out: { ...s.out, unavailable: s.out.unavailable + 1 } }   // explicit
      else if (RULES.cas and s.head != base) s' = { ...s, out: { ...s.out, conflicts: s.out.conflicts + 1 } }
      else s' = { ...setP(s, c, { ...p, st: Applied }), head: if (x.st == Held) content else 0,
                  out: { ...s.out, applied: s.out.applied + 1 },
                  appliedCount: s.appliedCount.setBy(c, n => n + 1),
                  lostUpdate: s.lostUpdate or s.head != base,
                  appliedBad: s.appliedBad or not(granted and unexpired and s.authority and content == p.digest
                                                   and x.st == Held) },
    }
  }

  action step = any { produce, repoint, ack, wfRelease, gc, request, userDecides, autoApprove, expire, tick,
                      revokeAuthority, apply }

  // ---- properties -------------------------------------------------------------------------------------------
  // what is applied was approved, unexpired, by a cell with the authority, as that content
  val approvedApplied: bool = not(s.appliedBad)
  val noLostUpdate: bool = not(s.lostUpdate)
  val appliedOnce: bool = CANDS.forall(c => s.appliedCount.get(c) <= 1)
  val noAutoUnlessConfigured: bool = not(s.autoUnconfigured)
  // an artifact a live approval needs is still there
  val neededPresent: bool = CANDS.forall(c => live(P(c)) implies C(c).st == Held)
  val safety: bool = and { approvedApplied, noLostUpdate, appliedOnce, noAutoUnlessConfigured, neededPresent }

  // witnesses
  val wApplied: bool = s.out.applied > 0
  val wAutoApplied: bool = CANDS.exists(c => P(c).st == Applied and P(c).auto)
  val wConflict: bool = s.out.conflicts > 0
  val wRefusedExpired: bool = s.out.refused > 0 and CANDS.exists(c => P(c).st == Expired)
  val wRefusedAuthority: bool = s.out.refused > 0 and not(s.authority) and CANDS.exists(c => P(c).st == Approved)
  val wAckedThenApplied: bool = CANDS.exists(c => P(c).st == Applied and not(C(c).opLease))
  val wReleased: bool = CANDS.exists(c => C(c).st == Released)
}
