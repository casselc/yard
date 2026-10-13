// -*- mode: Bluespec; -*-
// broker.qnt: the broker's accounting for one attempt (design/AGENT-OPERATIONS.md section 6).
//
// One attempt with independent token and money limits, a valuation pinned at acceptance, and model calls that run
// concurrently. A call is reserved at its maximum cost before it is sent; the provider may serve it whether or not
// its answer comes back; the broker may crash with calls in flight. What the attempt is charged is what the
// broker's durable ledger holds: an answered call at its confirmed usage, an unanswered one at its reserved
// maximum. A call on the local (halo) route that lost its answer is resolvable later from halo's operation record,
// which keeps the usage until acknowledged, but only while halo keeps its incarnation: halo's records are not
// durable, and a halo restart before the broker captured the usage makes the call unresolvable. It then stays at
// its maximum, as a provider call does, and the attempt is reported bounded rather than waiting for exactness.
//
// Rules (RULES; one mutant each in broker_modes.qnt):
//  atomic    a call is admitted only if every open reservation, every charge and its own maximum fit each limit
//  durable   the reservation is in the durable ledger before the call is sent
//  hold      an unanswered call stays charged at its maximum (never released at zero)
//  pinned    the valuation is the operator's, pinned for the attempt (never the graph's, which the agent can edit)
//  tokens    the token limit is enforced on its own, not only through money
//  honest    the final report says exact only when no call is unresolved
//  settle    the final report does not wait for an unresolved local call to become exact (halo may have lost it)
module broker {
  type Rules = { atomic: bool, durable: bool, hold: bool, pinned: bool, tokens: bool, honest: bool, settle: bool }
  const RULES: Rules

  pure val NC = 3              // calls the harness makes (each once)
  pure val CALLS = 0.to(NC - 1)
  pure val TOKLIM = 4          // the attempt's token limit
  pure val MONLIM = 2          // its money limit (integer units)
  pure val PRICE = 1           // the operator's price per token on the provider route (the local route: 0)

  type Route = Local | Provider
  // Free: not made. Reserved: in the ledger, not sent. Sent: in flight. Answered: usage confirmed.
  // Unresolved: no answer (lost, or the broker crashed); charged at its maximum until resolved.
  type CSt = Free | Reserved | Sent | Answered | Unresolved
  // known: the broker's ledger has the row. durable: it would survive a crash. sent: it left the broker
  // gone: halo restarted after the call reached it; its operation record (and the usage in it) is lost
  type Call = { st: CSt, route: Route, maxT: int, maxM: int, sent: bool, served: bool, realT: int, realM: int,
                known: bool, durable: bool, gone: bool }
  type Cert = Open | Exact | Bounded
  type S = {
    calls: int -> Call,
    ended: bool, report: Cert, crashes: int, resolved: int, refusals: int, haloRestarts: int,
    reportedExactWrongly: bool,
  }
  var s: S

  pure val C0: Call = { st: Free, route: Local, maxT: 0, maxM: 0, sent: false, served: false, realT: 0, realM: 0,
                        known: false, durable: false, gone: false }
  action init = s' = { calls: CALLS.mapBy(_ => C0), ended: false, report: Open, crashes: 0, resolved: 0, refusals: 0, haloRestarts: 0,
                       reportedExactWrongly: false }

  pure def upd(st: S, i: int, c: Call): S = { ...st, calls: st.calls.set(i, c) }
  // what the broker holds for a call
  pure def heldT(c: Call): int =
    if (not(c.known)) 0
    else if (c.st == Answered) c.realT
    else if (c.st == Free) 0
    else c.maxT
  pure def heldM(c: Call): int =
    if (not(c.known)) 0
    else if (c.st == Answered) c.realM
    else if (c.st == Free) 0
    else c.maxM
  def sumOf(f: Call => int): int = CALLS.fold(0, (acc, i) => acc + f(s.calls.get(i)))
  def confirmedT: int = sumOf(c => if (c.st == Answered) c.realT else 0)
  def confirmedM: int = sumOf(c => if (c.st == Answered) c.realM else 0)
  def chargedT: int = sumOf(heldT)
  def chargedM: int = sumOf(heldM)
  def realT: int = sumOf(c => c.realT)
  def realM: int = sumOf(c => c.realM)

  // ---- the harness asks for a call; the broker reserves and sends it -----------------------------------------
  action reserve: bool = {
    nondet i = CALLS.oneOf()
    nondet route = Set(Local, Provider).oneOf()
    nondet maxT = 1.to(2).oneOf()
    // the valuation used to enforce the money limit: the pinned operator price, or (mutant) the graph's, which
    // the agent has set to zero
    val price = if (route == Local) 0 else if (RULES.pinned) PRICE else 0
    val maxM = maxT * price
    val c = s.calls.get(i)
    // admission: everything held (open reservations, unresolved maxima, confirmed usage) plus this call's maximum
    // must fit each limit; the mutant counts confirmed usage only
    val usedT = if (RULES.atomic) chargedT else confirmedT
    val usedM = if (RULES.atomic) chargedM else confirmedM
    all {
      not(s.ended), c.st == Free,
      usedM + maxM <= MONLIM,
      if (RULES.tokens) usedT + maxT <= TOKLIM else true,
      s' = upd(s, i, { ...c, st: Reserved, route: route, maxT: maxT, maxM: maxM, known: true,
                         durable: RULES.durable }),
    }
  }

  // the broker refuses a call that would not fit (the harness sees 429 and the driver ends the task "budget")
  action refuse: bool = {
    nondet maxT = 1.to(2).oneOf()
    all { not(s.ended), chargedT + maxT > TOKLIM, s' = { ...s, refusals: s.refusals + 1 } }
  }

  action send: bool = {
    nondet i = CALLS.oneOf()
    val c = s.calls.get(i)
    all { c.st == Reserved, s' = upd(s, i, { ...c, st: Sent, sent: true }) }
  }

  // the provider serves a call it received: its real cost is at most the maximum (the broker set max_tokens and
  // bounded the input). It may serve after the broker gave up on the answer
  action serve: bool = {
    nondet i = CALLS.oneOf()
    nondet t = 1.to(2).oneOf()
    val c = s.calls.get(i)
    val tt = if (t > c.maxT) c.maxT else t
    val price = if (c.route == Local) 0 else PRICE
    all { c.sent, c.st != Answered, not(c.served), not(c.gone),
          s' = upd(s, i, { ...c, served: true, realT: tt, realM: tt * price }) }
  }

  action answer: bool = {
    nondet i = CALLS.oneOf()
    val c = s.calls.get(i)
    all { c.st == Sent, c.served, s' = upd(s, i, { ...c, st: Answered }) }
  }

  // the answer is lost (a dropped connection, a timeout): the call is unresolved. The mutant releases it at zero
  action lose: bool = {
    nondet i = CALLS.oneOf()
    val c = s.calls.get(i)
    all { c.st == Sent,
          s' = upd(s, i, if (RULES.hold) { ...c, st: Unresolved } else { ...c, st: Unresolved, known: false }) }
  }

  // the broker crashes and recovers: connections are gone, so every sent call is unresolved; a reservation that
  // was only in memory is forgotten (its call may already have been sent)
  action crash: bool = all {
    s.crashes < 2,
    s' = { ...s, crashes: s.crashes + 1,
           calls: CALLS.mapBy(i => {
             val c = s.calls.get(i)
             if (c.st == Sent or c.st == Reserved)
               { ...c, st: Unresolved, known: c.known and c.durable }
             else c }) },
  }

  // halo restarts (a new incarnation): every local call it had and the broker has not settled loses its record;
  // a call it had not served yet never runs. A call already served keeps its real cost
  action haloRestart: bool = all {
    s.haloRestarts < 2,
    s' = { ...s, haloRestarts: s.haloRestarts + 1,
           calls: CALLS.mapBy(i => {
             val c = s.calls.get(i)
             if (c.route == Local and c.sent and c.st != Answered) { ...c, gone: true } else c }) },
  }

  // a local call that lost its answer is resolved from halo's operation record, while halo still has it
  action resolveLocal: bool = {
    nondet i = CALLS.oneOf()
    val c = s.calls.get(i)
    all { c.st == Unresolved, c.route == Local, c.served, c.known, not(c.gone),
          s' = { ...upd(s, i, { ...c, st: Answered }), resolved: s.resolved + 1 } }
  }

  // the attempt ends: no more reservations; the final report once nothing is in flight
  action end: bool = all { not(s.ended), s' = { ...s, ended: true } }

  // the mutant waits until every unresolved local call is resolved exactly
  def reportAllowed: bool =
    RULES.settle or CALLS.forall(i => not(s.calls.get(i).st == Unresolved and s.calls.get(i).route == Local))
  def nothingInFlight: bool = CALLS.forall(i => s.calls.get(i).st != Sent and s.calls.get(i).st != Reserved)

  action finalReport: bool = {
    val unresolved = CALLS.exists(i => s.calls.get(i).st == Unresolved)
    val cert = if (unresolved and RULES.honest) Bounded else Exact
    all {
      s.ended, s.report == Open, nothingInFlight, reportAllowed,
      s' = { ...s, report: cert,
             reportedExactWrongly: cert == Exact and (chargedT != realT or chargedM != realM) },
    }
  }

  action step = any { reserve, refuse, send, serve, answer, lose, crash, haloRestart, resolveLocal, end, finalReport }

  // ---- properties -------------------------------------------------------------------------------------------
  // the ledger never holds less than what was really spent
  val accounted: bool = realT <= chargedT and realM <= chargedM
  // no limit is passed in reality, each on its own
  val withinTokens: bool = realT <= TOKLIM
  val withinMoney: bool = realM <= MONLIM
  // an exact report is exact
  val exactIsExact: bool = not(s.reportedExactWrongly)
  // never stuck: an ended attempt with nothing in flight can always report, even when a local call can no longer be
  // resolved (halo lost it)
  val neverStuck: bool = not(and {
    s.ended, s.report == Open, nothingInFlight, not(reportAllowed),
    CALLS.forall(i => (s.calls.get(i).st == Unresolved and s.calls.get(i).route == Local) implies s.calls.get(i).gone),
  })
  val safety: bool = and { accounted, withinTokens, withinMoney, exactIsExact, neverStuck }

  // witnesses
  val wConcurrent: bool = CALLS.filter(i => s.calls.get(i).st == Sent).size() >= 2
  val wBounded: bool = s.report == Bounded
  val wExact: bool = s.report == Exact and CALLS.exists(i => s.calls.get(i).st == Answered)
  val wResolvedLocal: bool = s.resolved > 0
  val wLocalBounded: bool = s.report == Bounded and s.haloRestarts > 0 and
    CALLS.exists(i => s.calls.get(i).route == Local and s.calls.get(i).gone and s.calls.get(i).st == Unresolved)
  val wCrashThenServed: bool = s.crashes > 0 and CALLS.exists(i => s.calls.get(i).st == Unresolved and s.calls.get(i).served)
  val wLimitRefused: bool = s.refusals > 0
}
