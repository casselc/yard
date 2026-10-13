// -*- mode: Bluespec; -*-
// clock.qnt: yard's deadline clock across yard-ctl restarts (design/AGENT-OPERATIONS.md section 3).
//
// Halo's deadlines are in its own clock, a monotonic clock that restarts with its incarnation, so a reset clock
// always comes with a new incarnation that every old copy is refused by. yard-ctl keeps its incarnation across a
// restart (its store survives), so its clock must too: deadlines (Halo-Not-After's analogue) are in Yard-Time, a
// logical clock that never goes backwards across restarts. yard-ctl persists a ceiling ahead of the times it hands
// out and, after a restart, resumes no lower than that ceiling.
//
// One attempt with a deadline, copies of its submit that arrive at any time (late ones included), its record
// pruned once the deadline has passed and its outcome is acknowledged, and restarts of yard-ctl, one of them close
// to the deadline. A copy is accepted only while Yard-Time is at or before the deadline and no record holds it.
//
// Rules (RULES; one mutant each in clock_modes.qnt):
//  persist   after a restart Yard-Time resumes at the persisted ceiling (the mutant: the process clock, from 0)
//  ahead     Yard-Time never passes the persisted ceiling (the ceiling is advanced, durably, first)
module clock {
  type Rules = { persist: bool, ahead: bool }
  const RULES: Rules

  pure val NOT_AFTER = 4
  pure val MAXT = 9
  pure val STEP = 3            // how far ahead the ceiling is persisted

  type RecSt = NoRec | Running | Done | Acked
  type S = {
    now: int, ceiling: int, issued: int,          // issued: the highest Yard-Time ever handed out (ghost)
    rec: RecSt, pruned: bool, runs: int,
    restarts: int, nearRestart: bool, lateRefused: int, prunedThenRefused: bool,
  }
  var s: S

  action init = s' = { now: 0, ceiling: STEP, issued: 0, rec: NoRec, pruned: false, runs: 0,
                       restarts: 0, nearRestart: false, lateRefused: 0, prunedThenRefused: false }

  // time passes. With `ahead`, the ceiling is persisted before Yard-Time would pass it
  action tick: bool = {
    val t = s.now + 1
    all { s.now < MAXT,
          if (RULES.ahead and t > s.ceiling) s' = { ...s, now: t, issued: t, ceiling: t + STEP }
          else s' = { ...s, now: t, issued: if (t > s.issued) t else s.issued } }
  }

  // the mutant persists the ceiling lazily: now and then, at the current time
  action persistLazily: bool = all { not(RULES.ahead), s' = { ...s, ceiling: s.now } }

  // a copy of the submit arrives, in any order and as late as it likes
  action submitCopy: bool = all {
    if (s.rec == NoRec and s.now <= NOT_AFTER) s' = { ...s, rec: Running, runs: s.runs + 1, pruned: false }
    else s' = { ...s, lateRefused: s.lateRefused + (if (s.rec == NoRec) 1 else 0),
                prunedThenRefused: s.prunedThenRefused or (s.rec == NoRec and s.pruned) },
  }

  action finish: bool = all { s.rec == Running, s' = { ...s, rec: Done } }
  action ack: bool = all { s.rec == Done, s' = { ...s, rec: Acked } }

  // the record (the tombstone of an acknowledged attempt) is pruned once its deadline has passed
  action prune: bool = all { s.rec == Acked, s.now > NOT_AFTER, s' = { ...s, rec: NoRec, pruned: true } }

  // yard-ctl restarts; the store (the record, the ceiling) survives, the incarnation is unchanged
  action restart: bool = all {
    s.restarts < 2,
    s' = { ...s, now: if (RULES.persist) s.ceiling else 0, restarts: s.restarts + 1,
           nearRestart: s.nearRestart or (s.now >= NOT_AFTER - 1 and s.now <= NOT_AFTER + 1) },
  }

  action step = any { tick, persistLazily, submitCopy, finish, ack, prune, restart }

  // ---- properties -------------------------------------------------------------------------------------------
  // an attempt runs at most once, whatever copies arrive and whenever yard-ctl restarts
  val runsOnce: bool = s.runs <= 1
  // Yard-Time never goes back below a time it already handed out
  val monotone: bool = s.now >= s.issued or s.restarts == 0
  val safety: bool = and { runsOnce, monotone }

  // witnesses
  val wNearDeadlineRestart: bool = s.nearRestart and s.runs == 1 and s.lateRefused > 0
  val wPrunedThenRefused: bool = s.prunedThenRefused
  val wAccepted: bool = s.runs == 1 and s.rec == Acked
}
