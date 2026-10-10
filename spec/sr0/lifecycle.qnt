// SR0: the session suspend/resume lifecycle of yard-ctl.
//
// HARNESS.md "Milestones: suspend and resume", SR0. The model is the ground
// truth for internal/lifecycle: every controller action below has a Go
// function of the same name (lifecycle.Machine), and the replay test
// (internal/lifecycle/replay_test.go) drives the Go machine through ITF
// traces of this model and compares the state after every step.
//
// Every call that crosses a process boundary (the VMM or jail backend, the
// STS mint, a file delete) is an *op*: a durable op row (st Pending,
// Unknown, Done, NotDone) plus copies in flight in the environment, which
// may apply late (after a timeout, after a yard-ctl restart), apply with the
// answer lost, never apply, or be sent again (casselc/observability
// otel-chdb/model/TEMPLATE.md). The controller learns an outcome only from
// an answer to its own incarnation, or by observing the effect once no copy
// can still land (the settle bound: the op's process has exited).
//
// Each design rule is a const; its unsafe choice is a named mutant module at
// the end of this file. README.md has the register, the mapping table and
// the results.
module lifecycle {
  // ------------------------------------------------------------------ types
  type SessId = str
  type State = Active | Idle | Suspending | Suspended | Resuming | Expired | Failed
  // the backend kind: "jail" | "service" | "fc" | "bhyve" | "kv" (a string, so
  // instances can name it without a cyclic import)
  type Kind = str
  // Suspending: PQuiesce -> PCheckpoint -> PDestroy -> (commit) | PAbort.
  // Resuming:   PRestore -> PMint -> (complete).
  type Phase = PNone | PQuiesce | PCheckpoint | PDestroy | PAbort | PRestore | PMint
  type OpKind = OQuiesce | OCheckpoint | ODestroy | OUnquiesce | ORestore | OMint | ODelete
  type OpSt = Pending | Unknown | Done | NotDone
  type InstSt = Running | Paused

  // A durable op row. arg: the instance name (quiesce, destroy, unquiesce),
  // the checkpoint id (restore, delete), the credential epoch (mint). A
  // checkpoint's own id names its artifact (create-only path).
  type Op = { id: int, kind: OpKind, sess: SessId, gen: int, arg: int, st: OpSt,
              sentAt: int, attempts: int, inc: int }
  // A request in flight: the effect may still apply. inc: the yard-ctl
  // incarnation that sent it (its answer reaches only that incarnation).
  type Copy = { op: int, attempt: int, inc: int, sentAt: int }
  // A live VM / jail / service instance. name: the generation it was
  // restored from (0: the original). Unique per session: the create-only
  // key a restore uses.
  type Inst = { name: int, st: InstSt }
  // A credential as the broker holds it for the session.
  type Cred = { epoch: int, reqAt: int, mintedAt: int }
  // A suspend artifact (memory file, service spec, KV spill) on the
  // encrypted dataset zroot/yard/data. ok = false: partial (killed mid-write).
  type Artifact = { sess: SessId, gen: int, ckpt: int, ok: bool, enc: bool, at: int, creds: Set[Cred] }

  // The SQLite sessions row.
  type Row = {
    state: State, kind: Kind, gen: int, phase: Phase,
    inst: int,          // name of the session's current instance
    ckpt: int,          // id of the current checkpoint op (its artifact), 0 none
    op: int,            // the op the current phase waits on, 0 none
    token: int,         // one-shot resume token, 0 none
    credEpoch: int,     // bumped at suspend; the STS mints only this epoch
    decidedAt: int,     // when the suspend was decided
    decidedSeq: int,    // the activity sequence the decision saw
    quiescedAt: int,    // when quiesce was known done
    suspendedAt: int,
    resumes: int,
    inbox: int,         // messages / approvals held for the session
  }

  // yard-ctl's view of activity (volatile): the last answered observation.
  type Obs = { pending: bool, reqAt: int, seq: int, seenAt: int, ansReqAt: int }

  // The environment per session: instances, workspace, activity.
  type World = {
    insts: Set[Inst],
    live: Set[int],       // the workspace dataset's contents (write ids)
    acked: Set[int],      // writes the harness saw acknowledged
    inflight: Set[int],   // writes issued, not landed
    actSeq: int,          // activity counter (model calls, tool calls)
    lastAct: int,         // time of the last activity
    creds: Set[Cred],
  }

  type Policy = { keepWarm: bool, maxAge: int }

  type Sys = {
    clock: int, ctlUp: bool, ctlInc: int,
    rows: SessId -> Row,
    ops: int -> Op,
    drivers: SessId -> Set[str],
    checked: SessId -> Set[str],      // nonAtomicConsume only: checked, not yet claimed
    obs: SessId -> Obs,
    copies: Set[Copy],
    world: SessId -> World,
    artifacts: Set[Artifact],
    snaps: int -> Set[int],           // ZFS snapshot (by checkpoint id) -> workspace contents
    starts: int -> int,               // instances started from each checkpoint
    claims: int -> int,               // successful claims of each resume token
    nextOp: int, nextToken: int, nextWrite: int,
    faults: int,                      // environment faults so far (bounded by MAX_FAULTS)
    msgs: int,                        // messages arrived so far (bounded by MAX_INBOX)
    last: str,                        // the last action (for witnesses)
  }

  // ------------------------------------------------------------- constants
  const SESSIONS: Set[SessId]
  const CLIENTS: Set[str]             // resume triggers (message, approval, timer)
  const KIND: SessId -> Kind
  const POLICY: SessId -> Policy
  const IDLE_TIMEOUT: int
  const OP_TIMEOUT: int
  const CRED_TTL: int
  const MAX_TIME: int
  const MAX_GEN: int
  const MAX_OPS: int
  const MAX_TOKENS: int
  const MAX_WRITES: int
  const MAX_ACT: int
  const MAX_INBOX: int              // messages per trace
  const MAX_ATTEMPTS: int
  const MAX_FAULTS: int             // per-trace budget of faults (lost copies, crashes, partial writes)
  // Design rules (true); false is the named mutant.
  const ATOMIC_CONSUME: bool        // token consume is one conditional UPDATE (nonAtomicConsume)
  const RESTORE_FENCE: bool         // restore creates a create-only instance name, retried only after verify (blindRestoreRetry)
  const DESTROY_SETTLE: bool        // commit only once the original instance is known gone (commitBeforeDestroy)
  const QUIESCE_SETTLE: bool        // checkpoint only once quiesce is known done (snapshotBeforeQuiesce)
  const CRED_EPOCH: bool            // the STS mints only the current epoch; the broker honours only it (noCredEpoch)
  const CKPT_TIMEOUT_UNKNOWN: bool  // a checkpoint timeout is unknown, not "not done" (checkpointTimeoutNotDone)
  const DELETE_OWED: bool           // a delete is an op row retried until observed (fireAndForgetDelete)
  const GC_BY_ROW: bool             // artifacts are deleted for rows, never by age (gcByAge)
  const OBS_AT_ANSWER: bool         // activity is dated when the answer arrives (observeAtRequest)
  const RECHECK_ACTIVITY: bool      // commit re-reads activity after quiesce (ignoreActivityDuringSuspend)
  const EXPIRE_CHECKS_INBOX: bool   // TTL expiry never drops held messages (expireDropsInbox)
  const RECOVER_UNKNOWN: bool       // after a restart, a pending op is unknown (recoverAssumesNotDone)

  pure val IDLER: str = "idler"
  pure val RECOVERY: str = "recovery"
  pure val DRIVERS: Set[str] = CLIENTS.union(Set(IDLER, RECOVERY))
  pure val SUSPEND_FAMILY: Set[State] = Set(Suspending, Suspended, Resuming)

  // ----------------------------------------------------------------- state
  var y: Sys

  // --------------------------------------------------------------- helpers
  pure def getOr(m: int -> int, k: int): int = if (m.keys().contains(k)) m.get(k) else 0
  pure def row(y: Sys, s: SessId): Row = y.rows.get(s)
  pure def wld(y: Sys, s: SessId): World = y.world.get(s)
  pure def opOf(y: Sys, id: int): Op = y.ops.get(id)
  pure def hasOp(y: Sys, id: int): bool = y.ops.keys().contains(id)
  pure def opSt(y: Sys, id: int): OpSt = if (hasOp(y, id)) y.ops.get(id).st else NotDone
  pure def setRow(y: Sys, s: SessId, r: Row): Sys = { ...y, rows: y.rows.set(s, r) }
  pure def setWorld(y: Sys, s: SessId, w: World): Sys = { ...y, world: y.world.set(s, w) }
  pure def setOp(y: Sys, o: Op): Sys = { ...y, ops: y.ops.put(o.id, o) }
  pure def hasInst(y: Sys, s: SessId, name: int): bool = wld(y, s).insts.exists(i => i.name == name)
  pure def running(y: Sys, s: SessId): bool = wld(y, s).insts.exists(i => i.st == Running)
  // settled: no copy of the op can still apply (its process has exited)
  pure def settled(y: Sys, id: int): bool = not(y.copies.exists(c => c.op == id))
  pure def resolved(y: Sys, id: int): bool = id == 0 or opSt(y, id) == Done or opSt(y, id) == NotDone
  pure def ckptOk(y: Sys, s: SessId, ckpt: int): bool =
    y.artifacts.exists(a => a.sess == s and a.ckpt == ckpt and a.ok)

  // Send a new op: a row (Pending) and its first copy.
  pure def newOp(y: Sys, k: OpKind, s: SessId, gen: int, arg: int): Sys = {
    val o = { id: y.nextOp, kind: k, sess: s, gen: gen, arg: arg, st: Pending,
              sentAt: y.clock, attempts: 1, inc: y.ctlInc }
    { ...y, ops: y.ops.put(o.id, o), nextOp: y.nextOp + 1,
      copies: y.copies.union(Set({ op: o.id, attempt: 1, inc: y.ctlInc, sentAt: y.clock })) }
  }
  // A delete of a checkpoint's artifacts. With DELETE_OWED it is an op that
  // stays owed until observed; the mutant fires it and records it as done.
  pure def issueDelete(y: Sys, s: SessId, ckpt: int): Sys =
    if (ckpt == 0) y
    else {
      val y1 = newOp(y, ODelete, s, row(y, s).gen, ckpt)
      if (DELETE_OWED) y1 else setOp(y1, { ...opOf(y1, y.nextOp), st: Done })
    }

  // The broker honours a credential: by epoch (design) or by TTL alone.
  pure def honored(y: Sys, s: SessId, c: Cred): bool =
    if (CRED_EPOCH) c.epoch == row(y, s).credEpoch else y.clock < c.mintedAt + CRED_TTL

  // ------------------------------------------- effects and observations
  // The effect of one copy of an op, applied by the backend / STS / fs.
  pure def effect(y: Sys, o: Op, c: Copy, partial: bool): Sys = {
    val s = o.sess
    val w = wld(y, s)
    match o.kind {
      | OQuiesce =>
          // jail_remove + wait for exit / FC pause: in-flight writes die
          setWorld(y, s, { ...w, inflight: Set(),
            insts: w.insts.map(i => if (i.name == o.arg) { ...i, st: Paused } else i) })
      | OUnquiesce =>
          setWorld(y, s, { ...w, insts: w.insts.map(i => if (i.name == o.arg) { ...i, st: Running } else i) })
      | ODestroy =>
          setWorld(y, s, { ...w, insts: w.insts.filter(i => i.name != o.arg) })
      | OCheckpoint =>
          // the ZFS snapshot plus the memory/spec/KV artifact; needs an instance
          if (w.insts.size() == 0) y
          else {
            val a = { sess: s, gen: o.gen, ckpt: o.id, ok: not(partial), enc: true, at: y.clock, creds: w.creds }
            { ...y, artifacts: y.artifacts.union(Set(a)),
              snaps: if (partial) y.snaps else y.snaps.put(o.id, w.live) }
          }
      | ORestore =>
          // create instance `gen` from checkpoint `arg`; the name is
          // create-only with RESTORE_FENCE
          if ((RESTORE_FENCE and hasInst(y, s, o.gen)) or not(ckptOk(y, s, o.arg))) y
          else {
            val a = y.artifacts.filter(x => x.sess == s and x.ckpt == o.arg and x.ok)
            val creds = a.fold(Set(), (acc, x) => acc.union(x.creds))
            val y1 = setWorld(y, s, { ...w, insts: w.insts.union(Set({ name: o.gen, st: Running })),
                                      live: y.snaps.get(o.arg), creds: creds, inflight: Set() })
            { ...y1, starts: y1.starts.put(o.arg, getOr(y1.starts, o.arg) + 1) }
          }
      | OMint =>
          // the STS refuses an epoch other than the row's (CRED_EPOCH)
          if (CRED_EPOCH and o.arg != row(y, s).credEpoch) y
          else setWorld(y, s, { ...w, creds: w.creds.union(Set({ epoch: o.arg, reqAt: c.sentAt, mintedAt: y.clock })) })
      | ODelete =>
          { ...y, artifacts: y.artifacts.filter(a => not(a.sess == s and a.ckpt == o.arg)) }
    }
  }

  // The resolving observation of each op kind (backend probe, digest check,
  // directory listing, the broker's credential list).
  pure def observedDone(y: Sys, o: Op): bool = {
    val s = o.sess
    val w = wld(y, s)
    match o.kind {
      | OQuiesce => not(w.insts.exists(i => i.name == o.arg and i.st == Running))
      | OUnquiesce => w.insts.exists(i => i.name == o.arg and i.st == Running)
      | ODestroy => not(hasInst(y, s, o.arg))
      | OCheckpoint => ckptOk(y, s, o.id)
      | ORestore => hasInst(y, s, o.gen)
      | OMint => w.creds.exists(c => c.epoch == o.arg)
      | ODelete => not(y.artifacts.exists(a => a.sess == s and a.ckpt == o.arg))
    }
  }

  // ===================================================== environment
  pure def canOpLand(y: Sys, c: Copy): bool = y.copies.contains(c)
  // late effect, answer delivered only to the incarnation that sent it. The
  // process exits 0 iff the effect holds (an idempotent create of an
  // existing name included); any failure exit is an error: unknown.
  pure def applyOpLand(y: Sys, c: Copy): Sys = {
    val o = opOf(y, c.op)
    val y1 = { ...effect(y, o, c, false), copies: y.copies.exclude(Set(c)) }
    val heard = y.ctlUp and c.inc == y.ctlInc and o.st == Pending
    if (heard) setOp(y1, { ...opOf(y1, c.op), st: if (observedDone(y1, o)) Done else Unknown }) else y1
  }
  // lost answer: applies; the caller hears nothing or an error
  pure def canFault(y: Sys): bool = y.faults < MAX_FAULTS
  pure def fault(y: Sys): Sys = { ...y, faults: y.faults + 1 }
  pure def applyOpLandAnswerLost(y: Sys, c: Copy): Sys =
    fault({ ...effect(y, opOf(y, c.op), c, false), copies: y.copies.exclude(Set(c)) })
  // a checkpoint killed mid-write leaves a partial artifact
  pure def canOpLandPartial(y: Sys, c: Copy): bool = canFault(y) and y.copies.contains(c) and opOf(y, c.op).kind == OCheckpoint
  pure def applyOpLandPartial(y: Sys, c: Copy): Sys =
    fault({ ...effect(y, opOf(y, c.op), c, true), copies: y.copies.exclude(Set(c)) })
  // lost request
  pure def applyOpLose(y: Sys, c: Copy): Sys = fault({ ...y, copies: y.copies.exclude(Set(c)) })

  pure def canTick(y: Sys): bool = y.clock < MAX_TIME
  pure def applyTick(y: Sys): Sys = { ...y, clock: y.clock + 1 }

  // harness activity inside a running instance (model call, tool call)
  pure def canActivity(y: Sys, s: SessId): bool = running(y, s) and wld(y, s).actSeq < MAX_ACT
  pure def applyActivity(y: Sys, s: SessId): Sys = {
    val w = wld(y, s)
    setWorld(y, s, { ...w, actSeq: w.actSeq + 1, lastAct: y.clock })
  }
  // a tool call's workspace write: issued, then lands (acked) or lands with the ack lost
  pure def canWriteIssue(y: Sys, s: SessId): bool = running(y, s) and y.nextWrite <= MAX_WRITES
  pure def applyWriteIssue(y: Sys, s: SessId): Sys = {
    val w = wld(y, s)
    { ...setWorld(y, s, { ...w, inflight: w.inflight.union(Set(y.nextWrite)) }), nextWrite: y.nextWrite + 1 }
  }
  pure def canWriteLand(y: Sys, s: SessId, n: int): bool = running(y, s) and wld(y, s).inflight.contains(n)
  pure def applyWriteLand(y: Sys, s: SessId, n: int, ack: bool): Sys = {
    val w = wld(y, s)
    setWorld(y, s, { ...w, inflight: w.inflight.exclude(Set(n)), live: w.live.union(Set(n)),
                     acked: if (ack) w.acked.union(Set(n)) else w.acked })
  }
  // an inbound message / approval, held durably by yard-ctl
  pure def canMessageArrive(y: Sys, s: SessId): bool =
    y.ctlUp and not(Set(Expired, Failed).contains(row(y, s).state)) and y.msgs < MAX_INBOX
  pure def applyMessageArrive(y: Sys, s: SessId): Sys = { ...setRow(y, s, { ...row(y, s), inbox: row(y, s).inbox + 1 }), msgs: y.msgs + 1 }
  // an instance dies (VMM crash, OOM kill)
  pure def canInstanceCrash(y: Sys, s: SessId): bool = canFault(y) and wld(y, s).insts.size() > 0
  pure def applyInstanceCrash(y: Sys, s: SessId): Sys = fault(setWorld(y, s, { ...wld(y, s), insts: Set(), inflight: Set() }))
  // the answer to an activity observation (slow observation)
  pure def canObsAnswer(y: Sys, s: SessId): bool = y.ctlUp and y.obs.get(s).pending
  pure def applyObsAnswer(y: Sys, s: SessId): Sys = {
    val o = y.obs.get(s)
    val seq = wld(y, s).actSeq
    val seenAt = if (seq == o.seq) o.seenAt else if (OBS_AT_ANSWER) y.clock else o.reqAt
    { ...y, obs: y.obs.set(s, { pending: false, reqAt: o.reqAt, seq: seq, seenAt: seenAt, ansReqAt: o.reqAt }) }
  }
  // yard-ctl dies: drivers and observations (memory) are gone; rows, ops,
  // copies in flight and instances stay
  pure def canCtlCrash(y: Sys): bool = canFault(y) and y.ctlUp
  pure def applyCtlCrash(y: Sys): Sys = { ...y, ctlUp: false, faults: y.faults + 1,
    drivers: SESSIONS.mapBy(_ => Set()), checked: SESSIONS.mapBy(_ => Set()),
    obs: SESSIONS.mapBy(_ => { pending: false, reqAt: 0, seq: -1, seenAt: 0, ansReqAt: -1 }) }
  pure def canCtlRestart(y: Sys): bool = not(y.ctlUp)
  pure def applyCtlRestart(y: Sys): Sys = { ...y, ctlUp: true, ctlInc: y.ctlInc + 1 }

  // =================================================== controller: ops
  // OpTimeout: an op of this incarnation unanswered past OP_TIMEOUT is unknown
  pure def canOpTimeout(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and {
    val o = opOf(y, id)
    o.st == Pending and o.inc == y.ctlInc and y.clock >= o.sentAt + OP_TIMEOUT
  }
  pure def applyOpTimeout(y: Sys, id: int): Sys = {
    val o = opOf(y, id)
    val st = if (o.kind == OCheckpoint and not(CKPT_TIMEOUT_UNKNOWN)) NotDone else Unknown
    setOp(y, { ...o, st: st })
  }
  // OpResolve: once settled, observe the effect
  pure def canOpResolve(y: Sys, id: int): bool =
    y.ctlUp and hasOp(y, id) and opOf(y, id).st == Unknown and settled(y, id)
  pure def applyOpResolve(y: Sys, id: int, done: bool): Sys =
    setOp(y, { ...opOf(y, id), st: if (done) Done else NotDone })
  // OpRetry: idempotent retry of a resolved-not-done op
  pure val RETRYABLE: Set[OpKind] = Set(OQuiesce, ODestroy, OUnquiesce, OMint, ODelete)
  pure def canOpRetry(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and {
    val o = opOf(y, id)
    o.st == NotDone and RETRYABLE.contains(o.kind) and o.attempts < MAX_ATTEMPTS
  }
  pure def applyOpRetry(y: Sys, id: int): Sys = {
    val o = opOf(y, id)
    val n = o.attempts + 1
    { ...setOp(y, { ...o, st: Pending, attempts: n, sentAt: y.clock, inc: y.ctlInc }),
      copies: y.copies.union(Set({ op: id, attempt: n, inc: y.ctlInc, sentAt: y.clock })) }
  }
  // RecoverOps: after a restart, a pending op of an earlier incarnation
  // has an unknown outcome (the mutant assumes not done)
  pure def canRecoverOps(y: Sys, s: SessId): bool = y.ctlUp and
    y.ops.keys().exists(id => { val o = opOf(y, id) o.sess == s and o.st == Pending and o.inc < y.ctlInc })
  pure def applyRecoverOps(y: Sys, s: SessId): Sys = {
    val st = if (RECOVER_UNKNOWN) Unknown else NotDone
    { ...y, ops: y.ops.keys().mapBy(id => {
        val o = opOf(y, id)
        if (o.sess == s and o.st == Pending and o.inc < y.ctlInc) { ...o, st: st } else o }) }
  }
  // Adopt: a new driver takes over an in-flight row
  pure def canAdopt(y: Sys, s: SessId): bool = y.ctlUp and SUSPEND_FAMILY.exclude(Set(Suspended)).contains(row(y, s).state)
    and y.drivers.get(s) == Set() and not(canRecoverOps(y, s))
  pure def applyAdopt(y: Sys, s: SessId): Sys = { ...y, drivers: y.drivers.set(s, Set(RECOVERY)) }

  // ========================================= controller: activity
  pure def canObsReq(y: Sys, s: SessId): bool = y.ctlUp and not(y.obs.get(s).pending)
  pure def applyObsReq(y: Sys, s: SessId): Sys =
    { ...y, obs: y.obs.set(s, { ...y.obs.get(s), pending: true, reqAt: y.clock }) }
  pure def idleSeen(y: Sys, s: SessId): bool = {
    val o = y.obs.get(s)
    o.seq >= 0 and o.seenAt + IDLE_TIMEOUT <= y.clock
  }
  pure def canGoIdle(y: Sys, s: SessId): bool = y.ctlUp and row(y, s).state == Active and row(y, s).inbox == 0 and idleSeen(y, s)
  pure def applyGoIdle(y: Sys, s: SessId): Sys = setRow(y, s, { ...row(y, s), state: Idle })
  pure def canTouch(y: Sys, s: SessId): bool = y.ctlUp and row(y, s).state == Idle and (row(y, s).inbox > 0 or not(idleSeen(y, s)))
  pure def applyTouch(y: Sys, s: SessId): Sys = setRow(y, s, { ...row(y, s), state: Active })
  // Deliver: a held message reaches the running harness (atomic: see README)
  pure def canDeliver(y: Sys, s: SessId): bool = y.ctlUp and Set(Active, Idle).contains(row(y, s).state)
    and row(y, s).inbox > 0 and hasInst(y, s, row(y, s).inst) and running(y, s)
  pure def applyDeliver(y: Sys, s: SessId): Sys = {
    val w = wld(y, s)
    setWorld(setRow(y, s, { ...row(y, s), state: Active, inbox: row(y, s).inbox - 1 }), s,
             { ...w, actSeq: w.actSeq + 1, lastAct: y.clock })
  }
  // CredRefresh: the broker asks the STS for a fresh credential
  // (bounded to one refresh per credential epoch)
  pure def canCredRefresh(y: Sys, s: SessId): bool = y.ctlUp and Set(Active, Idle).contains(row(y, s).state) and y.nextOp <= MAX_OPS
    and not(y.ops.keys().exists(id => { val o = opOf(y, id) o.sess == s and o.kind == OMint and o.arg == row(y, s).credEpoch }))
  pure def applyCredRefresh(y: Sys, s: SessId): Sys = newOp(y, OMint, s, row(y, s).gen, row(y, s).credEpoch)

  // ========================================== controller: suspend
  pure def hasDriver(y: Sys, s: SessId): bool = y.ctlUp and y.drivers.get(s) != Set()
  pure def inPhase(y: Sys, s: SessId, st: State, p: Phase): bool = row(y, s).state == st and row(y, s).phase == p

  pure def canSuspendBegin(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    and { y.ctlUp, r.state == Idle, not(POLICY.get(s).keepWarm), r.gen < MAX_GEN, y.drivers.get(s) == Set(),
          r.inbox == 0, idleSeen(y, s), y.nextOp <= MAX_OPS }
  }
  pure def applySuspendBegin(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    val y1 = newOp(y, OQuiesce, s, r.gen + 1, r.inst)
    { ...setRow(y1, s, { ...r, state: Suspending, phase: PQuiesce, gen: r.gen + 1, ckpt: 0, op: y.nextOp,
                         decidedAt: y.clock, decidedSeq: y.obs.get(s).seq }),
      drivers: y.drivers.set(s, Set(IDLER)) }
  }
  pure def canSuspendCheckpoint(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PQuiesce)
    and y.nextOp <= MAX_OPS and (if (QUIESCE_SETTLE) opSt(y, row(y, s).op) == Done else true)
  pure def applySuspendCheckpoint(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    setRow(newOp(y, OCheckpoint, s, r.gen, 0), s, { ...r, phase: PCheckpoint, ckpt: y.nextOp, op: y.nextOp, quiescedAt: y.clock })
  }
  // a partial or missing checkpoint: delete it, take a new one
  pure def canSuspendCheckpointRetry(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PCheckpoint)
    and opSt(y, row(y, s).op) == NotDone and y.nextOp + 1 <= MAX_OPS
  pure def applySuspendCheckpointRetry(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    val y1 = issueDelete(y, s, r.ckpt)
    setRow(newOp(y1, OCheckpoint, s, r.gen, 0), s, { ...r, ckpt: y1.nextOp, op: y1.nextOp })
  }
  pure def canSuspendDestroy(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PCheckpoint)
    and opSt(y, row(y, s).op) == Done and y.nextOp <= MAX_OPS
  pure def applySuspendDestroy(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    setRow(newOp(y, ODestroy, s, r.gen, r.inst), s, { ...r, phase: PDestroy, op: y.nextOp })
  }
  pure def activityRechecked(y: Sys, s: SessId): bool = {
    val o = y.obs.get(s)
    val r = row(y, s)
    not(o.pending) and o.ansReqAt >= r.quiescedAt and o.seq == r.decidedSeq and r.inbox == 0
  }
  pure def canSuspendCommit(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PDestroy)
    and y.nextToken <= MAX_TOKENS
    and (if (DESTROY_SETTLE) opSt(y, row(y, s).op) == Done else true)
    and (if (RECHECK_ACTIVITY) activityRechecked(y, s) else true)
  pure def applySuspendCommit(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    { ...setRow(y, s, { ...r, state: Suspended, phase: PNone, op: 0, inst: 0, token: y.nextToken,
                        credEpoch: r.credEpoch + 1, suspendedAt: y.clock }),
      nextToken: y.nextToken + 1, drivers: y.drivers.set(s, Set()) }
  }
  // abort before commit, once the step in flight is settled and resolved
  pure def canSuspendAbort(y: Sys, s: SessId): bool = hasDriver(y, s) and row(y, s).state == Suspending
    and Set(PQuiesce, PCheckpoint, PDestroy).contains(row(y, s).phase)
    and resolved(y, row(y, s).op) and y.nextOp + 1 <= MAX_OPS
  pure def applySuspendAbort(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    val y1 = issueDelete(y, s, r.ckpt)
    setRow(newOp(y1, OUnquiesce, s, r.gen, r.inst), s, { ...r, phase: PAbort, op: y1.nextOp })
  }
  pure def canSuspendAbortDone(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PAbort)
    and opSt(y, row(y, s).op) == Done
  pure def applySuspendAbortDone(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Idle, phase: PNone, op: 0, ckpt: 0 }), drivers: y.drivers.set(s, Set()) }
  // the instance is gone: nothing to unquiesce
  pure def canSuspendFail(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Suspending, PAbort)
    and opSt(y, row(y, s).op) == NotDone and not(hasInst(y, s, row(y, s).inst))
  pure def applySuspendFail(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Failed, phase: PNone, op: 0, ckpt: 0 }), drivers: y.drivers.set(s, Set()) }

  // =========================================== controller: resume
  // ResumeConsume: UPDATE ... SET state='resuming' WHERE state='suspended' AND token=?
  pure def canResumeConsume(y: Sys, s: SessId, d: str, tok: int): bool = and {
    y.ctlUp, ATOMIC_CONSUME, CLIENTS.contains(d), row(y, s).state == Suspended,
    tok != 0, row(y, s).token == tok, y.nextOp <= MAX_OPS,
  }
  pure def claim(y: Sys, s: SessId, d: str, tok: int): Sys = {
    val r = row(y, s)
    val y1 = newOp(y, ORestore, s, r.gen, r.ckpt)
    { ...setRow(y1, s, { ...r, state: Resuming, phase: PRestore, token: 0, op: y.nextOp }),
      drivers: y.drivers.set(s, y.drivers.get(s).union(Set(d))),
      claims: y1.claims.put(tok, getOr(y1.claims, tok) + 1) }
  }
  pure def applyResumeConsume(y: Sys, s: SessId, d: str, tok: int): Sys = claim(y, s, d, tok)
  // the losing side of the race (or a stale token): the UPDATE matched no row
  pure def canResumeReject(y: Sys, s: SessId, d: str, tok: int): bool = and {
    y.ctlUp, CLIENTS.contains(d), tok >= 1, tok < y.nextToken,
    not(row(y, s).state == Suspended and row(y, s).token == tok),
  }
  // mutant nonAtomicConsume: SELECT, then UPDATE without the condition
  pure def canResumeCheck(y: Sys, s: SessId, d: str, tok: int): bool = and {
    y.ctlUp, not(ATOMIC_CONSUME), CLIENTS.contains(d), row(y, s).state == Suspended,
    tok != 0, row(y, s).token == tok, not(y.checked.get(s).contains(d)),
  }
  pure def applyResumeCheck(y: Sys, s: SessId, d: str, tok: int): Sys =
    { ...y, checked: y.checked.set(s, y.checked.get(s).union(Set(d))) }
  pure def canResumeClaim(y: Sys, s: SessId, d: str, tok: int): bool =
    y.ctlUp and y.checked.get(s).contains(d) and y.nextOp <= MAX_OPS
  pure def applyResumeClaim(y: Sys, s: SessId, d: str, tok: int): Sys = {
    val y1 = claim(y, s, d, tok)
    { ...y1, checked: y1.checked.set(s, y1.checked.get(s).exclude(Set(d))) }
  }
  pure def drives(y: Sys, s: SessId, d: str): bool = y.ctlUp and y.drivers.get(s).contains(d)
  pure def canResumeMint(y: Sys, s: SessId, d: str): bool = drives(y, s, d) and inPhase(y, s, Resuming, PRestore)
    and opSt(y, row(y, s).op) == Done and hasInst(y, s, row(y, s).gen) and y.nextOp <= MAX_OPS
  pure def applyResumeMint(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    setRow(newOp(y, OMint, s, r.gen, r.credEpoch), s, { ...r, phase: PMint, op: y.nextOp })
  }
  pure def canResumeComplete(y: Sys, s: SessId, d: str): bool = drives(y, s, d) and inPhase(y, s, Resuming, PMint)
    and opSt(y, row(y, s).op) == Done and hasInst(y, s, row(y, s).gen) and y.nextOp <= MAX_OPS
  pure def applyResumeComplete(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    val y1 = issueDelete(y, s, r.ckpt)
    { ...setRow(y1, s, { ...r, state: Active, phase: PNone, op: 0, ckpt: 0, inst: r.gen, resumes: r.resumes + 1 }),
      drivers: y.drivers.set(s, Set()) }
  }
  // restore known not done: back to suspended with a fresh token
  pure def canResumeAbort(y: Sys, s: SessId, d: str): bool = drives(y, s, d) and inPhase(y, s, Resuming, PRestore)
    and opSt(y, row(y, s).op) == NotDone and y.nextToken <= MAX_TOKENS
  pure def applyResumeAbort(y: Sys, s: SessId, d: str): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Suspended, phase: PNone, op: 0, token: y.nextToken }),
      nextToken: y.nextToken + 1, drivers: y.drivers.set(s, Set()) }
  // restored, then the instance died
  pure def canResumeFail(y: Sys, s: SessId, d: str): bool = drives(y, s, d) and row(y, s).state == Resuming
    and Set(PRestore, PMint).contains(row(y, s).phase)
    and (row(y, s).phase == PMint or opSt(y, row(y, s).op) == Done)
    and not(hasInst(y, s, row(y, s).gen)) and y.nextOp <= MAX_OPS
  pure def applyResumeFail(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    val y1 = issueDelete(y, s, r.ckpt)
    { ...setRow(y1, s, { ...r, state: Failed, phase: PNone, op: 0, ckpt: 0 }), drivers: y.drivers.set(s, Set()) }
  }
  // mutant blindRestoreRetry: resend the restore on an unknown outcome
  pure def canRestoreBlindRetry(y: Sys, s: SessId, d: str): bool = not(RESTORE_FENCE) and drives(y, s, d)
    and inPhase(y, s, Resuming, PRestore) and opSt(y, row(y, s).op) == Unknown
    and opOf(y, row(y, s).op).attempts < MAX_ATTEMPTS
  pure def applyRestoreBlindRetry(y: Sys, s: SessId, d: str): Sys = {
    val o = opOf(y, row(y, s).op)
    val n = o.attempts + 1
    { ...setOp(y, { ...o, st: Pending, attempts: n, sentAt: y.clock, inc: y.ctlInc }),
      copies: y.copies.union(Set({ op: o.id, attempt: n, inc: y.ctlInc, sentAt: y.clock })) }
  }

  // ================================================ controller: TTL
  // Expire: UPDATE ... SET state='expired' WHERE state='suspended' AND id=? AND inbox=0
  pure def canExpire(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    and { y.ctlUp, r.state == Suspended, y.clock >= r.suspendedAt + POLICY.get(s).maxAge,
          if (EXPIRE_CHECKS_INBOX) r.inbox == 0 else true, y.nextOp <= MAX_OPS }
  }
  pure def applyExpire(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    setRow(issueDelete(y, s, r.ckpt), s, { ...r, state: Expired, token: 0, ckpt: 0 })
  }
  // mutant gcByAge: a sweeper deletes artifacts older than the TTL
  pure def canGcSweep(y: Sys, s: SessId): bool = y.ctlUp and not(GC_BY_ROW)
    and y.artifacts.exists(a => a.sess == s and y.clock >= a.at + POLICY.get(s).maxAge)
  pure def applyGcSweep(y: Sys, s: SessId): Sys =
    { ...y, artifacts: y.artifacts.filter(a => not(a.sess == s and y.clock >= a.at + POLICY.get(s).maxAge)) }

  // ================================================================ init
  action init = {
    nondet s0 = SESSIONS.oneOf()
    y' = {
      clock: 0, ctlUp: true, ctlInc: 1,
      rows: SESSIONS.mapBy(s => { state: Active, kind: KIND.get(s), gen: 0, phase: PNone, inst: 0, ckpt: 0, op: 0,
                                  token: 0, credEpoch: 1, decidedAt: 0, decidedSeq: 0, quiescedAt: 0,
                                  suspendedAt: 0, resumes: 0, inbox: 0 }),
      ops: Map(),
      drivers: SESSIONS.mapBy(_ => Set()),
      checked: SESSIONS.mapBy(_ => Set()),
      obs: SESSIONS.mapBy(_ => { pending: false, reqAt: 0, seq: -1, seenAt: 0, ansReqAt: -1 }),
      copies: Set(),
      world: SESSIONS.mapBy(_ => { insts: Set({ name: 0, st: Running }), live: Set(), acked: Set(), inflight: Set(),
                                   actSeq: 0, lastAct: 0, creds: Set({ epoch: 1, reqAt: 0, mintedAt: 0 }) }),
      artifacts: Set(),
      snaps: Map(),
      starts: Map(),
      claims: Map(),
      nextOp: 1, nextToken: 1, nextWrite: 1, faults: 0, msgs: 0,
      last: "init",
    }
  }

  // ============================================================= actions
  // Environment
  action Tick = all { canTick(y), y' = { ...applyTick(y), last: "Tick" } }
  action OpLand(c: Copy): bool = all { canOpLand(y, c), y' = { ...applyOpLand(y, c), last: "OpLand" } }
  action OpLandAnswerLost(c: Copy): bool = all { canFault(y), canOpLand(y, c), y' = { ...applyOpLandAnswerLost(y, c), last: "OpLandAnswerLost" } }
  action OpLandPartial(c: Copy): bool = all { canOpLandPartial(y, c), y' = { ...applyOpLandPartial(y, c), last: "OpLandPartial" } }
  action OpLose(c: Copy): bool = all { canFault(y), canOpLand(y, c), y' = { ...applyOpLose(y, c), last: "OpLose" } }
  action Activity(s: SessId): bool = all { canActivity(y, s), y' = { ...applyActivity(y, s), last: "Activity" } }
  action WriteIssue(s: SessId): bool = all { canWriteIssue(y, s), y' = { ...applyWriteIssue(y, s), last: "WriteIssue" } }
  action WriteLand(s: SessId, n: int): bool = all { canWriteLand(y, s, n), y' = { ...applyWriteLand(y, s, n, true), last: "WriteLand" } }
  action WriteLandAckLost(s: SessId, n: int): bool = all { canWriteLand(y, s, n), y' = { ...applyWriteLand(y, s, n, false), last: "WriteLandAckLost" } }
  action MessageArrive(s: SessId): bool = all { canMessageArrive(y, s), y' = { ...applyMessageArrive(y, s), last: "MessageArrive" } }
  action InstanceCrash(s: SessId): bool = all { canInstanceCrash(y, s), y' = { ...applyInstanceCrash(y, s), last: "InstanceCrash" } }
  action ObsAnswer(s: SessId): bool = all { canObsAnswer(y, s), y' = { ...applyObsAnswer(y, s), last: "ObsAnswer" } }
  action CtlCrash = all { canCtlCrash(y), y' = { ...applyCtlCrash(y), last: "CtlCrash" } }
  action CtlRestart = all { canCtlRestart(y), y' = { ...applyCtlRestart(y), last: "CtlRestart" } }

  // Controller (yard-ctl; Go lifecycle.Machine methods of the same names)
  action OpTimeout(id: int): bool = all { canOpTimeout(y, id), y' = { ...applyOpTimeout(y, id), last: "OpTimeout" } }
  action OpResolve(id: int): bool = all { canOpResolve(y, id), y' = { ...applyOpResolve(y, id, observedDone(y, opOf(y, id))), last: "OpResolve" } }
  action OpRetry(id: int): bool = all { canOpRetry(y, id), y' = { ...applyOpRetry(y, id), last: "OpRetry" } }
  action RecoverOps(s: SessId): bool = all { canRecoverOps(y, s), y' = { ...applyRecoverOps(y, s), last: "RecoverOps" } }
  action Adopt(s: SessId): bool = all { canAdopt(y, s), y' = { ...applyAdopt(y, s), last: "Adopt" } }
  action ObsReq(s: SessId): bool = all { canObsReq(y, s), y' = { ...applyObsReq(y, s), last: "ObsReq" } }
  action GoIdle(s: SessId): bool = all { canGoIdle(y, s), y' = { ...applyGoIdle(y, s), last: "GoIdle" } }
  action Touch(s: SessId): bool = all { canTouch(y, s), y' = { ...applyTouch(y, s), last: "Touch" } }
  action Deliver(s: SessId): bool = all { canDeliver(y, s), y' = { ...applyDeliver(y, s), last: "Deliver" } }
  action CredRefresh(s: SessId): bool = all { canCredRefresh(y, s), y' = { ...applyCredRefresh(y, s), last: "CredRefresh" } }
  action SuspendBegin(s: SessId): bool = all { canSuspendBegin(y, s), y' = { ...applySuspendBegin(y, s), last: "SuspendBegin" } }
  action SuspendCheckpoint(s: SessId): bool = all { canSuspendCheckpoint(y, s), y' = { ...applySuspendCheckpoint(y, s), last: "SuspendCheckpoint" } }
  action SuspendCheckpointRetry(s: SessId): bool = all { canSuspendCheckpointRetry(y, s), y' = { ...applySuspendCheckpointRetry(y, s), last: "SuspendCheckpointRetry" } }
  action SuspendDestroy(s: SessId): bool = all { canSuspendDestroy(y, s), y' = { ...applySuspendDestroy(y, s), last: "SuspendDestroy" } }
  action SuspendCommit(s: SessId): bool = all { canSuspendCommit(y, s), y' = { ...applySuspendCommit(y, s), last: "SuspendCommit" } }
  action SuspendAbort(s: SessId): bool = all { canSuspendAbort(y, s), y' = { ...applySuspendAbort(y, s), last: "SuspendAbort" } }
  action SuspendAbortDone(s: SessId): bool = all { canSuspendAbortDone(y, s), y' = { ...applySuspendAbortDone(y, s), last: "SuspendAbortDone" } }
  action SuspendFail(s: SessId): bool = all { canSuspendFail(y, s), y' = { ...applySuspendFail(y, s), last: "SuspendFail" } }
  action ResumeConsume(s: SessId, d: str, tok: int): bool = all { canResumeConsume(y, s, d, tok), y' = { ...applyResumeConsume(y, s, d, tok), last: "ResumeConsume" } }
  action ResumeReject(s: SessId, d: str, tok: int): bool = all { canResumeReject(y, s, d, tok), y' = { ...y, last: "ResumeReject" } }
  action ResumeCheck(s: SessId, d: str, tok: int): bool = all { canResumeCheck(y, s, d, tok), y' = { ...applyResumeCheck(y, s, d, tok), last: "ResumeCheck" } }
  action ResumeClaim(s: SessId, d: str, tok: int): bool = all { canResumeClaim(y, s, d, tok), y' = { ...applyResumeClaim(y, s, d, tok), last: "ResumeClaim" } }
  action ResumeMint(s: SessId, d: str): bool = all { canResumeMint(y, s, d), y' = { ...applyResumeMint(y, s, d), last: "ResumeMint" } }
  action ResumeComplete(s: SessId, d: str): bool = all { canResumeComplete(y, s, d), y' = { ...applyResumeComplete(y, s, d), last: "ResumeComplete" } }
  action ResumeAbort(s: SessId, d: str): bool = all { canResumeAbort(y, s, d), y' = { ...applyResumeAbort(y, s, d), last: "ResumeAbort" } }
  action ResumeFail(s: SessId, d: str): bool = all { canResumeFail(y, s, d), y' = { ...applyResumeFail(y, s, d), last: "ResumeFail" } }
  action RestoreBlindRetry(s: SessId, d: str): bool = all { canRestoreBlindRetry(y, s, d), y' = { ...applyRestoreBlindRetry(y, s, d), last: "RestoreBlindRetry" } }
  action Expire(s: SessId): bool = all { canExpire(y, s), y' = { ...applyExpire(y, s), last: "Expire" } }
  action GcSweep(s: SessId): bool = all { canGcSweep(y, s), y' = { ...applyGcSweep(y, s), last: "GcSweep" } }

  action envStep = {
    nondet s = SESSIONS.oneOf()
    nondet n = 1.to(MAX_WRITES).oneOf()
    any {
      Activity(s), WriteIssue(s), WriteLand(s, n), WriteLandAckLost(s, n),
      MessageArrive(s), InstanceCrash(s), ObsAnswer(s), CtlCrash, CtlRestart,
    }
  }
  action copyStep = {
    nondet c = y.copies.oneOf()
    any { OpLand(c), OpLandAnswerLost(c), OpLandPartial(c), OpLose(c) }
  }
  action ctlStep = {
    nondet s = SESSIONS.oneOf()
    nondet d = DRIVERS.oneOf()
    nondet tok = 1.to(MAX_TOKENS).oneOf()
    nondet id = 1.to(MAX_OPS).oneOf()
    any {
      OpTimeout(id), OpResolve(id), OpRetry(id), RecoverOps(s), Adopt(s),
      ObsReq(s), GoIdle(s), Touch(s), Deliver(s), CredRefresh(s),
      SuspendBegin(s), SuspendCheckpoint(s), SuspendCheckpointRetry(s), SuspendDestroy(s),
      SuspendCommit(s), SuspendAbort(s), SuspendAbortDone(s), SuspendFail(s),
      ResumeConsume(s, d, tok), ResumeReject(s, d, tok), ResumeCheck(s, d, tok), ResumeClaim(s, d, tok),
      ResumeMint(s, d), ResumeComplete(s, d), ResumeAbort(s, d), ResumeFail(s, d), RestoreBlindRetry(s, d),
      Expire(s), GcSweep(s),
    }
  }
  action step = any { Tick, envStep, copyStep, ctlStep }

  // Focused steps: each is a restriction of `step` (a subset of its actions,
  // or an action with an extra guard), so every trace they produce is a
  // trace of the full model. They bias random runs toward a narrow
  // interleaving (run_models.sh, the focused rows of README.md).
  action landStep = { nondet c = y.copies.oneOf() OpLand(c) }
  // activity observations are answered in every focused step
  action obsStep = { nondet s = SESSIONS.oneOf() ObsAnswer(s) }
  // no faults, no harness noise
  action stepQuiet = any { Tick, landStep, obsStep, ctlStep }
  // ... plus tool-call writes
  action stepWrites = {
    nondet s = SESSIONS.oneOf()
    nondet n = 1.to(MAX_WRITES).oneOf()
    any { Tick, landStep, obsStep, ctlStep, WriteIssue(s), WriteLand(s, n) }
  }
  // ... plus yard-ctl crashes and restarts
  action stepCrash = any { Tick, landStep, obsStep, ctlStep, CtlCrash, CtlRestart }
  // ... plus messages, arriving only while the session is suspended
  action stepInbox = {
    nondet s = SESSIONS.oneOf()
    any { Tick, landStep, obsStep, ctlStep, all { row(y, s).state == Suspended, MessageArrive(s) } }
  }

  // ========================================================== invariants
  // I1 a snapshot is resumed at most once: each token claimed at most once,
  // each checkpoint started at most once, at most one live instance.
  val tokenClaimedOnce: bool = y.claims.keys().forall(t => y.claims.get(t) <= 1)
  val restoredOnce: bool = y.starts.keys().forall(k => y.starts.get(k) <= 1)
  val oneInstance: bool = SESSIONS.forall(s => wld(y, s).insts.size() <= 1)
  val resumedAtMostOnce: bool = tokenClaimedOnce and restoredOnce and oneInstance

  // I2 no acknowledged workspace write is lost across suspend.
  val noAckedWriteLost: bool = SESSIONS.forall(s => {
    val r = row(y, s)
    val w = wld(y, s)
    if (r.state == Suspended) y.snaps.keys().contains(r.ckpt) and w.acked.subseteq(y.snaps.get(r.ckpt))
    else if (r.state == Expired) true
    else w.acked.subseteq(w.live)
  })

  // I3 a resumed session holds no honoured credential requested before it suspended.
  val noPreSuspendCredential: bool = SESSIONS.forall(s => {
    val r = row(y, s)
    (r.resumes > 0 and Set(Active, Idle).contains(r.state)) implies
      wld(y, s).creds.forall(c => honored(y, s, c) implies c.reqAt >= r.suspendedAt)
  })

  // I4 artifacts only on encrypted storage, and each either belongs to the
  // current suspend record or has a delete owed (an op row not yet done).
  pure def deleteOwed(y: Sys, a: Artifact): bool =
    y.ops.keys().exists(id => { val o = opOf(y, id) o.kind == ODelete and o.sess == a.sess and o.arg == a.ckpt and o.st != Done })
  val artifactsAccounted: bool = y.artifacts.forall(a => {
    val r = row(y, a.sess)
    and { a.enc, or { SUSPEND_FAMILY.contains(r.state) and a.ckpt == r.ckpt and a.gen == r.gen, deleteOwed(y, a) } }
  })

  // I5 a resume that holds the token finds its artifact until restored.
  val resumeKeepsArtifacts: bool = SESSIONS.forall(s => {
    val r = row(y, s)
    (r.state == Resuming and r.phase == PRestore and opSt(y, r.op) != Done) implies ckptOk(y, s, r.ckpt)
  })

  // I6 a session is suspended only after IDLE_TIMEOUT with no activity.
  val suspendedOnlyIdle: bool = SESSIONS.forall(s => {
    val r = row(y, s)
    r.state == Suspended implies wld(y, s).lastAct + IDLE_TIMEOUT <= r.decidedAt
  })

  // I7 TTL expiry never drops a held message.
  val noMessageLost: bool = SESSIONS.forall(s => row(y, s).state == Expired implies row(y, s).inbox == 0)

  val allInvariants: bool = and {
    resumedAtMostOnce, noAckedWriteLost, noPreSuspendCredential, artifactsAccounted,
    resumeKeepsArtifacts, suspendedOnlyIdle, noMessageLost,
  }

  // =========================================================== witnesses
  def stateSeen(st: State): bool = SESSIONS.exists(s => row(y, s).state == st)
  val wActive: bool = SESSIONS.exists(s => row(y, s).state == Active and row(y, s).resumes > 0)
  val wIdle: bool = stateSeen(Idle)
  val wSuspending: bool = stateSeen(Suspending)
  val wSuspended: bool = stateSeen(Suspended)
  val wResuming: bool = stateSeen(Resuming)
  val wExpired: bool = stateSeen(Expired)
  val wFailed: bool = stateSeen(Failed)
  val wResumedWithWrites: bool = SESSIONS.exists(s => row(y, s).resumes > 0 and wld(y, s).acked != Set())
  val wRaceRejected: bool = y.last == "ResumeReject" and stateSeen(Resuming)
  val wAbortedToIdle: bool = y.last == "SuspendAbortDone"
  val wResumeAborted: bool = y.last == "ResumeAbort"
  val wAdoptSuspending: bool = y.last == "Adopt" and stateSeen(Suspending)
  val wAdoptResuming: bool = y.last == "Adopt" and stateSeen(Resuming)
  val wRecoveredResume: bool = y.last == "ResumeComplete" and SESSIONS.exists(s => y.drivers.get(s) == Set() and row(y, s).resumes > 0)
    and y.ctlInc > 1
  val wResolvedUnknown: bool = y.last == "OpResolve"
  val wPartialRetried: bool = y.last == "SuspendCheckpointRetry"
  val wExpiredClean: bool = SESSIONS.exists(s => row(y, s).state == Expired and not(y.artifacts.exists(a => a.sess == s)))
  val wLateLand: bool = y.last == "OpLand" and y.ops.keys().exists(id => opOf(y, id).st == Unknown)
  val wHeldMessage: bool = SESSIONS.exists(s => row(y, s).state == Suspended and row(y, s).inbox > 0)
}

// ------------------------------------------------------------- instances
// The design: every rule on. One session (fc), keep-warm off.
module design {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// The design with two sessions (a jail service and a keep-warm KV session).
module design2 {
  import lifecycle(
    SESSIONS = Set("s1", "s2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "service", "s2" -> "kv"),
    POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }, "s2" -> { keepWarm: true, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// ---------------------------------------------------------------- mutants
// Each is the design with one rule off; README.md records which invariant
// breaks and the counterexample.

// nonAtomicConsume: the token check and the claim are separate statements (SELECT, then UPDATE). Breaks resumedAtMostOnce.
module nonAtomicConsume {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = false, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetry: a restore with an unknown outcome is resent at once, without a create-only instance name. Breaks resumedAtMostOnce.
module blindRestoreRetry {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = false, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// commitBeforeDestroy: commit once the destroy is sent, not once the original is known gone. Breaks resumedAtMostOnce.
module commitBeforeDestroy {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = false, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// snapshotBeforeQuiesce: checkpoint once quiesce is sent, before it settles. Breaks noAckedWriteLost.
module snapshotBeforeQuiesce {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = false,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpoch: credentials carry no epoch: the STS mints any request, the broker honours by TTL. Breaks noPreSuspendCredential.
module noCredEpoch {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = false, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// checkpointTimeoutNotDone: a checkpoint timeout is taken as not done. Breaks artifactsAccounted.
module checkpointTimeoutNotDone {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = false, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// fireAndForgetDelete: a delete is sent once and recorded as done. Breaks artifactsAccounted.
module fireAndForgetDelete {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = false, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// gcByAge: a sweeper deletes artifacts older than the TTL, whatever the row says. Breaks resumeKeepsArtifacts.
module gcByAge {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = false,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// observeAtRequest: new activity is dated when the observation was requested. Breaks suspendedOnlyIdle.
module observeAtRequest {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = false, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// ignoreActivityDuringSuspend: commit without re-reading activity (and held messages) after quiesce. Breaks suspendedOnlyIdle.
module ignoreActivityDuringSuspend {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = false, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInbox: TTL expiry ignores held messages. Breaks noMessageLost.
module expireDropsInbox {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = false, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// recoverAssumesNotDone: after a restart, a pending op is taken as not done. Breaks artifactsAccounted.
module recoverAssumesNotDone {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = false,
  ).* from "./lifecycle"
}

// ------------------------------------------------- focused instances
// For the mutants plain random runs miss: the same environment and focused
// step (`--step` in run_models.sh) for the mutant (`<m>Focus`) and the
// design (`<m>FocusDesign`), which must still hold.

// snapshotBeforeQuiesceFocus: step stepWrites; MAX_FAULTS 0, MAX_WRITES 4, MAX_ACT 0, MAX_INBOX 0
module snapshotBeforeQuiesceFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 4, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = false,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// snapshotBeforeQuiesceFocusDesign: step stepWrites; MAX_FAULTS 0, MAX_WRITES 4, MAX_ACT 0, MAX_INBOX 0
module snapshotBeforeQuiesceFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 4, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetryFocus: step stepQuiet; OP_TIMEOUT 1, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module blindRestoreRetryFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 1, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = false, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetryFocusDesign: step stepQuiet; OP_TIMEOUT 1, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module blindRestoreRetryFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 1, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpochFocus: step stepQuiet; CRED_TTL 100, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module noCredEpochFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 100, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = false, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpochFocusDesign: step stepQuiet; CRED_TTL 100, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module noCredEpochFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 100, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// recoverAssumesNotDoneFocus: step stepCrash; MAX_FAULTS 1, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module recoverAssumesNotDoneFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = false,
  ).* from "./lifecycle"
}

// recoverAssumesNotDoneFocusDesign: step stepCrash; MAX_FAULTS 1, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module recoverAssumesNotDoneFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInboxFocus: step stepInbox; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 2, maxAge 1
module expireDropsInboxFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 1 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 2, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = false, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInboxFocusDesign: step stepInbox; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 2, maxAge 1
module expireDropsInboxFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 1 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 2, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
}
