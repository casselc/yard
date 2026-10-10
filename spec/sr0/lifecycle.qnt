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
  type State = Active | Idle | Paused | Suspending | Suspended | Resuming | Expired | Failed
  // the backend kind: "jail" | "service" | "fc" | "bhyve" | "kv" (a string, so
  // instances can name it without a cyclic import)
  type Kind = str
  // Suspending: PQuiesce -> PCheckpoint -> PDestroy -> (commit) | PAbort.
  // Resuming:   [PKey ->] PRestore -> PMint -> (complete). PKey (SR1
  //             workspace keys): load the project key and mount the session's
  //             clone, only for a session with a project.
  // Paused (SR1 pause tier, SIGSTOP): PPause -> PNone -> PUnpause -> Idle.
  type Phase = PNone | PQuiesce | PCheckpoint | PDestroy | PAbort | PRestore | PMint | PPause | PUnpause | PKey
  // OLoadKey (session op): `zfs load-key` of the project root from stdin,
  // then mount the session clone. OUnmount, OUnloadKey (project ops: the op's
  // sess field is the project): unmount every dataset of the project, then
  // `zfs unload-key` of its root.
  type OpKind = OQuiesce | OCheckpoint | ODestroy | OUnquiesce | ORestore | OMint | ODelete | OPause | OUnpause
              | OLoadKey | OUnmount | OUnloadKey
  // Refused: a definite answer "refused, nothing done" (SR1 decision 2: the
  // restore refuses a workspace changed since the suspend snapshot).
  type OpSt = Pending | Unknown | Done | NotDone | Refused
  type InstSt = Running | Stopped

  // A durable op row. arg: the instance name (quiesce, destroy, unquiesce),
  // the checkpoint id (restore, delete), the credential epoch (mint). A
  // checkpoint's own id names its artifact (create-only path).
  // force: a restore with the explicit override (resume on a changed workspace).
  type Op = { id: int, kind: OpKind, sess: SessId, gen: int, arg: int, st: OpSt,
              sentAt: int, attempts: int, inc: int, force: bool }
  // A request in flight: the effect may still apply. inc: the yard-ctl
  // incarnation that sent it (its answer reaches only that incarnation).
  type Copy = { op: int, attempt: int, inc: int, sentAt: int }
  // A live VM / jail / service instance. name: the generation it was
  // restored from (0: the original). Unique per session: the create-only
  // key a restore uses. st Stopped: quiesced (SR1: every process stopped and
  // gone; FC/bhyve: VM paused). frozen: the SR1 pause tier stopped its
  // processes (SIGSTOP); they hold their memory but run nothing.
  type Inst = { name: int, st: InstSt, frozen: bool }
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
    force: bool,        // the current resume carries the override (decision 2)
    drift: bool,        // outcome: the last resume was refused, the workspace changed
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
    mounted: bool,        // SR1: the session's workspace clone is mounted
  }

  // SR1 workspace keys: yard-ctl's durable record of a project's key
  // (ws/<project> is an encryption root with a raw key held by yard-ctl).
  // loaded: yard-ctl believes the key is loaded (a load op was done and no
  // unload since). Unload: KUnmount (op OUnmount) -> KUnload (op OUnloadKey).
  type KPhase = KNone | KUnmount | KUnload
  type Proj = { phase: KPhase, op: int, loaded: bool }

  // SR1 liveness probe while awake (SR0 open decision 4), volatile like Obs:
  // requested (for the row's instance and generation), executed (it read the
  // instance: alive or not), answered later; or timed out.
  type Probe = { pending: bool, reqAt: int, inst: int, gen: int, executed: bool, result: bool,
                 answered: bool, alive: bool }

  // pause: the SR1 pause tier is on (an idle session is SIGSTOPped first);
  // suspendHold: how much longer than IDLE_TIMEOUT a paused session stays
  // paused before it may be suspended.
  type Policy = { keepWarm: bool, maxAge: int, pause: bool, suspendHold: int }

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
    keys: str -> bool,                // the kernel: project key loaded (environment)
    proj: str -> Proj,                // yard-ctl's project key records (durable)
    probe: SessId -> Probe,           // yard-ctl's liveness probes (volatile)
    silentDrift: bool,                // an instance was restored, without the override, on a changed workspace
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
  const PAUSE_FENCE: bool           // unpause only once the pause op is resolved (unpauseBeforePauseSettles)
  const RETRY_CURRENT: bool         // retry a stop/start/pause op only while the row still waits on it (retrySupersededOp)
  // SR1 (decided 2026-10-07)
  const PROJECT: SessId -> str      // the session's project ("": no workspace key)
  const DRIFT_REFUSE: bool          // a restore refuses a workspace changed since the snapshot, unless forced (resumeIgnoresDrift)
  const KEY_GUARD: bool             // unload a project key only when no session of it is active or in flight (unloadUnderActive)
  const KEY_FENCE: bool             // send a load only once the project's unload is resolved (loadDuringUnload)
  const RESUME_LOADS: bool          // a resume loads the key and mounts the clone before the restore (resumeWithoutKey)
  const PROBE_CURRENT: bool         // a dead verdict counts only for the row's current instance and generation (staleProbe)
  const PROBE_TIMEOUT_UNKNOWN: bool // a probe timeout is unknown, not dead (deadOnProbeTimeout)

  pure val IDLER: str = "idler"
  pure val RECOVERY: str = "recovery"
  pure val DRIVERS: Set[str] = CLIENTS.union(Set(IDLER, RECOVERY))
  pure val SUSPEND_FAMILY: Set[State] = Set(Suspending, Suspended, Resuming)
  pure val PROJECTS: Set[str] = SESSIONS.map(s => PROJECT.get(s)).exclude(Set(""))
  pure val PROJ_OPS: Set[OpKind] = Set(OUnmount, OUnloadKey)
  pure def hasProj(s: SessId): bool = PROJECT.get(s) != ""
  pure def sessOf(p: str): Set[SessId] = SESSIONS.filter(s => PROJECT.get(s) == p)
  pure def isProjOp(o: Op): bool = PROJ_OPS.contains(o.kind)
  // the states in which a project's key may be unloaded
  pure val KEY_IDLE: Set[State] = Set(Suspended, Expired, Failed)

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
  // running and not frozen: the harness can act (model calls, tool calls, take a message)
  pure def awake(y: Sys, s: SessId): bool = wld(y, s).insts.exists(i => i.st == Running and not(i.frozen))
  // settled: no copy of the op can still apply (its process has exited)
  pure def settled(y: Sys, id: int): bool = not(y.copies.exists(c => c.op == id))
  pure def resolved(y: Sys, id: int): bool = id == 0 or Set(Done, NotDone, Refused).contains(opSt(y, id))
  // SR1: the session's workspace is usable: no project key, or the key is
  // loaded and the session's clone mounted
  pure def wsUp(y: Sys, s: SessId): bool = not(hasProj(s)) or (y.keys.get(PROJECT.get(s)) and wld(y, s).mounted)
  // an instance exists and has processes (the probe's reading)
  pure def instAlive(y: Sys, s: SessId, name: int): bool = wld(y, s).insts.exists(i => i.name == name and i.st == Running)
  pure def ckptOk(y: Sys, s: SessId, ckpt: int): bool =
    y.artifacts.exists(a => a.sess == s and a.ckpt == ckpt and a.ok)

  // Send a new op: a row (Pending) and its first copy.
  pure def newOp(y: Sys, k: OpKind, s: SessId, gen: int, arg: int): Sys = newOpF(y, k, s, gen, arg, false)
  pure def newOpF(y: Sys, k: OpKind, s: SessId, gen: int, arg: int, force: bool): Sys = {
    val o = { id: y.nextOp, kind: k, sess: s, gen: gen, arg: arg, st: Pending,
              sentAt: y.clock, attempts: 1, inc: y.ctlInc, force: force }
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
  // SR1 decision 2: the restore reads `written@snap` (or zfs diff) first and
  // refuses, creating nothing, if the workspace changed since the snapshot
  // and the request carries no override. (The checkpoint must be good: a
  // missing one is not-done for its own reason.)
  pure def restoreRefused(y: Sys, o: Op): bool =
    DRIFT_REFUSE and not(o.force) and ckptOk(y, o.sess, o.arg)
      and not(RESTORE_FENCE and hasInst(y, o.sess, o.gen)) and wld(y, o.sess).live != y.snaps.get(o.arg)

  // The effect of one copy of an op, applied by the backend / STS / fs / zfs.
  pure def effect(y: Sys, o: Op, c: Copy, partial: bool): Sys =
    if (isProjOp(o)) projEffect(y, o) else sessEffect(y, o, c, partial)
  // Project ops. Unmount is taken as forced (the design does not count on
  // EBUSY from a jail's nullfs mount); unload-key refuses while any dataset
  // of the project is mounted (ZFS: "requires that the dataset is not
  // currently open or mounted").
  pure def projEffect(y: Sys, o: Op): Sys = {
    val p = o.sess
    match o.kind {
      | OUnmount => { ...y, world: y.world.keys().mapBy(s =>
          if (PROJECT.get(s) == p) { ...y.world.get(s), mounted: false } else y.world.get(s)) }
      | OUnloadKey => if (sessOf(p).exists(s => wld(y, s).mounted)) y else { ...y, keys: y.keys.set(p, false) }
      | _ => y
    }
  }
  pure def sessEffect(y: Sys, o: Op, c: Copy, partial: bool): Sys = {
    val s = o.sess
    val w = wld(y, s)
    match o.kind {
      | OQuiesce =>
          // SR1: stop every process (TERM, then KILL) and see none left; FC
          // pause: in-flight writes die. A frozen instance is stopped too
          // (SR1 sends SIGCONT after SIGTERM, SIGKILL needs no CONT).
          setWorld(y, s, { ...w, inflight: Set(),
            insts: w.insts.map(i => if (i.name == o.arg) { ...i, st: Stopped, frozen: false } else i) })
      | OUnquiesce =>
          // SR1: start the service again from its spec in the same jail, or
          // SIGCONT what is still there
          setWorld(y, s, { ...w, insts: w.insts.map(i => if (i.name == o.arg) { ...i, st: Running, frozen: false } else i) })
      | OPause =>
          // SIGSTOP every process of a running instance
          setWorld(y, s, { ...w, insts: w.insts.map(i => if (i.name == o.arg and i.st == Running) { ...i, frozen: true } else i) })
      | OUnpause =>
          setWorld(y, s, { ...w, insts: w.insts.map(i => if (i.name == o.arg) { ...i, frozen: false } else i) })
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
          // create-only with RESTORE_FENCE. The workspace is not rolled back
          // (SR1): with DRIFT_REFUSE a changed one is refused unless forced.
          if ((RESTORE_FENCE and hasInst(y, s, o.gen)) or not(ckptOk(y, s, o.arg)) or restoreRefused(y, o)) y
          else {
            val a = y.artifacts.filter(x => x.sess == s and x.ckpt == o.arg and x.ok)
            val creds = a.fold(Set(), (acc, x) => acc.union(x.creds))
            val y1 = setWorld(y, s, { ...w, insts: w.insts.union(Set({ name: o.gen, st: Running, frozen: false })),
                                      creds: creds, inflight: Set() })
            { ...y1, starts: y1.starts.put(o.arg, getOr(y1.starts, o.arg) + 1),
              silentDrift: y1.silentDrift or (not(o.force) and w.live != y.snaps.get(o.arg)) }
          }
      | OLoadKey =>
          // load-key (idempotent: "already loaded" is done), then mount the clone
          { ...setWorld(y, s, { ...w, mounted: true }), keys: y.keys.set(PROJECT.get(s), true) }
      | OMint =>
          // the STS refuses an epoch other than the row's (CRED_EPOCH)
          if (CRED_EPOCH and o.arg != row(y, s).credEpoch) y
          else setWorld(y, s, { ...w, creds: w.creds.union(Set({ epoch: o.arg, reqAt: c.sentAt, mintedAt: y.clock })) })
      | ODelete =>
          { ...y, artifacts: y.artifacts.filter(a => not(a.sess == s and a.ckpt == o.arg)) }
      | _ => y
    }
  }

  // The resolving observation of each op kind (backend probe, digest check,
  // directory listing, the broker's credential list).
  pure def observedDone(y: Sys, o: Op): bool =
    if (isProjOp(o)) {
      val p = o.sess
      match o.kind {
        | OUnmount => not(sessOf(p).exists(s => wld(y, s).mounted))
        | OUnloadKey => not(y.keys.get(p))
        | _ => false
      }
    } else sessObservedDone(y, o)
  pure def sessObservedDone(y: Sys, o: Op): bool = {
    val s = o.sess
    val w = wld(y, s)
    match o.kind {
      | OLoadKey => y.keys.get(PROJECT.get(s)) and w.mounted
      | OQuiesce => not(w.insts.exists(i => i.name == o.arg and i.st == Running))
      | OUnquiesce => w.insts.exists(i => i.name == o.arg and i.st == Running and not(i.frozen))
      | OPause => w.insts.exists(i => i.name == o.arg and i.frozen)
      | OUnpause => w.insts.exists(i => i.name == o.arg and not(i.frozen))
      | ODestroy => not(hasInst(y, s, o.arg))
      | OCheckpoint => ckptOk(y, s, o.id)
      | ORestore => hasInst(y, s, o.gen)
      | OMint => w.creds.exists(c => c.epoch == o.arg)
      | ODelete => not(y.artifacts.exists(a => a.sess == s and a.ckpt == o.arg))
      | _ => false
    }
  }

  // ===================================================== environment
  pure def canOpLand(y: Sys, c: Copy): bool = y.copies.contains(c)
  // late effect, answer delivered only to the incarnation that sent it. The
  // process exits 0 iff the effect holds (an idempotent create of an
  // existing name included); any failure exit is an error: unknown.
  // A restore that refused (decision 2) answers Refused: definite, nothing
  // was created.
  pure def applyOpLand(y: Sys, c: Copy): Sys = {
    val o = opOf(y, c.op)
    val refused = o.kind == ORestore and restoreRefused(y, o)
    val y1 = { ...effect(y, o, c, false), copies: y.copies.exclude(Set(c)) }
    val heard = y.ctlUp and c.inc == y.ctlInc and o.st == Pending
    if (heard) setOp(y1, { ...opOf(y1, c.op), st: if (observedDone(y1, o)) Done else if (refused) Refused else Unknown })
    else y1
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
  pure def canActivity(y: Sys, s: SessId): bool = awake(y, s) and wld(y, s).actSeq < MAX_ACT
  pure def applyActivity(y: Sys, s: SessId): Sys = {
    val w = wld(y, s)
    setWorld(y, s, { ...w, actSeq: w.actSeq + 1, lastAct: y.clock })
  }
  // a tool call's workspace write: issued, then lands (acked) or lands with the ack lost
  pure def canWriteIssue(y: Sys, s: SessId): bool = awake(y, s) and y.nextWrite <= MAX_WRITES
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
  // SR1 decision 2: the workspace changes while the session is suspended
  // (an operator, another tool, a per-call jail on the sandbox's workspace)
  pure def canWorkspaceEdit(y: Sys, s: SessId): bool =
    canFault(y) and row(y, s).state == Suspended and not(running(y, s)) and y.nextWrite <= MAX_WRITES
  pure def applyWorkspaceEdit(y: Sys, s: SessId): Sys = {
    val w = wld(y, s)
    fault({ ...setWorld(y, s, { ...w, live: w.live.union(Set(y.nextWrite)) }), nextWrite: y.nextWrite + 1 })
  }
  // SR1 decision 3: the liveness probe runs (reads the instance) and answers
  // later; a lost request or answer is a probe that never answers
  pure val NO_PROBE: Probe = { pending: false, reqAt: 0, inst: 0, gen: 0, executed: false, result: false,
                               answered: false, alive: false }
  pure def canProbeExec(y: Sys, s: SessId): bool = y.probe.get(s).pending and not(y.probe.get(s).executed)
  pure def applyProbeExec(y: Sys, s: SessId): Sys = {
    val p = y.probe.get(s)
    { ...y, probe: y.probe.set(s, { ...p, executed: true, result: instAlive(y, s, p.inst) }) }
  }
  pure def canProbeAnswer(y: Sys, s: SessId): bool = y.ctlUp and y.probe.get(s).pending and y.probe.get(s).executed
  pure def applyProbeAnswer(y: Sys, s: SessId): Sys = {
    val p = y.probe.get(s)
    { ...y, probe: y.probe.set(s, { ...p, pending: false, answered: true, alive: p.result }) }
  }
  // yard-ctl dies: drivers and observations (memory) are gone; rows, ops,
  // copies in flight and instances stay
  pure def canCtlCrash(y: Sys): bool = canFault(y) and y.ctlUp
  pure def applyCtlCrash(y: Sys): Sys = { ...y, ctlUp: false, faults: y.faults + 1,
    drivers: SESSIONS.mapBy(_ => Set()), checked: SESSIONS.mapBy(_ => Set()),
    obs: SESSIONS.mapBy(_ => { pending: false, reqAt: 0, seq: -1, seenAt: 0, ansReqAt: -1 }),
    probe: SESSIONS.mapBy(_ => NO_PROBE) }
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
  // OpRetry: idempotent retry of a resolved-not-done op. A delete and a
  // mint are owed whatever the row does next; a stop, start or pause op is
  // retried only while the row's phase still waits on it (RETRY_CURRENT):
  // once the row has moved on (abort, unpause), a resent SIGSTOP or quiesce
  // would land on the instance the next phase woke.
  pure val RETRYABLE: Set[OpKind] = Set(OQuiesce, ODestroy, OUnquiesce, OMint, ODelete, OPause, OUnpause,
                                        OLoadKey, OUnmount, OUnloadKey)
  pure def opCurrent(y: Sys, o: Op): bool =
    if (isProjOp(o)) y.proj.get(o.sess).op == o.id
    else Set(ODelete, OMint).contains(o.kind) or row(y, o.sess).op == o.id
  pure def canOpRetry(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and {
    val o = opOf(y, id)
    o.st == NotDone and RETRYABLE.contains(o.kind) and o.attempts < MAX_ATTEMPTS
      and (if (RETRY_CURRENT) opCurrent(y, o) else true)
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
  // Adopt: a new driver takes over an in-flight row (suspending, resuming,
  // or pausing / unpausing)
  pure def canAdopt(y: Sys, s: SessId): bool = y.ctlUp
    and (SUSPEND_FAMILY.exclude(Set(Suspended)).contains(row(y, s).state)
         or (row(y, s).state == Paused and row(y, s).phase != PNone))
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
    and row(y, s).inbox > 0 and hasInst(y, s, row(y, s).inst) and awake(y, s)
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

  // a paused session may be suspended once it has been idle for
  // IDLE_TIMEOUT + suspendHold (its quiesce stops the frozen processes)
  pure def pausedLongEnough(y: Sys, s: SessId): bool = {
    val o = y.obs.get(s)
    row(y, s).state == Paused and row(y, s).phase == PNone
      and o.seq >= 0 and o.seenAt + IDLE_TIMEOUT + POLICY.get(s).suspendHold <= y.clock
  }
  pure def canSuspendBegin(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    and { y.ctlUp, (r.state == Idle and idleSeen(y, s)) or pausedLongEnough(y, s), not(POLICY.get(s).keepWarm),
          r.gen < MAX_GEN, y.drivers.get(s) == Set(), r.inbox == 0, y.nextOp <= MAX_OPS }
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

  // ====================================== controller: pause tier (SR1)
  // PauseBegin: an idle session's processes are SIGSTOPped (frees CPU only)
  pure def canPauseBegin(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    and { y.ctlUp, r.state == Idle, POLICY.get(s).pause, y.drivers.get(s) == Set(), r.inbox == 0,
          idleSeen(y, s), y.nextOp <= MAX_OPS }
  }
  pure def applyPauseBegin(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    val y1 = newOp(y, OPause, s, r.gen, r.inst)
    { ...setRow(y1, s, { ...r, state: Paused, phase: PPause, op: y.nextOp }), drivers: y.drivers.set(s, Set(IDLER)) }
  }
  pure def canPauseDone(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Paused, PPause)
    and opSt(y, row(y, s).op) == Done
  pure def applyPauseDone(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), phase: PNone, op: 0 }), drivers: y.drivers.set(s, Set()) }
  // UnpauseBegin: a held message, new activity, or a pause known not done
  // wakes it. The fence: never while the pause op can still land (a late
  // SIGSTOP after the SIGCONT would freeze an awake session).
  pure def canUnpauseBegin(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    and { y.ctlUp, r.state == Paused, Set(PNone, PPause).contains(r.phase),
          if (PAUSE_FENCE) resolved(y, r.op) else true,
          r.inbox > 0 or not(idleSeen(y, s)) or (r.op != 0 and opSt(y, r.op) == NotDone),
          y.nextOp <= MAX_OPS }
  }
  pure def applyUnpauseBegin(y: Sys, s: SessId): Sys = {
    val r = row(y, s)
    val y1 = newOp(y, OUnpause, s, r.gen, r.inst)
    { ...setRow(y1, s, { ...r, phase: PUnpause, op: y.nextOp }), drivers: y.drivers.set(s, Set(IDLER)) }
  }
  pure def canUnpauseDone(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Paused, PUnpause)
    and opSt(y, row(y, s).op) == Done
  pure def applyUnpauseDone(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Idle, phase: PNone, op: 0 }), drivers: y.drivers.set(s, Set()) }
  // the instance is gone: nothing to unpause
  pure def canUnpauseFail(y: Sys, s: SessId): bool = hasDriver(y, s) and inPhase(y, s, Paused, PUnpause)
    and opSt(y, row(y, s).op) == NotDone and not(hasInst(y, s, row(y, s).inst))
  pure def applyUnpauseFail(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Failed, phase: PNone, op: 0 }), drivers: y.drivers.set(s, Set()) }

  // =========================================== controller: resume
  pure def drives(y: Sys, s: SessId, d: str): bool = y.ctlUp and y.drivers.get(s).contains(d)
  // ResumeConsume: UPDATE ... SET state='resuming' WHERE state='suspended' AND token=?
  pure def canResumeConsume(y: Sys, s: SessId, d: str, tok: int): bool = and {
    y.ctlUp, ATOMIC_CONSUME, CLIENTS.contains(d), row(y, s).state == Suspended,
    tok != 0, row(y, s).token == tok, y.nextOp <= MAX_OPS,
  }
  // force: the request carries the override (decision 2). A session with a
  // project first loads its key (PKey; the load is sent by ResumeLoadKey,
  // behind the KEY_FENCE), others restore at once.
  pure def claimF(y: Sys, s: SessId, d: str, tok: int, force: bool): Sys = {
    val r = row(y, s)
    val y1 = if (hasProj(s) and RESUME_LOADS) y else newOpF(y, ORestore, s, r.gen, r.ckpt, force)
    val r1 = if (hasProj(s) and RESUME_LOADS) { ...r, state: Resuming, phase: PKey, token: 0, op: 0, force: force }
             else { ...r, state: Resuming, phase: PRestore, token: 0, op: y.nextOp, force: force }
    { ...setRow(y1, s, r1),
      drivers: y.drivers.set(s, y.drivers.get(s).union(Set(d))),
      claims: y1.claims.put(tok, getOr(y1.claims, tok) + 1) }
  }
  pure def claim(y: Sys, s: SessId, d: str, tok: int): Sys = claimF(y, s, d, tok, false)
  pure def applyResumeConsume(y: Sys, s: SessId, d: str, tok: int): Sys = claim(y, s, d, tok)
  pure def applyResumeConsumeForce(y: Sys, s: SessId, d: str, tok: int): Sys = claimF(y, s, d, tok, true)
  // PKey: send the load (again, after one known not done) once the project's
  // unload, if any, is resolved (KEY_FENCE: a late unmount/unload-key would
  // otherwise land after the load)
  pure def canResumeLoadKey(y: Sys, s: SessId, d: str): bool = {
    val r = row(y, s)
    val pr = y.proj.get(PROJECT.get(s))
    and { drives(y, s, d), inPhase(y, s, Resuming, PKey), r.op == 0, y.nextOp <= MAX_OPS,
          if (KEY_FENCE) pr.phase == KNone and resolved(y, pr.op) else true }
  }
  pure def applyResumeLoadKey(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    setRow(newOp(y, OLoadKey, s, r.gen, 0), s, { ...r, op: y.nextOp })
  }
  // key loaded and clone mounted: restore
  pure def canResumeKeyDone(y: Sys, s: SessId, d: str): bool = drives(y, s, d) and inPhase(y, s, Resuming, PKey)
    and row(y, s).op != 0 and opSt(y, row(y, s).op) == Done and y.nextOp <= MAX_OPS
  pure def applyResumeKeyDone(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    val p = PROJECT.get(s)
    { ...setRow(newOpF(y, ORestore, s, r.gen, r.ckpt, r.force), s, { ...r, phase: PRestore, op: y.nextOp }),
      proj: y.proj.set(p, { ...y.proj.get(p), loaded: true }) }
  }
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
    { ...setRow(y1, s, { ...r, state: Active, phase: PNone, op: 0, ckpt: 0, inst: r.gen, resumes: r.resumes + 1,
                         force: false, drift: false }),
      drivers: y.drivers.set(s, Set()) }
  }
  // restore (or the key load) known not done, or the restore refused: back
  // to suspended with a fresh token. A refusal is recorded (drift).
  pure def canResumeAbort(y: Sys, s: SessId, d: str): bool = {
    val r = row(y, s)
    and { drives(y, s, d), r.state == Resuming, y.nextToken <= MAX_TOKENS,
          or { r.phase == PRestore and Set(NotDone, Refused).contains(opSt(y, r.op)),
               r.phase == PKey and r.op != 0 and opSt(y, r.op) == NotDone } }
  }
  pure def applyResumeAbort(y: Sys, s: SessId, d: str): Sys = {
    val r = row(y, s)
    val refused = r.phase == PRestore and opSt(y, r.op) == Refused
    { ...setRow(y, s, { ...r, state: Suspended, phase: PNone, op: 0, token: y.nextToken, force: false,
                        drift: refused }),
      nextToken: y.nextToken + 1, drivers: y.drivers.set(s, Set()) }
  }
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

  // ================================== controller: liveness (SR1 decision 3)
  // ProbeReq: ask whether the current instance is alive (an awake session)
  pure def canProbeReq(y: Sys, s: SessId): bool =
    y.ctlUp and Set(Active, Idle).contains(row(y, s).state) and not(y.probe.get(s).pending)
  pure def applyProbeReq(y: Sys, s: SessId): Sys =
    { ...y, probe: y.probe.set(s, { ...NO_PROBE, pending: true, reqAt: y.clock, inst: row(y, s).inst, gen: row(y, s).gen }) }
  // ProbeTimeout: no answer within OP_TIMEOUT: unknown (the mutant: dead)
  pure def canProbeTimeout(y: Sys, s: SessId): bool =
    y.ctlUp and y.probe.get(s).pending and y.clock >= y.probe.get(s).reqAt + OP_TIMEOUT
  pure def applyProbeTimeout(y: Sys, s: SessId): Sys = {
    val p = y.probe.get(s)
    { ...y, probe: y.probe.set(s, { ...p, pending: false, executed: false,
                                    answered: not(PROBE_TIMEOUT_UNKNOWN), alive: false }) }
  }
  // LostDetect: a definite "not alive" for the row's current instance and
  // generation (a suspend attempt bumps the generation): the session failed
  pure def canLostDetect(y: Sys, s: SessId): bool = {
    val r = row(y, s)
    val p = y.probe.get(s)
    and { y.ctlUp, Set(Active, Idle).contains(r.state), y.drivers.get(s) == Set(), p.answered, not(p.alive),
          if (PROBE_CURRENT) p.inst == r.inst and p.gen == r.gen else true }
  }
  pure def applyLostDetect(y: Sys, s: SessId): Sys =
    { ...setRow(y, s, { ...row(y, s), state: Failed, phase: PNone, op: 0 }), probe: y.probe.set(s, NO_PROBE) }

  // ============================== controller: project keys (SR1 layout D)
  // KeyUnloadBegin: no session of the project is active or in flight
  // (KEY_GUARD): unmount every dataset of it, then unload-key
  pure def canKeyUnloadBegin(y: Sys, p: str): bool = and {
    y.ctlUp, PROJECTS.contains(p), y.nextOp <= MAX_OPS,
    y.proj.get(p).phase == KNone, y.proj.get(p).loaded, resolved(y, y.proj.get(p).op),
    if (KEY_GUARD) sessOf(p).forall(s => KEY_IDLE.contains(row(y, s).state) and y.drivers.get(s) == Set()
                                         and not(y.ops.keys().exists(id => { val o = opOf(y, id)
                                           o.sess == s and o.kind == OLoadKey and not(resolved(y, id)) })))
    else true,
  }
  pure def applyKeyUnloadBegin(y: Sys, p: str): Sys =
    { ...newOp(y, OUnmount, p, 0, 0), proj: y.proj.set(p, { ...y.proj.get(p), phase: KUnmount, op: y.nextOp }) }
  pure def canKeyUnmountDone(y: Sys, p: str): bool = y.ctlUp and PROJECTS.contains(p) and y.nextOp <= MAX_OPS
    and y.proj.get(p).phase == KUnmount and opSt(y, y.proj.get(p).op) == Done
  pure def applyKeyUnmountDone(y: Sys, p: str): Sys =
    { ...newOp(y, OUnloadKey, p, 0, 0), proj: y.proj.set(p, { ...y.proj.get(p), phase: KUnload, op: y.nextOp }) }
  pure def canKeyUnloadDone(y: Sys, p: str): bool = y.ctlUp and PROJECTS.contains(p)
    and y.proj.get(p).phase == KUnload and opSt(y, y.proj.get(p).op) == Done
  pure def applyKeyUnloadDone(y: Sys, p: str): Sys =
    { ...y, proj: y.proj.set(p, { phase: KNone, op: 0, loaded: false }) }
  // an unmount or unload known not done (retries spent, or a session busy):
  // give up; the key stays loaded as far as yard-ctl knows
  pure def canKeyUnloadAbort(y: Sys, p: str): bool = y.ctlUp and PROJECTS.contains(p)
    and Set(KUnmount, KUnload).contains(y.proj.get(p).phase) and opSt(y, y.proj.get(p).op) == NotDone
  pure def applyKeyUnloadAbort(y: Sys, p: str): Sys =
    { ...y, proj: y.proj.set(p, { ...y.proj.get(p), phase: KNone, op: 0 }) }
  // after a restart, a pending project op is unknown
  pure def canRecoverProjOps(y: Sys, p: str): bool = PROJECTS.contains(p) and canRecoverOps(y, p)

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
                                  suspendedAt: 0, resumes: 0, inbox: 0, force: false, drift: false }),
      ops: Map(),
      drivers: SESSIONS.mapBy(_ => Set()),
      checked: SESSIONS.mapBy(_ => Set()),
      obs: SESSIONS.mapBy(_ => { pending: false, reqAt: 0, seq: -1, seenAt: 0, ansReqAt: -1 }),
      copies: Set(),
      world: SESSIONS.mapBy(_ => { insts: Set({ name: 0, st: Running, frozen: false }), live: Set(), acked: Set(), inflight: Set(),
                                   actSeq: 0, lastAct: 0, creds: Set({ epoch: 1, reqAt: 0, mintedAt: 0 }),
                                   mounted: true }),
      artifacts: Set(),
      snaps: Map(),
      starts: Map(),
      claims: Map(),
      nextOp: 1, nextToken: 1, nextWrite: 1, faults: 0, msgs: 0,
      // every project's key is loaded at the start (its sessions are active)
      keys: PROJECTS.mapBy(_ => true),
      proj: PROJECTS.mapBy(_ => { phase: KNone, op: 0, loaded: true }),
      probe: SESSIONS.mapBy(_ => NO_PROBE),
      silentDrift: false,
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
  action WorkspaceEdit(s: SessId): bool = all { canWorkspaceEdit(y, s), y' = { ...applyWorkspaceEdit(y, s), last: "WorkspaceEdit" } }
  action ProbeExec(s: SessId): bool = all { canProbeExec(y, s), y' = { ...applyProbeExec(y, s), last: "ProbeExec" } }
  action ProbeAnswer(s: SessId): bool = all { canProbeAnswer(y, s), y' = { ...applyProbeAnswer(y, s), last: "ProbeAnswer" } }

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
  action PauseBegin(s: SessId): bool = all { canPauseBegin(y, s), y' = { ...applyPauseBegin(y, s), last: "PauseBegin" } }
  action PauseDone(s: SessId): bool = all { canPauseDone(y, s), y' = { ...applyPauseDone(y, s), last: "PauseDone" } }
  action UnpauseBegin(s: SessId): bool = all { canUnpauseBegin(y, s), y' = { ...applyUnpauseBegin(y, s), last: "UnpauseBegin" } }
  action UnpauseDone(s: SessId): bool = all { canUnpauseDone(y, s), y' = { ...applyUnpauseDone(y, s), last: "UnpauseDone" } }
  action UnpauseFail(s: SessId): bool = all { canUnpauseFail(y, s), y' = { ...applyUnpauseFail(y, s), last: "UnpauseFail" } }
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
  // SR1 (2026-10-07)
  action ResumeConsumeForce(s: SessId, d: str, tok: int): bool = all { canResumeConsume(y, s, d, tok), y' = { ...applyResumeConsumeForce(y, s, d, tok), last: "ResumeConsumeForce" } }
  action ResumeLoadKey(s: SessId, d: str): bool = all { canResumeLoadKey(y, s, d), y' = { ...applyResumeLoadKey(y, s, d), last: "ResumeLoadKey" } }
  action ResumeKeyDone(s: SessId, d: str): bool = all { canResumeKeyDone(y, s, d), y' = { ...applyResumeKeyDone(y, s, d), last: "ResumeKeyDone" } }
  action ProbeReq(s: SessId): bool = all { canProbeReq(y, s), y' = { ...applyProbeReq(y, s), last: "ProbeReq" } }
  action ProbeTimeout(s: SessId): bool = all { canProbeTimeout(y, s), y' = { ...applyProbeTimeout(y, s), last: "ProbeTimeout" } }
  action LostDetect(s: SessId): bool = all { canLostDetect(y, s), y' = { ...applyLostDetect(y, s), last: "LostDetect" } }
  action KeyUnloadBegin(p: str): bool = all { canKeyUnloadBegin(y, p), y' = { ...applyKeyUnloadBegin(y, p), last: "KeyUnloadBegin" } }
  action KeyUnmountDone(p: str): bool = all { canKeyUnmountDone(y, p), y' = { ...applyKeyUnmountDone(y, p), last: "KeyUnmountDone" } }
  action KeyUnloadDone(p: str): bool = all { canKeyUnloadDone(y, p), y' = { ...applyKeyUnloadDone(y, p), last: "KeyUnloadDone" } }
  action KeyUnloadAbort(p: str): bool = all { canKeyUnloadAbort(y, p), y' = { ...applyKeyUnloadAbort(y, p), last: "KeyUnloadAbort" } }
  action RecoverProjOps(p: str): bool = all { canRecoverProjOps(y, p), y' = { ...applyRecoverOps(y, p), last: "RecoverProjOps" } }
  action GcSweep(s: SessId): bool = all { canGcSweep(y, s), y' = { ...applyGcSweep(y, s), last: "GcSweep" } }

  action envStep = {
    nondet s = SESSIONS.oneOf()
    nondet n = 1.to(MAX_WRITES).oneOf()
    any {
      Activity(s), WriteIssue(s), WriteLand(s, n), WriteLandAckLost(s, n),
      MessageArrive(s), InstanceCrash(s), ObsAnswer(s), CtlCrash, CtlRestart,
      // SR1 (2026-10-07), one branch
      any { WorkspaceEdit(s), ProbeExec(s), ProbeAnswer(s) },
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
      // the SR1 pause tier, last and as one branch: the simulator's choice
      // among the actions above keeps the weights it had before SR1
      any { PauseBegin(s), PauseDone(s), UnpauseBegin(s), UnpauseDone(s), UnpauseFail(s) },
      // SR1 2026-10-07 (keys, drift override, liveness), likewise one branch
      sr1Step(s, d, tok),
    }
  }
  action sr1Step(s: SessId, d: str, tok: int): bool = {
    nondet p = SESSIONS.map(x => PROJECT.get(x)).oneOf()
    any {
      ResumeConsumeForce(s, d, tok), ResumeLoadKey(s, d), ResumeKeyDone(s, d),
      ProbeReq(s), ProbeTimeout(s), LostDetect(s),
      KeyUnloadBegin(p), KeyUnmountDone(p), KeyUnloadDone(p), KeyUnloadAbort(p), RecoverProjOps(p),
    }
  }
  action step = any { Tick, envStep, copyStep, ctlStep }
  // stepCore: `step` without the SR1 2026-10-07 actions (a restriction of
  // it). The probes, edits and key actions take steps and simulator weight;
  // three mutants that random `step` runs found before them are run on this
  // (run_models.sh), and their scripted BreaksTests run on the full model.
  action envStepCore = {
    nondet s = SESSIONS.oneOf()
    nondet n = 1.to(MAX_WRITES).oneOf()
    any {
      Activity(s), WriteIssue(s), WriteLand(s, n), WriteLandAckLost(s, n),
      MessageArrive(s), InstanceCrash(s), ObsAnswer(s), CtlCrash, CtlRestart,
    }
  }
  action ctlStepCore = {
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
      // the SR1 pause tier, last and as one branch: the simulator's choice
      // among the actions above keeps the weights it had before SR1
      any { PauseBegin(s), PauseDone(s), UnpauseBegin(s), UnpauseDone(s), UnpauseFail(s) },
    }
  }
  action stepCore = any { Tick, envStepCore, copyStep, ctlStepCore }

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
  // ... with the crash only while a checkpoint copy is in flight
  action stepCrashCkpt = any {
    Tick, landStep, obsStep, ctlStep, CtlRestart,
    all { y.copies.exists(c => opOf(y, c.op).kind == OCheckpoint), CtlCrash },
  }
  // ... plus workspace edits while suspended (SR1 decision 2)
  action stepDrift = {
    nondet s = SESSIONS.oneOf()
    any { Tick, landStep, obsStep, ctlStep, WorkspaceEdit(s) }
  }
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
    (r.resumes > 0 and Set(Active, Idle, Paused).contains(r.state)) implies
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

  // I8 (SR1 pause tier) an awake session (active or idle) has no frozen
  // instance: a message is never handed to a SIGSTOPped harness, and a late
  // SIGSTOP never lands after the SIGCONT.
  val noFrozenAwake: bool = SESSIONS.forall(s =>
    Set(Active, Idle).contains(row(y, s).state) implies not(wld(y, s).insts.exists(i => i.frozen)))

  // I9 (SR1 decision 2) no instance is restored, without the override, on a
  // workspace that changed since its suspend snapshot.
  val noSilentDrift: bool = not(y.silentDrift)

  // I10 (SR1 decision 3) a failed session has no live instance: a session is
  // declared lost only on a definite "dead" for its current instance.
  val noLiveFailed: bool = SESSIONS.forall(s => row(y, s).state == Failed implies not(running(y, s)))

  // I11 (SR1 layout D) a running instance's project key is loaded and its
  // workspace clone mounted: a key is never unloaded (or a clone unmounted)
  // under a live session, and nothing is restored without its key.
  val keyUnderActive: bool = SESSIONS.forall(s => (hasProj(s) and running(y, s)) implies wsUp(y, s))

  val allInvariants: bool = and {
    resumedAtMostOnce, noAckedWriteLost, noPreSuspendCredential, artifactsAccounted,
    resumeKeepsArtifacts, suspendedOnlyIdle, noMessageLost, noFrozenAwake,
    noSilentDrift, noLiveFailed, keyUnderActive,
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
  // SR1 pause tier
  val wPaused: bool = SESSIONS.exists(s => row(y, s).state == Paused and row(y, s).phase == PNone)
  val wUnpaused: bool = y.last == "UnpauseDone"
  val wSuspendFromPaused: bool = y.last == "SuspendBegin" and y.ops.keys().exists(id => opOf(y, id).kind == OPause)
    and SESSIONS.exists(s => row(y, s).state == Suspending)
  val wAdoptPaused: bool = y.last == "Adopt" and stateSeen(Paused)
  val wPauseNotDone: bool = y.ops.keys().exists(id => opOf(y, id).kind == OPause and opOf(y, id).st == NotDone)
  // SR1 2026-10-07
  val wDriftRefused: bool = SESSIONS.exists(s => row(y, s).state == Suspended and row(y, s).drift)
  val wForcedResume: bool = SESSIONS.exists(s => row(y, s).state == Active and row(y, s).resumes > 0)
    and y.ops.keys().exists(id => opOf(y, id).kind == ORestore and opOf(y, id).force and opOf(y, id).st == Done)
  val wLost: bool = y.last == "LostDetect"
  val wProbeTimedOut: bool = y.last == "ProbeTimeout"
  val wKeyUnloaded: bool = PROJECTS.exists(p => not(y.keys.get(p)) and y.proj.get(p).phase == KNone)
  val wKeyReloaded: bool = y.last == "ResumeComplete" and y.ops.keys().exists(id => opOf(y, id).kind == OUnloadKey and opOf(y, id).st == Done)
  val wLoadWaited: bool = SESSIONS.exists(s => row(y, s).phase == PKey and row(y, s).op == 0)
    and PROJECTS.exists(p => y.proj.get(p).phase != KNone)
}

// ------------------------------------------------------------- instances
// The design: every rule on. One session (fc), keep-warm off.
module design {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// The design with two sessions (a jail service and a keep-warm KV session).
module design2 {
  import lifecycle(
    SESSIONS = Set("s1", "s2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "service", "s2" -> "kv"),
    POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }, "s2" -> { keepWarm: true, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> "w1", "s2" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// SR1: one service session with the pause tier (SIGSTOP when idle; suspend
// after IDLE_TIMEOUT + suspendHold, straight from Paused).
module designPause {
  import lifecycle(
    SESSIONS = Set("p1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("p1" -> "service"), POLICY = Map("p1" -> { keepWarm: false, maxAge: 3, pause: true, suspendHold: 1 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("p1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// SR1 workspace keys (layout D, 2026-10-07): two service sessions of one
// project "pa" (ws/pa is the encryption root; the sessions are its clones).
module designKeys {
  import lifecycle(
    SESSIONS = Set("k1", "k2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service", "k2" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }, "k2" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa", "k2" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// ---------------------------------------------------------------- mutants
// Each is the design with one rule off; README.md records which invariant
// breaks and the counterexample.

// nonAtomicConsume: the token check and the claim are separate statements (SELECT, then UPDATE). Breaks resumedAtMostOnce.
module nonAtomicConsume {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = false, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetry: a restore with an unknown outcome is resent at once, without a create-only instance name. Breaks resumedAtMostOnce.
module blindRestoreRetry {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = false, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// commitBeforeDestroy: commit once the destroy is sent, not once the original is known gone. Breaks resumedAtMostOnce.
module commitBeforeDestroy {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = false, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// snapshotBeforeQuiesce: checkpoint once quiesce is sent, before it settles. Breaks noAckedWriteLost.
module snapshotBeforeQuiesce {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = false,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpoch: credentials carry no epoch: the STS mints any request, the broker honours by TTL. Breaks noPreSuspendCredential.
module noCredEpoch {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = false, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// checkpointTimeoutNotDone: a checkpoint timeout is taken as not done. Breaks artifactsAccounted.
module checkpointTimeoutNotDone {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = false, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// fireAndForgetDelete: a delete is sent once and recorded as done. Breaks artifactsAccounted.
module fireAndForgetDelete {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = false, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// gcByAge: a sweeper deletes artifacts older than the TTL, whatever the row says. Breaks resumeKeepsArtifacts.
module gcByAge {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = false,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// observeAtRequest: new activity is dated when the observation was requested. Breaks suspendedOnlyIdle.
module observeAtRequest {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = false, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// ignoreActivityDuringSuspend: commit without re-reading activity (and held messages) after quiesce. Breaks suspendedOnlyIdle.
module ignoreActivityDuringSuspend {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = false, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInbox: TTL expiry ignores held messages. Breaks noMessageLost.
module expireDropsInbox {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = false, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// recoverAssumesNotDone: after a restart, a pending op is taken as not done. Breaks artifactsAccounted.
module recoverAssumesNotDone {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = false, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// unpauseBeforePauseSettles: SIGCONT is sent while the SIGSTOP op can still land (pause unknown or pending). Breaks noFrozenAwake.
module unpauseBeforePauseSettles {
  import lifecycle(
    SESSIONS = Set("p1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("p1" -> "service"), POLICY = Map("p1" -> { keepWarm: false, maxAge: 3, pause: true, suspendHold: 1 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = false, RETRY_CURRENT = true,
    PROJECT = Map("p1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// retrySupersededOp: a stop/start/pause op known not done is resent after the row moved on. Breaks noFrozenAwake.
module retrySupersededOp {
  import lifecycle(
    SESSIONS = Set("p1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("p1" -> "service"), POLICY = Map("p1" -> { keepWarm: false, maxAge: 3, pause: true, suspendHold: 1 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = false,
    PROJECT = Map("p1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// ------------------------------------------------- SR1 mutants (2026-10-07)
// resumeIgnoresDrift: the restore runs on a workspace changed since the snapshot, no override. Breaks noSilentDrift.
module resumeIgnoresDrift {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = false, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// deadOnProbeTimeout: a liveness probe with no answer in OP_TIMEOUT is taken as dead. Breaks noLiveFailed.
module deadOnProbeTimeout {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = false,
  ).* from "./lifecycle"
}

// staleProbe: a "dead" answer counts whatever instance or generation it was asked for. Breaks noLiveFailed.
module staleProbe {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = false, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// unloadUnderActive: the project key is unmounted and unloaded with a session still active. Breaks keyUnderActive.
module unloadUnderActive {
  import lifecycle(
    SESSIONS = Set("k1", "k2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service", "k2" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }, "k2" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa", "k2" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = false, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// loadDuringUnload: a resume sends its load while the project unload can still land. Breaks keyUnderActive.
module loadDuringUnload {
  import lifecycle(
    SESSIONS = Set("k1", "k2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service", "k2" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }, "k2" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa", "k2" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = false, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// resumeWithoutKey: the resume restores without loading the key and mounting the clone. Breaks keyUnderActive.
module resumeWithoutKey {
  import lifecycle(
    SESSIONS = Set("k1", "k2"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service", "k2" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }, "k2" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa", "k2" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = false,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
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
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 4, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = false,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// snapshotBeforeQuiesceFocusDesign: step stepWrites; MAX_FAULTS 0, MAX_WRITES 4, MAX_ACT 0, MAX_INBOX 0
module snapshotBeforeQuiesceFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 4, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetryFocus: step stepQuiet; OP_TIMEOUT 1, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module blindRestoreRetryFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 1, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = false, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// blindRestoreRetryFocusDesign: step stepQuiet; OP_TIMEOUT 1, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module blindRestoreRetryFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 1, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpochFocus: step stepQuiet; CRED_TTL 100, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module noCredEpochFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 100, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = false, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// noCredEpochFocusDesign: step stepQuiet; CRED_TTL 100, MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module noCredEpochFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 100, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// recoverAssumesNotDoneFocus: step stepCrashCkpt; MAX_FAULTS 1, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module recoverAssumesNotDoneFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = false, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// recoverAssumesNotDoneFocusDesign: step stepCrashCkpt; MAX_FAULTS 1, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module recoverAssumesNotDoneFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInboxFocus: step stepInbox; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 2, maxAge 1
module expireDropsInboxFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 1, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 2, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = false, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// expireDropsInboxFocusDesign: step stepInbox; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 2, maxAge 1
module expireDropsInboxFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 1, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16, MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 2, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// resumeIgnoresDriftFocus: step stepDrift; MAX_FAULTS 1, MAX_WRITES 1, MAX_ACT 0, MAX_INBOX 0
module resumeIgnoresDriftFocus {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 1, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = false, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// resumeIgnoresDriftFocusDesign: step stepDrift; MAX_FAULTS 1, MAX_WRITES 1, MAX_ACT 0, MAX_INBOX 0
module resumeIgnoresDriftFocusDesign {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 1, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 1,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("s1" -> ""), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// loadDuringUnloadFocus: step stepQuiet; one session k1 of project pa; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module loadDuringUnloadFocus {
  import lifecycle(
    SESSIONS = Set("k1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = false, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}

// loadDuringUnloadFocusDesign: step stepQuiet; one session k1 of project pa; MAX_FAULTS 0, MAX_WRITES 0, MAX_ACT 0, MAX_INBOX 0
module loadDuringUnloadFocusDesign {
  import lifecycle(
    SESSIONS = Set("k1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("k1" -> "service"),
    POLICY = Map("k1" -> { keepWarm: false, maxAge: 3, pause: false, suspendHold: 0 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 20,
    MAX_TOKENS = 4, MAX_WRITES = 0, MAX_ACT = 0, MAX_INBOX = 0, MAX_ATTEMPTS = 2, MAX_FAULTS = 0,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true, PAUSE_FENCE = true, RETRY_CURRENT = true,
    PROJECT = Map("k1" -> "pa"), DRIFT_REFUSE = true, KEY_GUARD = true, KEY_FENCE = true, RESUME_LOADS = true,
    PROBE_CURRENT = true, PROBE_TIMEOUT_UNKNOWN = true,
  ).* from "./lifecycle"
}
