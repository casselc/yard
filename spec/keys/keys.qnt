// -*- mode: Bluespec; -*-
// keys.qnt: the yard-ctl key service and its two consumers.
//
// One key service (yard-ctl): data keys are 32 random bytes, wrapped
// AES-256-GCM under a KEK derived from a TPM-resident RSA key (a local,
// fail-closed computation at start: not a cross-process call here), stored
// in yard-ctl's SQLite. Two consumers:
//   - ZFS (consumer "zfs"): one key per project, the encryption root
//     ws/<project>; yard-ctl loads it (zfs load-key from stdin + mount the
//     session clone) only while a session of the project is active or
//     resuming, and unmounts + unloads it when none is. A rekey is zfs
//     change-key on the project root. Crypto-shred = unmount, unload, zfs
//     destroy -r, delete every wrapped key version.
//   - halo_serve (consumer "spill"): one fresh key K per checkpoint,
//     registered with a JWT-bound POST /admin/keys/{sess}: seal at the
//     session epoch E, open at E+1 (after SuspendCommit bumps it), revoke.
//     IDENTITY.md "Spill keys". Shred = delete K at yard, then wait until no
//     registration carrying K can still land (token exp) and halo cannot hold
//     it (halo TTL, or a verified revoke).
//
// Every call that crosses a process boundary (zfs load-key, unmount,
// unload-key, destroy, change-key; halo register, spill, restore) is an op:
// a durable op row plus copies in flight, which may land late, land with the
// answer lost, never land, or be delivered twice (casselc/observability
// otel-chdb/model/TEMPLATE.md; AMBIGUITY.md). The controller learns an
// outcome from an answer to its own incarnation, or by observation once the
// op has settled: for zfs ops when the zfs process has exited (no copy), for
// a halo registration when every token of the op has expired (TOKEN_TTL).
//
// Each caller rule is a field of RULES; DESIGN has them all on, and each
// unsafe choice is a named mutant in keysTest.qnt. README.md has the
// register, the invariants and the results.
module keysTypes {
  type Rules = {
    reloadAlways: bool,     // a resume always sends load-key (idempotent), never trusts its belief (trustConsumerAfterRestart)
    keyFence: bool,         // load-key only once no unmount/unload of the project can still land (loadDuringUnload)
    keyGuard: bool,         // unmount/unload only when no session of the project is active or in flight (unloadUnderActive)
    shredSettle: bool,      // a shred completes only once no copy carrying the key can still land (shredBeforeLoadSettles)
    shredVerify: bool,      // a revoke counts only once observed done, not once sent (revokeOnlyByMessage)
    staleCheck: bool,       // halo refuses a registration below its highest epoch, and an open not right after a seal (staleEpochAccepted)
    haloDurable: bool,      // halo's per-session epochs (highest, last seal, last used) survive a halo restart (haloForgetsEpochs)
    usedCheck: bool,        // halo refuses a seal / open for an epoch whose key it already used (identityAsWritten)
    idempotentReg: bool,    // a register retry resends the same key; never a fresh key without verifying (blindRegisterRetry)
    rekeyKeepOld: bool,     // the old project key is deleted only once change-key is known done (rekeyDropsOld)
    // transport, not a caller rule: halo serves the key route only on its admin
    // Unix socket (SO_PEERCRED), so no third party can deliver a token again.
    // false = `--yard-keys-tcp 1` (tailnet), where a captured token may be
    // replayed until it expires (the halo-side mutants are run in that mode)
    socketOnly: bool,
    // halo-side behaviour, not a caller rule: halo zeroes a key at its token's
    // exp (SE fix round); false = before it, an unused key lived for HALO_TTL
    haloExpZero: bool,
  }
  pure val DESIGN: Rules = { reloadAlways: true, keyFence: true, keyGuard: true, shredSettle: true, shredVerify: true,
                             staleCheck: true, haloDurable: true, usedCheck: true, idempotentReg: true, rekeyKeepOld: true,
                             socketOnly: true, haloExpZero: true }
  pure val DESIGN_TCP: Rules = { ...DESIGN, socketOnly: false }
}

module keys {
  import keysTypes.* from "./keys"
  const RULES: Rules

  // ------------------------------------------------------------------ types
  type SessId = str
  type SState = Active | Suspending | Suspended | Resuming | Gone
  // suspend: PSeal (register seal) -> PSpill (spill) -> commit
  // resume:  POpen (register open) -> PLoad (zfs load-key + mount) -> PRestore (halo restore + jail) -> complete
  type SPhase = PNone | PSeal | PSpill | POpen | PLoad | PRestore
  type Use = Seal | Open | Revoke
  type OpKind = OLoadKey | OUnmount | OUnloadKey | ODestroy | OChangeKey | OReg | OSpill | ORestore
  type OpSt = Pending | Unknown | Done | NotDone
  // project key phases (yard-ctl's projects row)
  type PPhase = KIdle | KUnmount | KUnload | KRekey | KShred | KShredded

  // subj: the session (OLoadKey, OReg, OSpill, ORestore) or the project.
  // key: the key the op carries; ver: the epoch (halo) or 0.
  type Op = { id: int, kind: OpKind, subj: str, key: int, ver: int, use: Use, st: OpSt,
              attempts: int, inc: int, sentAt: int }
  // a copy in flight; iat: when it was sent (a halo registration's token
  // iat; the token expires at iat + TOKEN_TTL)
  type Copy = { op: int, attempt: int, inc: int, iat: int }
  // the keys table: wrapped = the wrapped key is in SQLite; shredding: deleted,
  // waiting for its settle bound; shredded: the shred is claimed complete
  type Key = { id: int, cons: str, subj: str, ver: int, wrapped: bool, shredding: bool, shredded: bool }
  type Sess = { st: SState, phase: SPhase, epoch: int, op: int, spill: int, resumes: int }
  // believed: yard-ctl's durable belief that the project key is loaded
  type Proj = { phase: PPhase, op: int, key: int, believed: bool }
  // exp: the registering token's exp: halo zeroes the key at min(exp, at + HALO_TTL)
  type Slot = { sess: SessId, epoch: int, key: int, use: Use, at: int, exp: int }
  type File = { sess: SessId, epoch: int, key: int }
  // the kernel: dataset exists, master key loaded, session clones mounted,
  // which user key wraps the master key now
  type Zfs = { exists: bool, master: bool, mounted: Set[SessId], key: int }
  // highest: the highest epoch seen; lastSeal: the last seal epoch registered;
  // lastSpill / lastRestore: the last epoch whose seal / open key was used;
  // fence: the revoke fence (`revoked_through`): nothing at a file epoch at or
  // below it is sealed or opened again. All five are durable in halo (fsync'd
  // before it answers). entry: the key of the file the session's cache entry
  // holds now (its checkpoint id; memory only: lost on a halo restart, and a
  // spill is then never restored: the session is re-prefilled).
  type Halo = { slots: Set[Slot], highest: SessId -> int, lastSeal: SessId -> int, lastSpill: SessId -> int,
                lastRestore: SessId -> int, fence: SessId -> int, entry: SessId -> int, jti: Set[int] }

  type Sys = {
    clock: int, ctlUp: bool, ctlInc: int,
    keys: int -> Key, ss: SessId -> Sess, proj: Proj, ops: int -> Op, copies: Set[Copy],
    wire: Set[Copy],            // every registration token sent (a network or an eavesdropper may deliver it again)
    inst: SessId -> bool,       // a running instance (jail with the workspace nullfs-mounted)
    zfs: Zfs, halo: Halo, files: Set[File],
    nextOp: int, nextKey: int, faults: int,
    staleInstall: bool,         // ghost: halo installed a registration, or a restore landed, under a stale epoch
    refusedStale: int,          // halo refusals for staleness (witnesses)
    haloRestarts: int, reboots: int, prefills: int,
    last: str,
  }

  // ------------------------------------------------------------- constants
  const SESSIONS: Set[SessId]
  const TOKEN_TTL: int    // registration token lifetime (300 s)
  const HALO_TTL: int     // halo forgets an unused registration after this (600 s)
  const OP_TIMEOUT: int
  const MAX_TIME: int
  const MAX_OPS: int
  const MAX_KEYS: int
  const MAX_EPOCH: int
  const MAX_ATTEMPTS: int
  const MAX_FAULTS: int
  pure val PROJ: str = "p"

  var y: Sys

  // ---------------------------------------------------------------- helpers
  pure def imax(a: int, b: int): int = if (a > b) a else b
  pure def opOf(y: Sys, id: int): Op = y.ops.get(id)
  pure def hasOp(y: Sys, id: int): bool = y.ops.keys().contains(id)
  pure def opSt(y: Sys, id: int): OpSt = if (hasOp(y, id)) opOf(y, id).st else NotDone
  pure def resolved(y: Sys, id: int): bool = id == 0 or opSt(y, id) == Done or opSt(y, id) == NotDone
  pure def sess(y: Sys, s: SessId): Sess = y.ss.get(s)
  pure def setSess(y: Sys, s: SessId, v: Sess): Sys = { ...y, ss: y.ss.set(s, v) }
  pure def setOp(y: Sys, o: Op): Sys = { ...y, ops: y.ops.put(o.id, o) }
  pure def keyOf(y: Sys, k: int): Key = y.keys.get(k)
  pure def setKey(y: Sys, k: Key): Sys = { ...y, keys: y.keys.put(k.id, k) }
  pure def jti(c: Copy): int = c.op * 100 + c.attempt
  pure def isProjOp(o: Op): bool = Set(OUnmount, OUnloadKey, ODestroy, OChangeKey).contains(o.kind)
  pure def isZfsOp(o: Op): bool = isProjOp(o) or o.kind == OLoadKey
  pure def isReg(o: Op): bool = o.kind == OReg and o.use != Revoke

  // a copy can still have an effect: a zfs (or restore/spill) copy until it
  // is gone; a halo registration until its token expires
  pure def canLand(y: Sys, c: Copy): bool =
    y.copies.contains(c) and (opOf(y, c.op).kind != OReg or y.clock <= c.iat + TOKEN_TTL)
  // settled: no copy of the op can still apply
  pure def settled(y: Sys, id: int): bool = not(y.copies.exists(c => c.op == id and canLand(y, c)))

  pure def newOp(y: Sys, k: OpKind, subj: str, key: int, ver: int, u: Use): Sys = {
    val o = { id: y.nextOp, kind: k, subj: subj, key: key, ver: ver, use: u, st: Pending,
              attempts: 1, inc: y.ctlInc, sentAt: y.clock }
    val c = { op: o.id, attempt: 1, inc: y.ctlInc, iat: y.clock }
    { ...y, ops: y.ops.put(o.id, o), nextOp: y.nextOp + 1, copies: y.copies.union(Set(c)),
      wire: if (isReg(o)) y.wire.union(Set(c)) else y.wire }
  }
  pure def newKey(y: Sys, cons: str, subj: str, ver: int): Sys =
    { ...y, keys: y.keys.put(y.nextKey, { id: y.nextKey, cons: cons, subj: subj, ver: ver, wrapped: true,
                                          shredding: false, shredded: false }), nextKey: y.nextKey + 1 }
  // shred begins: the wrapped key is deleted (SQLite secure_delete)
  pure def shredBegin(y: Sys, k: int): Sys =
    if (k == 0) y else setKey(y, { ...keyOf(y, k), wrapped: false, shredding: true })

  pure def liveSlot(y: Sys, sl: Slot): bool = y.clock < sl.at + HALO_TTL and (not(RULES.haloExpZero) or y.clock <= sl.exp)
  // the epoch of the file a registration seals (seal at E) or opens (open at E+1)
  pure def fileEpoch(u: Use, e: int): int = if (u == Open) e - 1 else e
  pure def holdsSlot(y: Sys, s: SessId, e: int, k: int, u: Use): bool =
    y.halo.slots.exists(sl => sl.sess == s and sl.epoch == e and sl.key == k and sl.use == u and liveSlot(y, sl))

  // ===================================================== effects
  // halo POST /admin/keys/{sess}: token checks, then install or revoke
  pure def haloReg(y: Sys, o: Op, c: Copy): Sys = {
    val h = y.halo
    val s = o.subj
    val tokOk = y.clock <= c.iat + TOKEN_TTL and not(h.jti.contains(jti(c)))
    // not below the highest epoch; an open right after its seal; never for an
    // epoch whose key was already used (a replayed or late token); never for a
    // file epoch at or below the revoke fence
    val fresh = and { o.ver >= h.highest.get(s),
                      o.use != Open or o.ver == h.lastSeal.get(s) + 1,
                      not(RULES.usedCheck) or o.use != Open or o.ver > h.lastRestore.get(s),
                      not(RULES.usedCheck) or o.use != Seal or o.ver > h.lastSpill.get(s),
                      fileEpoch(o.use, o.ver) > h.fence.get(s) }
    if (not(tokOk)) y
    // revoke (o.ver = `through`, the epoch of the last checkpoint yard wants
    // gone): never stale; the fence rises; keys and files at or below it go.
    // A later checkpoint of the same session is not touched.
    else if (o.use == Revoke) {
      val f = imax(h.fence.get(s), o.ver)
      { ...y, files: y.files.filter(x => not(x.sess == s and x.epoch <= f)),
        halo: { ...h, jti: h.jti.union(Set(jti(c))), fence: h.fence.set(s, f),
                slots: h.slots.filter(sl => not(sl.sess == s and fileEpoch(sl.use, sl.epoch) <= f)) } }
    }
    else if (RULES.staleCheck and not(fresh)) { ...y, refusedStale: y.refusedStale + 1, halo: { ...h, jti: h.jti.union(Set(jti(c))) } }
    else {
      val h1 = { ...h, jti: h.jti.union(Set(jti(c))), highest: h.highest.set(s, imax(h.highest.get(s), o.ver)) }
      {
        val cur = sess(y, s).epoch
        val stale = o.ver < cur
        val sl = { sess: s, epoch: o.ver, key: o.key, use: o.use, at: y.clock, exp: c.iat + TOKEN_TTL }
        { ...y, staleInstall: y.staleInstall or stale,
          halo: { ...h1,
                  slots: h1.slots.filter(x => not(x.sess == s and x.use == o.use and x.epoch == o.ver)).union(Set(sl)),
                  lastSeal: if (o.use == Seal) h1.lastSeal.set(s, imax(h1.lastSeal.get(s), o.ver)) else h1.lastSeal } }
      }
    }
  }

  pure def effect(y: Sys, o: Op, c: Copy): Sys = {
    val z = y.zfs
    match o.kind {
      // zfs load-key (stdin) of the project root, then zfs mount of the session clone.
      // The kernel checks the key: only the user key that wraps the master key now loads.
      | OLoadKey => if (z.exists and o.key == z.key) { ...y, zfs: { ...z, master: true, mounted: z.mounted.union(Set(o.subj)) } } else y
      // unmount every session clone of the project (the conservative reading: the
      // design does not count on EBUSY from a jail's nullfs mount)
      | OUnmount => { ...y, zfs: { ...z, mounted: Set() } }
      // unload-key requires nothing mounted
      | OUnloadKey => if (z.mounted == Set()) { ...y, zfs: { ...z, master: false } } else y
      | ODestroy => { ...y, zfs: { ...z, exists: false, master: false, mounted: Set() } }
      // change-key needs the key loaded; it rewraps the master key under the new user key
      | OChangeKey => if (z.exists and z.master) { ...y, zfs: { ...z, key: o.key } } else y
      | OReg => haloReg(y, o, c)
      // halo spill: seals with the registered seal key at its epoch, then forgets it
      | OSpill =>
          if (holdsSlot(y, o.subj, o.ver, o.key, Seal))
            { ...y, files: y.files.union(Set({ sess: o.subj, epoch: o.ver, key: o.key })),
              halo: { ...y.halo, lastSpill: y.halo.lastSpill.set(o.subj, imax(y.halo.lastSpill.get(o.subj), o.ver)),
                      entry: y.halo.entry.set(o.subj, o.key),
                      slots: y.halo.slots.filter(sl => not(sl.sess == o.subj and sl.use == Seal and sl.epoch == o.ver)) } }
          else y
      // halo restore (opens the file sealed at ver-1 with the open key at ver; the
      // cache entry must still hold that file: its checkpoint id), then the jail
      // starts on the workspace path, mounted or not
      | ORestore =>
          if (holdsSlot(y, o.subj, o.ver, o.key, Open) and y.files.contains({ sess: o.subj, epoch: o.ver - 1, key: o.key })
              and y.halo.entry.get(o.subj) == o.key)
            { ...y, inst: y.inst.set(o.subj, true),
              staleInstall: y.staleInstall or o.ver != sess(y, o.subj).epoch,
              halo: { ...y.halo, lastRestore: y.halo.lastRestore.set(o.subj, imax(y.halo.lastRestore.get(o.subj), o.ver)),
                      slots: y.halo.slots.filter(sl => not(sl.sess == o.subj and sl.use == Open and sl.epoch == o.ver)) } }
          else y
    }
  }

  // the resolving observation of each op (keystatus, mounted, zfs list, a dry-run
  // load-key -n with the new key, GET /admin/keys, the spill file, the jail)
  pure def observedDone(y: Sys, o: Op): bool = {
    val z = y.zfs
    match o.kind {
      | OLoadKey => z.master and z.mounted.contains(o.subj)
      | OUnmount => z.mounted == Set()
      | OUnloadKey => not(z.master)
      | ODestroy => not(z.exists)
      | OChangeKey => z.key == o.key
      | OReg => if (o.use == Revoke) y.halo.fence.get(o.subj) >= o.ver
                  and not(y.halo.slots.exists(sl => sl.sess == o.subj and fileEpoch(sl.use, sl.epoch) <= o.ver and liveSlot(y, sl)))
                else holdsSlot(y, o.subj, o.ver, o.key, o.use)
      | OSpill => y.files.contains({ sess: o.subj, epoch: o.ver, key: o.key })
      | ORestore => y.inst.get(o.subj)
    }
  }

  // ===================================================== environment
  pure def canFault(y: Sys): bool = y.faults < MAX_FAULTS
  pure def fault(y: Sys): Sys = { ...y, faults: y.faults + 1 }
  // late effect; the answer reaches only the incarnation that sent it
  pure def applyOpLand(y: Sys, c: Copy): Sys = {
    val o = opOf(y, c.op)
    val y1 = { ...effect(y, o, c), copies: y.copies.exclude(Set(c)) }
    val heard = y.ctlUp and c.inc == y.ctlInc and o.st == Pending
    if (heard) setOp(y1, { ...opOf(y1, c.op), st: if (observedDone(y1, o)) Done else Unknown }) else y1
  }
  pure def applyOpLandAnswerLost(y: Sys, c: Copy): Sys = fault({ ...effect(y, opOf(y, c.op), c), copies: y.copies.exclude(Set(c)) })
  // network duplicate of a halo registration: applies, and the copy may land again
  pure def applyOpLandDup(y: Sys, c: Copy): Sys = fault(effect(y, opOf(y, c.op), c))
  pure def applyOpLose(y: Sys, c: Copy): Sys = fault({ ...y, copies: y.copies.exclude(Set(c)) })

  // host reboot: the kernel forgets every key, mounts and jails go, the zfs
  // processes die, and yard-ctl (same host) crashes
  pure def applyReboot(y: Sys): Sys = fault({ ...y, zfs: { ...y.zfs, master: false, mounted: Set() },
    inst: SESSIONS.mapBy(_ => false), ctlUp: false, reboots: y.reboots + 1,
    copies: y.copies.filter(c => not(isZfsOp(opOf(y, c.op))) and opOf(y, c.op).kind != ORestore) })
  // halo restart: keys, seen jtis and the cache index (memory) are gone; the
  // per-session epochs and the fence survive only if halo keeps them durably
  pure def applyHaloRestart(y: Sys): Sys = fault({ ...y, haloRestarts: y.haloRestarts + 1,
    halo: if (RULES.haloDurable) { ...y.halo, slots: Set(), jti: Set(), entry: SESSIONS.mapBy(_ => 0) }
          else { slots: Set(), jti: Set(), highest: SESSIONS.mapBy(_ => 0), lastSeal: SESSIONS.mapBy(_ => 0),
                 lastSpill: SESSIONS.mapBy(_ => 0), lastRestore: SESSIONS.mapBy(_ => 0), fence: SESSIONS.mapBy(_ => 0),
                 entry: SESSIONS.mapBy(_ => 0) } })

  // ===================================================== controller: ops
  pure def canOpTimeout(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and {
    val o = opOf(y, id)
    o.st == Pending and o.inc == y.ctlInc and y.clock >= o.sentAt + OP_TIMEOUT
  }
  pure def canOpResolve(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and opOf(y, id).st == Unknown and settled(y, id)
  // retry: a resolved-not-done op the row still waits on (or a revoke); a halo
  // registration is resent with a fresh token (same use, epoch and key: a no-op 200)
  pure def opCurrent(y: Sys, o: Op): bool =
    if (isProjOp(o)) y.proj.op == o.id
    else if (o.kind == OReg and o.use == Revoke) true
    else sess(y, o.subj).op == o.id
  pure def canOpRetry(y: Sys, id: int): bool = y.ctlUp and hasOp(y, id) and {
    val o = opOf(y, id)
    o.st == NotDone and o.attempts < MAX_ATTEMPTS and o.kind != ORestore and opCurrent(y, o)
  }
  pure def applyOpRetry(y: Sys, id: int): Sys = {
    val o = opOf(y, id)
    val n = o.attempts + 1
    val c = { op: id, attempt: n, inc: y.ctlInc, iat: y.clock }
    { ...setOp(y, { ...o, st: Pending, attempts: n, sentAt: y.clock, inc: y.ctlInc }), copies: y.copies.union(Set(c)),
      wire: if (isReg(o)) y.wire.union(Set(c)) else y.wire }
  }
  pure def canRecoverOps(y: Sys): bool = y.ctlUp and y.ops.keys().exists(id => opOf(y, id).st == Pending and opOf(y, id).inc < y.ctlInc)
  pure def applyRecoverOps(y: Sys): Sys =
    { ...y, ops: y.ops.keys().mapBy(id => { val o = opOf(y, id) if (o.st == Pending and o.inc < y.ctlInc) { ...o, st: Unknown } else o }) }

  // ===================================================== controller: sessions
  pure def inPhase(y: Sys, s: SessId, st: SState, p: SPhase): bool = sess(y, s).st == st and sess(y, s).phase == p
  pure def curDone(y: Sys, s: SessId): bool = opSt(y, sess(y, s).op) == Done
  pure def curNotDone(y: Sys, s: SessId): bool = opSt(y, sess(y, s).op) == NotDone
  pure def opsLeft(y: Sys, n: int): bool = y.nextOp + n - 1 <= MAX_OPS

  // SuspendBegin: a fresh spill key K (created and wrapped: one SQLite
  // transaction), registered for seal at the current epoch
  pure def canSuspendBegin(y: Sys, s: SessId): bool = and { y.ctlUp, inPhase(y, s, Active, PNone), y.inst.get(s),
    sess(y, s).epoch < MAX_EPOCH, y.nextKey <= MAX_KEYS, opsLeft(y, 1) }
  pure def applySuspendBegin(y: Sys, s: SessId): Sys = {
    val e = sess(y, s).epoch
    val k = y.nextKey
    val y1 = newOp(newKey(y, "spill", s, e), OReg, s, k, e, Seal)
    setSess(y1, s, { ...sess(y, s), st: Suspending, phase: PSeal, op: y.nextOp, spill: k })
  }
  // mutant blindRegisterRetry: an unanswered seal is replaced by a fresh key
  // and a new registration, without verifying or shredding the first key
  pure def canSealFreshKey(y: Sys, s: SessId): bool = and { y.ctlUp, not(RULES.idempotentReg), inPhase(y, s, Suspending, PSeal),
    opSt(y, sess(y, s).op) == Unknown, y.nextKey <= MAX_KEYS, opsLeft(y, 1) }
  pure def applySealFreshKey(y: Sys, s: SessId): Sys = {
    val e = sess(y, s).epoch
    val k = y.nextKey
    val y1 = newOp(newKey(y, "spill", s, e), OReg, s, k, e, Seal)
    setSess(y1, s, { ...sess(y, s), op: y.nextOp, spill: k })
  }
  pure def canSuspendSpill(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Suspending, PSeal) and curDone(y, s) and opsLeft(y, 1)
  pure def applySuspendSpill(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(newOp(y, OSpill, s, r.spill, r.epoch, Seal), s, { ...r, phase: PSpill, op: y.nextOp })
  }
  // the spill was refused (no seal key: halo restarted or forgot it): verify
  // (GET /admin/keys was the observation) and register the same key again
  pure def canSuspendReseal(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Suspending, PSpill) and curNotDone(y, s) and opsLeft(y, 1)
  pure def applySuspendReseal(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(newOp(y, OReg, s, r.spill, r.epoch, Seal), s, { ...r, phase: PSeal, op: y.nextOp })
  }
  // commit: the instance is gone (SR0's quiesce/destroy), the epoch is bumped
  pure def canSuspendCommit(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Suspending, PSpill) and curDone(y, s)
  pure def applySuspendCommit(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    { ...setSess(y, s, { ...r, st: Suspended, phase: PNone, op: 0, epoch: r.epoch + 1 }), inst: y.inst.set(s, false) }
  }
  pure def canResumeBegin(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Suspended, PNone) and opsLeft(y, 1)
  pure def applyResumeBegin(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(newOp(y, OReg, s, r.spill, r.epoch, Open), s, { ...r, st: Resuming, phase: POpen, op: y.nextOp })
  }
  // the key fence: no unmount / unload of the project can still land
  pure def projQuiet(y: Sys): bool = y.proj.phase == KIdle and
    y.ops.keys().forall(id => { val o = opOf(y, id) not(Set(OUnmount, OUnloadKey).contains(o.kind)) or resolved(y, id) })
  pure def canResumeLoad(y: Sys, s: SessId): bool = and { y.ctlUp, inPhase(y, s, Resuming, POpen), curDone(y, s),
    if (RULES.keyFence) projQuiet(y) else Set(KIdle, KUnmount, KUnload).contains(y.proj.phase), opsLeft(y, 1) }
  pure def applyResumeLoad(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    if (RULES.reloadAlways or not(y.proj.believed))
      setSess(newOp(y, OLoadKey, s, y.proj.key, 0, Seal), s, { ...r, phase: PLoad, op: y.nextOp })
    else // trust the belief: straight to the restore
      setSess(newOp(y, ORestore, s, r.spill, r.epoch, Open), s, { ...r, phase: PRestore, op: y.nextOp })
  }
  pure def canResumeRestore(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Resuming, PLoad) and curDone(y, s) and opsLeft(y, 1)
  pure def applyResumeRestore(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    { ...setSess(newOp(y, ORestore, s, r.spill, r.epoch, Open), s, { ...r, phase: PRestore, op: y.nextOp }),
      proj: { ...y.proj, believed: true } }
  }
  // the restore was refused (halo lost the open key) and the cache entry still
  // holds the file: register open again
  pure def canResumeReopen(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Resuming, PRestore) and curNotDone(y, s)
    and y.halo.entry.get(s) == sess(y, s).spill and opsLeft(y, 1)
  // the restore was refused and halo's cache no longer holds the spill (a halo
  // restart: GET /admin/keys / the entry is gone): the session starts without it
  // (re-prefill); K was never used to open and is shredded
  pure def canResumePrefill(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Resuming, PRestore) and curNotDone(y, s)
    and y.halo.entry.get(s) != sess(y, s).spill
  pure def applyResumePrefill(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    { ...setSess(shredBegin(y, r.spill), s, { ...r, st: Active, phase: PNone, op: 0, spill: 0, resumes: r.resumes + 1 }),
      inst: y.inst.set(s, true), prefills: y.prefills + 1 }
  }
  pure def applyResumeReopen(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(newOp(y, OReg, s, r.spill, r.epoch, Open), s, { ...r, phase: POpen, op: y.nextOp })
  }
  // complete: K was used once; delete it (shred begins)
  pure def canResumeComplete(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Resuming, PRestore) and curDone(y, s)
  pure def applyResumeComplete(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(shredBegin(y, r.spill), s, { ...r, st: Active, phase: PNone, op: 0, spill: 0, resumes: r.resumes + 1 })
  }
  // the TTL: a suspended session expires; its spill key is shredded
  pure def canExpire(y: Sys, s: SessId): bool = y.ctlUp and inPhase(y, s, Suspended, PNone)
  pure def applyExpire(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    setSess(shredBegin(y, r.spill), s, { ...r, st: Gone, spill: 0 })
  }
  // the operator kills, SR0 fails, or `yard-svc down` removes (SR0 Removed) a
  // session (Gone: it no longer blocks the project's unload): Active, Suspending, Suspended,
  // or Resuming before the load. Its jail is removed, the op it waited on is
  // abandoned (no longer current: never retried; its copies may still land),
  // and its spill key's shred begins.
  pure def canKill(y: Sys, s: SessId): bool = y.ctlUp and {
    val r = sess(y, s)
    Set(Active, Suspending, Suspended).contains(r.st) or (r.st == Resuming and Set(POpen, PLoad).contains(r.phase))
  }
  pure def applyKill(y: Sys, s: SessId): Sys = {
    val r = sess(y, s)
    { ...setSess(shredBegin(y, r.spill), s, { ...r, st: Gone, phase: PNone, op: 0, spill: 0 }), inst: y.inst.set(s, false) }
  }

  // ===================================================== controller: spill-key shred
  pure def regOpsOf(y: Sys, k: int): Set[int] = y.ops.keys().filter(id => isReg(opOf(y, id)) and opOf(y, id).key == k)
  pure def lastIat(y: Sys, k: int): int = regOpsOf(y, k).fold(0, (m, id) => imax(m, opOf(y, id).sentAt))
  // no registration token carrying k can still be accepted (each expired)
  pure def tokensExpired(y: Sys, k: int): bool = y.clock > lastIat(y, k) + TOKEN_TTL
  pure def revokeOf(y: Sys, k: int): Set[int] =
    y.ops.keys().filter(id => opOf(y, id).kind == OReg and opOf(y, id).use == Revoke and opOf(y, id).key == k)
  // revoke: sent once no registration of k can land; `through` = k's checkpoint
  // epoch (the token's own epoch is the session's current one: never stale)
  pure def canSendRevoke(y: Sys, k: int): bool = y.ctlUp and y.keys.keys().contains(k) and {
    val kk = keyOf(y, k)
    kk.cons == "spill" and kk.shredding and not(kk.shredded) and revokeOf(y, k) == Set() and tokensExpired(y, k) and opsLeft(y, 1)
  }
  pure def applySendRevoke(y: Sys, k: int): Sys = {
    val kk = keyOf(y, k)
    newOp(y, OReg, kk.subj, k, kk.ver, Revoke)
  }
  // a revoke observed done (GET /admin/keys shows no key), sent after every
  // token of k expired (so nothing can install k after it)
  pure def revokeOk(y: Sys, k: int): bool = revokeOf(y, k).exists(id => if (RULES.shredVerify) opOf(y, id).st == Done else true)
  pure def canShredSpill(y: Sys, k: int): bool = y.ctlUp and y.keys.keys().contains(k) and {
    val kk = keyOf(y, k)
    and { kk.cons == "spill", kk.shredding, not(kk.shredded),
          if (RULES.shredSettle) tokensExpired(y, k) and (y.clock >= lastIat(y, k) + TOKEN_TTL + HALO_TTL or revokeOk(y, k)) else true }
  }
  pure def applyShredSpill(y: Sys, k: int): Sys = setKey(y, { ...keyOf(y, k), shredded: true })

  // ===================================================== controller: project key
  pure def projSessionsIdle(y: Sys): bool = SESSIONS.forall(s => Set(Suspended, Gone).contains(sess(y, s).st) and sess(y, s).phase == PNone)
  pure def loadsResolved(y: Sys): bool = y.ops.keys().forall(id => opOf(y, id).kind != OLoadKey or resolved(y, id))
  // unload when no session of the project is active or in flight, and no
  // load-key (of a killed resume) can still land
  pure def canUnloadBegin(y: Sys): bool = and { y.ctlUp, y.proj.phase == KIdle, y.proj.believed, y.zfs.exists,
    if (RULES.keyGuard) projSessionsIdle(y) and loadsResolved(y) else true, opsLeft(y, 1) }
  pure def applyUnloadBegin(y: Sys): Sys = { ...newOp(y, OUnmount, PROJ, y.proj.key, 0, Seal), proj: { ...y.proj, phase: KUnmount, op: y.nextOp } }
  pure def canUnmountDone(y: Sys): bool = y.ctlUp and y.proj.phase == KUnmount and opSt(y, y.proj.op) == Done and opsLeft(y, 1)
  pure def applyUnmountDone(y: Sys): Sys = { ...newOp(y, OUnloadKey, PROJ, y.proj.key, 0, Seal), proj: { ...y.proj, phase: KUnload, op: y.nextOp } }
  pure def canUnloadDone(y: Sys): bool = y.ctlUp and y.proj.phase == KUnload and opSt(y, y.proj.op) == Done
  pure def applyUnloadDone(y: Sys): Sys = { ...y, proj: { ...y.proj, phase: KIdle, op: 0, believed: false } }
  // rekey (zfs change-key on the project root) while the key is loaded: the new
  // key is created and wrapped first; the old one is deleted once change-key is done
  pure def canRekeyBegin(y: Sys): bool = and { y.ctlUp, y.proj.phase == KIdle, y.proj.believed, y.zfs.exists,
    y.nextKey <= MAX_KEYS, opsLeft(y, 1), SESSIONS.exists(s => sess(y, s).st == Active) }
  pure def applyRekeyBegin(y: Sys): Sys = {
    val k2 = y.nextKey
    val old = y.proj.key
    val y1 = newOp(newKey(y, "zfs", PROJ, keyOf(y, old).ver + 1), OChangeKey, PROJ, k2, 0, Seal)
    if (RULES.rekeyKeepOld) { ...y1, proj: { ...y.proj, phase: KRekey, op: y.nextOp } }
    else { ...setKey(y1, { ...keyOf(y1, old), wrapped: false }), proj: { ...y.proj, phase: KRekey, op: y.nextOp, key: k2 } }
  }
  pure def canRekeyDone(y: Sys): bool = y.ctlUp and y.proj.phase == KRekey and opSt(y, y.proj.op) == Done
  pure def applyRekeyDone(y: Sys): Sys = {
    val k2 = opOf(y, y.proj.op).key
    val old = y.proj.key
    // the old user key is retired, not shredded: change-key leaves the old
    // wrapped master key on disk (zfs-change-key(8)); only destroy shreds
    val y1 = if (old != k2) setKey(y, { ...keyOf(y, old), wrapped: false }) else y
    { ...y1, proj: { ...y.proj, phase: KIdle, op: 0, key: k2 } }
  }
  pure def canRekeyAbort(y: Sys): bool = y.ctlUp and y.proj.phase == KRekey and opSt(y, y.proj.op) == NotDone
  pure def applyRekeyAbort(y: Sys): Sys = {
    val k2 = opOf(y, y.proj.op).key
    val y1 = if (RULES.rekeyKeepOld) setKey(y, { ...keyOf(y, k2), wrapped: false }) else y
    { ...y1, proj: { ...y1.proj, phase: KIdle, op: 0 } }
  }
  // crypto-shred of the project: every session gone, the key unloaded; zfs destroy -r
  pure def canShredBegin(y: Sys): bool = and { y.ctlUp, y.proj.phase == KIdle, not(y.proj.believed), y.zfs.exists,
    SESSIONS.forall(s => sess(y, s).st == Gone), opsLeft(y, 1) }
  pure def applyShredBegin(y: Sys): Sys = {
    val y1 = { ...newOp(y, ODestroy, PROJ, y.proj.key, 0, Seal), proj: { ...y.proj, phase: KShred, op: y.nextOp } }
    // the wrapped keys go first: nothing can be loaded from yard-ctl again
    { ...y1, keys: y1.keys.keys().mapBy(k => { val kk = keyOf(y1, k) if (kk.cons == "zfs") { ...kk, wrapped: false, shredding: true } else kk }) }
  }
  pure def zfsCopiesGone(y: Sys): bool = not(y.copies.exists(c => isZfsOp(opOf(y, c.op))))
  pure def canShredDone(y: Sys): bool = y.ctlUp and y.proj.phase == KShred and
    (if (RULES.shredSettle) opSt(y, y.proj.op) == Done and zfsCopiesGone(y) else true)
  pure def applyShredDone(y: Sys): Sys =
    { ...y, proj: { ...y.proj, phase: KShredded, op: 0 },
      keys: y.keys.keys().mapBy(k => { val kk = keyOf(y, k) if (kk.cons == "zfs") { ...kk, shredded: true } else kk }) }

  // ===================================================== init and actions
  action init = y' = {
    clock: 0, ctlUp: true, ctlInc: 1,
    keys: Map(1 -> { id: 1, cons: "zfs", subj: PROJ, ver: 1, wrapped: true, shredding: false, shredded: false }),
    ss: SESSIONS.mapBy(_ => { st: Active, phase: PNone, epoch: 1, op: 0, spill: 0, resumes: 0 }),
    proj: { phase: KIdle, op: 0, key: 1, believed: true },
    ops: Map(), copies: Set(),
    inst: SESSIONS.mapBy(_ => true),
    zfs: { exists: true, master: true, mounted: SESSIONS, key: 1 },
    halo: { slots: Set(), highest: SESSIONS.mapBy(_ => 0), lastSeal: SESSIONS.mapBy(_ => 0),
            lastSpill: SESSIONS.mapBy(_ => 0), lastRestore: SESSIONS.mapBy(_ => 0), fence: SESSIONS.mapBy(_ => 0),
            entry: SESSIONS.mapBy(_ => 0), jti: Set() },
    wire: Set(),
    files: Set(),
    nextOp: 1, nextKey: 2, faults: 0, staleInstall: false, refusedStale: 0, haloRestarts: 0, reboots: 0, prefills: 0,
    last: "init",
  }

  action Tick = all { y.clock < MAX_TIME, y' = { ...y, clock: y.clock + 1, last: "Tick" } }
  action OpLand(c: Copy): bool = all { y.copies.contains(c), y' = { ...applyOpLand(y, c), last: "OpLand" } }
  action OpLandAnswerLost(c: Copy): bool = all { canFault(y), y.copies.contains(c), y' = { ...applyOpLandAnswerLost(y, c), last: "OpLandAnswerLost" } }
  action OpLandDup(c: Copy): bool = all { canFault(y), y.copies.contains(c), opOf(y, c.op).kind == OReg, y' = { ...applyOpLandDup(y, c), last: "OpLandDup" } }
  // a registration token delivered again (network duplicate, or an eavesdropper:
  // halo has no TLS) while it has not expired
  action Replay(c: Copy): bool = all { canFault(y), not(RULES.socketOnly), y.wire.contains(c), y.clock <= c.iat + TOKEN_TTL,
    y' = { ...fault(effect(y, opOf(y, c.op), c)), last: "Replay" } }
  action OpLose(c: Copy): bool = all { canFault(y), y.copies.contains(c), y' = { ...applyOpLose(y, c), last: "OpLose" } }
  action Reboot = all { canFault(y), y' = { ...applyReboot(y), last: "Reboot" } }
  action HaloRestart = all { canFault(y), y' = { ...applyHaloRestart(y), last: "HaloRestart" } }
  action CtlCrash = all { canFault(y), y.ctlUp, y' = { ...y, ctlUp: false, faults: y.faults + 1, last: "CtlCrash" } }
  action CtlRestart = all { not(y.ctlUp), y' = { ...y, ctlUp: true, ctlInc: y.ctlInc + 1, last: "CtlRestart" } }

  action OpTimeout(id: int): bool = all { canOpTimeout(y, id), y' = { ...setOp(y, { ...opOf(y, id), st: Unknown }), last: "OpTimeout" } }
  action OpResolve(id: int): bool = all { canOpResolve(y, id),
    y' = { ...setOp(y, { ...opOf(y, id), st: if (observedDone(y, opOf(y, id))) Done else NotDone }), last: "OpResolve" } }
  action OpRetry(id: int): bool = all { canOpRetry(y, id), y' = { ...applyOpRetry(y, id), last: "OpRetry" } }
  action RecoverOps = all { canRecoverOps(y), y' = { ...applyRecoverOps(y), last: "RecoverOps" } }

  action SuspendBegin(s: SessId): bool = all { canSuspendBegin(y, s), y' = { ...applySuspendBegin(y, s), last: "SuspendBegin" } }
  action SealFreshKey(s: SessId): bool = all { canSealFreshKey(y, s), y' = { ...applySealFreshKey(y, s), last: "SealFreshKey" } }
  action SuspendSpill(s: SessId): bool = all { canSuspendSpill(y, s), y' = { ...applySuspendSpill(y, s), last: "SuspendSpill" } }
  action SuspendReseal(s: SessId): bool = all { canSuspendReseal(y, s), y' = { ...applySuspendReseal(y, s), last: "SuspendReseal" } }
  action SuspendCommit(s: SessId): bool = all { canSuspendCommit(y, s), y' = { ...applySuspendCommit(y, s), last: "SuspendCommit" } }
  action ResumeBegin(s: SessId): bool = all { canResumeBegin(y, s), y' = { ...applyResumeBegin(y, s), last: "ResumeBegin" } }
  action ResumeLoad(s: SessId): bool = all { canResumeLoad(y, s), y' = { ...applyResumeLoad(y, s), last: "ResumeLoad" } }
  action ResumeRestore(s: SessId): bool = all { canResumeRestore(y, s), y' = { ...applyResumeRestore(y, s), last: "ResumeRestore" } }
  action ResumeReopen(s: SessId): bool = all { canResumeReopen(y, s), y' = { ...applyResumeReopen(y, s), last: "ResumeReopen" } }
  action ResumePrefill(s: SessId): bool = all { canResumePrefill(y, s), y' = { ...applyResumePrefill(y, s), last: "ResumePrefill" } }
  action ResumeComplete(s: SessId): bool = all { canResumeComplete(y, s), y' = { ...applyResumeComplete(y, s), last: "ResumeComplete" } }
  action Expire(s: SessId): bool = all { canExpire(y, s), y' = { ...applyExpire(y, s), last: "Expire" } }
  action Kill(s: SessId): bool = all { canKill(y, s), y' = { ...applyKill(y, s), last: "Kill" } }
  action SendRevoke(k: int): bool = all { canSendRevoke(y, k), y' = { ...applySendRevoke(y, k), last: "SendRevoke" } }
  action ShredSpill(k: int): bool = all { canShredSpill(y, k), y' = { ...applyShredSpill(y, k), last: "ShredSpill" } }
  action UnloadBegin = all { canUnloadBegin(y), y' = { ...applyUnloadBegin(y), last: "UnloadBegin" } }
  action UnmountDone = all { canUnmountDone(y), y' = { ...applyUnmountDone(y), last: "UnmountDone" } }
  action UnloadDone = all { canUnloadDone(y), y' = { ...applyUnloadDone(y), last: "UnloadDone" } }
  action RekeyBegin = all { canRekeyBegin(y), y' = { ...applyRekeyBegin(y), last: "RekeyBegin" } }
  action RekeyDone = all { canRekeyDone(y), y' = { ...applyRekeyDone(y), last: "RekeyDone" } }
  action RekeyAbort = all { canRekeyAbort(y), y' = { ...applyRekeyAbort(y), last: "RekeyAbort" } }
  action ShredBegin = all { canShredBegin(y), y' = { ...applyShredBegin(y), last: "ShredBegin" } }
  action ShredDone = all { canShredDone(y), y' = { ...applyShredDone(y), last: "ShredDone" } }

  action envStep = any { Reboot, HaloRestart, CtlCrash, CtlRestart, replayStep }
  action replayStep = { nondet c = y.wire.oneOf() Replay(c) }
  action copyStep = {
    nondet c = y.copies.oneOf()
    any { OpLand(c), OpLand(c), OpLand(c), OpLandAnswerLost(c), OpLandDup(c), OpLose(c) }
  }
  action ctlStep = {
    nondet s = SESSIONS.oneOf()
    nondet id = 1.to(MAX_OPS).oneOf()
    nondet k = 1.to(MAX_KEYS).oneOf()
    any {
      OpTimeout(id), OpResolve(id), OpRetry(id), RecoverOps,
      SuspendBegin(s), SealFreshKey(s), SuspendSpill(s), SuspendReseal(s), SuspendCommit(s),
      ResumeBegin(s), ResumeLoad(s), ResumeRestore(s), ResumeReopen(s), ResumePrefill(s), ResumeComplete(s),
      SendRevoke(k), ShredSpill(k),
      UnloadBegin, UnmountDone, UnloadDone, RekeyBegin, RekeyDone, RekeyAbort, ShredDone,
    }
  }
  // the endings (expiry, kill, project shred) are always enabled somewhere: one
  // branch of their own keeps them from ending most traces early
  action endStep = { nondet s = SESSIONS.oneOf() any { Expire(s), Kill(s), ShredBegin } }
  action step = any { Tick, Tick, envStep, copyStep, copyStep, copyStep, ctlStep, ctlStep, ctlStep, ctlStep, ctlStep, endStep }

  // Focused step (a restriction of `step`: every trace is a trace of the
  // full model): one session's spill-key life, with duplicated and lost
  // registrations and halo restarts, no project actions and no reboot. It
  // reaches the late-registration interleavings the spill mutants need in
  // a few hundred traces (run.sh, README "Focused runs").
  action spillCopy = {
    nondet c = y.copies.oneOf()
    any { OpLand(c), OpLand(c), OpLandDup(c), OpLandAnswerLost(c) }
  }
  action spillReplay = { nondet c = y.wire.oneOf() Replay(c) }
  action spillCtl = {
    nondet id = 1.to(MAX_OPS).oneOf()
    nondet k = 1.to(MAX_KEYS).oneOf()
    any {
      OpTimeout(id), OpResolve(id), OpRetry(id),
      SuspendBegin("s1"), SealFreshKey("s1"), SuspendSpill("s1"), SuspendReseal("s1"), SuspendCommit("s1"),
      ResumeBegin("s1"), ResumeLoad("s1"), ResumeRestore("s1"), ResumeReopen("s1"), ResumePrefill("s1"), ResumeComplete("s1"),
      Expire("s1"), Kill("s1"),
      SendRevoke(k), ShredSpill(k),
    }
  }
  action stepSpill = any { Tick, HaloRestart, spillReplay, spillCopy, spillCopy, spillCtl, spillCtl, spillCtl }
  // stepReplay (a restriction of `step`): s1's suspend and resume with every
  // copy landing, halo restarts and token replays, and no clock: tokens stay
  // valid, which is the window the halo-side rules guard (TCP mode only)
  action replayLand = { nondet c = y.copies.oneOf() OpLand(c) }
  action replayCtl = any {
    SuspendBegin("s1"), SuspendSpill("s1"), SuspendCommit("s1"),
    ResumeBegin("s1"), ResumeLoad("s1"), ResumeRestore("s1"), ResumeComplete("s1"),
  }
  action stepReplay = any { HaloRestart, spillReplay, replayLand, replayLand, replayCtl, replayCtl }

  // ===================================================== invariants
  // K1 nothing is installed in a consumer, or resumed, under a stale epoch
  val noStaleEpoch: bool = not(y.staleInstall)
  // K2 after a shred, no consumer can decrypt: no consumer holds the key and no
  // copy in flight can still install it
  val noDecryptAfterShred: bool = y.keys.keys().forall(k => {
    val kk = keyOf(y, k)
    kk.shredded implies (
      if (kk.cons == "spill")
        not(y.halo.slots.exists(sl => sl.key == k and liveSlot(y, sl))) and tokensExpired(y, k)
      else not(y.zfs.master) and not(y.copies.exists(c => opOf(y, c.op).kind == OLoadKey)))
  })
  // K3 a key is never unloaded (nor its clone unmounted) under a running session
  val keyUnderRunning: bool = SESSIONS.forall(s => y.inst.get(s) implies (y.zfs.master and y.zfs.mounted.contains(s)))
  // K4 every live wrapped spill key belongs to a suspend record (no orphan
  // that is never shredded), and a suspended session's key is still there
  val keysAccounted: bool =
    y.keys.keys().forall(k => { val kk = keyOf(y, k)
      (kk.cons == "spill" and kk.wrapped) implies SESSIONS.exists(s => sess(y, s).spill == k) })
    and SESSIONS.forall(s => sess(y, s).st == Suspended implies keyOf(y, sess(y, s).spill).wrapped)
  // K5 the user key that wraps the project's master key is in the store (until the shred)
  val projectKeyAvailable: bool = (y.zfs.exists and not(Set(KShred, KShredded).contains(y.proj.phase))) implies keyOf(y, y.zfs.key).wrapped
  val safety: bool = and { noStaleEpoch, noDecryptAfterShred, keyUnderRunning, keysAccounted, projectKeyAvailable }

  // ===================================================== witnesses
  val wResumed: bool = SESSIONS.exists(s => sess(y, s).resumes > 0)
  val wResumedTwice: bool = SESSIONS.exists(s => sess(y, s).resumes > 1)
  val wUnloaded: bool = y.last == "UnloadDone"
  val wReloaded: bool = y.last == "ResumeRestore" and SESSIONS.exists(s => sess(y, s).st == Resuming) and
    y.ops.keys().exists(id => opOf(y, id).kind == OUnloadKey and opOf(y, id).st == Done)
  val wSpillShredded: bool = y.keys.keys().exists(k => keyOf(y, k).cons == "spill" and keyOf(y, k).shredded)
  val wShredByRevoke: bool = y.last == "ShredSpill" and y.keys.keys().exists(k => keyOf(y, k).shredded and revokeOk(y, k)
    and y.clock < lastIat(y, k) + TOKEN_TTL + HALO_TTL)
  val wProjectShredded: bool = y.proj.phase == KShredded
  val wRekeyed: bool = y.last == "RekeyDone"
  val wStaleRefused: bool = y.refusedStale > 0
  val wResumeAfterHaloRestart: bool = y.last == "ResumeComplete" and y.haloRestarts > 0
  val wResumeAfterReboot: bool = y.last == "ResumeComplete" and y.reboots > 0
  val wResealed: bool = y.last == "SuspendReseal"
  val wReopened: bool = y.last == "ResumeReopen"
  val wPrefilled: bool = y.last == "ResumePrefill"
  val wRevokeFenced: bool = SESSIONS.exists(s => y.halo.fence.get(s) > 0) and y.refusedStale > 0
}
