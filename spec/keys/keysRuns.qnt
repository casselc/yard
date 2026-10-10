// -*- mode: Bluespec; -*-
// keysRuns.qnt: scripted runs of keys.qnt. Each *BreaksTest replays a
// counterexample on its mutant and ends with the property false; the
// matching *DesignTest runs the same schedule on the design and shows the
// fatal step refused (.fail()) or the property kept. Instances (runs*) are
// at the end of keysTest.qnt; run.sh runs them.
module keysRuns {
  import keysTypes.* from "./keys"
  const R: Rules
  import keys(RULES = R, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"

  // the one copy of op id in flight lands, answered
  action land(id: int): bool = { nondet c = y.copies.filter(c => c.op == id).oneOf() OpLand(c) }
  action lose(id: int): bool = { nondet c = y.copies.filter(c => c.op == id).oneOf() OpLose(c) }
  action replay(id: int): bool = { nondet c = y.wire.filter(c => c.op == id).oneOf() Replay(c) }

  // s1 suspended at epoch 1 -> 2: seal (op 1, key 2), spill (op 2), commit
  run suspended = init.then(SuspendBegin("s1")).then(land(1)).then(SuspendSpill("s1")).then(land(2)).then(SuspendCommit("s1"))
  // ... and resumed: open (op 3), load-key (op 4), restore (op 5), complete
  run resumed = suspended.then(ResumeBegin("s1")).then(land(3)).then(ResumeLoad("s1")).then(land(4))
    .then(ResumeRestore("s1")).then(land(5)).then(ResumeComplete("s1"))

  run happyPathTest = resumed.expect(and { safety, sess(y, "s1").resumes == 1, keyOf(y, 2).shredding })
    .then(Tick).then(Tick).then(Tick).then(Tick).then(Tick).then(Tick).then(Tick).then(Tick)
    .then(ShredSpill(2)).expect(and { safety, wSpillShredded })

  // unload under active sessions
  run unloadUnderActiveBreaksTest = init.then(UnloadBegin).then(land(1)).expect(not(keyUnderRunning))
  run unloadUnderActiveDesignTest = init.then(UnloadBegin).fail()

  // shred K at ResumeComplete, while its registration tokens are still valid
  run shredBeforeLoadSettlesBreaksTest = resumed.then(ShredSpill(2)).expect(not(noDecryptAfterShred))
  run shredBeforeLoadSettlesDesignTest = resumed.then(ShredSpill(2)).fail()

  // open registered (slot live), session killed, revoke sent but not landed
  run revokeSchedule = suspended.then(ResumeBegin("s1")).then(land(3)).then(Kill("s1"))
    .then(Tick).then(Tick).then(Tick).then(SendRevoke(2))
  // obsolete as a break since halo's fix round: halo zeroes a key at its token's
  // exp, so once every token of K expired no slot holds it, verified revoke or
  // not (README finding 6). The mutant now keeps K2 on this schedule.
  run revokeOnlyByMessageHoldsTest = revokeSchedule.then(ShredSpill(2)).expect(noDecryptAfterShred)
  run revokeOnlyByMessageDesignTest = revokeSchedule.then(ShredSpill(2)).fail()
  run revokeVerifiedTest = revokeSchedule.then(land(4)).then(ShredSpill(2)).expect(and { safety, wShredByRevoke })

  // host reboot while s1 is suspended: the kernel forgot the project key
  run rebootSchedule = suspended.then(Reboot).then(CtlRestart).then(ResumeBegin("s1")).then(land(3)).then(ResumeLoad("s1"))
  run trustConsumerAfterRestartBreaksTest = rebootSchedule.then(land(4)).expect(not(keyUnderRunning))
  run trustConsumerAfterRestartDesignTest = rebootSchedule.expect(opOf(y, 4).kind == OLoadKey)
    .then(land(4)).then(ResumeRestore("s1")).then(land(5)).then(ResumeComplete("s1")).expect(and { safety, wResumeAfterReboot })

  // s2 killed, s1 suspended, unload begins (op 3: unmount); s1 resumes meanwhile
  run unloadSchedule = suspended.then(Kill("s2")).then(UnloadBegin).then(ResumeBegin("s1")).then(land(4))
  run loadDuringUnloadBreaksTest = unloadSchedule.then(ResumeLoad("s1")).then(land(5)).then(land(3))
    .then(ResumeRestore("s1")).then(land(6)).expect(not(keyUnderRunning))
  run loadDuringUnloadDesignTest = unloadSchedule.then(ResumeLoad("s1")).fail()
  run reloadAfterUnloadTest = unloadSchedule.then(land(3)).then(UnmountDone).then(land(5)).then(UnloadDone)
    .then(ResumeLoad("s1")).then(land(6)).then(ResumeRestore("s1")).then(land(7)).then(ResumeComplete("s1"))
    .expect(and { safety, sess(y, "s1").st == Active, y.zfs.master })

  // the seal's answer is lost: a fresh key instead of verify-and-retry
  run sealUnknown = init.then(SuspendBegin("s1")).then(lose(1)).then(Tick).then(Tick).then(OpTimeout(1))
  run blindRegisterRetryBreaksTest = sealUnknown.then(SealFreshKey("s1")).expect(not(keysAccounted))
  run blindRegisterRetryDesignTest = sealUnknown.then(SealFreshKey("s1")).fail()
  run sealVerifyRetryTest = sealUnknown.then(Tick).then(OpResolve(1)).then(OpRetry(1)).then(land(1))
    .then(SuspendSpill("s1")).expect(and { safety, opOf(y, 1).st == Done })

  // rekey: the old key deleted when change-key is sent
  run rekeyDropsOldBreaksTest = init.then(RekeyBegin).expect(not(projectKeyAvailable))
  run rekeyDropsOldDesignTest = init.then(RekeyBegin).then(lose(1)).then(Tick).then(Tick).then(OpTimeout(1))
    .then(OpResolve(1)).then(RekeyAbort).expect(and { safety, y.zfs.key == 1, y.proj.key == 1 })

  // a seal token delivered again after the spill used it and halo restarted
  // a seal token delivered again after a halo restart: since round 3 the
  // seal names an entry id of the old incarnation and is refused whatever the
  // epoch rules (README finding 9)
  run sealReplaySchedule = suspended.then(HaloRestart).then(replay(1))
  run sealReplayRefusedTest = sealReplaySchedule.expect(and { safety, y.halo.slots == Set() })
  run haloForgetsEpochsHoldsTest = sealReplaySchedule.expect(noStaleEpoch)
  run identityAsWrittenHoldsTest = sealReplaySchedule.expect(noStaleEpoch)
  // an open token (epoch 2) delivered again after the session suspended
  // again (epoch 3) and halo restarted (its op records and jtis gone)
  run staleSchedule = resumed.then(SuspendBegin("s1")).then(land(6)).then(SuspendSpill("s1")).then(land(7))
    .then(SuspendCommit("s1")).then(HaloRestart).then(replay(3))
  run staleEpochAcceptedBreaksTest = staleSchedule.expect(not(noStaleEpoch))
  run staleDesignTest = staleSchedule.expect(and { safety, y.refusedStale == 1 })

  // the key service additions (internal/keysvc): abort, verify-retry, revoke `through`
  // an abort after the spill landed: the epoch is burnt (no new seal at it), K is
  // shredding, and its revoke fences exactly that epoch
  run abortAfterSpill = init.then(SuspendBegin("s1")).then(land(1)).then(SuspendSpill("s1")).then(land(2)).then(SuspendAbort("s1"))
  run abortBurnsEpochTest = abortAfterSpill.expect(and { safety, wAborted, keyOf(y, 2).shredding, burntEpoch(y, "s1", 1) })
    .then(SuspendBegin("s1")).fail()
  run abortRevokeFencesTest = abortAfterSpill.then(Tick).then(Tick).then(Tick).then(SendRevoke(2)).then(land(3))
    .expect(and { safety, y.halo.fence.get("s1") == 1, opOf(y, 3).st == Done, y.files == Set() })
    .then(ShredSpill(2)).expect(and { safety, wShredByRevoke })
  // an abort before the spill: the epoch is not burnt; a new key seals at it
  // (replacing the unused slot); the unspilled key gets no revoke, and is
  // shredded by the time bound alone
  run abortBeforeSpill = init.then(SuspendBegin("s1")).then(land(1)).then(SuspendAbort("s1"))
  run abortBeforeSpillTest = abortBeforeSpill.then(SuspendBegin("s1")).then(land(2))
    .expect(and { safety, holdsSlot(y, "s1", 1, 3, Seal), not(holdsSlot(y, "s1", 1, 2, Seal)) })
    .then(SuspendSpill("s1")).then(land(3)).then(SuspendCommit("s1")).expect(and { safety, wResuspendedAfterAbort })
  run abortNoRevokeTest = abortBeforeSpill.then(Tick).then(Tick).then(Tick).then(SendRevoke(2)).fail()
  run abortShredByTimeTest = abortBeforeSpill.then(Tick).then(Tick).then(Tick).then(Tick).then(Tick).then(Tick).then(Tick)
    .then(Tick).then(ShredSpill(2)).expect(and { safety, keyOf(y, 2).shredded })
  // verify, then idempotent retry: the seal's copy is lost; verify misses; resend
  run verifyRetryTest = init.then(SuspendBegin("s1")).then(lose(1)).then(Tick).then(Tick).then(OpTimeout(1))
    .then(OpVerifyRetry(1)).expect(and { opOf(y, 1).st == Pending, opOf(y, 1).attempts == 2 })
    .then(land(1)).then(SuspendSpill("s1")).expect(and { safety, opOf(y, 1).st == Done })
  // ... or the answer only was lost: verify sees the slot and the op is done
  run verifySeesTest = init.then(SuspendBegin("s1")).then({ nondet c = y.copies.oneOf() OpLandAnswerLost(c) })
    .then(Tick).then(Tick).then(OpTimeout(1)).then(OpVerifyRetry(1)).expect(and { safety, opOf(y, 1).st == Done, opOf(y, 1).attempts == 1 })
  // a revoke through the consumed checkpoint's epoch leaves the next checkpoint's seal key
  // a revoke through the consumed checkpoint (T = 2) that lands after the next
  // checkpoint's seal at 2 cancels that pending seal (round 4/5: registrations
  // at epochs <= T go) and leaves the fence at 1; the spill is refused, and
  // a new operation (reseal: a new op id, the same key) seals it
  run revokeCancelsPendingSeal = resumed.then(Tick).then(Tick).then(Tick).then(SuspendBegin("s1")).then(land(6))
    .then(SendRevoke(2)).then(land(7))
  run revokeCancelsPendingSealTest = revokeCancelsPendingSeal
    .expect(and { safety, y.halo.fence.get("s1") == 1, not(holdsSlot(y, "s1", 2, 3, Seal)), opOf(y, 7).st == Done,
                  recOf(y.halo, "s1", Seal, 6).exists(x => x.st == "cancelled") })
    .then(SuspendSpill("s1")).then(land(8)).then(Tick).then(OpResolve(8)).then(SuspendReseal("s1")).then(land(9))
    .then(SuspendSpill("s1")).then(land(10)).then(SuspendCommit("s1")).expect(and { safety, sess(y, "s1").st == Suspended })
  // K8: the seal at 2 lands with its answer lost; the delayed revoke (T = 2)
  // cancels it; verify misses and yard resends the same operation (a fresh
  // token): halo answers 409 "cancelled"; yard renews (a new op id, a new key)
  run cancelDup = resumed.then(Tick).then(Tick).then(Tick).then(SuspendBegin("s1"))
    .then({ nondet c = y.copies.filter(c => c.op == 6).oneOf() OpLandAnswerLost(c) })
    .then(SendRevoke(2)).then(land(7)).then(Tick).then(Tick).then(OpTimeout(6)).then(OpVerifyRetry(6)).then(land(6))
  run cancelDupDesignTest = cancelDup.expect(and { safety, not(holdsSlot(y, "s1", 2, 3, Seal)), opOver(y, opOf(y, 6)) })
    .then(RenewOp("s1")).then(land(8)).expect(and { safety, holdsSlot(y, "s1", 2, 4, Seal), keyOf(y, 3).shredding })
  run cancelWeakensBreaksTest = cancelDup.expect(not(noCancelledInstall))
  // K9 / renewal: the seal lands with its answer lost at 0; its slot dies with its
  // token; verify misses at 3 and resends; the copy lands at 5 = first + TTL:
  // outlived (409); a new operation with a new key seals
  run outlived = init.then(SuspendBegin("s1")).then({ nondet c = y.copies.oneOf() OpLandAnswerLost(c) })
    .then(Tick).then(Tick).then(OpTimeout(1)).then(Tick).then(OpVerifyRetry(1)).then(Tick).then(Tick).then(land(1))
  run outlivedRenewTest = outlived.expect(and { safety, opOf(y, 1).st == Unknown, opOver(y, opOf(y, 1)) })
    .then(RenewOp("s1")).then(land(2)).expect(and { safety, holdsSlot(y, "s1", 1, 3, Seal), keyOf(y, 2).shredding,
                                                    opOf(y, 2).oid == 2 })
  run capResetsBreaksTest = outlived.expect(not(slotWithinCap))
  // K10: the renewal carries the old op id over (yard) and halo does not check it
  // K10: an abort before the spill; the next checkpoint's seal at the same
  // epoch carries the previous seal's op id (yard), and halo does not check it
  run opIdReuse = init.then(SuspendBegin("s1")).then(land(1)).then(SuspendAbort("s1")).then(SuspendBegin("s1")).then(land(2))
  run opIdReuseDesignTest = opIdReuse.expect(and { safety, holdsSlot(y, "s1", 1, 3, Seal), opOf(y, 2).oid == 2 })
  run opIdReusedBreaksTest = opIdReuse.expect(not(opIdOneOperation))


  // halo round 4: a delayed revoke. K2's revoke (minted at T = 2 after the
  // resume) is in flight; s1 seals K3 at 2, spills, commits (epoch 3).
  // Explicit through = 1 leaves K3's file; the server default (bounded:
  // min(last spill 2, T 2) = 2) erases it (revokeDefaultThrough).
  run delayedRevoke = resumed.then(Tick).then(Tick).then(Tick).then(SendRevoke(2))
    .then(SuspendBegin("s1")).then(land(7)).then(SuspendSpill("s1")).then(land(8)).then(SuspendCommit("s1"))
    .then(land(6))
  run delayedRevokeDesignTest = delayedRevoke.expect(and { safety, y.halo.fence.get("s1") == 1, opOf(y, 6).tep == 2 })
  run revokeDefaultThroughBreaksTest = delayedRevoke.expect(not(checkpointKept))
  // ... one cycle later (the newer spill at T + 1 = 3): only an unbounded revoke
  // erases it (unboundedRevoke); the bounded default fences 2 and keeps it
  run delayedRevoke2 = resumed.then(Tick).then(Tick).then(Tick).then(SendRevoke(2))
    .then(SuspendBegin("s1")).then(land(7)).then(SuspendSpill("s1")).then(land(8)).then(SuspendCommit("s1"))
    .then(ResumeBegin("s1")).then(land(9)).then(ResumeLoad("s1")).then(land(10)).then(ResumeRestore("s1")).then(land(11))
    .then(ResumeComplete("s1")).then(SuspendBegin("s1")).then(land(12)).then(SuspendSpill("s1")).then(land(13))
    .then(SuspendCommit("s1")).then(land(6))
  run delayedRevokeNextCycleDesignTest = delayedRevoke2.expect(and { safety, sess(y, "s1").epoch == 4, y.halo.fence.get("s1") == 1 })
  run unboundedRevokeBreaksTest = delayedRevoke2.expect(not(checkpointKept))
  run delayedRevokeNextCycleAuthorityTest = delayedRevoke2.expect(revokeBoundedByAuthority)
  // K7: an uncapped default fences the checkpoint spilled at T + 1 = 3
  run revokeUncappedBreaksTest = delayedRevoke2.expect(not(revokeBoundedByAuthority))
  // K7: a delayed revoke at T = 2 (explicit through 1) lands after the seal at 2
  // and the spill and commit, then after a seal at T + 1 = 3: an unscoped revoke
  // zeroes that seal key; the design leaves it
  run delayedRevokeAfterSeal = resumed.then(Tick).then(Tick).then(Tick).then(SendRevoke(2))
    .then(SuspendBegin("s1")).then(land(7)).then(SuspendSpill("s1")).then(land(8)).then(SuspendCommit("s1"))
    .then(ResumeBegin("s1")).then(land(9)).then(ResumeLoad("s1")).then(land(10)).then(ResumeRestore("s1")).then(land(11))
    .then(ResumeComplete("s1")).then(SuspendBegin("s1")).then(land(12)).then(land(6))
  run delayedRevokeAfterSealDesignTest = delayedRevokeAfterSeal.expect(and { safety, holdsSlot(y, "s1", 3, 4, Seal), opOf(y, 6).tep == 2 })
  run revokeUnscopedBreaksTest = delayedRevokeAfterSeal.expect(not(revokeBoundedByAuthority))
  // on revokeDefaultThrough (bounded halo): the T+1 checkpoint survives
  run delayedRevokeNextCycleHoldsTest = delayedRevoke2.expect(checkpointKept)

  // crypto-shred of the project: both sessions gone, unload, destroy
  run projectShredTest = init.then(Kill("s1")).then(Kill("s2")).then(UnloadBegin).then(land(1)).then(UnmountDone)
    .then(land(2)).then(UnloadDone).then(ShredBegin).then(land(3)).then(ShredDone)
    .expect(and { safety, wProjectShredded, not(y.zfs.exists) })
}
