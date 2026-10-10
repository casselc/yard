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
  run revokeOnlyByMessageBreaksTest = revokeSchedule.then(ShredSpill(2)).expect(not(noDecryptAfterShred))
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
  run staleSchedule = suspended.then(HaloRestart).then(replay(1))
  run staleEpochAcceptedBreaksTest = staleSchedule.expect(not(noStaleEpoch))
  run haloForgetsEpochsBreaksTest = staleSchedule.expect(not(noStaleEpoch))
  run identityAsWrittenBreaksTest = staleSchedule.expect(not(noStaleEpoch))
  run staleDesignTest = staleSchedule.expect(and { safety, y.refusedStale == 1 })
  // over the Unix socket nobody but yard-ctl sends: the replay cannot happen (runsDesignSocket)
  run socketReplayImpossibleTest = suspended.then(HaloRestart).then(replay(1)).fail()

  // revoke `through` = the checkpoint's epoch: s1 resumed (K=2 at epoch 1), then
  // suspended again (K=6... at epoch 2); the revoke of the first checkpoint (through 1)
  // leaves the second seal alone, and a late open for epoch 2 (file epoch 1) is fenced
  run revokeThroughTest = resumed.then(SuspendBegin("s1")).then(land(6))
    .then(Tick).then(Tick).then(Tick).then(SendRevoke(2)).then(land(7))
    .expect(and { safety, y.halo.fence.get("s1") == 1, opOf(y, 7).st == Done })
    .then(SuspendSpill("s1")).expect(and { safety, sess(y, "s1").phase == PSpill })

  // halo restarts after the spill: the cache index is gone, the restore is
  // refused, and the session starts without its spill (re-prefill); K is shredded
  run prefillAfterHaloRestartTest = suspended.then(HaloRestart).then(ResumeBegin("s1")).then(land(3))
    .then(ResumeLoad("s1")).then(land(4)).then(ResumeRestore("s1")).then(land(5))
    .expect(opOf(y, 5).st == Unknown).then(Tick).then(OpResolve(5)).then(ResumeReopen("s1")).fail()
  run prefillAfterHaloRestart2Test = suspended.then(HaloRestart).then(ResumeBegin("s1")).then(land(3))
    .then(ResumeLoad("s1")).then(land(4)).then(ResumeRestore("s1")).then(land(5)).then(Tick).then(OpResolve(5))
    .then(ResumePrefill("s1")).expect(and { safety, sess(y, "s1").st == Active, keyOf(y, 2).shredding, wPrefilled })

  // crypto-shred of the project: both sessions gone, unload, destroy
  run projectShredTest = init.then(Kill("s1")).then(Kill("s2")).then(UnloadBegin).then(land(1)).then(UnmountDone)
    .then(land(2)).then(UnloadDone).then(ShredBegin).then(land(3)).then(ShredDone)
    .expect(and { safety, wProjectShredded, not(y.zfs.exists) })
}
