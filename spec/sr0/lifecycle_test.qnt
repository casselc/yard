// Scripted runs of the SR0 lifecycle (quint test). Design runs end in
// "DesignTest"; each mutant's counterexample replays as "*BreaksTest" in the
// mutant's own module (its run is the prefix the design blocks).
module lifecycle_test {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"

  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }

  // observe, wait out the idle timeout, go idle
  run idlePrefix = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))

  run suspendPrefix = idlePrefix
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))

  run suspendDesignTest = suspendPrefix.then(SuspendCommit("s1"))
    .expect(and { y.rows.get("s1").state == Suspended, y.rows.get("s1").token == 1, allInvariants })

  run resumeDesignTest = suspendPrefix.then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1))
    .then(ResumeReject("s1", "timer", 1))
    .then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg"))
    .expect(and { y.rows.get("s1").state == Active, y.rows.get("s1").resumes == 1, allInvariants })

  run suspendedP = suspendPrefix.then(SuspendCommit("s1"))

  // the restore request is lost: timeout, settle, observe, not done; back
  // to suspended with a fresh token; a second resume succeeds
  run resumeAbortDesignTest = suspendedP
    .then(ResumeConsume("s1", "msg", 1)).then(OpLose(cp(4, 1, 1, 2)))
    .then(Tick).then(Tick).then(OpTimeout(4)).then(OpResolve(4)).then(ResumeAbort("s1", "msg"))
    .expect(and { y.rows.get("s1").state == Suspended, y.rows.get("s1").token == 2, allInvariants })
    .then(ResumeConsume("s1", "timer", 2)).then(OpLand(cp(5, 1, 1, 4)))
    .then(ResumeMint("s1", "timer")).then(OpLand(cp(6, 1, 1, 4))).then(ResumeComplete("s1", "timer"))
    .expect(and { y.rows.get("s1").state == Active, allInvariants })

  // restored, then the instance dies: failed, artifact delete owed and done
  run resumeFailDesignTest = suspendedP
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(InstanceCrash("s1")).then(ResumeFail("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .expect(and { y.rows.get("s1").state == Failed, y.artifacts == Set(), allInvariants })

  // TTL: expired, the owed delete is lost, retried and done
  run expireDesignTest = suspendedP.then(3.reps(_ => Tick)).then(Expire("s1"))
    .then(OpLose(cp(4, 1, 1, 5))).then(Tick).then(Tick).then(OpTimeout(4)).then(OpResolve(4)).then(OpRetry(4))
    .then(OpLand(cp(4, 2, 1, 7)))
    .expect(and { y.rows.get("s1").state == Expired, y.artifacts == Set(), allInvariants })

  // a checkpoint killed mid-write: unknown, settled, partial seen; deleted and retaken
  run partialDesignTest = idlePrefix
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLandPartial(cp(2, 1, 1, 2)))
    .then(Tick).then(Tick).then(OpTimeout(2)).then(OpResolve(2)).then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(5, 1, 1, 4)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .expect(and { y.rows.get("s1").state == Suspended, y.rows.get("s1").ckpt == 4, allInvariants })

  // yard-ctl dies mid-suspend with the checkpoint in flight; the new
  // incarnation waits for it to settle, sees it done, and carries on
  run crashSuspendDesignTest = idlePrefix
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart)
    .then(RecoverOps("s1")).then(Adopt("s1"))
    .then(OpLand(cp(2, 1, 1, 2))).then(OpResolve(2))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 2, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .expect(and { y.rows.get("s1").state == Suspended, allInvariants })

  // yard-ctl dies mid-resume with the restore in flight; it lands late, the
  // recovery driver resolves it as done, mints and completes
  run crashResumeDesignTest = suspendedP
    .then(ResumeConsume("s1", "msg", 1)).then(CtlCrash).then(CtlRestart)
    .then(RecoverOps("s1")).then(Adopt("s1")).then(OpLand(cp(4, 1, 1, 2))).then(OpResolve(4))
    .then(ResumeMint("s1", "recovery")).then(OpLand(cp(5, 1, 2, 2))).then(ResumeComplete("s1", "recovery"))
    .expect(and { y.rows.get("s1").state == Active, y.ctlInc == 2, allInvariants })

  // yard-ctl dies mid-suspend before quiesce lands, the abort path
  // unquiesces and the session is Idle again
  run crashAbortDesignTest = idlePrefix
    .then(SuspendBegin("s1")).then(CtlCrash).then(CtlRestart)
    .then(RecoverOps("s1")).then(Adopt("s1")).then(OpLand(cp(1, 1, 1, 2))).then(OpResolve(1))
    .then(SuspendAbort("s1")).then(OpLand(cp(2, 1, 2, 2))).then(SuspendAbortDone("s1"))
    .expect(and { y.rows.get("s1").state == Idle, allInvariants })

  // a message held while suspended, delivered after the resume
  run heldMessageDesignTest = suspendedP.then(MessageArrive("s1"))
    .then(3.reps(_ => Tick)).then(Expire("s1")).fail()
  run heldMessageDeliveredDesignTest = suspendedP.then(MessageArrive("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2))).then(ResumeComplete("s1", "msg"))
    .then(Deliver("s1"))
    .expect(and { y.rows.get("s1").inbox == 0, y.rows.get("s1").state == Active, allInvariants })
}

// ------------------------------------------------- scripted counterexamples
// Each mutant's counterexample as a fixed run (`*BreaksTest`, run in a module
// that imports the mutant), and the step the design blocks (`*DesignTest`).

module designScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run snapshotBeforeQuiesceDesignTest = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1")).fail()
  run checkpointTimeoutNotDoneDesignTest = ctndP.then(SuspendAbort("s1")).fail()
  run commitBeforeDestroyDesignTest = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2))).then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2))).then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2))).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1")).fail()
  run blindRestoreRetryDesignTest = brrP.then(RestoreBlindRetry("s1", "msg")).fail()
  run nonAtomicConsumeDesignTest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(ResumeConsume("s1", "timer", 1)).fail()
  run noCredEpochDesignTest = lateMintRest.expect(noPreSuspendCredential)
  run gcByAgeDesignTest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1")).fail()
  run expireDropsInboxDesignTest = ediP.then(Expire("s1")).fail()
  run observeAtRequestDesignTest = oarP.then(GoIdle("s1")).fail()
  run ignoreActivityDuringSuspendDesignTest = iadP.then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1")).fail()
  run fireAndForgetDeleteDesignTest = ffdRest.expect(artifactsAccounted)
  run recoverAssumesNotDoneDesignTest = randP.then(SuspendCheckpointRetry("s1")).fail()
  run snapshotBeforeQuiescePrefixTest = idleP.then(SuspendBegin("s1")).expect(allInvariants)
  run checkpointTimeoutNotDonePrefixTest = ctndP.expect(allInvariants)
  run commitBeforeDestroyPrefixTest = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2))).then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2))).then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2))).then(ObsReq("s1")).then(ObsAnswer("s1")).expect(allInvariants)
  run blindRestoreRetryPrefixTest = brrP.expect(allInvariants)
  run nonAtomicConsumePrefixTest = suspendedP.then(ResumeConsume("s1", "msg", 1)).expect(allInvariants)
  run gcByAgePrefixTest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).expect(allInvariants)
  run expireDropsInboxPrefixTest = ediP.expect(allInvariants)
  run observeAtRequestPrefixTest = oarP.expect(allInvariants)
  run ignoreActivityDuringSuspendPrefixTest = iadP.then(ObsReq("s1")).then(ObsAnswer("s1")).expect(allInvariants)
  run recoverAssumesNotDonePrefixTest = randP.expect(allInvariants)
  // the first restore copy still lands on the design, and is fenced
  run blindRestoreLateCopyDesignTest = brrP.then(OpLand(cp(4, 1, 1, 2))).then(OpResolve(4)).expect(and { allInvariants, y.ops.get(4).st == Done })
}

module snapshotBeforeQuiesceScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = false,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run snapshotBeforeQuiesceBreaksTest = sbqRest.expect(not(noAckedWriteLost))
}

module checkpointTimeoutNotDoneScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = false, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run checkpointTimeoutNotDoneBreaksTest = ctndRest.expect(not(artifactsAccounted))
}

module commitBeforeDestroyScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = false, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run commitBeforeDestroyBreaksTest = cbdRest.expect(not(resumedAtMostOnce))
}

module blindRestoreRetryScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = false, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run blindRestoreRetryBreaksTest = brrRest.expect(not(resumedAtMostOnce))
}

module nonAtomicConsumeScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = false, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run nonAtomicConsumeBreaksTest = nacRest.expect(not(resumedAtMostOnce))
}

module noCredEpochScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = false, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run noCredEpochBreaksTest = lateMintRest.expect(not(noPreSuspendCredential))
}

module gcByAgeScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = false,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run gcByAgeBreaksTest = gbaRest.expect(not(resumeKeepsArtifacts))
}

module expireDropsInboxScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = false, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run expireDropsInboxBreaksTest = ediRest.expect(not(noMessageLost))
}

module observeAtRequestScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = false, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run observeAtRequestBreaksTest = oarRest.expect(not(suspendedOnlyIdle))
}

module ignoreActivityDuringSuspendScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = false, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run ignoreActivityDuringSuspendBreaksTest = iadRest.expect(not(suspendedOnlyIdle))
}

module fireAndForgetDeleteScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = false, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = true,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run fireAndForgetDeleteBreaksTest = ffdRest.expect(not(artifactsAccounted))
}

module recoverAssumesNotDoneScripts {
  import lifecycle(
    SESSIONS = Set("s1"), CLIENTS = Set("msg", "timer"),
    KIND = Map("s1" -> "fc"), POLICY = Map("s1" -> { keepWarm: false, maxAge: 3 }),
    IDLE_TIMEOUT = 2, OP_TIMEOUT = 2, CRED_TTL = 8, MAX_TIME = 24, MAX_GEN = 2, MAX_OPS = 16,
    MAX_TOKENS = 4, MAX_WRITES = 2, MAX_ACT = 3, MAX_INBOX = 1, MAX_ATTEMPTS = 2, MAX_FAULTS = 3,
    ATOMIC_CONSUME = true, RESTORE_FENCE = true, DESTROY_SETTLE = true, QUIESCE_SETTLE = true,
    CRED_EPOCH = true, CKPT_TIMEOUT_UNKNOWN = true, DELETE_OWED = true, GC_BY_ROW = true,
    OBS_AT_ANSWER = true, RECHECK_ACTIVITY = true, EXPIRE_CHECKS_INBOX = true, RECOVER_UNKNOWN = false,
  ).* from "./lifecycle"
  pure def cp(id: int, att: int, inc: int, at: int): Copy = { op: id, attempt: att, inc: inc, sentAt: at }
  // idle at clock 2
  run idleP = init.then(ObsReq("s1")).then(ObsAnswer("s1")).then(Tick).then(Tick).then(GoIdle("s1"))
  // quiesced and checkpointed and destroyed (ops 1-3 at clock 2), activity re-read
  run destroyedP = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1"))
  run suspendedP = destroyedP.then(SuspendCommit("s1"))

  // snapshotBeforeQuiesce: the checkpoint is taken while quiesce is in
  // flight; a tool call's write lands after it and is acked; resume would
  // roll the workspace back to the snapshot.
  run sbqP = idleP.then(SuspendBegin("s1")).then(SuspendCheckpoint("s1"))
  run sbqRest = sbqP.then(OpLand(cp(2, 1, 1, 2)))
    .then(WriteIssue("s1")).then(WriteLand("s1", 1))
    .then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // checkpointTimeoutNotDone: a checkpoint times out, is taken as not done,
  // the abort deletes it, and then it completes: an artifact nobody owes a
  // delete for, on an Idle session.
  run ctndP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(Tick).then(Tick).then(OpTimeout(2))
  run ctndRest = ctndP.then(SuspendAbort("s1"))
    .then(OpLand(cp(3, 1, 1, 4))).then(OpLand(cp(4, 1, 1, 4))).then(SuspendAbortDone("s1"))
    .then(OpLand(cp(2, 1, 1, 2)))

  // commitBeforeDestroy: the destroy request is lost, commit goes ahead,
  // and a resume starts a second copy beside the paused original.
  run cbdRest = idleP
    .then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLose(cp(3, 1, 1, 2)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))

  // blindRestoreRetry: the restore times out, is resent at once, and both
  // copies start the instance.
  run brrP = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(Tick).then(Tick).then(OpTimeout(4))
  run brrRest = brrP.then(RestoreBlindRetry("s1", "msg"))
    .then(OpLand(cp(4, 1, 1, 2))).then(OpLand(cp(4, 2, 1, 4)))

  // nonAtomicConsume: two triggers both check the token, then both claim.
  run nacRest = suspendedP
    .then(ResumeCheck("s1", "msg", 1)).then(ResumeCheck("s1", "timer", 1))
    .then(ResumeClaim("s1", "msg", 1)).then(ResumeClaim("s1", "timer", 1))

  // noCredEpoch: a refresh requested before the suspend lands after the
  // resume; without an epoch the STS mints it and the broker honours it
  // (the original credential has expired by TTL, so only the late one is
  // in play).
  run lateMintP = idleP.then(CredRefresh("s1"))
    .then(SuspendBegin("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(3, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(4, 1, 1, 2)))
    .then(Tick).then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))
    .then(5.reps(_ => Tick))
    .then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(5, 1, 1, 8)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(6, 1, 1, 8)))
    .then(ResumeComplete("s1", "msg"))
  run lateMintRest = lateMintP.then(OpLand(cp(1, 1, 1, 2)))

  // gcByAge: a sweeper deletes the artifact of a session whose resume holds
  // the token.
  run gbaRest = suspendedP.then(3.reps(_ => Tick)).then(ResumeConsume("s1", "msg", 1)).then(GcSweep("s1"))

  // expireDropsInbox: a message is held for a suspended session; TTL
  // expiry drops it.
  run ediP = suspendedP.then(MessageArrive("s1")).then(3.reps(_ => Tick))
  run ediRest = ediP.then(Expire("s1"))

  // observeAtRequest: activity happens between the observation request and
  // its answer; dated at the request, it looks idle too early.
  run oarP = init.then(Tick).then(ObsReq("s1")).then(Tick).then(Activity("s1")).then(ObsAnswer("s1")).then(Tick)
  run oarRest = oarP
    .then(GoIdle("s1")).then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 3)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 3)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 3)))
    .then(ObsReq("s1")).then(ObsAnswer("s1")).then(SuspendCommit("s1"))

  // ignoreActivityDuringSuspend: activity after the decision, before the
  // quiesce lands; commit without re-reading it.
  run iadP = idleP.then(SuspendBegin("s1")).then(Activity("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(OpLand(cp(2, 1, 1, 2)))
    .then(SuspendDestroy("s1")).then(OpLand(cp(3, 1, 1, 2)))
  run iadRest = iadP.then(SuspendCommit("s1"))

  // fireAndForgetDelete: the delete after a resume is lost; nobody owes it.
  run ffdRest = suspendedP.then(ResumeConsume("s1", "msg", 1)).then(OpLand(cp(4, 1, 1, 2)))
    .then(ResumeMint("s1", "msg")).then(OpLand(cp(5, 1, 1, 2)))
    .then(ResumeComplete("s1", "msg")).then(OpLose(cp(6, 1, 1, 2)))

  // recoverAssumesNotDone: yard-ctl restarts with a checkpoint in flight,
  // takes it as not done, deletes it and takes another; the first lands.
  run randP = idleP.then(SuspendBegin("s1")).then(OpLand(cp(1, 1, 1, 2)))
    .then(SuspendCheckpoint("s1")).then(CtlCrash).then(CtlRestart).then(RecoverOps("s1")).then(Adopt("s1"))
  run randRest = randP.then(SuspendCheckpointRetry("s1"))
    .then(OpLand(cp(3, 1, 2, 2))).then(OpLand(cp(2, 1, 1, 2)))
  run recoverAssumesNotDoneBreaksTest = randRest.expect(not(artifactsAccounted))
}
