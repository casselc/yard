// -*- mode: Bluespec; -*-
// wardenRuns.qnt: scripted runs of warden.qnt, parametric in the rules.
// wardenTest.qnt instantiates this module once per design, finding and
// mutant (modules runs<Name>). Each `<name>BreaksTest` replays the shortest
// schedule we know that breaks the property its mutant is named for (on the
// mutant it ends with the property false); the matching `<name>DesignTest`
// replays the same schedule on the design, where the fatal step is refused
// or disabled. Time is in ticks of 5 minutes.
module wardenRuns {
  import basicSpells.* from "./spells/basicSpells"
  import wardenLogic.* from "./wardenLogic"
  const R: Rules
  import warden(RULES = R).* from "./warden"

  // ---------------------------------------------------------------- fixtures
  pure val A = "sbxA"
  pure val B = "sbxB"
  pure def content(x: Sbx, q: int, v: int, p: Pol, rg: str, t: int): Content =
    { sbx: x, req: q, ver: v, pol: p, region: rg, ttl: t }
  pure val roA = content(A, 1, 1, "ro", "r1", 4)       // a low-tier card, 20-min TTL
  pure val roA6 = content(A, 1, 1, "ro", "r1", 6)      // ... with a 30-min TTL
  pure val roA_v2 = content(A, 1, 2, "ro", "r2", 4)    // the agent re-asked for region r2
  pure val roA2 = content(A, 2, 1, "ro", "r2", 6)      // a second low-tier request
  pure val iamA1 = content(A, 1, 1, "iam", "r1", 4)    // two escalation cards
  pure val iamA2 = content(A, 2, 1, "iam", "r1", 4)
  pure def keyOf(c: Content): CardKey = { sbx: c.sbx, req: c.req }
  pure def intentOf(c: Content): Intent = { pol: c.pol, region: c.region, ttl: c.ttl }
  pure def wreq(c: Content): { tap: Sbx, req: int, intent: Intent } = { tap: c.sbx, req: c.req, intent: intentOf(c) }
  // the decision binds the final hash: the card re-hashed with the approved TTL
  pure def fin(c: Content, ttl: int): Hash = hash(finalContent(c, ttl))
  pure def dec(c: Content, ttl: int, at: int, asr: Option[Asr]): Decision =
    { key: keyOf(c), h: fin(c, ttl), approve: true, ttl: ttl, clickAt: at, asr: asr }
  pure val iamA6 = content(A, 1, 1, "iam", "r1", 6)    // an escalation asking 30 min

  // ---------------------------------------------------------------- steps
  action sbxAsks(c: Content): bool =
    doWith(c.sbx, t => t.effects.contains(send(CTL, WReq(wreq(c)))))
  action ctlIntake(c: Content): bool = CTL.with_cue(listen_intake, wreq(c)).perform(act_intake)
  action userAsk(c: Content, t: int): bool = USER.with_cue(listen_need_challenge, fin(c, t)).perform(act_ask_challenge)
  action ctlChallenge(c: Content, t: int): bool = CTL.with_cue(listen_challenge_req, fin(c, t)).perform(act_challenge)
  // the user clicks approve on card c at TTL ttl (clicked now), with assertion asr
  action userApproves(c: Content, ttl: int, asr: Option[Asr]): bool =
    doWith(USER, t => t.effects.contains(send(CTL, DecisionMsg(dec(c, ttl, now, asr)))))
  action ctlDecides(d: Decision): bool = CTL.with_cue(listen_decision, d).perform(act_decision)
  action brokerFetch(x: Sbx): bool = BROKER.with_cue(listen_fetch, x).perform(act_fetch)
  // yard-ctl signs a JWT for the broker's pending request
  action ctlSigns: bool = doWith(CTL, t => t.effects.size() > 0 and t.post_state.jwtN > ctlSt.jwtN)
  action brokerExchanges: bool = doWith(BROKER, t => t.post_state.usedJwt.size() > brokerSt.usedJwt.size())
  pure def errAnswer(t: Transition): bool = 0.to(9).exists(i => t.effects.contains(send(BROKER, MintErr({ att: i }))))
  // the cloud mints and answers with credentials / with an error
  action cloudMints: bool = doWith(CLOUD, t => t.post_state.minted.size() > minted.size() and not(errAnswer(t)))
  action cloudMintsErr: bool = doWith(CLOUD, t => t.post_state.minted.size() > minted.size() and errAnswer(t))
  action cloudRefuses: bool = doWith(CLOUD, t => t.post_state.done.size() > cloudSt.done.size() and t.post_state.minted == minted)
  action brokerTakesCreds: bool = doWith(BROKER, t => t.post_state.answered.size() > brokerSt.answered.size())
  action brokerTakesErr(i: int): bool = BROKER.with_cue(listen_err, i).perform(act_err)
  action brokerTimesOut(i: int): bool =
    BROKER.with_cue(listen_timeout, brokerSt.pend.filter(a => a.att == i).getOnlyElement()).perform(act_timeout)
  action brokerServes(tap: Sbx): bool =
    doWith(BROKER, t => t.post_state.served.exists(p => p._1 == tap and not(brokerSt.served.contains(p))))
  action loseCreds(i: int): bool = loseMsg(BROKER, CredsMsg({ att: i, cred: minted.filter(c => c.id == i).getOnlyElement() }))
  action userAborts(c: Content): bool = USER.with_cue(listen_abortable, hash(c)).perform(act_abort_button)
  action ctlAborts(c: Content): bool = CTL.with_cue(listen_abort, hash(c)).perform(act_abort)
  action cloudDenies: bool = doWith(CLOUD, t => t.post_state.deny.keys().size() > cloudSt.deny.keys().size())
  action ctlSuspends(x: Sbx): bool = CTL.with_cue(listen_suspend, x).perform(act_suspend)
  action brokerHearsEpoch: bool = doWith(BROKER, t => t.post_state.epochSeen != brokerSt.epochSeen
                                                     and t.post_state.usedJwt == brokerSt.usedJwt and t.post_state.synced)
  action ctlResumes(x: Sbx): bool = CTL.with_cue(listen_resume, x).perform(act_resume)
  action ctlResendsNotice(x: Sbx): bool = CTL.with_cue(listen_resuming, x).perform(act_resend_notice)
  action ctlTakesAck(x: Sbx): bool = CTL.with_cue(listen_epoch_ack, x).perform(act_epoch_ack)
  action brokerCrashes: bool = doWith(BROKER, t => t.post_state.restarts > brokerSt.restarts)
  action brokerPulls: bool = BROKER.with_cue(listen_need_pull, brokerSt.pulls).perform(act_need_pull)
  action ctlAnswersPull(n: int): bool = CTL.with_cue(listen_pull, n).perform(act_pull)
  action brokerTakesEpochs: bool = doWith(BROKER, t => t.post_state.synced and not(brokerSt.synced))
  action cloudDeniesOrphan(i: int): bool = CLOUD.with_cue(listen_orphan_deny, i).perform(act_orphan_deny)
  action brokerSeesIp: bool = BROKER.with_cue(listen_ip, 1).perform(act_ip)
  action ctlReconciles(i: int): bool = CTL.with_cue(listen_reconcile, i).perform(act_reconcile)
  action sbxWithdraws(x: Sbx, q: int): bool = doWith(x, t => t.effects.contains(send(CTL, WWithdraw({ tap: x, req: q }))))
  action ctlWithdraws(x: Sbx, q: int): bool = CTL.with_cue(listen_withdraw, { tap: x, req: q }).perform(act_withdraw)
  action userTemplateButton(x: Sbx, p: Pol): bool = USER.with_cue(listen_template_button, (x, p)).perform(act_template_button)
  action ctlTemplate(x: Sbx, p: Pol): bool = CTL.with_cue(listen_template, (x, p)).perform(act_template)

  // a card asked, shown, approved and granted at time 0
  action approvedAt0(c: Content, ttl: int): bool =
    init.then(sbxAsks(c)).then(ctlIntake(c)).then(userApproves(c, ttl, None)).then(ctlDecides(dec(c, ttl, 0, None)))
  // ... then one mint in the current slot, answered with credentials, held by the broker
  action mintOnce(x: Sbx): bool =
    brokerFetch(x).then(ctlSigns).then(brokerExchanges).then(cloudMints).then(brokerTakesCreds)

  // ================================================================ the design's paths
  run happyPathTest =
    approvedAt0(roA, 4).then(mintOnce(A)).then(brokerServes(A))
      .expect(and { safety, wServed, minted.size() == 1 })

  run escalationTest =
    init.then(sbxAsks(iamA1)).then(ctlIntake(iamA1)).then(userAsk(iamA1, 4)).then(ctlChallenge(iamA1, 4))
      .then(userApproves(iamA1, 4, Some({ h: hash(iamA1), chAt: 0 })))
      .then(ctlDecides(dec(iamA1, 4, 0, Some({ h: hash(iamA1), chAt: 0 }))))
      .then(mintOnce(A)).then(brokerServes(A))
      .expect(and { safety, wEscMinted })

  // the mint applied but its answer was lost: the broker waits out the JWT
  // (the settle bound), drops the attempt, and mints in the next slot
  run lostAnswerRemintTest =
    approvedAt0(roA6, 6).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges).then(cloudMints)
      .then(loseCreds(0)).then(tick).then(tick).then(brokerTimesOut(0))
      .then(mintOnce(A)).then(brokerServes(A))
      .expect(and { safety, wRemintAfterLoss, wServed })

  // a JWT that arrives late is refused by the cloud: a definite "not done"
  run expiredJwtRefusedTest =
    approvedAt0(roA6, 6).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges)
      .then(tick).then(tick).then(cloudRefuses).then(brokerTakesErr(0))
      .expect(and { safety, minted.size() == 0, brokerSt.pend.size() == 0 })

  // decision 12: a mint whose answer was lost has no warden.mint row; once
  // CloudTrail has it (15 min) the reconciler records it
  action lostAnswerSchedule: bool =
    approvedAt0(roA6, 6).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges).then(cloudMints)
      .then(loseCreds(0)).then(tick).then(tick).then(tick)
  run reconcileTest = lostAnswerSchedule.then(ctlReconciles(0)).then(cloudDeniesOrphan(0))
    .expect(and { safety, ctlSt.orphans == Set(0), wOrphanRevoked })
  run noReconcilerBreaksTest = lostAnswerSchedule.expect(not(orphansReconcilable))
  // 2026-10-07 round 3: a reconciled orphan is revoked, not just recorded
  run orphanOnlyRecordedBreaksTest = lostAnswerSchedule.then(ctlReconciles(0)).expect(not(orphansReconcilable))

  // round 3: resume completes only on the broker's acknowledgement; the
  // notice is lost once and re-sent; the old-epoch credential is dropped
  action resumeSchedule: bool = approvedAt0(roA, 4).then(mintOnce(A)).then(ctlSuspends(A)).then(ctlResumes(A))
  run resumeWithoutBrokerAckBreaksTest = resumeSchedule.expect(not(brokerHonoursCurrentEpoch))
  run resumeWithoutBrokerAckDesignTest = resumeSchedule.expect(and { safety, ctlSt.sess.get(A) == SResuming })
  run resumeAckTest =
    resumeSchedule.then(loseMsg(BROKER, EpochNotice({ sbx: A, epoch: 1 }))).then(ctlResendsNotice(A))
      .then(brokerHearsEpoch).then(ctlTakesAck(A))
      .expect(and { safety, wResumed, brokerSt.held.size() == 0 })

  // round 3: a restarted broker pulls the epochs before it exchanges or serves
  run brokerRestartPullTest =
    approvedAt0(roA, 4).then(mintOnce(A)).then(ctlSuspends(A)).then(brokerCrashes)
      .then(brokerPulls).then(ctlAnswersPull(0)).then(brokerTakesEpochs)
      .expect(and { safety, wBrokerResynced, brokerSt.epochSeen.get(A) == 1 })

  // decision 10: a withdraw revokes the task's grant
  run withdrawRevokesTest =
    approvedAt0(roA, 4).then(sbxWithdraws(A, 1)).then(ctlWithdraws(A, 1))
      .expect(and { safety, wWithdrawRevoked, ctlSt.grants.get(hash(roA)).revokedAt == 0 })

  // decision 10: approving the agent's newer version revokes the older grant
  action supersedeSchedule: bool =
    approvedAt0(roA, 4).then(sbxAsks(roA_v2)).then(ctlIntake(roA_v2))
      .then(userApproves(roA_v2, 4, None)).then(ctlDecides(dec(roA_v2, 4, 0, None)))
  run supersedeRevokesTest = supersedeSchedule.expect(and { safety, wSupersededRevoked })
  run supersedeKeepsGrantBreaksTest = supersedeSchedule.expect(not(oneLiveGrantPerTask))

  // decision 7: an IP change re-mints at once, a new key under the per-grant cap
  run ipChangeRemintTest =
    approvedAt0(roA6, 6).then(mintOnce(A)).then(ipChange).then(brokerSeesIp).then(tick).then(mintOnce(A))
      .expect(and { safety, wIpRemint, minted.size() == 2 })

  // decision 4: the passkey signs the final hash, with the shortened TTL; an
  // assertion over the card as asked (30 min) does not approve 20 min
  run passkeyBindsShortTtlTest =
    init.then(sbxAsks(iamA6)).then(ctlIntake(iamA6)).then(userAsk(iamA6, 6)).then(ctlChallenge(iamA6, 6))
      .then(userApproves(iamA6, 4, Some({ h: fin(iamA6, 6), chAt: 0 })))
      .then(ctlDecides(dec(iamA6, 4, 0, Some({ h: fin(iamA6, 6), chAt: 0 }))))
      .expect(and { safety, ctlSt.refused.contains("passkey"), ctlSt.grants.keys().size() == 0 })
  run passkeyShortTtlTest =
    init.then(sbxAsks(iamA6)).then(ctlIntake(iamA6)).then(userAsk(iamA6, 4)).then(ctlChallenge(iamA6, 4))
      .then(userApproves(iamA6, 4, Some({ h: fin(iamA6, 4), chAt: 0 })))
      .then(ctlDecides(dec(iamA6, 4, 0, Some({ h: fin(iamA6, 4), chAt: 0 }))))
      .then(mintOnce(A)).expect(and { safety, wEscMinted, wShorterTtl })

  // SR0: a JWT signed before a suspend reaches the broker after it learnt the
  // new epoch; the broker refuses it
  action staleEpochSchedule: bool =
    approvedAt0(roA, 4).then(brokerFetch(A)).then(ctlSigns).then(ctlSuspends(A)).then(ctlResumes(A))
      .then(brokerHearsEpoch).then(brokerExchanges)
  run staleEpochAcceptedBreaksTest = staleEpochSchedule.expect(not(brokerHonoursCurrentEpoch))
  run staleEpochAcceptedDesignTest =
    staleEpochSchedule.expect(and { safety, wStaleEpochRefused, brokerSt.pend.size() == 0 })

  // AWS mode hands the VM its credentials (decision 5): the strict P6 is false by design
  run awsEcsHandsVmCredsTest =
    approvedAt0(roA, 4).then(mintOnce(A)).then(brokerServes(A))
      .expect(and { safety, not(noCloudCredInSandbox) })

  // ================================================================ mutants
  // approval not hash-bound: the user approves v1, the agent re-asks (v2),
  // the warden binds the late approval to the card's current version
  action approvalNotHashBoundSchedule: bool =
    init.then(sbxAsks(roA)).then(ctlIntake(roA)).then(userApproves(roA, 4, None))
      .then(sbxAsks(roA_v2)).then(ctlIntake(roA_v2))
      .then(ctlDecides(dec(roA, 4, 0, None)))
  run approvalNotHashBoundBreaksTest =
    approvalNotHashBoundSchedule.then(mintOnce(A)).expect(not(mintedMatchesApproval))
  run approvalNotHashBoundDesignTest =
    approvalNotHashBoundSchedule.expect(and { ctlSt.refused.contains("hash"), ctlSt.grants.keys().size() == 0, safety })

  // edit in place: approved v1, then the agent re-asks; the mint renders the card by id
  action editInPlaceSchedule: bool =
    approvedAt0(roA, 4).then(sbxAsks(roA_v2)).then(ctlIntake(roA_v2)).then(mintOnce(A))
  run editInPlaceBreaksTest = editInPlaceSchedule.expect(not(mintedMatchesApproval))
  run editInPlaceDesignTest = editInPlaceSchedule.expect(and { safety, minted.forall(c => c.policy == roA) })

  // blind retry: an error answer after the mint applied, the broker re-sends the JWT
  action blindRetrySchedule: bool =
    approvedAt0(roA, 4).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges).then(cloudMintsErr).then(brokerTakesErr(0))
  run blindRetryBreaksTest = blindRetrySchedule.then(cloudMints).expect(not(atMostOneMintPerSlot))
  run blindRetryDesignTest = blindRetrySchedule.expect(and { safety, brokerSt.pend.size() == 0, minted.size() == 1 })

  // wait for an answer: the answer is lost, the attempt is never resolved
  action waitForAnswerSchedule: bool =
    approvedAt0(roA6, 6).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges).then(cloudMints)
      .then(loseCreds(0)).then(tick).then(tick)
  run waitForAnswerBreaksTest = waitForAnswerSchedule.expect(not(settledAttemptResolvable))
  run waitForAnswerDesignTest = waitForAnswerSchedule.then(brokerTimesOut(0)).expect(safety)

  // passkey not bound: a step-up made for escalation card 1 approves card 2
  action passkeyNotBoundSchedule: bool =
    init.then(sbxAsks(iamA1)).then(ctlIntake(iamA1)).then(sbxAsks(iamA2)).then(ctlIntake(iamA2))
      .then(userAsk(iamA1, 4)).then(ctlChallenge(iamA1, 4))
      .then(userApproves(iamA2, 4, Some({ h: hash(iamA1), chAt: 0 })))
      .then(ctlDecides(dec(iamA2, 4, 0, Some({ h: hash(iamA1), chAt: 0 }))))
  run passkeyNotBoundBreaksTest = passkeyNotBoundSchedule.then(mintOnce(A)).expect(not(escalationHasFreshPasskey))
  run passkeyNotBoundDesignTest =
    passkeyNotBoundSchedule.expect(and { safety, ctlSt.refused.contains("passkey"), ctlSt.grants.keys().size() == 0 })

  // passkey not fresh: the assertion is made at 0, the decision reaches the warden at 10 min
  action passkeyNotFreshSchedule: bool =
    init.then(sbxAsks(iamA1)).then(ctlIntake(iamA1)).then(userAsk(iamA1, 4)).then(ctlChallenge(iamA1, 4))
      .then(userApproves(iamA1, 4, Some({ h: hash(iamA1), chAt: 0 }))).then(tick).then(tick)
      .then(ctlDecides(dec(iamA1, 4, 0, Some({ h: hash(iamA1), chAt: 0 }))))
  run passkeyNotFreshBreaksTest = passkeyNotFreshSchedule.then(mintOnce(A)).expect(not(escalationHasFreshPasskey))
  run passkeyNotFreshDesignTest =
    passkeyNotFreshSchedule.expect(and { safety, ctlSt.refused.contains("passkey"), ctlSt.grants.keys().size() == 0 })

  // raw forward (Azure mode): the broker hands the VM the real token
  action rawForwardSchedule: bool = approvedAt0(roA, 4).then(mintOnce(A)).then(brokerServes(A))
  run rawForwardBreaksTest = rawForwardSchedule.expect(not(noCloudCredInSandbox))
  run rawForwardDesignTest = rawForwardSchedule.expect(safetyStrict)

  // forward JWT: the broker hands the VM the STS JWT
  action forwardJwtSchedule: bool = approvedAt0(roA, 4).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges)
  run forwardJwtBreaksTest = forwardJwtSchedule.expect(not(noFederatedCredInSandbox))
  run forwardJwtDesignTest = forwardJwtSchedule.expect(and { safety, ghostX.revealed.size() == 0 })

  // TTL not clamped: the card asks 30 min, the user approves 20 min, a mint at 10 min lives to 25 min
  action ttlNotClampedSchedule: bool = approvedAt0(roA6, 4).then(tick).then(tick)
  run ttlNotClampedBreaksTest = ttlNotClampedSchedule.then(mintOnce(A)).expect(not(credWithinApprovedTtl))
  run ttlNotClampedDesignTest = ttlNotClampedSchedule.expect(and {
    safety, not(ctlSt.grants.values().exists(g => mintable(R, g, ctlSt.issued, now, 0))) })

  // expiry checked at request: a JWT signed at 5 min for a 20-min grant
  // lands at 10 min, and its 15-min session outlives the grant
  action expiryAtRequestSchedule: bool =
    approvedAt0(roA, 4).then(tick).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges).then(tick)
  run expiryAtRequestBreaksTest = expiryAtRequestSchedule.then(cloudMints).expect(not(credWithinApprovedTtl))
  run expiryAtRequestDesignTest = expiryAtRequestSchedule.then(cloudRefuses).expect(and { safety, minted.size() == 0 })

  // expiry dated at the click: clicked at 15 min, arrives at 20 min
  action expiryAtClickSchedule: bool =
    init.then(sbxAsks(roA)).then(ctlIntake(roA)).then(tick).then(tick).then(tick)
      .then(userApproves(roA, 4, None)).then(tick).then(ctlDecides(dec(roA, 4, 3, None)))
  run expiryAtClickBreaksTest = expiryAtClickSchedule.expect(not(deadCardsNotRedeemed))
  run expiryAtClickDesignTest =
    expiryAtClickSchedule.expect(and { safety, ctlSt.refused.contains("expired"), ctlSt.grants.keys().size() == 0 })

  // a draft counts as approval
  action draftApprovesSchedule: bool = init.then(sbxAsks(roA)).then(ctlIntake(roA))
  run draftApprovesBreaksTest = draftApprovesSchedule.then(mintOnce(A)).expect(not(noMintWithoutUserApproval))
  run draftApprovesDesignTest = draftApprovesSchedule.expect(and { safety, ctlSt.grants.keys().size() == 0 })

  // a duplicate delivery of the approval restarts the grant
  action replayExtendsSchedule: bool = approvedAt0(roA, 4).then(tick).then(tick).then(ctlDecides(dec(roA, 4, 0, None)))
  run replayExtendsBreaksTest = replayExtendsSchedule.expect(not(oneGrantPerApproval))
  run replayExtendsDesignTest =
    replayExtendsSchedule.expect(and { safety, ctlSt.refused.contains("status"), ctlSt.grants.get(hash(roA)).start == 0 })

  // the broker believes the claimed sandbox: B's SDK names A
  action trustClaimedSchedule: bool = approvedAt0(roA, 4).then(mintOnce(A))
  run trustClaimedBreaksTest = trustClaimedSchedule.then(brokerServes(B)).expect(not(sandboxOnlyOwnCreds))
  run trustClaimedDesignTest = trustClaimedSchedule.expect(and {
    safety, listen_servable(brokerCtx).forall(x => x.tap == A) })

  // ================================================================ WARDEN.md as written (findings)
  // re-minting while the grant is live: a mint at 15 min of a 20-min grant lives to 30 min
  action asWrittenEndSchedule: bool = approvedAt0(roA, 4).then(tick).then(tick).then(tick)
  run asWrittenEndBreaksTest = asWrittenEndSchedule.then(mintOnce(A)).expect(not(credWithinApprovedTtl))
  run asWrittenEndDesignTest = asWrittenEndSchedule.expect(and {
    safety, not(ctlSt.grants.values().exists(g => mintable(R, g, ctlSt.issued, now, 0))) })

  // the revoke dated at the revoke: a JWT signed before the abort mints after it
  action asWrittenRevokeSchedule: bool =
    approvedAt0(roA, 4).then(brokerFetch(A)).then(ctlSigns).then(brokerExchanges)
      .then(userAborts(roA)).then(ctlAborts(roA)).then(cloudDenies).then(tick).then(cloudMints)
  run asWrittenRevokeBreaksTest = asWrittenRevokeSchedule.expect(not(revokedCredsUnusable))
  run asWrittenRevokeDesignTest = asWrittenRevokeSchedule.expect(and { safety, minted.size() == 1 })

  // the session-template button: approving one low-tier card approves the
  // next one of that template, with parameters nobody saw
  action sessionTemplateSchedule: bool =
    init.then(sbxAsks(roA)).then(ctlIntake(roA)).then(userTemplateButton(A, "ro")).then(ctlTemplate(A, "ro"))
      .then(sbxAsks(roA2)).then(ctlIntake(roA2)).then(mintOnce(A))
  run sessionTemplateBreaksTest =
    sessionTemplateSchedule.expect(and { not(mintedMatchesApproval), noMintWithoutUserApproval })
}
