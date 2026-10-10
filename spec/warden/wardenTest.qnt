// -*- mode: Bluespec; -*-
// wardenTest.qnt: the instances of warden.qnt (the design, the design as
// WARDEN.md is written where this model finds it unsafe, and one mutant per
// unsafe caller rule) and scripted runs. run.sh checks them all.

// ---------------------------------------------------------------- the design
module designAws {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = DESIGN_AWS).* from "./warden"
}
module designAzure {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = DESIGN_AZURE).* from "./warden"
}

// ---------------------------------------------------------------- WARDEN.md as written (findings)
// re-mint every 10 min while the grant is live, 15-min sessions: credentials outlive the approved TTL
module asWrittenEnd {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, endRule: WhileLive }).* from "./warden"
}
// "Revoke active sessions" dated at the revoke: a JWT already signed mints after it
module asWrittenRevoke {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, cutoff: CutoffAtRevoke }).* from "./warden"
}
// the "approve this template for the session" button (WARDEN 5) against decision round 2 #5
module sessionTemplateButton {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, sessionTemplate: true }).* from "./warden"
}

// ---------------------------------------------------------------- mutants
module approvalNotHashBound {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, hashBound: false }).* from "./warden"
}
module editInPlace {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, editsSupersede: false, mintFromApproved: false }).* from "./warden"
}
module blindRetry {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, retry: BlindRetry }).* from "./warden"
}
module waitForAnswer {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, retry: WaitForAnswer }).* from "./warden"
}
module passkeyNotBound {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, passkeyBound: false }).* from "./warden"
}
module passkeyNotFresh {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, passkeyFresh: false }).* from "./warden"
}
module rawForward {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AZURE, rawForward: true }).* from "./warden"
}
module forwardJwt {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, forwardJwt: true }).* from "./warden"
}
module ttlNotClamped {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, ttlClamp: false }).* from "./warden"
}
module expiryAtRequest {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, endRule: CheckAtRequest }).* from "./warden"
}
module expiryAtClick {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, expiryAt: AtClick }).* from "./warden"
}
module draftApproves {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, draftApproves: true }).* from "./warden"
}
module replayExtends {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, replayExtends: true }).* from "./warden"
}
module staleEpochAccepted {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, epochCheck: false }).* from "./warden"
}
module noReconciler {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, reconciler: false }).* from "./warden"
}
module supersedeKeepsGrant {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, revokeOnSupersede: false }).* from "./warden"
}
module resumeWithoutBrokerAck {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, brokerAck: false }).* from "./warden"
}
module orphanOnlyRecorded {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, orphanRevoke: false }).* from "./warden"
}
module trustClaimed {
  import wardenLogic.* from "./wardenLogic"
  import warden(RULES = { ...DESIGN_AWS, trustClaimed: true }).* from "./warden"
}

// ---------------------------------------------------------------- scripted runs (wardenRuns.qnt), per instance
module runsDesignAws { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = DESIGN_AWS).* from "./wardenRuns" }
module runsDesignAzure { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = DESIGN_AZURE).* from "./wardenRuns" }
module runsAsWrittenEnd { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, endRule: WhileLive }).* from "./wardenRuns" }
module runsAsWrittenRevoke { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, cutoff: CutoffAtRevoke }).* from "./wardenRuns" }
module runsSessionTemplateButton { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, sessionTemplate: true }).* from "./wardenRuns" }
module runsApprovalNotHashBound { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, hashBound: false }).* from "./wardenRuns" }
module runsEditInPlace { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, editsSupersede: false, mintFromApproved: false }).* from "./wardenRuns" }
module runsBlindRetry { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, retry: BlindRetry }).* from "./wardenRuns" }
module runsWaitForAnswer { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, retry: WaitForAnswer }).* from "./wardenRuns" }
module runsPasskeyNotBound { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, passkeyBound: false }).* from "./wardenRuns" }
module runsPasskeyNotFresh { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, passkeyFresh: false }).* from "./wardenRuns" }
module runsRawForward { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AZURE, rawForward: true }).* from "./wardenRuns" }
module runsForwardJwt { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, forwardJwt: true }).* from "./wardenRuns" }
module runsTtlNotClamped { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, ttlClamp: false }).* from "./wardenRuns" }
module runsExpiryAtRequest { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, endRule: CheckAtRequest }).* from "./wardenRuns" }
module runsExpiryAtClick { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, expiryAt: AtClick }).* from "./wardenRuns" }
module runsDraftApproves { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, draftApproves: true }).* from "./wardenRuns" }
module runsReplayExtends { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, replayExtends: true }).* from "./wardenRuns" }
module runsStaleEpochAccepted { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, epochCheck: false }).* from "./wardenRuns" }
module runsNoReconciler { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, reconciler: false }).* from "./wardenRuns" }
module runsSupersedeKeepsGrant { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, revokeOnSupersede: false }).* from "./wardenRuns" }
module runsResumeWithoutBrokerAck { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, brokerAck: false }).* from "./wardenRuns" }
module runsOrphanOnlyRecorded { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, orphanRevoke: false }).* from "./wardenRuns" }
module runsTrustClaimed { import wardenLogic.* from "./wardenLogic"  import wardenRuns(R = { ...DESIGN_AWS, trustClaimed: true }).* from "./wardenRuns" }
