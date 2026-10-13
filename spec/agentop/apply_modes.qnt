// -*- mode: Bluespec; -*-
// apply_modes: the design under each approval configuration, and one mutant per rule of apply.qnt.
// adesign: today's configuration, automated approval enabled nowhere
module adesign {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// aEnabledUntested: a cell enables automated approval before its harness passed: still the user only
module aEnabledUntested {
  import apply(AUTO_ENABLED = true, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// aAutoConfigured: enabled and tested
module aAutoConfigured {
  import apply(AUTO_ENABLED = true, HARNESS_TESTED = true,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// applyWithoutApproval: approval off -> approvedApplied
module applyWithoutApproval {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: false, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// expiryAtApproval: expiry off -> approvedApplied (a late apply on an expired approval)
module expiryAtApproval {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: false, authority: true, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// authorityAtRequest: authority off -> approvedApplied (authority withdrawn after approval)
module authorityAtRequest {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: false, bound: true, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// approvalByName: bound off -> approvedApplied (the name now holds other content)
module approvalByName {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: false, cas: true, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// applyStaleBase: cas off -> noLostUpdate
module applyStaleBase {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: false, autoGate: true, lease: true, explicit: true }).* from "./apply"
}
// autoApproveUnconfigured: autoGate off -> noAutoUnlessConfigured
module autoApproveUnconfigured {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: false, lease: true, explicit: true }).* from "./apply"
}
// ackReleasesArtifacts: lease off -> neededPresent
module ackReleasesArtifacts {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: false, explicit: true }).* from "./apply"
}
// substituteEmpty: explicit off -> approvedApplied (a released candidate applied as empty content)
module substituteEmpty {
  import apply(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { approval: true, expiry: true, authority: true, bound: true, cas: true, autoGate: true, lease: false, explicit: false }).* from "./apply"
}
