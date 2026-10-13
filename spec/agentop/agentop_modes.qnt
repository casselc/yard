// -*- mode: Bluespec; -*-
// agentop_modes: the design under each approval configuration, and one mutant per rule.
// design: today's configuration, automated approval enabled nowhere (every apply needs the user)
module design {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// enabledUntested: a cell enables automated approval before its harness passed: still the user only
module enabledUntested {
  import agentop(AUTO_ENABLED = true, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// autoConfigured: a cell with automated approval enabled and its harness tested
module autoConfigured {
  import agentop(AUTO_ENABLED = true, HARNESS_TESTED = true,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// brokerNoCap: cap off -> withinCap
module brokerNoCap {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: false, meter: true, adopt: true, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// meterFromHarness: meter off -> accounted
module meterFromHarness {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: false, adopt: true, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// rerunOnRestart: adopt off -> runsOnce
module rerunOnRestart {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: false, revoke: true, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// scopeNotRevoked: revoke off -> noCallsAfterEnd
module scopeNotRevoked {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: false, approval: true, autoGate: true, cas: true }).* from "./agentop"
}
// applyWithoutApproval: approval off -> noApplyWithoutApproval
module applyWithoutApproval {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: false, autoGate: true, cas: true }).* from "./agentop"
}
// autoApproveUnconfigured: autoGate off -> noAutoUnlessConfigured
module autoApproveUnconfigured {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: true, autoGate: false, cas: true }).* from "./agentop"
}
// applyStaleBase: cas off -> noLostUpdate
module applyStaleBase {
  import agentop(AUTO_ENABLED = false, HARNESS_TESTED = false,
    RULES = { cap: true, meter: true, adopt: true, revoke: true, approval: true, autoGate: true, cas: false }).* from "./agentop"
}
