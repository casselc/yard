// -*- mode: Bluespec; -*-
// keysTest.qnt: the instances of keys.qnt (the design and one mutant per
// unsafe caller rule) and scripted runs. run.sh checks them all.
module design {
  import keysTypes.* from "./keys"
  import keys(RULES = DESIGN, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module shredBeforeLoadSettles {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, shredSettle: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module revokeOnlyByMessage {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, shredVerify: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module staleEpochAccepted {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, staleCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module haloForgetsEpochs {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, haloDurable: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module unloadUnderActive {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, keyGuard: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module loadDuringUnload {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, keyFence: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module trustConsumerAfterRestart {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, reloadAlways: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module blindRegisterRetry {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, idempotentReg: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module rekeyDropsOld {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, rekeyKeepOld: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// IDENTITY.md "Spill keys" as written (2026-10-07): stale = below the highest
// epoch, replay = a seen jti, open only right after a seal; no refusal of an
// epoch whose key was already used. Even with durable epochs, a seal token
// delivered again after a halo restart (jti memory gone) reinstalls a used key.
module identityAsWritten {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, usedCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// halo round 4 (2026-10-07 crypto review): a revoke's default through is
// min(last spill, token epoch). With the server default (no explicit through)
// even the bounded rule erases a newer checkpoint spilled at the token's epoch
// by the time a delayed revoke lands; with halo round 3 (unbounded) also one
// spilled after it.
module revokeDefaultThrough {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, explicitThrough: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module unboundedRevoke {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, explicitThrough: false, revokeCapped: false, revokeScoped: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// K7 mutants (round 4, halo SE): an uncapped default (fence = last spill; yard
// relying on the default exercises it) and unscoped zeroing (every key of the
// session, whatever yard sends)
module revokeUncapped {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, explicitThrough: false, revokeCapped: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module revokeUnscoped {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, revokeScoped: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// round 5 (halo SE): operations
module cancelWeakens {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, cancelSticky: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module capResets {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, capFixed: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module opIdReused {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, freshOpIds: false, opIdChecked: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}

// ---------------------------------------------------------------- scripted runs
module runsDesign { import keysTypes.* from "./keys"  import keysRuns(R = DESIGN).* from "./keysRuns" }
module runsShredBeforeLoadSettles { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, shredSettle: false }).* from "./keysRuns" }
module runsRevokeOnlyByMessage { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, shredVerify: false }).* from "./keysRuns" }
module runsStaleEpochAccepted { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, staleCheck: false }).* from "./keysRuns" }
module runsHaloForgetsEpochs { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, haloDurable: false }).* from "./keysRuns" }
module runsIdentityAsWritten { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, usedCheck: false }).* from "./keysRuns" }
module runsUnloadUnderActive { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, keyGuard: false }).* from "./keysRuns" }
module runsLoadDuringUnload { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, keyFence: false }).* from "./keysRuns" }
module runsTrustConsumerAfterRestart { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, reloadAlways: false }).* from "./keysRuns" }
module runsBlindRegisterRetry { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, idempotentReg: false }).* from "./keysRuns" }
module runsRevokeDefaultThrough { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, explicitThrough: false }).* from "./keysRuns" }
module runsUnboundedRevoke { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, explicitThrough: false, revokeCapped: false, revokeScoped: false }).* from "./keysRuns" }
module runsRevokeUncapped { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, explicitThrough: false, revokeCapped: false }).* from "./keysRuns" }
module runsRevokeUnscoped { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, revokeScoped: false }).* from "./keysRuns" }
module runsCancelWeakens { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, cancelSticky: false }).* from "./keysRuns" }
module runsCapResets { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, capFixed: false }).* from "./keysRuns" }
module runsOpIdReused { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, freshOpIds: false, opIdChecked: false }).* from "./keysRuns" }
module runsRekeyDropsOld { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, rekeyKeepOld: false }).* from "./keysRuns" }
