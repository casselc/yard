// -*- mode: Bluespec; -*-
// keysTest.qnt: the instances of keys.qnt (the design and one mutant per
// unsafe caller rule) and scripted runs. run.sh checks them all.
module design {
  import keysTypes.* from "./keys"
  import keys(RULES = DESIGN, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// the design in TCP mode (`--yard-keys-tcp 1` over the tailnet): a captured
// token may be delivered again until it expires
module designTcp {
  import keysTypes.* from "./keys"
  import keys(RULES = DESIGN_TCP, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module shredBeforeLoadSettles {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, shredSettle: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// halo before the fix round: an unused key lived for HALO_TTL after its token expired
module revokeOnlyByMessage {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, shredVerify: false, haloExpZero: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// with SE's zeroing at token exp the unverified revoke is harmless (halo's copy is gone at exp)
module revokeOnlyByMessageExpZero {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, shredVerify: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module staleEpochAccepted {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN_TCP, staleCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// the same rule off over the Unix socket (the design transport): no third party can deliver a token again
module staleEpochAcceptedSocket {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, staleCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
module haloForgetsEpochs {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN_TCP, haloDurable: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// the same rule off over the Unix socket (the design transport): no third party can deliver a token again
module haloForgetsEpochsSocket {
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
  import keys(RULES = { ...DESIGN_TCP, usedCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}
// the same rule off over the Unix socket (the design transport): no third party can deliver a token again
module identityAsWrittenSocket {
  import keysTypes.* from "./keys"
  import keys(RULES = { ...DESIGN, usedCheck: false }, SESSIONS = Set("s1", "s2"), TOKEN_TTL = 2, HALO_TTL = 5, OP_TIMEOUT = 2, MAX_TIME = 30,
              MAX_OPS = 24, MAX_KEYS = 7, MAX_EPOCH = 4, MAX_ATTEMPTS = 2, MAX_FAULTS = 3).* from "./keys"
}

// ---------------------------------------------------------------- scripted runs
module runsDesign { import keysTypes.* from "./keys"  import keysRuns(R = DESIGN_TCP).* from "./keysRuns" }
module runsDesignSocket { import keysTypes.* from "./keys"  import keysRuns(R = DESIGN).* from "./keysRuns" }
module runsShredBeforeLoadSettles { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, shredSettle: false }).* from "./keysRuns" }
module runsRevokeOnlyByMessage { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, shredVerify: false, haloExpZero: false }).* from "./keysRuns" }
module runsStaleEpochAccepted { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN_TCP, staleCheck: false }).* from "./keysRuns" }
module runsHaloForgetsEpochs { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN_TCP, haloDurable: false }).* from "./keysRuns" }
module runsIdentityAsWritten { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN_TCP, usedCheck: false }).* from "./keysRuns" }
module runsUnloadUnderActive { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, keyGuard: false }).* from "./keysRuns" }
module runsLoadDuringUnload { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, keyFence: false }).* from "./keysRuns" }
module runsTrustConsumerAfterRestart { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, reloadAlways: false }).* from "./keysRuns" }
module runsBlindRegisterRetry { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, idempotentReg: false }).* from "./keysRuns" }
module runsRekeyDropsOld { import keysTypes.* from "./keys"  import keysRuns(R = { ...DESIGN, rekeyKeepOld: false }).* from "./keysRuns" }
