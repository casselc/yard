// Instances of the guest resume model: the design and one module per unsafe rule (mutant).
// spec/guestresume/run.sh runs them all; README.md has the results table.

// the design: every rule on, assumption A1 on
module design {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// actOnlyOnEpoch: the agent ignores the VM generation: a clone (no epoch bump) is never handled
module actOnlyOnEpoch {
  import guestresume(
    ACT_ON_GEN = false, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// actOnlyOnGen: the agent ignores the host epoch: a lost notify is never handled
module actOnlyOnGen {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = false, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// epochNotMonotonic: any epoch != done starts a run: a stale HELLO from before the restore re-runs a done key
module epochNotMonotonic {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = false, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// noDedupe: every signal starts a run: a duplicate notify re-runs a done key
module noDedupe {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = false, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// acceptWhileResuming: exec is accepted while the resume actions are still running
module acceptWhileResuming {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = false, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// skipEntropy: the host bytes are not written: only the kernel's vmgenid mix, lost with the notify
module skipEntropy {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = false, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// servicesBeforeEntropy: services restart before the host bytes are in the kernel RNG
module servicesBeforeEntropy {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = false, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// staleReply: any host answer is used: one to an earlier request carries old time and bytes
module staleReply {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = false, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// clearOnComplete: a run's end marks everything seen during it as done
module clearOnComplete {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = false, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// timeoutIgnored: a restart that times out leaves the old process running
module timeoutIgnored {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = false, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// timeoutCountsDone: a restart that times out is recorded as done
module timeoutCountsDone {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = false, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// notifyLostOnClone: finding (assumption A1 off): a clone whose notify is lost is undetectable
module notifyLostOnClone {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = true,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// keyFromSeen: the run is keyed by the newest epoch seen, not the answer's (the model's second finding)
module keyFromSeen {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = false, VERIFY_RESEED = true, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// entropyDoneEarly: entropy reported done right after the writes, before a reseed took them
module entropyDoneEarly {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = false, ENTROPY_GATE = true, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}

// entropyFailOpen: a run whose writes failed or timed out still restarts services and completes its key
module entropyFailOpen {
  import guestresume(
    ACT_ON_GEN = true, ACT_ON_EPOCH = true, EPOCH_MONOTONIC = true, DEDUPE = true, GATE_WORK = true, ADD_ENTROPY = true, ENTROPY_FIRST = true, NONCE_CHECK = true, RECHECK_AT_END = true, KILL_ON_TIMEOUT = true, TIMEOUT_UNKNOWN = true, KEY_FROM_ANSWER = true, VERIFY_RESEED = true, ENTROPY_GATE = false, CLONE_NOTIFY_LOSABLE = false,
    MAX_GEN = 2, MAX_EPOCH = 3, MAX_TIME = 12, SETTLE = 1, SVC_TIMEOUT = 2, RESEED_GAP = 1,
  ).* from "./guestresume"
}
