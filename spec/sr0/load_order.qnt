// Order monitor for observed cold/unforced-or-explicitly-forced resume steps.
// Core lifecycle.qnt models request/effect/answer, late copies and crashes.
// This monitor checks the backend's observed I/O boundaries, including mount
// metadata writes that do not represent application edits. It is not a new
// atomic-call model of cross-process outcomes.
module loadOrder {
  const MOUNT_METADATA: int // supplied by this test fixture, not a universal ZFS size
  type State = { key: bool, checked: bool, allowed: bool, pending: bool,
                 mounted: bool, issued: bool, observed: int, physical: int, force: bool }
  var s: State
  action init = s' = { key: false, checked: false, allowed: false, pending: false,
                      mounted: false, issued: false, observed: -1, physical: -1, force: false }

  // Successful key-only phase completion, with actual post-state facts.
  action key_ready(loaded: bool, mounted: bool): bool = all {
    loaded, not(s.pending),
    s' = { ...s, key: loaded, mounted: mounted, checked: false, allowed: false,
           issued: false, observed: -1, force: false }
  }
  // Completed synchronized property read, before the backend may mount.
  action observe(n: int, force: bool): bool = all {
    s.key, not(s.pending), not(s.issued), n >= 0,
    s' = { ...s, checked: true, observed: n, physical: n, force: force, allowed: n == 0 or force }
  }
  action mount_request = all {
    s.key, s.checked, s.allowed, not(s.mounted), not(s.pending),
    s' = { ...s, pending: true, issued: true }
  }
  // Test-observed effect; n can differ from the pre-mount read solely because
  // writable mounting clears a ZIL header (native reproduction: 8192 bytes).
  action mount_effect(n: int): bool = all {
    s.pending, not(s.mounted), n >= 0, n == s.physical + MOUNT_METADATA,
    s' = { ...s, mounted: true, physical: n }
  }
  action mount_answer = all { s.pending, s.mounted, s' = { ...s, pending: false } }

  val noMountBeforeAcceptance = s.issued implies (s.key and s.checked and s.allowed)
  val realDriftNeedsOverride = (s.checked and s.observed > 0 and not(s.force)) implies not(s.allowed)
  val observedBeforeMount = (s.issued and not(s.force)) implies s.observed == 0
}
