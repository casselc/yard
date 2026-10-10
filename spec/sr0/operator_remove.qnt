// Manual-down order monitor. The core model handles the Removed fence and
// external-call ambiguity. This monitor adds the backend boundary omitted
// there: an absent jail may still have orphan nullfs views blocking unmount.
module operatorRemove {
  const ORPHANS: bool
  var s: { removed: bool, settled: bool, views: bool, pending: bool, cleaned: bool, awaiting: bool, key: bool }
  action init = s' = { removed: false, settled: false, views: ORPHANS, pending: false, cleaned: false, awaiting: false, key: true }
  action fence(removed: bool): bool = all { removed, s' = { ...s, removed: true } }
  action session_settled(done: bool): bool = all { s.removed, done, s' = { ...s, settled: true } }
  action cleanup_request = all { s.removed, s.settled, not(s.pending), s' = { ...s, pending: true } }
  action cleanup_effect(views: bool): bool = all { s.pending, not(views), s' = { ...s, views: views } }
  action cleanup_answer = all { s.pending, not(s.views), s' = { ...s, pending: false, cleaned: true } }
  action project_wait_request = all { s.cleaned, not(s.views), not(s.pending), s' = { ...s, awaiting: true } }
  action project_settled(loaded: bool): bool = all { s.awaiting, s.cleaned, not(s.views), s' = { ...s, awaiting: false, key: loaded } }
  action project_wait_failed = all { s.awaiting, s' = { ...s, awaiting: false } }
  val cleanupAfterFence = s.pending implies (s.removed and s.settled)
  val noKeyReleaseBeforeCleanup = not(s.key) implies (s.cleaned and not(s.views))
}
