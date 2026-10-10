#!/bin/sh
# Run every SR0 instance with quint run at a fixed seed: design instances
# must hold every invariant, each mutant must break its own invariant.
# Then runs the scripted runs (quint test): every design path and
# DesignTest must pass, and each mutant's BreaksTest must pass (it replays
# the counterexample and expects the invariant to fail).
# Usage: sh run_models.sh [seed] [max-samples] [max-steps]
# Prints one row per instance: instance, invariant, expected, result, traces.
set -u
cd "$(dirname "$0")"
SEED=${1:-0x5eed}
SAMPLES=${2:-3000}
STEPS=${3:-100}
OUT=${OUT:-${TMPDIR:-/tmp}/sr0-results}
mkdir -p "$OUT"

row() { # instance invariant expect [step]
  inst=$1 inv=$2 expect=$3 stp=${4:-step}
  log="$OUT/$inst.$inv.log"
  quint run lifecycle.qnt --main "$inst" --step "$stp" --invariant "$inv" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --seed "$SEED" --verbosity 1 >"$log" 2>&1
  if grep -q '^\[violation\]' "$log"; then got=breaks; else got=holds; fi
  n=$(sed -n 's/.*(\([0-9]*\)ms at \([0-9]*\) traces\/second).*/\1 \2/p' "$log" | awk '{printf "%d", $1*$2/1000}')
  ok=OK; [ "$got" = "$expect" ] || [ "$expect" = either ] || ok=OFF
  printf '%s\t%s\t%s\t%s\t%s\t~%s traces\t%s\n' "$inst" "$stp" "$inv" "$expect" "$got" "$n" "$ok"
}

{
row design allInvariants holds &
row design2 allInvariants holds &
row designPause allInvariants holds &
row designKeys allInvariants holds &
row nonAtomicConsume resumedAtMostOnce breaks &
# random runs under `step` rarely reach these five (README): either result is
# expected here; the focused rows below and the scripted BreaksTests catch them
row blindRestoreRetry resumedAtMostOnce either &
row commitBeforeDestroy resumedAtMostOnce breaks stepCore &
row snapshotBeforeQuiesce noAckedWriteLost either &
row noCredEpoch noPreSuspendCredential either &
row checkpointTimeoutNotDone artifactsAccounted breaks stepCore &
row fireAndForgetDelete artifactsAccounted breaks &
row gcByAge resumeKeepsArtifacts breaks &
row observeAtRequest suspendedOnlyIdle breaks &
row ignoreActivityDuringSuspend suspendedOnlyIdle breaks &
row expireDropsInbox noMessageLost either &
row recoverAssumesNotDone artifactsAccounted either &
row unpauseBeforePauseSettles noFrozenAwake breaks stepCore &
row retrySupersededOp noFrozenAwake breaks &
# SR1 2026-10-07: drift refusal, liveness, workspace keys
row resumeIgnoresDrift noSilentDrift either &
row deadOnProbeTimeout noLiveFailed breaks &
row staleProbe noLiveFailed breaks &
row unloadUnderActive keyUnderActive breaks &
row loadDuringUnload keyUnderActive either &
row resumeWithoutKey keyUnderActive breaks &
# focused instances (the mutants plain random runs miss) and the design
# under the same environment and step
row snapshotBeforeQuiesceFocus noAckedWriteLost breaks stepWrites &
row snapshotBeforeQuiesceFocusDesign allInvariants holds stepWrites &
row blindRestoreRetryFocus resumedAtMostOnce breaks stepQuiet &
row blindRestoreRetryFocusDesign allInvariants holds stepQuiet &
row noCredEpochFocus noPreSuspendCredential breaks stepQuiet &
row noCredEpochFocusDesign allInvariants holds stepQuiet &
row recoverAssumesNotDoneFocus artifactsAccounted breaks stepCrashCkpt &
row recoverAssumesNotDoneFocusDesign allInvariants holds stepCrashCkpt &
row expireDropsInboxFocus noMessageLost breaks stepInbox &
row expireDropsInboxFocusDesign allInvariants holds stepInbox &
row resumeIgnoresDriftFocus noSilentDrift breaks stepDrift &
row resumeIgnoresDriftFocusDesign allInvariants holds stepDrift &
row loadDuringUnloadFocus keyUnderActive breaks stepQuiet &
row loadDuringUnloadFocusDesign allInvariants holds stepQuiet &
wait
} | sort | tee "$OUT/rows.txt"

echo
echo "scripted runs (quint test):"
tfail=0
for m in lifecycle_test designScripts nonAtomicConsumeScripts blindRestoreRetryScripts commitBeforeDestroyScripts \
    snapshotBeforeQuiesceScripts noCredEpochScripts checkpointTimeoutNotDoneScripts fireAndForgetDeleteScripts \
    gcByAgeScripts observeAtRequestScripts ignoreActivityDuringSuspendScripts expireDropsInboxScripts \
    recoverAssumesNotDoneScripts pauseScripts unpauseBeforePauseSettlesScripts retrySupersededOpScripts \
    sr1Scripts resumeIgnoresDriftScripts deadOnProbeTimeoutScripts staleProbeScripts \
    keysScripts unloadUnderActiveScripts loadDuringUnloadScripts resumeWithoutKeyScripts; do
  quint test lifecycle_test.qnt --main "$m" --max-samples 1 --seed "$SEED" >"$OUT/$m.test.log" 2>&1
  np=$(sed -n 's/^ *\([0-9]*\) passing.*/\1/p' "$OUT/$m.test.log")
  nf=$(sed -n 's/^ *\([0-9]*\) failed.*/\1/p' "$OUT/$m.test.log" | grep . || echo 0)
  printf '%s\t%s passing, %s failing\n' "$m" "$np" "$nf"
  [ -n "$np" ] && [ "$np" -gt 0 ] && [ "$nf" = 0 ] || tfail=$((tfail + 1))
done
off=$(grep -c 'OFF$' "$OUT/rows.txt" || true)
echo
echo "failures: $((off + tfail)) ($off simulation rows OFF, $tfail scripted modules failing)"
