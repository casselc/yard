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
  ok=OK; [ "$got" = "$expect" ] || ok=OFF
  printf '%s\t%s\t%s\t%s\t%s\t~%s traces\t%s\n' "$inst" "$stp" "$inv" "$expect" "$got" "$n" "$ok"
}

{
row design allInvariants holds &
row design2 allInvariants holds &
row nonAtomicConsume resumedAtMostOnce breaks &
row blindRestoreRetry resumedAtMostOnce breaks &
row commitBeforeDestroy resumedAtMostOnce breaks &
row snapshotBeforeQuiesce noAckedWriteLost breaks &
row noCredEpoch noPreSuspendCredential breaks &
row checkpointTimeoutNotDone artifactsAccounted breaks &
row fireAndForgetDelete artifactsAccounted breaks &
row gcByAge resumeKeepsArtifacts breaks &
row observeAtRequest suspendedOnlyIdle breaks &
row ignoreActivityDuringSuspend suspendedOnlyIdle breaks &
row expireDropsInbox noMessageLost breaks &
row recoverAssumesNotDone artifactsAccounted breaks &
# focused instances (the mutants plain random runs miss) and the design
# under the same environment and step
row snapshotBeforeQuiesceFocus noAckedWriteLost breaks stepWrites &
row snapshotBeforeQuiesceFocusDesign allInvariants holds stepWrites &
row blindRestoreRetryFocus resumedAtMostOnce breaks stepQuiet &
row blindRestoreRetryFocusDesign allInvariants holds stepQuiet &
row noCredEpochFocus noPreSuspendCredential breaks stepQuiet &
row noCredEpochFocusDesign allInvariants holds stepQuiet &
row recoverAssumesNotDoneFocus artifactsAccounted breaks stepCrash &
row recoverAssumesNotDoneFocusDesign allInvariants holds stepCrash &
row expireDropsInboxFocus noMessageLost breaks stepInbox &
row expireDropsInboxFocusDesign allInvariants holds stepInbox &
wait
} | sort

echo
echo "scripted runs (quint test):"
for m in lifecycle_test designScripts nonAtomicConsumeScripts blindRestoreRetryScripts commitBeforeDestroyScripts \
    snapshotBeforeQuiesceScripts noCredEpochScripts checkpointTimeoutNotDoneScripts fireAndForgetDeleteScripts \
    gcByAgeScripts observeAtRequestScripts ignoreActivityDuringSuspendScripts expireDropsInboxScripts \
    recoverAssumesNotDoneScripts; do
  quint test lifecycle_test.qnt --main "$m" --max-samples 1 --seed "$SEED" >"$OUT/$m.test.log" 2>&1
  printf '%s\t%s passing, %s failing\n' "$m" \
    "$(sed -n 's/^ *\([0-9]*\) passing.*/\1/p' "$OUT/$m.test.log")" \
    "$(sed -n 's/^ *\([0-9]*\) failed.*/\1/p' "$OUT/$m.test.log" | grep . || echo 0)"
done
