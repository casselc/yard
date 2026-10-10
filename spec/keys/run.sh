#!/usr/bin/env bash
# run.sh: the checks of the key-service model (quint 0.32, `quint run` and
# `quint test` only; never `quint verify`). As spec/warden/run.sh:
#  - `sim` rows: the design by simulation (expect ok) under the full step and
#    the focused spill step, with the witnesses (every one must be reached in
#    one of the two); each mutant against the invariant it is named for
#    (expect VIOLATED), under the step its counterexample needs;
#  - `runs` rows: the scripted runs (keysRuns.qnt): on the design every
#    non-Breaks test passes; each `*BreaksTest` on its mutant ends with the
#    property false.
# Prints "failures: N" (must be 0).
#
#   spec/keys/run.sh                 # SAMPLES=1200 SSAMPLES=1500 KSAMPLES=1200 MSAMPLES=1000 STEPS=80 SEED=0x5eed
#   OUT=results.txt spec/keys/run.sh
set -u
OUT=${OUT:-/dev/stdout}
SEED=${SEED:-0x5eed}
SAMPLES=${SAMPLES:-1200}     # the design, full step (about 4 traces/s)
SSAMPLES=${SSAMPLES:-1500}   # the design, focused spill step
KSAMPLES=${KSAMPLES:-1200}   # the design, the key service's step (the replay traces' step)
MSAMPLES=${MSAMPLES:-1000}   # mutants (they break within a few hundred traces)
STEPS=${STEPS:-80}
cd "$(dirname "$0")" || exit 1
F=keysTest.qnt
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES (design) / $SSAMPLES (design, stepSpill) / $MSAMPLES (mutants)" | tee "$OUT"
fails=0
WIT="wResumed wResumedTwice wUnloaded wReloaded wSpillShredded wShredByRevoke wProjectShredded wRekeyed wStaleRefused wResumeAfterHaloRestart wResumeAfterReboot wResealed wReopened wAborted wResuspendedAfterAbort wVerifyRetried wRevokeFenced wRenewed"
declare -A seen
sim() { # main step invariant samples expect [witness...]
  local m=$1 st=$2 inv=$3 n=$4 ex=$5; shift 5
  local t0 out v; t0=$(date +%s.%N)
  if [ $# -gt 0 ]; then out=$(quint run "$F" --main "$m" --step "$st" --invariant "$inv" --max-samples "$n" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 --witnesses "$@" 2>&1)
  else out=$(quint run "$F" --main "$m" --step "$st" --invariant "$inv" --max-samples "$n" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1); fi
  v=ok; echo "$out" | grep -q "\[violation\]" && v=VIOLATED
  echo "$out" | grep -q -E "\[ok\]|\[violation\]" || v=ERROR
  [ "$v" = "$ex" ] || fails=$((fails + 1))
  printf "sim   %-26s %-10s %-20s %5s x %-3s %-8s (expect %-8s) %6.1fs\n" "$m" "$st" "$inv" "$n" "$STEPS" "$v" "$ex" \
    "$(echo "$(date +%s.%N) - $t0" | bc)" | tee -a "$OUT"
  if [ $# -gt 0 ]; then
    echo "$out" | grep -E "witnessed in" | sed "s/^/wit   $m $st: /" | tee -a "$OUT"
    for w in "$@"; do echo "$out" | grep -q -E "^$w was witnessed in [1-9]" && seen[$w]=1; done
  fi
}
runs() { # main match
  local out n f; out=$(quint test "$F" --main "$1" --match "$2" --max-samples 1 2>&1)
  n=$(echo "$out" | grep -c " ok "); f=$(echo "$out" | grep -c -E "^ +[0-9]+\) ")
  [ "$n" -gt 0 ] && [ "$f" -eq 0 ] || fails=$((fails + 1))
  printf "runs  %-32s %-34s passed %d failed %d (expect all-pass)\n" "$1" "$2" "$n" "$f" | tee -a "$OUT"
}

# ---- the design (sim + witnesses) ----
sim design step      safety "$SAMPLES"  ok $WIT
sim design stepSpill safety "$SSAMPLES" ok $WIT
sim design stepKeysvc safety "$KSAMPLES" ok $WIT
sim design stepRevoke safety "$MSAMPLES" ok $WIT
miss=0; for w in $WIT; do [ -n "${seen[$w]:-}" ] || { miss=1; echo "wit   $w: not reached in any design run" | tee -a "$OUT"; }; done
[ $miss = 0 ] || fails=$((fails + 1))

# ---- mutants ----
sim unloadUnderActive         stepCore  keyUnderRunning     "$MSAMPLES" VIOLATED
sim loadDuringUnload          stepCoreFast keyUnderRunning  "$MSAMPLES" VIOLATED
sim trustConsumerAfterRestart stepCore  keyUnderRunning     "$MSAMPLES" VIOLATED
sim blindRegisterRetry        stepCore  keysAccounted       "$MSAMPLES" VIOLATED
sim rekeyDropsOld             stepCore  projectKeyAvailable "$MSAMPLES" VIOLATED
sim shredBeforeLoadSettles    stepSpill noDecryptAfterShred "$MSAMPLES" VIOLATED
# obsolete as a break since halo zeroes a key at its token's exp (README finding 6): must hold
sim revokeOnlyByMessage       stepSpill noDecryptAfterShred "$MSAMPLES" ok
# Since halo binds a seal to its incarnation (round 3), a seal token replayed into a restarted
# halo is refused whatever the epoch rules: haloForgetsEpochs and identityAsWritten keep K1
# (README finding 9), and staleEpochAccepted's counterexample is a long one (an open token
# replayed after a further suspend and a halo restart) that random runs do not reach: its
# break is the scripted staleEpochAcceptedBreaksTest below.
sim haloForgetsEpochs         stepSpill noStaleEpoch        "$MSAMPLES" ok
sim identityAsWritten         stepSpill noStaleEpoch        "$MSAMPLES" ok
sim revokeDefaultThrough      stepRevoke checkpointKept     "$MSAMPLES" VIOLATED
sim unboundedRevoke           stepRevoke checkpointKept     "$MSAMPLES" VIOLATED
sim design                    stepRevokeLate safety         "$MSAMPLES" ok
# the bounded default stays within the token's authority (K7) though it breaks K6
sim revokeDefaultThrough      stepRevokeLate revokeBoundedByAuthority "$MSAMPLES" ok
sim revokeUncapped            stepRevokeLate revokeBoundedByAuthority "$MSAMPLES" VIOLATED
sim revokeUnscoped            stepRevokeLate revokeBoundedByAuthority "$MSAMPLES" VIOLATED
# round 5: operations
sim cancelWeakens             stepRevoke noCancelledInstall "$MSAMPLES" VIOLATED
sim capResets                 stepKeysvc slotWithinCap      "$MSAMPLES" VIOLATED
sim opIdReused                stepRevoke opIdOneOperation   "$MSAMPLES" VIOLATED

# ---- scripted runs ----
runs runsDesign '^(?!.*(Breaks|Holds)).*Test$'
runs runsRevokeOnlyByMessage '^revokeOnlyByMessageHoldsTest$'
runs runsHaloForgetsEpochs '^haloForgetsEpochsHoldsTest$'
runs runsIdentityAsWritten '^identityAsWrittenHoldsTest$'
# round 4: with the bounded default, a revoke delayed past a spill at T+1 keeps it
runs runsRevokeDefaultThrough '^delayedRevokeNextCycleHoldsTest$'
for m in ShredBeforeLoadSettles:shredBeforeLoadSettles \
         StaleEpochAccepted:staleEpochAccepted \
         UnloadUnderActive:unloadUnderActive LoadDuringUnload:loadDuringUnload \
         TrustConsumerAfterRestart:trustConsumerAfterRestart BlindRegisterRetry:blindRegisterRetry RekeyDropsOld:rekeyDropsOld \
         RevokeDefaultThrough:revokeDefaultThrough UnboundedRevoke:unboundedRevoke \
         RevokeUncapped:revokeUncapped RevokeUnscoped:revokeUnscoped \
         CancelWeakens:cancelWeakens CapResets:capResets OpIdReused:opIdReused; do
  runs "runs${m%%:*}" "^${m##*:}BreaksTest\$"
done

echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
