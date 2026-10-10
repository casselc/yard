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
#   spec/keys/run.sh                 # SAMPLES=1200 SSAMPLES=1500 MSAMPLES=1000 STEPS=80 SEED=0x5eed
#   OUT=results.txt spec/keys/run.sh
set -u
OUT=${OUT:-/dev/stdout}
SEED=${SEED:-0x5eed}
SAMPLES=${SAMPLES:-1200}     # the design, full step (about 4 traces/s)
SSAMPLES=${SSAMPLES:-1500}   # the design, focused spill step
MSAMPLES=${MSAMPLES:-1000}   # mutants (they break within a few hundred traces)
STEPS=${STEPS:-80}
cd "$(dirname "$0")" || exit 1
F=keysTest.qnt
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES (design) / $SSAMPLES (design, stepSpill) / $MSAMPLES (mutants)" | tee "$OUT"
fails=0
WIT="wResumed wResumedTwice wUnloaded wReloaded wSpillShredded wShredByRevoke wProjectShredded wRekeyed wStaleRefused wResumeAfterHaloRestart wResumeAfterReboot wResealed wReopened wPrefilled wRevokeFenced"
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
sim design    step      safety "$SAMPLES"  ok $WIT
sim design    stepSpill safety "$SSAMPLES" ok $WIT
sim designTcp stepSpill safety "$SSAMPLES" ok $WIT
sim design    stepReplay safety "$MSAMPLES" ok $WIT
sim designTcp stepReplay safety "$MSAMPLES" ok $WIT
miss=0; for w in $WIT; do [ -n "${seen[$w]:-}" ] || { miss=1; echo "wit   $w: not reached in any design run" | tee -a "$OUT"; }; done
[ $miss = 0 ] || fails=$((fails + 1))

# ---- mutants ----
sim unloadUnderActive         step      keyUnderRunning     "$MSAMPLES" VIOLATED
sim loadDuringUnload          step      keyUnderRunning     "$MSAMPLES" VIOLATED
sim trustConsumerAfterRestart step      keyUnderRunning     "$MSAMPLES" VIOLATED
sim blindRegisterRetry        step      keysAccounted       "$MSAMPLES" VIOLATED
sim rekeyDropsOld             step      projectKeyAvailable "$MSAMPLES" VIOLATED
sim shredBeforeLoadSettles    stepSpill noDecryptAfterShred "$MSAMPLES" VIOLATED
sim revokeOnlyByMessage       stepSpill noDecryptAfterShred "$MSAMPLES" VIOLATED
sim revokeOnlyByMessageExpZero stepSpill noDecryptAfterShred "$MSAMPLES" ok
# the halo-side rules in TCP mode (a captured token can be delivered again) ...
sim staleEpochAccepted        stepReplay noStaleEpoch       "$MSAMPLES" VIOLATED
sim haloForgetsEpochs         stepReplay noStaleEpoch       "$MSAMPLES" VIOLATED
sim identityAsWritten         stepReplay noStaleEpoch       "$MSAMPLES" VIOLATED
# ... and over the Unix socket (the design transport), where only yard-ctl sends: the same
# rule off is not reachable by yard's own traffic (defence in depth there; expect ok)
sim staleEpochAcceptedSocket  stepReplay noStaleEpoch       "$MSAMPLES" ok
sim haloForgetsEpochsSocket   stepReplay noStaleEpoch       "$MSAMPLES" ok
sim identityAsWrittenSocket   stepReplay noStaleEpoch       "$MSAMPLES" ok

# ---- scripted runs ----
runs runsDesign '^(?!.*Breaks)(?!socket).*Test$'
runs runsDesignSocket '^socket.*Test$'
for m in ShredBeforeLoadSettles:shredBeforeLoadSettles RevokeOnlyByMessage:revokeOnlyByMessage \
         StaleEpochAccepted:staleEpochAccepted HaloForgetsEpochs:haloForgetsEpochs IdentityAsWritten:identityAsWritten \
         UnloadUnderActive:unloadUnderActive LoadDuringUnload:loadDuringUnload \
         TrustConsumerAfterRestart:trustConsumerAfterRestart BlindRegisterRetry:blindRegisterRetry RekeyDropsOld:rekeyDropsOld; do
  runs "runs${m%%:*}" "^${m##*:}BreaksTest\$"
done

echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
