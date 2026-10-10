#!/usr/bin/env bash
# run.sh: the checks of the guest resume model (quint 0.32, `quint run` and `quint test` only; never
# `quint verify`). As spec/warden/run.sh:
#  - `sim` rows: the design by simulation (expect ok), each mutant against the property it is named for
#    (expect VIOLATED), and the finding behind assumption A1 (notifyLostOnClone, expect VIOLATED);
#  - `wit` row: every witness of the design is reached in at least one trace;
#  - `runs` rows: the scripted runs: `*DesignTest` on the design (all pass), `<mutant>BreaksTest` on its
#    mutant (ends with the property false; passes).
# One quint process at a time.
#
#   spec/guestresume/run.sh                        # SAMPLES=20000 MSAMPLES=20000 STEPS=200 SEED=0x5eed
#   OUT=results.txt spec/guestresume/run.sh
set -u
OUT=${OUT:-/dev/stdout}
SEED=${SEED:-0x5eed}
SAMPLES=${SAMPLES:-20000}    # the design and its witnesses
MSAMPLES=${MSAMPLES:-20000}  # mutants (stop at the first violation)
STEPS=${STEPS:-200}
cd "$(dirname "$0")" || exit 1
F=guestresumeTest.qnt
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES (design) / $MSAMPLES (mutants)" | tee "$OUT"
fails=0
sim() { # main invariant samples expect [note]
  local t0 out v; t0=$(date +%s.%N)
  out=$(quint run "$F" --main "$1" --invariant "$2" --max-samples "$3" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  v=ok; echo "$out" | grep -q "\[violation\]" && v=VIOLATED
  echo "$out" | grep -q -E "\[ok\]|\[violation\]" || v=ERROR
  [ "$v" = "$4" ] || fails=$((fails + 1))
  printf "sim   %-22s %-18s %6s x %-3s %-8s (expect %-8s) %6.1fs %s\n" "$1" "$2" "$3" "$STEPS" "$v" "$4" \
    "$(echo "$(date +%s.%N) - $t0" | bc)" "${5:-}" | tee -a "$OUT"
}
wit() { # main witnesses...
  local m=$1; shift
  local out; out=$(quint run "$F" --main "$m" --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 --witnesses "$@" 2>&1)
  echo "$out" | grep -E "witnessed in" | sed "s/^/wit   $m /" | tee -a "$OUT"
  if echo "$out" | grep -q "witnessed in 0 trace" || ! echo "$out" | grep -q "witnessed in"; then
    fails=$((fails + 1)); echo "wit   $m: a witness was not reached (or the run failed)" | tee -a "$OUT"
  fi
}
runs() { # main match
  local out n f; out=$(quint test "$F" --main "$1" --match "$2" --max-samples 1 2>&1)
  n=$(echo "$out" | grep -c " ok "); f=$(echo "$out" | grep -c "failed after")
  [ "$n" -gt 0 ] && [ "$f" -eq 0 ] || fails=$((fails + 1))
  printf "runs  %-22s %-36s passed %d failed %d (expect all-pass)\n" "$1" "$2" "$n" "$f" | tee -a "$OUT"
}

# ---- the design ----
sim design noStaleWork      "$SAMPLES" ok
sim design atMostOncePerKey "$SAMPLES" ok "(per VM instance: a clone of a mid-run snapshot finishes that run again)"
sim design recordHonest     "$SAMPLES" ok
sim design entropyHonest    "$SAMPLES" ok
wit design wRun wHostRestoreRun wCloneRun wLostNotifyRun wDupIgnored wStaleRejected wRefused wWorkAfterRun \
  wRecheckRun wSvcTimeout wTwoClones wEntRetry wOtherReseed

# ---- mutants ----
sim actOnlyOnEpoch        noStaleWork      "$MSAMPLES" VIOLATED "a clone (no epoch bump)"
sim actOnlyOnGen          noStaleWork      "$MSAMPLES" VIOLATED "a lost notify"
sim epochNotMonotonic     atMostOncePerKey "$MSAMPLES" VIOLATED "a stale HELLO re-runs a done key"
sim noDedupe              atMostOncePerKey "$MSAMPLES" VIOLATED "a duplicate notify re-runs a done key"
sim acceptWhileResuming   noStaleWork      "$MSAMPLES" VIOLATED
sim skipEntropy           noStaleWork      "$MSAMPLES" VIOLATED "needs a lost notify (the kernel's vmgenid mix covers the rest)"
sim servicesBeforeEntropy noStaleWork      "$MSAMPLES" VIOLATED
sim staleReply            noStaleWork      "$MSAMPLES" VIOLATED
sim clearOnComplete       noStaleWork      "$MSAMPLES" VIOLATED
sim timeoutIgnored        noStaleWork      "$MSAMPLES" VIOLATED
sim timeoutCountsDone     recordHonest     "$MSAMPLES" VIOLATED
sim keyFromSeen           noStaleWork      "$MSAMPLES" VIOLATED "finding: was the first design"
sim notifyLostOnClone     noStaleWork      "$MSAMPLES" VIOLATED "finding behind assumption A1"
sim entropyDoneEarly      entropyHonest    "$MSAMPLES" VIOLATED "done before a reseed took the bytes"
sim entropyDoneEarly      noStaleWork      "$MSAMPLES" VIOLATED "...and a service seeds from the stale RNG"
sim entropyFailOpen       noStaleWork      "$MSAMPLES" VIOLATED "failed writes open the gate"

# ---- scripted runs ----
runs design "DesignTest\$"
for m in actOnlyOnEpoch actOnlyOnGen epochNotMonotonic noDedupe acceptWhileResuming skipEntropy \
         servicesBeforeEntropy staleReply clearOnComplete timeoutIgnored timeoutCountsDone keyFromSeen notifyLostOnClone \
         entropyDoneEarly entropyFailOpen; do
  runs "$m" "^${m}BreaksTest\$"
done

echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
