#!/usr/bin/env bash
# run.sh: the checks of the agent-operations model (design/AGENT-OPERATIONS.md; `quint run` only, never `quint verify`).
#   OUT=results.txt spec/agentop/run.sh      # SAMPLES=10000 STEPS=40 SEED=0x5eed
set -u
cd "$(dirname "$0")" || exit 1
OUT=${OUT:-/dev/null}; SEED=${SEED:-0x5eed}; SAMPLES=${SAMPLES:-10000}; STEPS=${STEPS:-40}
F=agentop_modes.qnt
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES" | tee "$OUT"
fails=0
sim() { # main invariant expect
  local out v
  out=$(quint run "$F" --main "$1" --invariant "$2" --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  v=ok; echo "$out" | grep -q "\[violation\]" && v=VIOLATED
  echo "$out" | grep -q -E "\[ok\]|\[violation\]" || v=ERROR
  [ "$v" = "$3" ] || fails=$((fails + 1))
  printf "sim   %-24s %-24s %-8s (expect %s)\n" "$1" "$2" "$v" "$3" | tee -a "$OUT"
}
wit() { # main witnesses...
  local m=$1 out; shift
  out=$(quint run "$F" --main "$m" --witnesses "$@" --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  echo "$out" | grep -E "witnessed" | sed "s/^/wit   $m /" | tee -a "$OUT"
  [ "$(echo "$out" | grep -c witnessed)" = "$#" ] || fails=$((fails + 1))
  echo "$out" | grep -q "in 0 trace" && fails=$((fails + 1))
}
sim design                  safety                  ok
sim enabledUntested         safety                  ok
sim autoConfigured          safety                  ok
sim brokerNoCap             withinCap               VIOLATED
sim meterFromHarness        accounted               VIOLATED
sim rerunOnRestart          runsOnce                VIOLATED
sim scopeNotRevoked         noCallsAfterEnd         VIOLATED
sim applyWithoutApproval    noApplyWithoutApproval  VIOLATED
sim autoApproveUnconfigured noAutoUnlessConfigured  VIOLATED
sim applyStaleBase          noLostUpdate            VIOLATED
wit design wApplied wReviewSettled wCapHit wCrashSettled wRestartAdopted wConflict wDenied
wit autoConfigured wAutoApplied
echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
