#!/usr/bin/env bash
# run.sh: the checks of the agent-operations models (design/AGENT-OPERATIONS.md section 12; `quint run` only, never
# `quint verify`).
#   OUT=results.txt spec/agentop/run.sh      # SAMPLES=10000 STEPS=40 SEED=0x5eed
#
#   broker_modes.qnt     the broker's accounting: concurrent reservations, lost answers, crashes, valuation, limits
#   executor_modes.qnt   yard-ctl's recovery: ambiguous start and stop, fencing by allocation, delayed revocation
#   clock_modes.qnt      Yard-Time, the deadline clock, across yard-ctl restarts (incarnation kept)
#   apply_modes.qnt      candidates, artifact leases, approvals and the compare-and-set apply
#   agentop_modes.qnt    revision 1's model, kept as evidence under its assumptions (atomic calls of known cost,
#                        a VM whose liveness yard-node always knows, a broker that never crashes, approval inside
#                        the apply)
set -u
cd "$(dirname "$0")" || exit 1
OUT=${OUT:-/dev/null}; SEED=${SEED:-0x5eed}; SAMPLES=${SAMPLES:-10000}; STEPS=${STEPS:-40}
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES" | tee "$OUT"
fails=0
sim() { # file main invariant expect
  local out v
  out=$(quint run "$1" --main "$2" --invariant "$3" --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  v=ok; echo "$out" | grep -q "\[violation\]" && v=VIOLATED
  echo "$out" | grep -q -E "\[ok\]|\[violation\]" || v=ERROR
  [ "$v" = "$4" ] || fails=$((fails + 1))
  printf "sim   %-20s %-26s %-24s %-8s (expect %s)\n" "${1%_modes.qnt}" "$2" "$3" "$v" "$4" | tee -a "$OUT"
}
wit() { # file main witnesses...
  local f=$1 m=$2 out; shift 2
  out=$(quint run "$f" --main "$m" --witnesses "$@" --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  echo "$out" | grep -E "witnessed" | sed "s/^/wit   ${f%_modes.qnt} $m /" | tee -a "$OUT"
  [ "$(echo "$out" | grep -c witnessed)" = "$#" ] || fails=$((fails + 1))
  echo "$out" | grep -q "in 0 trace" && fails=$((fails + 1))
}
B=broker_modes.qnt
sim $B bdesign            safety        ok
sim $B checkConfirmedOnly withinTokens  VIOLATED
sim $B volatileReserve    accounted     VIOLATED
sim $B dropUnanswered     accounted     VIOLATED
sim $B valuationFromGraph withinMoney   VIOLATED
sim $B moneyOnly          withinTokens  VIOLATED
sim $B claimExact         exactIsExact  VIOLATED
sim $B awaitExactLocal    neverStuck    VIOLATED
wit $B bdesign wConcurrent wBounded wExact wResolvedLocal wCrashThenServed wLimitRefused wLocalBounded
C=clock_modes.qnt
sim $C cdesign       safety   ok
sim $C processClock  runsOnce VIOLATED
sim $C ceilingBehind runsOnce VIOLATED
wit $C cdesign wNearDeadlineRestart wPrunedThenRefused wAccepted
E=executor_modes.qnt
sim $E edesign              safety            ok
sim $E restartStartsAgain   oneLive           VIOLATED
sim $E bindByCid            attributed        VIOLATED
sim $E unreachableIsStopped stoppedIsStopped  VIOLATED
sim $E endBeforeRevoke      noSpendAfterFinal VIOLATED
sim $E captureFromUnstopped candidateStable   VIOLATED
sim $E tombstoneVolatile    oneLive           VIOLATED
wit $E edesign wCompleted wLost wFencedAlive wFencedRefused wUpgraded wRealloc wRevokePending wWatchdog wTombAcrossRestart
A=apply_modes.qnt
sim $A adesign                 safety                 ok
sim $A aEnabledUntested        safety                 ok
sim $A aAutoConfigured         safety                 ok
sim $A applyWithoutApproval    approvedApplied        VIOLATED
sim $A expiryAtApproval        approvedApplied        VIOLATED
sim $A authorityAtRequest      approvedApplied        VIOLATED
sim $A approvalByName          approvedApplied        VIOLATED
sim $A applyStaleBase          noLostUpdate           VIOLATED
sim $A autoApproveUnconfigured noAutoUnlessConfigured VIOLATED
sim $A ackReleasesArtifacts    neededPresent          VIOLATED
sim $A substituteEmpty         approvedApplied        VIOLATED
wit $A adesign wApplied wConflict wRefusedExpired wRefusedAuthority wAckedThenApplied wReleased
wit $A aAutoConfigured wAutoApplied
F=agentop_modes.qnt
sim $F design                  safety                  ok
sim $F enabledUntested         safety                  ok
sim $F autoConfigured          safety                  ok
sim $F brokerNoCap             withinCap               VIOLATED
sim $F meterFromHarness        accounted               VIOLATED
sim $F rerunOnRestart          runsOnce                VIOLATED
sim $F scopeNotRevoked         noCallsAfterEnd         VIOLATED
sim $F applyWithoutApproval    noApplyWithoutApproval  VIOLATED
sim $F autoApproveUnconfigured noAutoUnlessConfigured  VIOLATED
sim $F applyStaleBase          noLostUpdate            VIOLATED
wit $F design wApplied wReviewSettled wCapHit wCrashSettled wRestartAdopted wConflict wDenied
wit $F autoConfigured wAutoApplied
echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
