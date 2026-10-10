#!/usr/bin/env bash
# run.sh: the checks of the warden/broker approval-and-mint model (quint 0.32,
# `quint run` and `quint test` only). As in casselc/observability
# otel-chdb/model/open_models.sh:
#  - `sim` rows: the design instances by simulation (expect ok), and each
#    mutant against the invariant it is named for (expect VIOLATED); the
#    rows marked "pre-2026-10-07" are WARDEN.md's text before the decisions
#    this model led to;
#  - `wit` row: every witness of the design is reached in at least one trace;
#  - `runs` rows: the scripted runs (wardenRuns.qnt): `*BreaksTest` on its
#    mutant ends with the property false, `*DesignTest` on the design shows
#    the fatal step refused or disabled; expect all-pass.
# One quint process at a time.
#
#   spec/warden/run.sh                         # SAMPLES=20000 MSAMPLES=5000 STEPS=80 SEED=0x5eed
#   OUT=results.txt spec/warden/run.sh
set -u
OUT=${OUT:-/dev/stdout}
SEED=${SEED:-0x5eed}
SAMPLES=${SAMPLES:-20000}    # design instances and witnesses
MSAMPLES=${MSAMPLES:-5000}   # mutants and findings (they break within a few hundred traces)
STEPS=${STEPS:-80}
cd "$(dirname "$0")" || exit 1
F=wardenTest.qnt
echo "quint $(quint --version), seed $SEED, steps $STEPS, samples $SAMPLES (design) / $MSAMPLES (mutants)" | tee "$OUT"
fails=0
sim() { # main invariant samples expect [note]
  local t0 out v; t0=$(date +%s.%N)
  out=$(quint run "$F" --main "$1" --invariant "$2" --max-samples "$3" --max-steps "$STEPS" --seed "$SEED" --verbosity 1 2>&1)
  v=ok; echo "$out" | grep -q "\[violation\]" && v=VIOLATED
  echo "$out" | grep -q -E "\[ok\]|\[violation\]" || v=ERROR
  [ "$v" = "$4" ] || fails=$((fails + 1))
  printf "sim   %-22s %-28s %6s x %-3s %-8s (expect %-8s) %6.1fs %s\n" "$1" "$2" "$3" "$STEPS" "$v" "$4" \
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
  printf "runs  %-26s %-60s passed %d failed %d (expect all-pass)\n" "$1" "$2" "$n" "$f" | tee -a "$OUT"
}

# ---- the design ----
sim designAws   safety       "$SAMPLES" ok
sim designAzure safetyStrict "$SAMPLES" ok "(surrogate mode: no cloud credential in the VM either)"
sim designAws   noCloudCredInSandbox "$MSAMPLES" VIOLATED "by decision 5: AWS mode hands the VM 15-min credentials"
wit designAws wMinted wServed wEscMinted wShorterTtl wDenied wWithdrawn wBlocked wExpiredRefused \
  wStaleVersionRefused wPasskeyRefused wOrphanMint wLateAdopted wRemint wRemintAfterLoss wRevokeApplied \
  wRefusedExpiredJwt wBrokerCrash wReconciled wStaleEpochRefused wIpRemint wSupersededRevoked wWithdrawRevoked \
  wOrphanRevoked wResumed wBrokerResynced

# ---- WARDEN.md before 2026-10-07 (now mutants) ----
sim asWrittenEnd          credWithinApprovedTtl  "$MSAMPLES" VIOLATED "pre-2026-10-07: re-mint while live outlives the TTL"
sim asWrittenRevoke       revokedCredsUnusable   "$MSAMPLES" VIOLATED "pre-2026-10-07: revoke cutoff dated at the revoke"
sim sessionTemplateButton mintedMatchesApproval  "$MSAMPLES" VIOLATED "pre-2026-10-07: the session-template button"
sim sessionTemplateButton noMintWithoutUserApproval "$MSAMPLES" ok "(still a user act, but not on the minted card)"

# ---- mutants ----
sim approvalNotHashBound mintedMatchesApproval     "$MSAMPLES" VIOLATED
sim editInPlace          mintedMatchesApproval     "$MSAMPLES" VIOLATED
sim blindRetry           atMostOneMintPerSlot      "$MSAMPLES" VIOLATED
sim waitForAnswer        settledAttemptResolvable  "$MSAMPLES" VIOLATED
sim passkeyNotBound      escalationHasFreshPasskey "$MSAMPLES" VIOLATED
sim passkeyNotFresh      escalationHasFreshPasskey "$MSAMPLES" VIOLATED
sim rawForward           noCloudCredInSandbox      "$MSAMPLES" VIOLATED
sim forwardJwt           noFederatedCredInSandbox  "$MSAMPLES" VIOLATED
sim ttlNotClamped        credWithinApprovedTtl     "$MSAMPLES" VIOLATED
sim expiryAtRequest      credWithinApprovedTtl     "$MSAMPLES" VIOLATED
sim expiryAtClick        deadCardsNotRedeemed      "$MSAMPLES" VIOLATED
sim draftApproves        noMintWithoutUserApproval "$MSAMPLES" VIOLATED
sim replayExtends        oneGrantPerApproval       "$MSAMPLES" VIOLATED
sim trustClaimed         sandboxOnlyOwnCreds       "$MSAMPLES" VIOLATED
sim staleEpochAccepted   brokerHonoursCurrentEpoch "$MSAMPLES" VIOLATED
sim noReconciler         orphansReconcilable       "$MSAMPLES" VIOLATED
sim supersedeKeepsGrant  oneLiveGrantPerTask       "$MSAMPLES" VIOLATED
sim resumeWithoutBrokerAck brokerHonoursCurrentEpoch "$MSAMPLES" VIOLATED
sim orphanOnlyRecorded   orphansReconcilable       "$MSAMPLES" VIOLATED

# ---- scripted runs ----
runs runsDesignAws   "happyPathTest|escalationTest|lostAnswerRemintTest|expiredJwtRefusedTest|awsEcsHandsVmCredsTest|reconcileTest|resumeAckTest|brokerRestartPullTest|withdrawRevokesTest|supersedeRevokesTest|ipChangeRemintTest|passkeyBindsShortTtlTest|passkeyShortTtlTest|^(?!rawForward).*DesignTest"
runs runsDesignAzure "happyPathTest|escalationTest|lostAnswerRemintTest|rawForwardDesignTest"
for m in ApprovalNotHashBound:approvalNotHashBound EditInPlace:editInPlace BlindRetry:blindRetry \
         WaitForAnswer:waitForAnswer PasskeyNotBound:passkeyNotBound PasskeyNotFresh:passkeyNotFresh \
         RawForward:rawForward ForwardJwt:forwardJwt TtlNotClamped:ttlNotClamped ExpiryAtRequest:expiryAtRequest \
         ExpiryAtClick:expiryAtClick DraftApproves:draftApproves ReplayExtends:replayExtends TrustClaimed:trustClaimed \
         AsWrittenEnd:asWrittenEnd AsWrittenRevoke:asWrittenRevoke SessionTemplateButton:sessionTemplate \
         StaleEpochAccepted:staleEpochAccepted NoReconciler:noReconciler SupersedeKeepsGrant:supersedeKeepsGrant \
         ResumeWithoutBrokerAck:resumeWithoutBrokerAck OrphanOnlyRecorded:orphanOnlyRecorded; do
  runs "runs${m%%:*}" "^${m##*:}BreaksTest\$"
done

echo "failures: $fails" | tee -a "$OUT"
exit $((fails > 0))
