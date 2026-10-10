#!/bin/sh
# Generate the ITF traces internal/keysvc's replay test drives the Go
# controller (keysvc.Ctl) through:
#  - the scripted design runs that use only key-service actions (quint test
#    --out-itf; the replay infers the arguments from the state change);
#  - random runs of the design under stepKeysvc and stepRevoke (quint run --mbt), of which a
#    greedy cover is kept: traces adding an action, or a (previous action,
#    action) pair, not yet covered.
# Written gzipped. Usage: sh gen_traces.sh [chunks of 300 random traces] [seed]
set -eu
cd "$(dirname "$0")"
CHUNKS=${1:-4}
SEED=${2:-0x5eed}
OUT=../../internal/keysvc/testdata/traces
TMP=$(mktemp -d "${TMPDIR:-/tmp}/keystraces.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT" "$TMP/rand" "$TMP/keep"
rm -f "$OUT"/*.itf.json*
quint test keysTest.qnt --main runsDesign --max-samples 1 \
  --match '^(happyPath|shredBeforeLoadSettlesDesign|revokeVerified|sealVerifyRetry|staleDesign|abortBurnsEpoch|abortRevokeFences|abortBeforeSpill|abortNoRevoke|abortShredByTime|verifyRetry|verifySees|revokeCancelsPendingSeal|cancelDupDesign|outlivedRenew|opIdReuseDesign|delayedRevokeDesign|delayedRevokeNextCycleDesign|delayedRevokeNextCycleAuthority|delayedRevokeAfterSealDesign)Test$' \
  --out-itf "$TMP/keep/script-{test}.itf.json" >/dev/null
k=0
while [ "$k" -lt "$CHUNKS" ]; do
  quint run keysTest.qnt --main design --step stepKeysvc --mbt --max-steps 80 --max-samples 300 --n-traces 300 \
    --seed "$((SEED + k))" --verbosity 0 --out-itf "$TMP/rand/design-$k-{seq}.itf.json" >/dev/null
  k=$((k + 1))
done
# the delayed-revoke cycles (stepRevoke: s1's cycles, revokes landing late)
quint run keysTest.qnt --main design --step stepRevoke --mbt --max-steps 80 --max-samples 300 --n-traces 300 \
  --seed "$SEED" --verbosity 0 --out-itf "$TMP/rand/revoke-{seq}.itf.json" >/dev/null
quint run keysTest.qnt --main design --step stepRevokeLate --mbt --max-steps 80 --max-samples 300 --n-traces 300 \
  --seed "$SEED" --verbosity 0 --out-itf "$TMP/rand/late-{seq}.itf.json" >/dev/null
python3 - "$TMP/rand" "$TMP/keep" <<'PY'
import json, sys, glob, shutil
src, dst = sys.argv[1], sys.argv[2]
covered, kept = set(), 0
def feats(path):
    acts = [s.get('mbt::actionTaken', '') for s in json.load(open(path))['states']]
    return set(acts) | {a + '>' + b for a, b in zip(acts, acts[1:])}
cands = {p: feats(p) for p in sorted(glob.glob(src + '/*.itf.json'))}
while True:
    best = max(cands, key=lambda p: len(cands[p] - covered), default=None)
    if best is None or not (cands[best] - covered):
        break
    covered |= cands.pop(best)
    shutil.copy(best, dst)
    kept += 1
print('random traces kept:', kept, 'features:', len(covered))
PY
for f in "$TMP"/keep/*.itf.json; do gzip -9 -c "$f" > "$OUT/$(basename "$f").gz"; done
ls "$OUT" | wc -l
du -sh "$OUT"
