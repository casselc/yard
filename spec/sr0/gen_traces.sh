#!/bin/sh
# Generate the ITF traces internal/lifecycle's replay test drives the Go
# state machine through:
#  - every scripted design run (quint test --out-itf; the replay infers the
#    arguments from the state change, the action from y.last);
#  - random design runs (quint run --mbt), of which a greedy cover is kept:
#    traces adding an action, or a (previous action, action) pair, not yet
#    covered.
# Written gzipped. Usage: sh gen_traces.sh [chunks of 300 random traces per instance] [seed]
# (quint keeps a chunk's traces in memory: 2000 at once exhausts its heap)
set -eu
cd "$(dirname "$0")"
CHUNKS=${1:-6}
SEED=${2:-0x5eed}
OUT=../../internal/lifecycle/testdata/traces
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sr0traces.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT" "$TMP/rand" "$TMP/keep"
rm -f "$OUT"/*.itf.json*
for m in lifecycle_test designScripts pauseScripts sr1Scripts keysScripts; do
  quint test lifecycle_test.qnt --main "$m" --max-samples 1 --out-itf "$TMP/keep/script-{test}.itf.json" >/dev/null
done
for inst in design design2 designPause designKeys; do
  k=0
  while [ "$k" -lt "$CHUNKS" ]; do
    quint run lifecycle.qnt --main "$inst" --mbt --max-steps 100 --max-samples 300 --n-traces 300 \
      --seed "$((SEED + k))" --verbosity 0 --out-itf "$TMP/rand/$inst-$k-{seq}.itf.json" >/dev/null
    k=$((k + 1))
  done
done
python3 - "$TMP/rand" "$TMP/keep" <<'PY'
import json, os, sys, glob, shutil
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
