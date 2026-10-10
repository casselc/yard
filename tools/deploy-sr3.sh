#!/bin/sh
# deploy-sr3.sh -- copy the SR3 scripts (ops/sr3 and the shared ops/lib.sh) to the NUC as the unprivileged
# user. Nothing is built here: sr3-00-build.sh builds on the NUC itself, from its /usr/src.
# (tools/deploy-nuc.sh also copies ops/, sr3 included, along with the Go binaries.)
# usage: tools/deploy-sr3.sh [user@host]      (default chuck@100.64.0.10)
set -eu
NUC=${1:-chuck@100.64.0.10}
Y=$(cd "$(dirname "$0")/.." && pwd)
cd "$Y"
for f in ops/lib.sh ops/sr3/*.sh; do sh -n "$f"; done
ssh -o BatchMode=yes "$NUC" "sh -c 'mkdir -p yard/ops/sr3'"
scp -q ops/lib.sh "$NUC":yard/ops/
scp -q ops/sr3/*.sh "$NUC":yard/ops/sr3/
ssh -o BatchMode=yes "$NUC" "sh -c 'chmod 0755 yard/ops/sr3/*.sh && for f in yard/ops/sr3/*.sh; do sh -n \$f || exit 1; done && ls -l yard/ops/sr3'"
