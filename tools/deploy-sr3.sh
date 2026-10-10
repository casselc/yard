#!/bin/sh
# deploy-sr3.sh -- copy the SR3 scripts (ops/sr3 and the shared ops/lib.sh) to the NUC as the unprivileged
# user, plus the source patches in ops/sr3/patches. Nothing is built here: sr3-00-build.sh builds on the NUC itself, from its /usr/src.
# (tools/deploy-nuc.sh also copies ops/, sr3 included, along with the Go binaries.)
# Files go to yard/ops/.sr3-new first and are then renamed into place, so a script that is running keeps
# reading its old file (sh reads a script 1024 bytes at a time while it runs, and scp rewrites a file in
# place: that killed run 20261007T173757Z, see sr3-30-cycles.sh RUN 5).
# usage: tools/deploy-sr3.sh [user@host]      (default chuck@100.64.0.10)
set -eu
NUC=${1:-chuck@100.64.0.10}
Y=$(cd "$(dirname "$0")/.." && pwd)
cd "$Y"
for f in ops/lib.sh ops/sr3/*.sh ops/sr3/repro/*.sh; do sh -n "$f"; done
ssh -o BatchMode=yes "$NUC" "sh -c 'rm -rf yard/ops/.sr3-new && mkdir -p yard/ops/sr3/patches yard/ops/sr3/repro yard/ops/.sr3-new/patches yard/ops/.sr3-new/repro'"
scp -q ops/lib.sh ops/sr3/*.sh "$NUC":yard/ops/.sr3-new/
scp -q ops/sr3/patches/*.diff "$NUC":yard/ops/.sr3-new/patches/
scp -q ops/sr3/repro/*.sh "$NUC":yard/ops/.sr3-new/repro/
ssh -o BatchMode=yes "$NUC" "sh -c 'cd yard/ops/.sr3-new && chmod 0755 *.sh && for f in *.sh; do sh -n \$f || exit 1; done &&
	mv lib.sh ../lib.sh && mv *.sh ../sr3/ && mv patches/*.diff ../sr3/patches/ && mv repro/*.sh ../sr3/repro/ && cd .. && rmdir .sr3-new/patches .sr3-new/repro .sr3-new &&
	ls -l sr3 sr3/patches && sha256 sr3/patches/*.diff'"
