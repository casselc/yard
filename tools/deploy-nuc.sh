#!/bin/sh
# deploy-nuc.sh -- build the FreeBSD binaries and test binaries on the Halo and copy them, the ops
# scripts and the shim source to the NUC as the unprivileged user (no root on the NUC).
# SR1: also yard-svc (service sessions through the lifecycle) and yard-devsrv (the e2e's dev server);
# then on the NUC: cd ~/yard/ops/sr1 && sudo sh sr1-10-e2e.sh  (undo: sudo sh sr1-10-e2e-undo.sh).
# usage: tools/deploy-nuc.sh [user@host]      (default chuck@100.64.0.10)
set -eu
NUC=${1:-chuck@100.64.0.10}
# the checkout to build (a worktree too): env.sh pins Y to the main checkout for the Go caches only
R=$(cd "$(dirname "$0")/.." && pwd)
. "$R/env.sh"
cd "$R"
rm -rf out && mkdir -p out/tests
export CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64
go build -trimpath -o out/yard-ctl ./cmd/yard-ctl
go build -trimpath -o out/yard-spawn ./cmd/yard-spawn
go build -trimpath -o out/yard-svc ./cmd/yard-svc
go build -trimpath -o out/yard-devsrv ./cmd/yard-devsrv
go test -c -trimpath -tags tpmhw -o out/keyring.tpmhw.test ./internal/keyring
for p in sts keyring issuer ctl spawn mount jail rctl pfanchor lifecycle service wskey; do go test -c -trimpath -o out/tests/$p.test ./internal/$p; done
git rev-parse --short HEAD >out/REVISION
git diff --quiet || echo "+dirty" >>out/REVISION
ssh -o BatchMode=yes "$NUC" "sh -c 'mkdir -p yard/bin/tests yard/src yard/ops'"
scp -q out/yard-ctl out/yard-spawn out/yard-svc out/yard-devsrv out/keyring.tpmhw.test out/REVISION "$NUC":yard/bin/
scp -q out/tests/*.test "$NUC":yard/bin/tests/
scp -q shim/yard-exec-shim.c "$NUC":yard/src/
scp -q -r ops/. "$NUC":yard/ops/
# scp drops the execute bits; the shim is compiled there with the base system cc
ssh -o BatchMode=yes "$NUC" "sh -c 'chmod 0755 yard/bin/yard-ctl yard/bin/yard-spawn yard/bin/yard-svc yard/bin/yard-devsrv yard/bin/keyring.tpmhw.test yard/bin/tests/*.test && cc -O2 -Wall -Wextra -Werror -o yard/bin/yard-exec-shim yard/src/yard-exec-shim.c -lutil && cat yard/bin/REVISION'"
