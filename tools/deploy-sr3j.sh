#!/bin/sh
# deploy-sr3j.sh -- cross-build sr3j-chan (Go, FreeBSD/amd64) on the Halo and copy the SR3J spike
# (ops/sr3j: scripts, C sources, bhyve patch, the sr3j-chan binary; SR3's bhyve patches 0001+0002; the shared
# ops/lib.sh unless the NUC has a newer one) to the NUC as
# the unprivileged user. bhyve and the C helpers are built on the NUC by sr3j-00-build.sh (as that user).
# usage: tools/deploy-sr3j.sh [user@host]      (default chuck@100.64.0.10)
set -eu
NUC=${1:-chuck@100.64.0.10}
# env.sh pins Y to the main checkout, so this worktree's root is kept in R and the build runs in a subshell
R=$(cd "$(dirname "$0")/.." && pwd)
cd "$R"
mkdir -p ops/sr3j/bin
(. "$R/env.sh" && cd "$R" && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -o ops/sr3j/bin/sr3j-chan ./cmd/sr3j-chan)
echo "rev=$(git rev-parse --short HEAD)$(git diff --quiet -- cmd/sr3j-chan internal/guestagent || echo +dirty)" >ops/sr3j/bin/sr3j-chan.rev
for f in ops/lib.sh ops/sr3j/*.sh; do sh -n "$f"; done
ssh -o BatchMode=yes "$NUC" "sh -c 'mkdir -p yard/ops/sr3j/src yard/ops/sr3j/patches yard/ops/sr3j/bin'"
# ops/lib.sh is shared: never replace a newer one (branch sr1-service-jails adds $VMROOT, encryption roots;
# sr3j-lib.sh follows $VMROOT when it is defined). Ours goes only where none, or one without VMROOT, is.
if ssh -o BatchMode=yes "$NUC" "sh -c 'grep -q ^VMROOT= yard/ops/lib.sh'" 2>/dev/null; then
	echo "deploy-sr3j: keeping the NUC's ops/lib.sh (it defines VMROOT: a newer one, e.g. sr1's)"
else
	scp -q ops/lib.sh "$NUC":yard/ops/
fi
scp -q ops/sr3j/*.sh "$NUC":yard/ops/sr3j/
scp -q ops/sr3j/src/*.c "$NUC":yard/ops/sr3j/src/
scp -q ops/sr3j/patches/*.diff "$NUC":yard/ops/sr3j/patches/
# the SR3 userland patches sr3j-00-build.sh applies first (0001, 0002; same files as on main)
ssh -o BatchMode=yes "$NUC" "sh -c 'mkdir -p yard/ops/sr3/patches'"
scp -q ops/sr3/patches/0001-bhyve-snapshot-restore-reregisters-pci-bars.diff ops/sr3/patches/0002-bhyve-vmgenc-notify-on-restore.diff \
	"$NUC":yard/ops/sr3/patches/
scp -q ops/sr3j/bin/sr3j-chan ops/sr3j/bin/sr3j-chan.rev "$NUC":yard/ops/sr3j/bin/
ssh -o BatchMode=yes "$NUC" "sh -c 'chmod 0755 yard/ops/sr3j/*.sh yard/ops/sr3j/bin/sr3j-chan && for f in yard/ops/sr3j/*.sh; do sh -n \$f || exit 1; done && ls -l yard/ops/sr3j yard/ops/sr3j/bin'"
