#!/bin/sh
# build.sh: the review harness image (design/AGENT-OPERATIONS.md section 9), rootless.
#   ops/agent-image/build.sh OUT.ext4
# Environment (defaults are the Halo's):
#   FC_DIR      Firecracker spike dir with guest/ubuntu-24.04.squashfs (P0-2)
#   CLAUDE_BIN  the Claude Code native binary to install
#   RG_BIN      a static ripgrep
#   GUEST_BIN   yard-guest (CGO_ENABLED=0 go build ./cmd/yard-guest)
# podman unshare gives a user namespace in which we are uid 0, so the image's files are root-owned; the agent user
# (uid 1000) owns nothing on the root filesystem, which the VM mounts read-only anyway.
set -eu
export PATH="$PATH:/usr/sbin:/sbin"
OUT=$1
FC_DIR=${FC_DIR:-/work/platform/firecracker}
CLAUDE_BIN=$(readlink -f "${CLAUDE_BIN:-/usr/local/bin/claude}")
RG_BIN=${RG_BIN:-$FC_DIR/dl/ripgrep/x/ripgrep-14.1.1-x86_64-unknown-linux-musl/rg}
GUEST_BIN=$(readlink -f "${GUEST_BIN:-out/yard-guest}")
TMP=${TMPDIR:-/tmp}/agent-image.$$
for f in "$CLAUDE_BIN" "$RG_BIN" "$GUEST_BIN" "$FC_DIR/guest/ubuntu-24.04.squashfs"; do
  [ -f "$f" ] || { echo "build.sh: missing $f" >&2; exit 1; }
done
export FC_DIR CLAUDE_BIN RG_BIN GUEST_BIN OUT TMP
podman unshare sh -euc '
R=$TMP/root
rm -rf "$TMP"; mkdir -p "$TMP"
unsquashfs -q -d $R $FC_DIR/guest/ubuntu-24.04.squashfs >/dev/null
install -m755 "$GUEST_BIN" $R/sbin/yard-guest
install -m755 "$CLAUDE_BIN" $R/usr/local/bin/claude
install -m755 "$RG_BIN" $R/usr/local/bin/rg
mkdir -p $R/workspace $R/home/agent
# the agent user is uid 1000; the uid-1000 user of the base image, ubuntu, is removed first
sed -i "/^ubuntu:/d" $R/etc/passwd $R/etc/group $R/etc/shadow $R/etc/gshadow 2>/dev/null || true
echo "agent:x:1000:1000:agent:/home/agent:/bin/bash" >>$R/etc/passwd
echo "agent:x:1000:" >>$R/etc/group
echo "agent:!:20000::::::" >>$R/etc/shadow
rm -f "$OUT"; truncate -s 1536M "$OUT"
mkfs.ext4 -q -F -L agent-root -d $R "$OUT"
rm -rf "$TMP"
'
sha256sum "$OUT" "$GUEST_BIN" "$CLAUDE_BIN" "$RG_BIN"
"$CLAUDE_BIN" --version
