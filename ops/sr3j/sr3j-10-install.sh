#!/bin/sh
# sr3j-10-install.sh -- SR3J: install the staged spike build under /usr/local/yard/sr3j (root:wheel).
# PURPOSE   Copy bhyve + bhyvectl (snapshot build + the netgraph datafd patch), sr3j-launch, sr3j-probe and
#           sr3j-chan staged by sr3j-00-build.sh (as the ops owner, ~/yard-sr3j/stage/usr/local/yard/sr3j)
#           after checking the staged SHA256 manifest. sr3j-launch runs as root later, so it must be a
#           root-owned copy, never the build user's file. Base and /usr/local/yard/bhyve-snap are untouched.
# PREDICT   < 1 s; afterwards /usr/local/yard/sr3j has 5 binaries + BUILDINFO + SHA256, all root:wheel.
# CHANGES   Directory /usr/local/yard/sr3j (and /usr/local/yard if absent).
# UNDO      sudo sh sr3j-10-install-undo.sh
# RUNTIME   seconds. Idempotent (identical files: nothing to do).
. "$(dirname "$0")/sr3j-lib.sh"
step_wrap sr3j-10-install "$0" "$@"

[ -f "$STAGE/SHA256" ] || die "no staged build at $STAGE (run sr3j-00-build.sh as $OWNER first)"
sed 's/^/  BUILDINFO /' "$STAGE/BUILDINFO"
(cd "$STAGE" && while read -r h f; do [ "$(sha256 -q "$f")" = "$h" ] || { echo "MISMATCH $f"; exit 1; }; done <SHA256) ||
	die "staged files do not match $STAGE/SHA256"
if [ -f "$INST/SHA256" ] && cmp -s "$STAGE/SHA256" "$INST/SHA256" &&
	(cd "$INST" && while read -r h f; do [ "$(sha256 -q "$f" 2>/dev/null)" = "$h" ] || exit 1; done <SHA256); then
	say "already installed and identical; nothing to do"; exit 0
fi
for p in $(pgrep -x bhyve 2>/dev/null) $(pgrep -x sr3j-chan 2>/dev/null); do
	case "$(procstat -b "$p" 2>/dev/null | awk 'NR==2{print $NF}')" in "$INST"/*) die "pid $p runs from $INST; stop it first" ;; esac
done
if [ ! -d /usr/local/yard ]; then install -d -o root -g wheel -m 0755 /usr/local/yard; echo /usr/local/yard >>"$STATE/sr3j-dirs-created"; fi
if [ ! -d "$INST" ]; then install -d -o root -g wheel -m 0755 "$INST"; echo "$INST" >>"$STATE/sr3j-dirs-created"; fi
for f in bhyve bhyvectl sr3j-launch sr3j-probe sr3j-chan; do install -o root -g wheel -m 0555 "$STAGE/$f" "$INST/$f"; done
for f in BUILDINFO SHA256; do install -o root -g wheel -m 0444 "$STAGE/$f" "$INST/$f"; done
(cd "$INST" && while read -r h f; do [ "$(sha256 -q "$f")" = "$h" ] || { echo "MISMATCH $f"; exit 1; }; done <SHA256) || die "installed files do not match SHA256"
ls -l "$INST"
say "OK; next: sudo sh sr3j-20-e2e.sh   (SR3J_NET=tap|ngd|ngfd, default tap)"
