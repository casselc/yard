#!/bin/sh
# sr3j-10-install-undo.sh -- undo sr3j-10-install.sh: remove /usr/local/yard/sr3j.
# SAFETY    Refuses while any process runs a binary from there. Removes /usr/local/yard only if this step
#           created it and it is empty (SR3's bhyve-snap lives there too).
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3j-lib.sh"
step_wrap sr3j-10-install-undo "$0" "$@"
for p in $(pgrep -x bhyve 2>/dev/null) $(pgrep -x sr3j-chan 2>/dev/null) $(pgrep -x bhyvectl 2>/dev/null); do
	case "$(procstat -b "$p" 2>/dev/null | awk 'NR==2{print $NF}')" in "$INST"/*) die "pid $p runs from $INST; stop it first" ;; esac
done
if [ -d "$INST" ]; then rm -f "$INST"/bhyve "$INST"/bhyvectl "$INST"/sr3j-launch "$INST"/sr3j-probe "$INST"/sr3j-chan "$INST"/BUILDINFO "$INST"/SHA256; fi
if [ -f "$STATE/sr3j-dirs-created" ]; then
	sort -r "$STATE/sr3j-dirs-created" | while read -r d; do rmdir "$d" 2>/dev/null && say "removed $d" || say "$d not empty or gone; left"; done
	: >"$STATE/sr3j-dirs-created"
fi
say "OK"
