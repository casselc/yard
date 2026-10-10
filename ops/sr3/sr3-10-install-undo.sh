#!/bin/sh
# sr3-10-install-undo.sh -- undo sr3-10-install.sh: remove /usr/local/yard/bhyve-snap.
# SAFETY    Refuses while vmm.ko from there is loaded (run sr3-20-vmm-undo.sh first) or a bhyve from
#           there is running. Removes only the five files it installed, then the directories it created
#           if they are empty. Base is not touched.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-10-install-undo "$0" "$@"
[ -d "$SNAP" ] || { say "nothing to do: $SNAP does not exist"; exit 0; }
[ "$(vmm_path)" != "$SKO" ] || die "$SKO is the loaded vmm module; run sr3-20-vmm-undo.sh first"
for p in $(bhyve_pids); do
	case "$(procstat -b "$p" 2>/dev/null | awk 'NR==2{print $NF}')" in
		"$SBHYVE") die "bhyve pid $p runs from $SBHYVE; stop it first" ;;
	esac
done
rm -f "$SNAP/vmm.ko" "$SNAP/bhyve" "$SNAP/bhyvectl" "$SNAP/BUILDINFO" "$SNAP/SHA256"
say "removed the snapshot build files from $SNAP"
for d in "$SNAP" /usr/local/yard; do
	if grep -qx "$d" "$STATE/sr3-dirs-created" 2>/dev/null; then
		if rmdir "$d" 2>/dev/null; then say "removed $d"; else say "kept $d (not empty)"; fi
		grep -vx "$d" "$STATE/sr3-dirs-created" >"$STATE/sr3-dirs-created.tmp" || true
		mv "$STATE/sr3-dirs-created.tmp" "$STATE/sr3-dirs-created"
	fi
done
say "OK"
