#!/bin/sh
# sr3-10-install.sh -- SR3: install the staged snapshot build under /usr/local/yard/bhyve-snap.
# VARIANT   SR3_VARIANT=<name> installs the patched build staged by `SR3_PATCHES=... SR3_VARIANT=<name>
#           sr3-00-build.sh` to /usr/local/yard/bhyve-snap-<name> instead. Its vmm.ko is unused when the
#           BUILDINFO says kmod=base, and is the variant's module (sr3-20-vmm.sh with the same
#           SR3_VARIANT loads it) when it says kmod=own.
# PURPOSE   Copy vmm.ko, bhyve and bhyvectl built by sr3-00-build.sh (as the ops owner, from
#           ~/yard-sr3/stage/usr/local/yard/bhyve-snap) to /usr/local/yard/bhyve-snap, root:wheel,
#           after checking the staged SHA256 file. Base (/boot/kernel/vmm.ko, /usr/sbin/bhyve,
#           /usr/sbin/bhyvectl, /usr/lib/libvmmapi.so*) is never touched; pkgbase keeps owning it.
#           The SHA256 values are printed so you can compare them with the build report.
# PREDICT   < 1 s. Afterwards: /usr/local/yard/bhyve-snap/{vmm.ko,bhyve,bhyvectl,BUILDINFO,SHA256},
#           `bhyvectl` there lists --checkpoint and --suspend.
# CHANGES   New directory /usr/local/yard/bhyve-snap (and /usr/local/yard if absent). Nothing else.
# UNDO      sudo sh sr3-10-install-undo.sh   (refuses while the module or the bhyve from there is in use)
# RUNTIME   seconds. Idempotent: identical files are reported and left as they are.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-10-install "$0" "$@"

[ -f "$STAGE/SHA256" ] || die "no staged build at $STAGE (run sr3-00-build.sh as $OWNER first)"
say "staged build: $STAGE"
sed 's/^/  BUILDINFO /' "$STAGE/BUILDINFO"
# verify the stage against its own manifest (the manifest is only as trusted as the build user)
(cd "$STAGE" && while read -r h f; do
	[ "$(sha256 -q "$f")" = "$h" ] || { echo "MISMATCH $f"; exit 1; }
done <SHA256) || die "staged files do not match $STAGE/SHA256"
sed 's/^/  SHA256 /' "$STAGE/SHA256"

if [ -f "$SNAP/SHA256" ] && cmp -s "$STAGE/SHA256" "$SNAP/SHA256" &&
	(cd "$SNAP" && while read -r h f; do [ "$(sha256 -q "$f" 2>/dev/null)" = "$h" ] || exit 1; done <SHA256); then
	say "already installed and identical; nothing to do"
	exit 0
fi

# never replace a module or binary that is in use (an install only ever writes $SNAP)
if [ "$(vmm_path)" = "$SNAP/vmm.ko" ]; then die "$SNAP/vmm.ko is the loaded vmm module; run sr3-20-vmm-undo.sh first"; fi
for p in $(bhyve_pids); do
	case "$(procstat -b "$p" 2>/dev/null | awk 'NR==2{print $NF}')" in
		"$SBHYVE") die "bhyve pid $p runs from $SBHYVE; stop it first" ;;
	esac
done

if [ ! -d /usr/local/yard ]; then
	install -d -o root -g wheel -m 0755 /usr/local/yard
	echo /usr/local/yard >>"$STATE/sr3-dirs-created"
fi
if [ ! -d "$SNAP" ]; then
	install -d -o root -g wheel -m 0755 "$SNAP"
	echo "$SNAP" >>"$STATE/sr3-dirs-created"
fi
install -o root -g wheel -m 0444 "$STAGE/vmm.ko" "$SNAP/vmm.ko"
install -o root -g wheel -m 0555 "$STAGE/bhyve" "$SNAP/bhyve"
install -o root -g wheel -m 0555 "$STAGE/bhyvectl" "$SNAP/bhyvectl"
install -o root -g wheel -m 0444 "$STAGE/BUILDINFO" "$SNAP/BUILDINFO"
install -o root -g wheel -m 0444 "$STAGE/SHA256" "$SNAP/SHA256"
(cd "$SNAP" && while read -r h f; do [ "$(sha256 -q "$f")" = "$h" ] || { echo "MISMATCH $f"; exit 1; }; done <SHA256) ||
	die "installed files do not match SHA256"
ls -l "$SNAP"
"$SBHYVECTL" 2>&1 | grep -E -- '--(checkpoint|suspend)' || die "installed bhyvectl lacks --checkpoint/--suspend"
if grep -qx 'kmod=own' "$SNAP/BUILDINFO"; then
	say "OK (kmod=own: this variant has its own vmm.ko); next: sudo env SR3_VARIANT=$VARIANT sh sr3-20-vmm.sh"
else
	say "OK; next: sudo sh sr3-20-vmm.sh"
fi
