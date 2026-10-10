#!/bin/sh
# sr3j-20-e2e-undo.sh -- undo sr3j-20-e2e.sh: everything it created, including what a crashed run left.
# CHANGES   Runtime objects (sr3j_teardown in sr3j-lib.sh): processes of the VM uids 2100000/2100001, VMs
#           sr3ja/sr3jb, jails sr3j_a/sr3j_b, nullfs/devfs mounts under the jail roots, the run's clone and
#           snapshot datasets, devfs rulesets 2101/2102, the pf anchor yard/sr3j-a, the fake broker, the
#           tap/vmnet/ngeth/ngd objects recorded in ops/state/sr3j-net. Then the persistent ones:
#           zfs $VMDS (jail roots, base image) and $SNAPPARENT only if ops/state/sr3j-zfs-created says this
#           spike created them, and kernel modules listed in ops/state/sr3j-kld-loaded if nothing uses them.
# SAFETY    Never touches /usr/local/yard/{bhyve-snap,sr3j} (sr3j-10-install-undo.sh), base, or SR3's datasets.
#           ops/logs results are kept.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3j-lib.sh"
step_wrap sr3j-20-e2e-undo "$0" "$@"
sr3j_teardown
set +e
# anything still mounted below the container (should be nothing after teardown)
mount -p | awk -v r="$VMMNT/" 'index($2, r) == 1 && $3 != "zfs" {print $2}' | sort -r | while read -r m; do umount -f "$m" && say "unmounted $m"; done
if [ -f "$STATE/sr3j-zfs-created" ]; then
	for d in $(sort -r "$STATE/sr3j-zfs-created" | uniq); do
		if ds_exists "$d"; then
			if [ "$d" = "$SNAPPARENT" ] && [ -n "$(zfs list -H -o name -r -d 1 "$d" | sed 1d)" ]; then say "$d has children not created here; left"; continue; fi
			zfs destroy -r "$d" && say "destroyed $d"
		fi
		grep -vx "$d" "$STATE/sr3j-zfs-created" >"$STATE/sr3j-zfs-created.tmp"; mv "$STATE/sr3j-zfs-created.tmp" "$STATE/sr3j-zfs-created"
	done
fi
if [ -f "$STATE/sr3j-kld-loaded" ]; then
	for m in $(sort -r "$STATE/sr3j-kld-loaded" | uniq); do
		case $m in
			nmdm) ls /dev | grep -q '^nmdm' && { say "nmdm devices exist; nmdm left loaded"; continue; } ;;
			ng_eiface) ifconfig -l | grep -q ngeth && { say "ngeth interfaces exist; ng_eiface left loaded"; continue; } ;;
		esac
		if kldunload "$m" 2>/dev/null; then say "unloaded $m"; else say "$m busy; left loaded"; continue; fi
		grep -vx "$m" "$STATE/sr3j-kld-loaded" >"$STATE/sr3j-kld-loaded.tmp"; mv "$STATE/sr3j-kld-loaded.tmp" "$STATE/sr3j-kld-loaded"
	done
fi
rm -f "$STATE/sr3j-broker.pid"
say "OK"
