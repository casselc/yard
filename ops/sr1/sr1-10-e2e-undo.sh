#!/bin/sh
# sr1-10-e2e-undo.sh -- undo sr1-10-e2e.sh: everything it created, including what an interrupted run left.
# CHANGES   Runtime objects first (sr1_teardown in sr1-lib.sh): `yard-svc down` for the sessions web, kill,
#           hang (instance jails, ysr1 snapshots, artifacts, records), yard-spawn sbx-destroy sr1e2e (the
#           sandbox jail and every child, its mounts, epair and pf anchor yard/sbx-sr1e2e), any jail still
#           named ysbx_sr1e2e.*, the task sr1e2e (uid freed, rctl user: rules removed). Then the datasets
#           listed in ops/state/sr1-zfs-created, newest first: zroot/yard/ws/sr1p with its clones and base
#           snapshots (unmounted first; destroyed with -R, also with its key unloaded), zroot/yard/ws (only if
#           sr1 created it and it has no other child), zroot/yard/data/sr1 (lifecycle db with the wrapped
#           project key, state, artifacts, the test KEK kek.test). The ws root's key file
#           /yard/data/yard/keys/ws.key is kept unless YARD_DESTROY_KEY=yes (with the root gone it opens
#           nothing; deleting it is the crypto-shred of any raw-send copy of the ws tree).
# SAFETY    Never touches a dataset sr1 did not create, other sandboxes, or other task uids. ops/logs results
#           are kept.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr1-lib.sh"
step_wrap sr1-10-e2e-undo "$0" "$@"
sr1_teardown
set +e
mount -p | awk -v r="/yard/jails/$SBX/" 'index($2, r) == 1 {print $2}' | sort -r | while read -r m; do umount -f "$m" && say "unmounted $m"; done
if [ -f "$ZCREATED" ]; then
	for d in $(sort -r "$ZCREATED" | uniq); do
		if ds_exists "$d"; then
			if [ "$d" = "$WSROOT" ] && [ -n "$(zfs list -H -o name -r -d 1 "$d" | sed 1d)" ]; then say "$d has children not created here; left"; continue; fi
			for m in $(zfs list -H -r -o name,mounted "$d" | awk '$2 == "yes" {print $1}' | sort -r); do
				zfs unmount "$m" || zfs unmount -f "$m"
			done
			zfs destroy -R "$d" && say "destroyed $d"
		fi
		grep -vx "$d" "$ZCREATED" >"$ZCREATED.tmp"; mv "$ZCREATED.tmp" "$ZCREATED"
	done
fi
if [ "${YARD_DESTROY_KEY:-}" = yes ] && ! ds_exists "$WSROOT" && [ -f "$KEYDIR/ws.key" ]; then
	rm -f "$KEYDIR/ws.key" && say "deleted $KEYDIR/ws.key (YARD_DESTROY_KEY=yes)"
fi
[ -d "/yard/jails/$SBX" ] && rmdir "/yard/jails/$SBX/root" "/yard/jails/$SBX" 2>/dev/null
say "OK"
