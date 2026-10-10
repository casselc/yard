#!/bin/sh
# sr3-30-cycles-undo.sh -- undo sr3-30-cycles.sh: remove the SR3 guest, snapshot artifacts and test network.
# SAFETY    Destroys VM $SR3_VM (default sr3-fbsd) only if it exists and no bhyve for it runs (stop that
#           first); empties pf anchor yard/sr3; destroys the tap (default tap93) only if it has the SR3
#           address 10.78.93.1; destroys zroot/yard/data/vmsnap and $VMROOT/sr3 only if this
#           step created them (ops/state/sr3-zfs-created). Results in ops/logs are kept.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-30-cycles-undo "$0" "$@"
VM=${SR3_VM:-sr3-fbsd}; TAP=${SR3_TAP:-tap93}
for p in $(bhyve_pids); do
	if ps -o args= -p "$p" | grep -q " $VM\$"; then die "a bhyve for $VM is running (pid $p); stop it first"; fi
done
if [ -e "/dev/vmm/$VM" ]; then
	say "VM $VM exists (no process); destroying"
	if [ -x "$SBHYVECTL" ]; then "$SBHYVECTL" --vm="$VM" --destroy; else bhyvectl --vm="$VM" --destroy; fi
fi
rm -f "/var/run/bhyve/$VM" /var/run/bhyve/sr3-vcon.sock
if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
	pfctl -a yard/sr3 -f /dev/null 2>/dev/null && say "pf anchor yard/sr3 emptied"
fi
if ifconfig "$TAP" >/dev/null 2>&1; then
	if ifconfig "$TAP" | grep -q 'inet 10.78.93.1 '; then ifconfig "$TAP" destroy; say "destroyed $TAP"
	else say "$TAP exists without the SR3 address; left as is"; fi
fi
for d in $YDS/data/vmsnap $VMROOT/sr3; do
	if grep -qx "$d" "$STATE/sr3-zfs-created" 2>/dev/null; then
		if ds_exists "$d"; then zfs destroy -r "$d"; say "destroyed $d"; fi
		grep -vx "$d" "$STATE/sr3-zfs-created" >"$STATE/sr3-zfs-created.tmp" || true
		mv "$STATE/sr3-zfs-created.tmp" "$STATE/sr3-zfs-created"
	elif ds_exists "$d"; then say "$d exists but was not created by sr3-30; left as is"; fi
done
say "OK"
