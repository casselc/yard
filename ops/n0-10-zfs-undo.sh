#!/bin/sh
# n0-10-zfs-undo.sh -- undo n0-10-zfs.sh: destroy the zroot/yard tree.
# SAFETY    Refuses if any dataset under zroot/yard holds more than 1 MiB of its own data, or has
#           snapshots, unless YARD_DESTROY=yes (sudo -E). Run n0-20-audit-undo.sh first (auditd writes
#           into /yard/audit). Destroying zroot/yard/data destroys the encrypted service data for good.
# RUNTIME   seconds.
. "$(dirname "$0")/lib.sh"
step_wrap n0-10-zfs-undo "$0" "$@"
ds_exists $YDS || { say "nothing to do: $YDS does not exist"; exit 0; }
if service auditd onestatus >/dev/null 2>&1 && grep -q "^dir:$YMNT/audit" /etc/security/audit_control 2>/dev/null; then
	die "auditd is writing to $YMNT/audit; run n0-20-audit-undo.sh first"
fi
big=$(zfs list -H -p -r -o name,usedbydataset $YDS | awk '$2 > 1048576 {print $1}')
snaps=$(zfs list -H -t snapshot -o name -r $YDS | head -5)
if [ -n "$big$snaps" ] && [ "${YARD_DESTROY:-}" != yes ]; then
	say "datasets with data: $big"; say "snapshots: $snaps"
	die "refusing; re-run with YARD_DESTROY=yes sudo -E sh $0 to destroy anyway"
fi
zfs destroy -r $YDS
: >"$STATE/zfs-created"
say "destroyed $YDS"
