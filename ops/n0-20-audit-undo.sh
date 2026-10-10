#!/bin/sh
# n0-20-audit-undo.sh -- undo n0-20-audit.sh.
# CHANGES   Restores /etc/security/audit_control and the previous auditd_enable; stops auditd unless it
#           was running before yard. Trail files in /yard/audit are kept.
. "$(dirname "$0")/lib.sh"
step_wrap n0-20-audit-undo "$0" "$@"
restore_orig /etc/security/audit_control
rc_restore auditd_enable
if [ "$(cat "$STATE/auditd-was-running" 2>/dev/null)" = yes ]; then
	audit -s; audit -n; say "auditd was running before yard: left running with the original config"
else
	service auditd onestop 2>/dev/null || true; say "auditd stopped"
fi
rm -f "$STATE/auditd-was-running"
say "OK (trails kept in /yard/audit)"
