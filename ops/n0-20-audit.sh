#!/bin/sh
# n0-20-audit.sh -- N0: auditd on at boot as yard's second audit stream (CONTROL-PLANE §3 "auditd").
# PURPOSE   Install /etc/security/audit_control with the classes the design needs and trails on the
#           reserved dataset /yard/audit, enable auditd at boot (sysrc) and start it now.
#             flags:lo,aa,ad,ex      login/logout, authn/authz, administrative, exec -- for every user
#             naflags:lo,aa          non-attributable events of the same kind
#             policy:cnt,argv        keep running if the disk fills (cnt); record execve argv
#                                    (FreeBSD has no zonename policy: the zone token is automatic for
#                                    jailed credentials -- Phase 0 S7)
#             filesz:20M, expire-after:60d OR 10G  (trails are snapshotted/sent to the Halo later, N6)
#           yard-spawn additionally sets a per-call mask (ex|pc) with setaudit_addr before jail_attach.
# PREDICT   auditd running after the script; /yard/audit holds one open trail (*.not_terminated);
#           praudit of it shows this script's own execve records (ex class). auditd keeps its
#           `current` symlink at the fixed path /var/audit/current (OpenBSM AUDIT_CURRENT_LINK), not
#           in dir:, so the check looks there and falls back to the newest open trail.
#           Volume estimate: ~300-600 bytes per exec record with argv; at a few thousand execs/hour
#           that is ~1-3 MB/hour, i.e. well under the 50G quota for 60 days.
# CHANGES   /etc/security/audit_control (original kept in ops/state/orig/), rc.conf auditd_enable=YES,
#           auditd started. Requires n0-10-zfs.sh (dataset zroot/yard/audit).
# UNDO      sudo sh n0-20-audit-undo.sh   (restores audit_control and auditd_enable, stops auditd if it
#           was not running before; trails in /yard/audit are left for you to delete or keep)
# RUNTIME   seconds.
. "$(dirname "$0")/lib.sh"
step_wrap n0-20-audit "$0" "$@"
ds_exists $YDS/audit || die "$YDS/audit missing: run n0-10-zfs.sh first"
[ "$(zfs get -H -o value mounted $YDS/audit)" = yes ] || die "$YDS/audit not mounted"
AC=/etc/security/audit_control
NEW=$STATE/audit_control.yard
cat >$NEW <<ACEOF
#
# yard N0 (ops/n0-20-audit.sh). Original kept in the yard ops state/orig/ directory.
#
dir:$YMNT/audit
dist:off
flags:lo,aa,ad,ex
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:20M
expire-after:60d OR 10G
ACEOF
if [ -f $AC ] && cmp -s $NEW $AC; then
	say "audit_control already the yard version"
else
	backup_once $AC
	install -m 0600 -o root -g wheel $NEW $AC
	say "installed $AC:"; grep -v '^#' $AC | sed 's/^/    /'
fi
if [ ! -f "$STATE/auditd-was-running" ]; then
	if service auditd onestatus >/dev/null 2>&1; then echo yes >"$STATE/auditd-was-running"; else echo no >"$STATE/auditd-was-running"; fi
fi
rc_set auditd_enable YES
if service auditd status >/dev/null 2>&1; then
	audit -s   # re-read audit_control (new dir/flags take effect at the next trail)
	audit -n
	say "auditd was running: told it to re-read audit_control and rotated"
else
	service auditd start
fi
sleep 1
service auditd status
ls -la $YMNT/audit | tail -5
cur=$(readlink /var/audit/current 2>/dev/null || true)
[ -n "$cur" ] || cur=$(ls -t $YMNT/audit/*.not_terminated 2>/dev/null | head -1)
[ -n "$cur" ] || die "no open trail in $YMNT/audit"
case $cur in $YMNT/audit/*) ;; *) die "open trail $cur is not under $YMNT/audit" ;; esac
say "current trail: $cur; last records:"
praudit -l "$cur" 2>/dev/null | tail -3 | cut -c1-300 || true
say "OK"
