#!/bin/sh
# n0-50-pf-undo.sh -- undo n0-50-pf.sh: stop any timer, revert pf to its pre-yard state, restore
# /etc/pf.conf (removed if it did not exist) and the rc.conf pf_enable/pf_rules/pflog_enable values.
. "$(dirname "$0")/lib.sh"
step_wrap n0-50-pf-undo "$0" "$@"
set +e
YARD_OPS_INNER=1 sh "$OPS/n0-50-pf.sh" rollback
rc_restore pflog_enable; service pflog onestop 2>/dev/null
rc_restore pf_enable
rc_restore pf_rules
restore_orig /etc/pf.conf
rm -f "$STATE/pf-confirmed" "$STATE/pf-prev" "$STATE/pf.conf.rendered"
say "OK"
