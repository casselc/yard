#!/bin/sh
# brk-10-install-undo.sh -- undo brk-10-install.sh. Stop the jail first (brk-20-jail.sh stop).
# Keeps zroot/yard/data/brk (secrets, audit) unless BRK_DESTROY_DATA=yes.
YARD_OPS=$(cd "$(dirname "$0")/.." && pwd); export YARD_OPS
. "$YARD_OPS/lib.sh"
step_wrap brk-10-install-undo "$0" "$@"
jls -j yard-brk jid >/dev/null 2>&1 && die "jail yard-brk is running: brk-20-jail.sh stop first"
rm -rf /usr/local/libexec/yard-brk && say "removed /usr/local/libexec/yard-brk"
rm -rf $YMNT/jails/brk && say "removed $YMNT/jails/brk"
if ifconfig lo1 inet 2>/dev/null | grep -q "inet 10.77.255.253 "; then ifconfig lo1 inet 10.77.255.253 -alias; say "removed lo1 alias"; fi
if [ "${BRK_DESTROY_DATA:-no}" = yes ] && ds_exists $YDS/data/brk; then zfs destroy -r $YDS/data/brk; say "destroyed $YDS/data/brk"
else say "kept $YDS/data/brk"; fi
if id _yardbrk >/dev/null 2>&1; then pw userdel _yardbrk; pw groupdel _yardbrk 2>/dev/null || true; say "removed _yardbrk"; fi
