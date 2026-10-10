#!/bin/sh
# n0-40-template-undo.sh -- undo n0-40-template.sh: destroy zroot/yard/tmpl/base (refuses while mounted
# into any jail root, i.e. while a nullfs mount of /yard/tmpl/base exists).
. "$(dirname "$0")/lib.sh"
step_wrap n0-40-template-undo "$0" "$@"
TDS=$YDS/tmpl/base
ds_exists $TDS || { say "nothing to do"; exit 0; }
if mount -p -t nullfs | awk '{print $1}' | grep -q "^$YMNT/tmpl/base"; then die "template is nullfs-mounted somewhere; tear those jails down first"; fi
zfs destroy -r $TDS && say "destroyed $TDS"
