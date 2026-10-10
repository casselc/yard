#!/bin/sh
# n0-30-tasks-undo.sh -- undo n0-30-tasks.sh.
# CHANGES   Restores /etc/login.conf (+cap_mkdb) and /etc/devfs.rules, removes the accounts and group
#           this step created, $ETC/tasks.conf, rctl_enable / if_epair_load, and any user: rctl rules in
#           the task uid range; unloads if_epair if this step loaded it and nothing uses it.
. "$(dirname "$0")/lib.sh"
step_wrap n0-30-tasks-undo "$0" "$@"
set +e
for r in $(rctl 2>/dev/null | awk -F: '$1=="user" && $2>=2000000 && $2<=2099999 {print $1":"$2}' | sort -u); do
	rctl -r "$r" && say "removed rctl rules $r"
done
restore_orig /etc/login.conf; cap_mkdb /etc/login.conf
restore_orig /etc/devfs.rules; service devfs restart
if [ -f "$STATE/accounts-created" ]; then
	sort -r "$STATE/accounts-created" | while IFS=: read -r kind n; do
		case $kind in
			user) pw userdel "$n" && pw groupdel "$n" 2>/dev/null; say "removed user $n" ;;
			group) pw groupdel "$n" && say "removed group $n" ;;
		esac
	done
	: >"$STATE/accounts-created"
fi
if [ -f "$STATE/files-created" ]; then xargs rm -f <"$STATE/files-created"; : >"$STATE/files-created"; say "removed created files"; fi
rmdir /usr/local/etc/yard 2>/dev/null
rc_restore rctl_enable
rc_restore if_epair_load /boot/loader.conf
if grep -q '^if_epair$' "$STATE/kld-loaded" 2>/dev/null; then
	if ifconfig -l | grep -q epair; then say "if_epair in use; left loaded"
	else kldunload if_epair && say "unloaded if_epair"; sed -i '' '/^if_epair$/d' "$STATE/kld-loaded"; fi
fi
say "OK"
