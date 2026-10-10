#!/bin/sh
# yard-unlock.sh -- after a reboot: load the key of zroot/yard/data (passphrase prompt) and mount it.
# PREDICT   Prompts once; afterwards `zfs get keystatus zroot/yard/data` = available and /yard/data/* mounted.
# CHANGES   Runtime only (key loaded in kernel memory until reboot or `zfs unload-key`).
# UNDO      `zfs unmount -f zroot/yard/data` (unmounts children too), then `zfs unload-key zroot/yard/data`.
. "$(dirname "$0")/lib.sh"
step_wrap yard-unlock "$0" "$@"
ks=$(zfs get -H -o value keystatus $YDS/data)
if [ "$ks" = available ]; then say "key already loaded"; else
	say "enter the zroot/yard/data passphrase"
	zfs load-key $YDS/data </dev/tty 2>/dev/tty
fi
zfs mount -a
zfs list -r -o name,keystatus,mounted $YDS/data
say "OK"
