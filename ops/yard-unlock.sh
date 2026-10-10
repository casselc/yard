#!/bin/sh
# yard-unlock.sh -- after a reboot: unlock the yard encryption roots and mount them.
#   1. zroot/yard/data   keyformat=passphrase keylocation=prompt: you type the passphrase once.
#   2. zroot/yard/ws     (workspaces root) and zroot/yard/vmx (VM disks; $VMROOT): keyformat=raw, keylocation=
#                        file:///yard/data/yard/keys/{ws,vmx}.key -- the key files live on data, so they load
#                        without a prompt once step 1 is done. A root that does not exist yet is skipped.
#   NOT loaded here: the per-project encryption roots zroot/yard/ws/<project> (keyformat=raw keylocation=prompt).
#   Their raw keys are held by yard-ctl (wrapped under its keyring, in its SQLite) and fed to `zfs load-key` on
#   stdin only while a session of that project is active or resuming; yard-ctl unloads them when the project
#   has no active session. `zfs mount -a` skips them while their keys are unloaded.
# PREDICT   One prompt; afterwards `zfs get keystatus` = available on data, ws and vmx (those that exist),
#           /yard/data/*, /yard/ws and /yard/vmx/* mounted; ws/<project> datasets keystatus unavailable.
# CHANGES   Runtime only (keys loaded in kernel memory until reboot or `zfs unload-key`).
# UNDO      For each root (vmx, ws, then data): `zfs unmount -f <root>` (children too), `zfs unload-key <root>`.
. "$(dirname "$0")/lib.sh"
step_wrap yard-unlock "$0" "$@"
ks=$(zfs get -H -o value keystatus $YDS/data)
if [ "$ks" = available ]; then say "$YDS/data: key already loaded"; else
	say "enter the zroot/yard/data passphrase"
	zfs load-key $YDS/data </dev/tty 2>/dev/tty
fi
zfs mount $YDS/data 2>/dev/null || true   # the key files of the other roots are on it
encroot_load $WSROOT
encroot_load $VMROOT
say "project keys under $WSROOT are not loaded here: yard-ctl/yard-svc loads them (keylocation=prompt, stdin)"
zfs mount -a
for r in $YDS/data $WSROOT $VMROOT; do
	ds_exists "$r" && zfs list -r -d 1 -o name,encryptionroot,keystatus,mounted "$r"
done
say "OK"
