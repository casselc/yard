#!/bin/sh
# n0-10-zfs.sh -- N0: the yard ZFS dataset layout (CONTROL-PLANE §1 "Data", §3 "ZFS encryption", §6).
# PURPOSE   Create the dataset tree under zroot/yard (mounted at /yard). Everything that holds
#           service state lives under ONE encryption root, zroot/yard/data (aes-256-gcm), so one
#           unlock opens it all. Audit trails, templates, jail roots and VM disks stay unencrypted
#           so auditd and the jail template work at boot before anyone unlocks.
#
#             zroot/yard                 /yard            setuid=off atime=off
#             zroot/yard/audit           /yard/audit      exec=off reservation=2G quota=50G (auditd dir:)
#             zroot/yard/tmpl            /yard/tmpl       jail base templates (n0-40)
#             zroot/yard/jails           /yard/jails      long-lived jail roots, J0 test sandboxes
#             zroot/yard/vmx             /yard/vmx        ENCRYPTION ROOT (raw key file /yard/data/yard/keys/vmx.key
#                                        on the data root), exec=off, file-backed bhyve disks (not zvols:
#                                        securelevel 2). Decided 2026-10-07: VMROOT in lib.sh; created after
#                                        the data root (its key lives there). Existing installs with the
#                                        old unencrypted zroot/yard/vm migrate with n0-60-vmx.sh.
#             zroot/yard/ws              /yard/ws         (2026-10-07, not made here) workspaces, own encryption root;
#                                        created by the SR1 e2e via encroot_create (lib.sh)
#             zroot/yard/data            /yard/data       ENCRYPTION ROOT, exec=off
#               data/yard  reservation=2G   yard-ctl SQLite + audit chain
#               data/sign                   signer sequence log
#               data/brk                    NUC broker + gw
#               data/ntfy  data/otelq  data/apply
#               data/ch    quota=400G       ClickHouse
#
# KEY       DEFAULT: keyformat=passphrase keylocation=prompt -- the same scheme zroot/home/user already
#           uses. You type the passphrase twice when this runs; after every reboot the data datasets stay
#           locked (services that need them fail closed) until you run `sudo sh yard-unlock.sh`.
#           NOT done here (decision for later, see the report): the CONTROL-PLANE design of raw keys sealed
#           in the TPM (PCR7+PCR15) with offline escrow. Switching later is `zfs change-key` (no data rewrite).
#           If you prefer a key file now: YARD_KEYFILE=/path/to/32-byte-raw-key sudo -E sh n0-10-zfs.sh
#           (keyformat=raw, keylocation=file://...; YOU own escrow of that file).
# PREDICT   < 5 s plus typing. Afterwards `zfs list -r zroot/yard` shows 14 datasets (vmx instead of vm, plus data/keys), data/* with
#           encryption=aes-256-gcm encryptionroot=zroot/yard/data keystatus=available; pool free space
#           drops by the 4G of reservations only.
# CHANGES   New datasets only. No existing dataset is modified; nothing under zroot/jails or zroot/var.
# UNDO      sudo sh n0-10-zfs-undo.sh   (refuses if any yard dataset holds data unless YARD_DESTROY=yes)
# RUNTIME   seconds.
. "$(dirname "$0")/lib.sh"
step_wrap n0-10-zfs "$0" "$@"

zpool list -H -o name $POOL >/dev/null || die "pool $POOL missing"
mk() { # mk DATASET [zfs create -o ...]
	d=$1; shift
	if ds_exists "$d"; then say "exists: $d"; else zfs create "$@" "$d"; say "created $d"; echo "$d" >>"$STATE/zfs-created"; fi
}
mk $YDS -o mountpoint=$YMNT -o setuid=off -o atime=off -o compression=lz4
mk $YDS/audit -o exec=off -o reservation=2G -o quota=50G
mk $YDS/tmpl
mk $YDS/jails

if ds_exists $YDS/data; then
	say "exists: $YDS/data ($(zfs get -H -o value encryption,keyformat,keylocation,keystatus $YDS/data | tr '\n' ' '))"
	[ "$(zfs get -H -o value encryption $YDS/data)" != off ] || die "$YDS/data exists but is NOT encrypted; refusing to continue"
	[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked; run yard-unlock.sh first"
elif [ -n "${YARD_KEYFILE:-}" ]; then
	[ -f "$YARD_KEYFILE" ] || die "YARD_KEYFILE $YARD_KEYFILE not found"
	[ "$(stat -f %z "$YARD_KEYFILE")" = 32 ] || die "YARD_KEYFILE must be exactly 32 raw bytes"
	zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation="file://$YARD_KEYFILE" \
		-o exec=off -o setuid=off $YDS/data
	echo "$YDS/data" >>"$STATE/zfs-created"
	say "created $YDS/data with raw key file $YARD_KEYFILE -- escrow that file offline NOW"
else
	say "creating encryption root $YDS/data: type a NEW passphrase (min 8 chars) twice at the prompt"
	# The prompt goes straight to the terminal: the log pipe would hide a prompt with no newline.
	zfs create -o encryption=aes-256-gcm -o keyformat=passphrase -o keylocation=prompt \
		-o exec=off -o setuid=off $YDS/data </dev/tty 2>/dev/tty
	echo "$YDS/data" >>"$STATE/zfs-created"
	say "created $YDS/data (passphrase, prompt). Keep the passphrase in your password manager: it is also needed to restore raw-send backups."
fi
mk $YDS/data/yard -o reservation=2G
mk $YDS/data/sign
mk $YDS/data/brk
mk $YDS/data/ntfy
mk $YDS/data/otelq
mk $YDS/data/apply
mk $YDS/data/ch -o quota=400G
# yard-ctl's key database (wrapped keys): never snapshotted or backed up (n0-70-keys.sh sets the same)
mk $YDS/data/keys -o com.sun:auto-snapshot=false -o yard:backup=never
# VM disks: an encryption root of their own, keyed from the data root (lib.sh encroot_create)
if ds_exists "$VMROOT"; then say "exists: $VMROOT"
elif [ "$VMROOT" = "$YDS/vm" ]; then mk $YDS/vm -o exec=off   # YARD_VMROOT=zroot/yard/vm: the old layout
else encroot_create "$VMROOT" "$KEYDIR/vmx.key" -o exec=off -o setuid=off; echo "$VMROOT" >>"$STATE/zfs-created"; fi
chmod 0750 $YMNT/audit
chown root:audit $YMNT/audit
chmod 0700 $YMNT/data/sign
zfs list -r -o name,mountpoint,encryption,encryptionroot,keystatus,exec,setuid,reservation,quota,used $YDS
say "OK"
