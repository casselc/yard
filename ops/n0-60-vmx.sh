#!/bin/sh
# n0-60-vmx.sh -- encrypted VM disks: create the encryption root $VMROOT (default zroot/yard/vmx) and move the
#           VM datasets of the old, unencrypted zroot/yard/vm into it (decided 2026-10-07, CONTROL-PLANE.md
#           "Workspace layout").
# PURPOSE   zroot/yard/vm holds the SR3/SR3J guest images (vm/sr3 @prepared @prepared2; vm/sr3j container with
#           the jail roots, vm/sr3j/base @raw @agent-*) unencrypted. $VMROOT is its own encryption root
#           (aes-256-gcm, keyformat=raw, key file /yard/data/yard/keys/vmx.key on the data encryption root, so
#           yard-unlock.sh loads it without a prompt), exec=off setuid=off like vm. The sr3/sr3j scripts use
#           $VMROOT (ops/lib.sh; YARD_VMROOT=zroot/yard/vm selects the old tree).
# HOW       Per child of zroot/yard/vm, parents first: snapshot @ymig-<ts> (the current head), full NON-raw send
#           of the oldest snapshot, then `send -I` up to @ymig-<ts>, `recv -u` into $VMROOT/<same name>. No -R/-p
#           and no raw stream: those would carry encryption=off and vm/sr3j's local mountpoint; the copy
#           inherits encryption, exec=off and the mountpoint (/yard/vmx/...) from $VMROOT. Verify: the same
#           snapshot names in order, and the same tree (type, mode, owner, size of every path) and sha256 of
#           every file at @ymig-<ts> on both sides. Then @ymig-<ts> is destroyed on both, and the entries of
#           ops/state/sr3-zfs-created and sr3j-zfs-created are rewritten to the new names (backups *.pre-vmx),
#           so the sr3/sr3j undo scripts find the copies.
#           YARD_DESTROY_OLD=yes (sudo -E): afterwards destroy the verified old datasets, and zroot/yard/vm itself
#           if it is then empty. Without it the old datasets stay (the space is used twice: ~3.8 G today).
# REFUSES   while a VM exists (/dev/vmm) or bhyve runs, while anything but ZFS is mounted below /yard/vm (a jail
#           root in use), while a clone of a source exists (vm/sr3j/a-disk during an sr3j run), if a target
#           exists that this script did not make, or if zroot/yard/data is locked.
# PREDICT   (2026-10-07, before any run) Copy: ~3.8 G referenced (2.5 G vm/sr3 incl. @prepared, 1.25 G
#           vm/sr3j/base), lz4 + aes-gcm on the NUC's NVMe: 15-40 s in all (100-250 MB/s, one stream at a
#           time). Verify: the two 6.0 GiB sparse disk.img files hashed on both sides (4 x 6.0 GiB apparent, holes
#           read as zeros from memory) at ~0.5-1 GB/s: 30-60 s. Total 1-2 min. Afterwards `zfs list -r $VMROOT`
#           shows vmx/sr3 @prepared @prepared2, vmx/sr3j, vmx/sr3j/base @raw @agent-740131a72c71-3287eb, all
#           encryptionroot=zroot/yard/vmx, mounted under /yard/vmx; verify OK for 3 datasets.
# CHANGES   New dataset $VMROOT and copies of vm/*; key file /yard/data/yard/keys/vmx.key (new, 0400);
#           @ymig-<ts> snapshots (removed again); ops/state/{sr3,sr3j}-zfs-created rewritten; records in
#           ops/state/vmx-created, vmx-migrated, vmx-old-destroyed. With YARD_DESTROY_OLD=yes: old vm/* destroyed.
# UNDO      sudo sh n0-60-vmx-undo.sh  (copies back first if the old datasets were destroyed)
# RUNTIME   1-2 minutes. Idempotent: a dataset already migrated (ops/state/vmx-migrated) is skipped.
. "$(dirname "$0")/lib.sh"
step_wrap n0-60-vmx "$0" "$@"
OLD=$YDS/vm
REC=$STATE/vmx-migrated      # "verified <old> <new>" per dataset
[ "$VMROOT" != "$OLD" ] || die "YARD_VMROOT is the old tree $OLD; nothing to migrate to"
[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"
TAG=ymig-$(date -u +%Y%m%dT%H%M%SZ)

# ---------------- preconditions (no changes yet)
SRCS=
if ds_exists $OLD; then SRCS=$(zfs list -H -o name -t filesystem -r $OLD | sed 1d); fi
[ -n "$SRCS" ] || say "no datasets under $OLD to migrate"
vm_quiet "$YMNT/vm"
cl=$(zfs list -H -o name,origin -t filesystem,volume -r $POOL | awk -v o="$OLD/" 'index($2, o) == 1 {print $1}')
[ -z "$cl" ] || die "clones of $OLD datasets exist ($cl): run the matching undo (sr3j-20-e2e-undo.sh) first"
for s in $SRCS; do
	t=$VMROOT/${s#"$OLD"/}
	if grep -Fqx "verified $s $t" "$REC" 2>/dev/null; then continue; fi
	ds_exists "$t" && die "$t exists but this script did not verify a copy into it; inspect it (or run n0-60-vmx-undo.sh)"
	for sn in $(zfs list -H -t snapshot -o name -d 1 "$s"); do
		case ${sn#*@} in ymig-*) die "$sn is a leftover migration snapshot (an interrupted run?): zfs destroy $sn, then re-run" ;; esac
	done
done

# ---------------- the encryption root
if ds_exists "$VMROOT"; then encroot_create "$VMROOT" "$KEYDIR/vmx.key"
else
	encroot_create "$VMROOT" "$KEYDIR/vmx.key" -o exec=off -o setuid=off
	echo "$VMROOT" >>"$STATE/vmx-created"
fi
[ "$(zfs get -H -o value keystatus "$VMROOT")" = available ] || die "$VMROOT is locked: run yard-unlock.sh"
[ "$(zfs get -H -o value mounted "$VMROOT")" = yes ] || zfs mount "$VMROOT"

# ---------------- copy and verify, parents first (zfs list order)
moved=0
for s in $SRCS; do
	t=$VMROOT/${s#"$OLD"/}
	if grep -Fqx "verified $s $t" "$REC" 2>/dev/null; then say "already migrated: $s -> $t"; continue; fi
	ds_copy "$s" "$t" "$TAG"
	echo "copied $s $t" >>"$REC"
	if ! ds_verify "$s" "$t" "$TAG"; then
		die "verify FAILED for $s -> $t; both kept (@$TAG too). Inspect, then n0-60-vmx-undo.sh removes the copy"
	fi
	zfs destroy "$s@$TAG"; zfs destroy "$t@$TAG"
	echo "verified $s $t" >>"$REC"
	for f in sr3-zfs-created sr3j-zfs-created; do
		[ -f "$STATE/$f" ] || continue
		grep -Fqx "$s" "$STATE/$f" || continue
		[ -e "$STATE/$f.pre-vmx" ] || cp -p "$STATE/$f" "$STATE/$f.pre-vmx"
		sed "s|^$s\$|$t|" "$STATE/$f" >"$STATE/$f.tmp" && mv "$STATE/$f.tmp" "$STATE/$f"
		say "ops/state/$f: $s -> $t"
	done
	moved=$((moved + 1))
done
say "$moved dataset(s) migrated this run"

# ---------------- optionally destroy the old datasets (children first)
if [ "${YARD_DESTROY_OLD:-}" = yes ]; then
	for s in $(printf '%s\n' $SRCS | sort -r); do
		t=$VMROOT/${s#"$OLD"/}
		grep -Fqx "verified $s $t" "$REC" || { say "$s not verified; kept"; continue; }
		ds_exists "$s" || continue
		zfs destroy -r "$s"; echo "$s" >>"$STATE/vmx-old-destroyed"; say "destroyed old $s"
	done
	if ds_exists $OLD && [ -z "$(zfs list -H -o name -r $OLD | sed 1d)" ] && [ -z "$(zfs list -H -t snapshot -o name -d 1 $OLD)" ]; then
		zfs destroy $OLD; echo "$OLD" >>"$STATE/vmx-old-destroyed"; say "destroyed the empty $OLD"
	fi
else
	say "old datasets kept (YARD_DESTROY_OLD=yes destroys them after a verified copy)"
fi
zfs list -r -o name,used,mountpoint,encryption,encryptionroot,keystatus,mounted,exec "$VMROOT"
zfs list -r -t snapshot -o name,used "$VMROOT"
say "OK"
