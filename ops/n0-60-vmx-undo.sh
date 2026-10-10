#!/bin/sh
# n0-60-vmx-undo.sh -- undo n0-60-vmx.sh: VM datasets back under the unencrypted zroot/yard/vm.
# HOW       Per dataset in ops/state/vmx-migrated ("copied"/"verified <old> <new>"):
#             - the old dataset still exists: the copy under $VMROOT is destroyed (with its snapshots);
#             - the old one was destroyed (YARD_DESTROY_OLD=yes): the copy is sent back to its old name the same
#               way (non-raw, oldest snapshot then -I to @yundo-<ts>; zroot/yard/vm is re-created exec=off if
#               needed), verified (snapshot names, tree, sha256 of every file), and only then destroyed.
#           The entries of ops/state/sr3-zfs-created / sr3j-zfs-created go back to the old names. $VMROOT is
#           destroyed only if it is empty and n0-60 created it (ops/state/vmx-created). The key file
#           /yard/data/yard/keys/vmx.key is kept unless YARD_DESTROY_KEY=yes (sudo -E): deleting it is a
#           crypto-shred of anything still encrypted under $VMROOT (snapshots, raw-send backups).
# REFUSES   while a VM exists or bhyve runs, while anything but ZFS is mounted below $VMROOTMNT, while a clone of
#           a $VMROOT dataset exists (an sr3j run: sr3j-20-e2e-undo.sh first).
# PREDICT   Old datasets kept: seconds. Old ones destroyed: as n0-60 (1-2 min for ~3.8 G plus the hash check).
# RUNTIME   seconds to 2 minutes. Idempotent.
. "$(dirname "$0")/lib.sh"
step_wrap n0-60-vmx-undo "$0" "$@"
OLD=$YDS/vm
REC=$STATE/vmx-migrated
[ "$VMROOT" != "$OLD" ] || die "YARD_VMROOT is the old tree $OLD; unset it"
TAG=yundo-$(date -u +%Y%m%dT%H%M%SZ)
PAIRS=
[ -f "$REC" ] && PAIRS=$(awk '{print $2 " " $3}' "$REC" | awk '!seen[$0]++')

if [ -n "$PAIRS" ]; then
	vm_quiet "$VMROOTMNT"
	cl=$(zfs list -H -o name,origin -t filesystem,volume -r $POOL | awk -v o="$VMROOT/" 'index($2, o) == 1 {print $1}')
	[ -z "$cl" ] || die "clones of $VMROOT datasets exist ($cl): run sr3j-20-e2e-undo.sh first"
fi

# pass 1, parents first: send back what no longer exists under the old name
printf '%s\n' "$PAIRS" | while read -r s t; do
	[ -n "$s" ] || continue
	ds_exists "$s" && continue
	ds_exists "$t" || { say "neither $s nor $t exists; nothing to restore"; continue; }
	[ "$(zfs get -H -o value keystatus "$t")" = available ] || die "$t is locked: run yard-unlock.sh"
	if ! ds_exists $OLD; then zfs create -o exec=off $OLD; say "re-created $OLD (exec=off)"; fi
	ds_copy "$t" "$s" "$TAG"
	ds_verify "$t" "$s" "$TAG" || die "verify FAILED for $t -> $s; both kept (@$TAG too)"
	zfs destroy "$t@$TAG"; zfs destroy "$s@$TAG"
	say "restored $s from $t"
done

# pass 2, children first: drop the copies (their old datasets exist now)
printf '%s\n' "$PAIRS" | sort -r -k 1,1 | while read -r s t; do
	[ -n "$s" ] || continue
	ds_exists "$t" || continue
	ds_exists "$s" || die "$s missing; refusing to destroy its only copy $t"
	zfs destroy -r "$t"; say "destroyed copy $t"
done
printf '%s\n' "$PAIRS" | while read -r s t; do
	[ -n "$s" ] || continue
	for f in sr3-zfs-created sr3j-zfs-created; do
		[ -f "$STATE/$f" ] && grep -Fqx "$t" "$STATE/$f" || continue
		sed "s|^$t\$|$s|" "$STATE/$f" >"$STATE/$f.tmp" && mv "$STATE/$f.tmp" "$STATE/$f"
		say "ops/state/$f: $t -> $s"
	done
done
rm -f "$REC" "$STATE/vmx-old-destroyed" "$STATE/sr3-zfs-created.pre-vmx" "$STATE/sr3j-zfs-created.pre-vmx"

if ds_exists "$VMROOT"; then
	if ! grep -Fqx "$VMROOT" "$STATE/vmx-created" 2>/dev/null; then say "$VMROOT was not created by n0-60; left"
	elif [ -n "$(zfs list -H -o name -r "$VMROOT" | sed 1d)" ]; then say "$VMROOT has other children; left"
	else zfs destroy -r "$VMROOT"; say "destroyed $VMROOT"; rm -f "$STATE/vmx-created"; fi
fi
if [ "${YARD_DESTROY_KEY:-}" = yes ] && [ -e "$KEYDIR/vmx.key" ]; then
	if ds_exists "$VMROOT"; then die "$VMROOT still exists; refusing to delete its key"; fi
	rm -f "$KEYDIR/vmx.key"; say "deleted $KEYDIR/vmx.key (crypto-shred of any remaining copy encrypted under it)"
else
	if [ -e "$KEYDIR/vmx.key" ]; then say "kept $KEYDIR/vmx.key (YARD_DESTROY_KEY=yes deletes it)"; fi
fi
if ds_exists $OLD; then zfs list -r -o name,used,mountpoint,encryption $OLD; fi
say "OK"
