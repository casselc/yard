#!/bin/sh
# n0-70-keys.sh -- the key service's storage and root (SR1 decisions of 2026-10-07, round 2).
# PURPOSE   1. zroot/yard/data/keys: its own dataset (under the data encryption root) for yard-ctl's key
#              database (wskeys: wrapped ZFS workspace keys and halo spill keys), with NO snapshot or backup
#              policy: com.sun:auto-snapshot=false (the property zfstools / zfs-auto-snapshot and sanoid's
#              defaults honour; FreeBSD base has no snapshot daemon of its own) and yard:backup=never (yard's
#              own backup scripts skip it). A shred (wskey.Shred: wrapped key NULLed, secure_delete, WAL
#              truncated) is then immediate on the NUC: no snapshot keeps the old bytes. Anything already
#              copied elsewhere (a raw send of a parent taken with -R before this, a disk image) stays
#              openable with the TPM wrap key until it ages out.
#           2. The TPM wrap key at 0x81010012: a dedicated persistent RSA-2048 key (never one of the rotating
#              STS keys 0x81010010/11). The KEK is derived from its deterministic signature; evicting it
#              shreds every wrapped key at once. `yard-svc kek-tpm` creates and checks it.
# ARGS      [all|dataset|tpm]  (default all)
# PREDICT   dataset: < 1 s. tpm: one in-TPM RSA-2048 keygen 1.5-3 s (Phase 0: 1.5 and 2.7 s), then one
#           signature (~20 ms); prints the handle, kid and a KEK fingerprint (16 hex). Re-run: "exists", the
#           same kid and fingerprint, nothing created.
# CHANGES   zroot/yard/data/keys (mode 0700 root) recorded in ops/state/keys-created; the TPM persistent
#           handle 0x81010012 recorded in ops/state/keys-tpm-created (only if this script created it).
# UNDO      sudo sh n0-70-keys-undo.sh   (destructive parts need YARD_DESTROY_KEY=yes: a crypto-shred)
# RUNTIME   seconds. Idempotent. Needs zroot/yard/data unlocked; refuses while /dev/tpm0 is open (the
#           tpm20 wedge rule: one TPM client at a time).
. "$(dirname "$0")/lib.sh"
step_wrap n0-70-keys "$0" "$@"
WHAT=${1:-all}
case $WHAT in all|dataset|tpm) ;; *) die "usage: n0-70-keys.sh [all|dataset|tpm]" ;; esac
KDS=$YDS/data/keys
HANDLE=0x81010012
SVC=$OPS/../bin/yard-svc
[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"

if [ "$WHAT" != tpm ]; then
	if ds_exists "$KDS"; then say "exists: $KDS"
	else
		zfs create -o com.sun:auto-snapshot=false -o yard:backup=never -o exec=off -o setuid=off "$KDS"
		echo "$KDS" >>"$STATE/keys-created"; say "created $KDS"
	fi
	# also on an existing dataset: the policy properties are the point
	zfs set com.sun:auto-snapshot=false yard:backup=never "$KDS"
	chown root:wheel "$YMNT/data/keys"; chmod 0700 "$YMNT/data/keys"
	n=$(zfs list -H -t snapshot -o name -d 1 "$KDS" | wc -l | tr -d ' ')
	[ "$n" = 0 ] || say "WARNING: $KDS has $n snapshot(s): they keep shredded keys; destroy them"
	zfs get -H -o property,value encryptionroot,com.sun:auto-snapshot,yard:backup,exec,setuid,mountpoint "$KDS" | sed 's/^/  /'
fi

if [ "$WHAT" != dataset ]; then
	[ -x "$SVC" ] || die "missing $SVC (run tools/deploy-nuc.sh)"
	[ -c /dev/tpm0 ] || die "/dev/tpm0 missing (kldload tpm)"
	users=$(fstat /dev/tpm0 2>/dev/null | awk 'NR>1{print $2"("$3")"}' | sort -u | tr '\n' ' ')
	[ -z "$users" ] || die "/dev/tpm0 is open by: $users -- exactly one TPM client at a time (tpm20 wedge rule)"
	out=$($SVC kek-tpm -handle $HANDLE -create) || die "kek-tpm failed: $out"
	say "wrap key: $out"
	case $out in *'"created":true'*) echo "$HANDLE" >>"$STATE/keys-tpm-created" ;; esac
	case $out in *'"exists":true'*) ;; *) die "the wrap key is not there after create" ;; esac
fi
say "OK"
