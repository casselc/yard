#!/bin/sh
# n0-70-keys-undo.sh -- undo n0-70-keys.sh. Both parts are crypto-shreds and need YARD_DESTROY_KEY=yes:
#           evicting the TPM wrap key 0x81010012 makes every key wrapped under it unreadable (every workspace
#           project and spill file), and destroying zroot/yard/data/keys deletes the wrapped keys themselves.
#           Only what n0-70 created (ops/state/keys-tpm-created, keys-created) is touched.
# CHANGES   Without YARD_DESTROY_KEY=yes: nothing; it lists what it would remove and how many live keys exist.
# RUNTIME   seconds. Idempotent. Refuses while /dev/tpm0 is open.
. "$(dirname "$0")/lib.sh"
step_wrap n0-70-keys-undo "$0" "$@"
KDS=$YDS/data/keys
SVC=$OPS/../bin/yard-svc
tpm=$(cat "$STATE/keys-tpm-created" 2>/dev/null | head -1)
ds=$(grep -x "$KDS" "$STATE/keys-created" 2>/dev/null | head -1)
[ -n "$tpm$ds" ] || { say "n0-70 created nothing; nothing to undo"; exit 0; }
if [ "${YARD_DESTROY_KEY:-}" != yes ]; then
	[ -n "$tpm" ] && say "would evict the TPM wrap key $tpm (crypto-shred of every wrapped key)"
	[ -n "$ds" ] && say "would destroy $KDS ($(ls "$YMNT/data/keys" 2>/dev/null | wc -l | tr -d ' ') file(s))"
	die "refusing without YARD_DESTROY_KEY=yes (sudo env YARD_DESTROY_KEY=yes sh n0-70-keys-undo.sh)"
fi
if [ -n "$tpm" ]; then
	[ -x "$SVC" ] || die "missing $SVC"
	users=$(fstat /dev/tpm0 2>/dev/null | awk 'NR>1{print $2"("$3")"}' | sort -u | tr '\n' ' ')
	[ -z "$users" ] || die "/dev/tpm0 is open by: $users"
	out=$($SVC kek-tpm -handle "$tpm" -evict) || die "evict failed: $out"
	say "evicted: $out"; rm -f "$STATE/keys-tpm-created"
fi
if [ -n "$ds" ]; then
	if ds_exists "$KDS"; then zfs destroy -r "$KDS" && say "destroyed $KDS"; fi
	grep -vx "$KDS" "$STATE/keys-created" >"$STATE/keys-created.tmp" || true; mv "$STATE/keys-created.tmp" "$STATE/keys-created"
fi
say "OK"
