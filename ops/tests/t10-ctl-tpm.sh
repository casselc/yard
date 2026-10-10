#!/bin/sh
# t10-ctl-tpm.sh -- yard-ctl keyring against the REAL TPM (root: /dev/tpm0 is root:wheel 0600).
# PURPOSE   Part 1: open the production keys 0x81010010/0x81010011 READ-ONLY and sign/verify 10x each
#           through the thread-locked transport (no create/evict/rotate on them).
#           Part 2: full init -> sign -> rotate -> reopen -> retire cycle on SCRATCH handles
#           0x81010020/0x81010021 (must be empty; evicted again at the end; the test refuses to touch
#           an occupied scratch handle).
# PREDICT   Part 1: sign p50 19-21 ms per key (Phase 0: 19.6 ms). Part 2: init (2 in-TPM RSA-2048
#           keygens) 3-6 s (Phase 0 creates took 1.5 and 2.7 s), retire (evict + 1 keygen) 1.5-3 s;
#           old token verifies during grace and fails after retire; persistent handle set identical
#           before and after. Total < 15 s. Wedge risk: none expected -- all TPM I/O is on one locked thread.
# CHANGES   Transient only: creates and evicts keys at 0x81010020/21. Production keys untouched.
# UNDO      Automatic. If interrupted: ~/yard/bin/keyring.tpmhw.test is safe to re-run; to drop a leftover
#           scratch key use the Phase 0 tool: yard-signer evict -tpm /dev/tpm0 -handles 0x81010020,0x81010021
# RUNTIME   ~15 s.
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
step_wrap t10-ctl-tpm "$0" "$@"
B=$OPS/../bin
[ -c /dev/tpm0 ] || die "/dev/tpm0 missing (kldload tpm)"
users=$(fstat /dev/tpm0 2>/dev/null | awk 'NR>1{print $2"("$3")"}' | sort -u | tr '\n' ' ')
[ -z "$users" ] || die "/dev/tpm0 is open by: $users -- exactly one TPM client at a time (tpm20 wedge rule)"
say "revision $(cat $B/REVISION 2>/dev/null)"
cd "$STATE"
YARD_TPM=/dev/tpm0 YARD_TPM_SCRATCH=1 $B/keyring.tpmhw.test -test.v -test.run 'TestTPM' -test.timeout 120s
say "OK"
