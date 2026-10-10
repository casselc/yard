#!/bin/sh
# apicv-restore-panic.sh -- standalone reproducer (no yard dependencies) for the vmm snapshot bug fixed
# by ops/sr3/patches/0004: with APICv virtual interrupt delivery, restoring a guest that was suspended
# while busy with interrupts panics the HOST ("ISR and isrvec_stk out of sync", vlapic.c:543).
#
# !!! EXPECTED RESULT ON AN UNPATCHED vmm.ko IS A HOST PANIC. Run it only on a disposable test host, with
# !!! nothing else running, a dump device configured (dumpdev) and REPRO_ACK=panic-the-host set.
#
# Needs (root):
#   - vmm.ko and bhyve/bhyvectl built with BHYVE_SNAPSHOT (kernel option / WITH_BHYVE_SNAPSHOT=yes);
#     BHYVE= and BHYVECTL= point at that bhyve (default: the ones in PATH), and that vmm.ko is loaded
#   - Intel VMX with hw.vmm.vmx.cap.virtual_interrupt_delivery=1 (checked; with 0 the bug cannot occur)
#   - a FreeBSD guest disk image (e.g. FreeBSD-15.1-RELEASE-amd64-ufs.raw) whose /etc/rc.conf has
#     ifconfig_vtnet0="inet 10.99.0.2/30" (GUESTIP; HOSTIP=/GUESTIP= override the /30), booted with
#     bhyveload; the guest needs no agent:
#     the load is a host ping flood at its virtio-net interface
# usage: REPRO_ACK=panic-the-host sh apicv-restore-panic.sh /path/to/disk.img [cycles, default 20]
#
# What it does, per cycle: ping -f -s 1400 the guest for 1 s, bhyvectl --suspend while the flood runs
# (a vCPU is then likely to have a virtio-net interrupt in service and/or interrupts posted), wait for
# bhyve to exit, recreate the VM with bhyveload, bhyve -r the checkpoint, wait until the guest answers
# ping again. The next cycle suspends the restored guest.
# Expected:  unpatched, virtual_interrupt_delivery=1: host panic within a few cycles (on the first test
#            host, Intel N150, 15.1-STABLE fabb224f2f15, the first restore of a guest suspended while
#            busy panicked the host; this script's own hit rate is not yet measured).
#            With 0004: all cycles complete and the guest keeps answering ping. With APICv off (kenv
#            hw.vmm.vmx.use_apic_vid=0 before loading vmm.ko; needs REPRO_CONTROL=yes): no panic, but restores
#            can hang on a separate non-APICv restore problem (2/10 in SR3 run 20261007T195236Z).
set -eu
[ "${REPRO_ACK:-}" = panic-the-host ] || { echo "refusing: this is expected to panic the host; read the header"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
IMG=${1:?usage: $0 disk.img [cycles]}; N=${2:-20}
BHYVE=${BHYVE:-bhyve}; BHYVECTL=${BHYVECTL:-bhyvectl}
VM=apicvrepro; TAP=${TAP:-tap99}; HOSTIP=${HOSTIP:-10.99.0.1}; GUESTIP=${GUESTIP:-10.99.0.2}; MEM=1024M
W=$(mktemp -d /var/tmp/apicvrepro.XXXXXX); CKP=$W/vm.ckp

vid=$(sysctl -n hw.vmm.vmx.cap.virtual_interrupt_delivery 2>/dev/null || echo '?')
echo "virtual_interrupt_delivery=$vid posted_interrupts=$(sysctl -n hw.vmm.vmx.cap.posted_interrupts 2>/dev/null || echo '?')"
echo "kernel: $(uname -v)"; echo "vmm: $(kldstat -v -n vmm 2>/dev/null | sed -n 2p)"
if [ "$vid" != 1 ]; then
	# a leftover kenv hw.vmm.vmx.use_apic_vid=0 turns APICv off at every vmm.ko load
	[ "${REPRO_CONTROL:-}" = yes ] || { echo "refusing: virtual_interrupt_delivery=$vid, the bug cannot trigger (check kenv hw.vmm.vmx.use_apic_vid; REPRO_CONTROL=yes runs it as a control)"; exit 2; }
	echo "CONTROL RUN: virtual interrupt delivery is off; the bug cannot trigger"
fi

cleanup() {
	set +e
	[ -n "${FLOOD:-}" ] && kill "$FLOOD" 2>/dev/null
	[ -n "${BPID:-}" ] && kill "$BPID" 2>/dev/null && wait "$BPID" 2>/dev/null
	[ -e /dev/vmm/$VM ] && $BHYVECTL --vm=$VM --destroy
	ifconfig $TAP destroy 2>/dev/null; rm -rf "$W"
}
trap 'rc=$?; [ $rc = 0 ] || echo "exit rc=$rc"; cleanup' EXIT

ifconfig $TAP create >/dev/null 2>&1 || true
ifconfig $TAP inet $HOSTIP/30 up
DEV="-u -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,$IMG -s 3:0,virtio-net,$TAP -l com1,stdio"
load() { bhyveload -m $MEM -d "$IMG" -e autoboot_delay=0 $VM >"$W/bhyveload.log" 2>&1; }
up() { # wait for the guest to answer ping (the tap loses its address when bhyve closes it)
	ifconfig $TAP inet $HOSTIP/30 up 2>/dev/null
	i=0; until ping -c 1 -t 1 $GUESTIP >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt "$1" ] || return 1; done
}

load; $BHYVE -c 2 -m $MEM $DEV $VM </dev/null >"$W/console.log" 2>&1 & BPID=$!
up 120 || { echo "guest did not come up (check its rc.conf: $GUESTIP)"; exit 1; }
echo "booted"
c=1; while [ $c -le "$N" ]; do
	ping -f -q -s 1400 $GUESTIP >/dev/null 2>&1 & FLOOD=$!; sleep 1
	rm -f "$CKP"*
	$BHYVECTL --vm=$VM --suspend="$CKP" >/dev/null || { echo "cycle $c: bhyvectl --suspend failed (rc $?)"; exit 1; }
	# wait returns the killed ping's status (non-zero): keep set -e from ending the run here
	kill $FLOOD 2>/dev/null; wait $FLOOD 2>/dev/null || true; FLOOD=
	wait $BPID 2>/dev/null || true; BPID=
	[ -e /dev/vmm/$VM ] && $BHYVECTL --vm=$VM --destroy
	load; $BHYVE -c 2 -m $MEM $DEV -r "$CKP" $VM </dev/null >>"$W/console.log" 2>&1 & BPID=$!
	echo "cycle $c: suspended under ping flood, restored"
	if ! up 60; then echo "cycle $c: guest does not answer after restore (wedged; on an unpatched host a panic may follow)"; exit 1; fi
	c=$((c + 1))
done
echo "PASS: $N suspend-under-load/restore cycles, guest alive"
