#!/bin/sh
# sr3-30-cycles.sh -- SR3: bhyve suspend/restore and live-checkpoint cycles on the Phase 0 guest.
# PURPOSE   HARNESS.md SR3: measure suspend time, restore time, artifact sizes and failure modes over
#           SR3_N (default 50) `bhyvectl --suspend` / `bhyve -r` cycles plus SR3_LIVE (default 5)
#           `bhyvectl --checkpoint` (live, the VM keeps running) cycles, using the snapshot build from
#           /usr/local/yard/bhyve-snap with its vmm.ko loaded (sr3-20-vmm.sh).
#   Guest   The Phase 0 guest: official FreeBSD-15.1-RELEASE-amd64-ufs.raw (xz sha256 a8e2c0f8...e9409,
#           from ~/yard-p0/dl), 2 vCPU / 2560M, bhyveload + bhyve -A -H -P, hostbridge, lpc (com1 on
#           stdio -> console log), virtio-blk (disk image), virtio-net on a host tap (10.78.93.0/30).
#           Prepared once (serial console in loader.conf, a static vtnet0 address, and an rc.d
#           heartbeat agent) on zroot/yard/vm/sr3, snapshotted @prepared, rolled back at every cold boot.
#           The agent prints, once per second, to the console:
#             SR3TICK n=<counter> pid=<its pid> tok=<random, memory only> t=<guest epoch> disk=ok|bad log=ok|bad
#           disk = a 4 KiB block written+fsynced then read back with O_DIRECT (virtio-blk round trip);
#           log  = an fsynced append-only file whose line count must equal start count + n.
#           Readiness = Phase 0's "login:" on the console AND the first SR3TICK.
#   Checks after every restore: same tok and pid (memory and process continued), counter continued
#           (first n after restore - last n before suspend in 1..2), disk=ok, log=ok, host->guest ping
#           over virtio-net, guest clock skew (guest t - host t).
#   Outcome classes (per the SR0 model): every suspend/restore/checkpoint outcome is done / notdone /
#           unknown, judged only after the settle bound, never from the command's answer:
#     suspend: answer = bhyvectl rc (it only delivers the request; bhyve does the work and exits).
#              settle  = bhyve process exit (hard cap SR3_SUSP_EXIT_CAP s, cap hits recorded).
#              done    = process exited, .ckp/.meta/.kern complete (ckp = guest RAM bytes, meta is closed
#                        JSON, kern > 0), and /dev/vmm/<vm> gone.
#              notdone = process still alive and the guest still ticking (no effect), or process exited
#                        without complete artifacts (VM lost; flagged lost=yes).
#              unknown = anything else (alive but not ticking = hang, VM left in /dev/vmm, ...).
#     restore: done = process alive and a new tick within SR3_RESTORE_CAP s; state_ok separately says
#              whether tok/pid/counter/disk/log all held (done with state_ok=no = CORRUPTION -> gate fails).
#              notdone = process exited and no VM left; unknown = alive but no tick (hang) or VM left.
#     live:    done = process alive, guest ticking, artifacts complete; notdone = ticking but artifacts
#              incomplete; unknown otherwise.
#     Counted separately: answer=error but effect done, and answer=ok but effect not done.
#           Before every cold boot and every restore the script checks /dev/vmm/<vm>; a VM found there is
#           recorded first and destroyed after.
#   Phases timed separately: suspend request->answer, answer->process exit; restore: bhyveload (VM recreate) ->
#           restore start, restore start->first tick (guest responsive); live request->answer, answer->artifacts complete.
#   Probe   (SR3_PROBE_VCON=1, default) one extra cold boot with a virtio-console device (the CONTROL-PLANE
#           runner transport), which has no snapshot support in bhyve's source: one --suspend, expected
#           class notdone with the VM still running.
# PREDICT   (stated 2026-10-07 before any run; hypothesis: suspend/restore cost is dominated by moving all of
#           guest RAM through write()/read() on lz4+AES-GCM ZFS, the device state is tiny)
#           .ckp = exactly guest RAM, 2,684,354,560 B logical (vm_snapshot_mem writes all of it, not sparse);
#             on disk (lz4, mostly zero pages) 0.2-0.7 GB. .kern 20-200 KB, .meta 5-30 KB.
#           suspend request->answer < 50 ms; answer->exit 2.0 s (range 1-5); total 2.0 s (1-5).
#           restore start->VM present < 0.3 s; start->first tick 1.5 s (0.7-4; ARC-hot read of the file).
#           live checkpoint: guest paused for the whole memory write, ~2 s (1-5); bhyve keeps running.
#           Devices: hostbridge, lpc(+uart), virtio-blk, virtio-net snapshot OK (also ahci, e1000,
#           virtio-rnd, xhci, fbuf have pe_snapshot in source); virtio-console/9p/scsi, nvme, hda,
#           passthru have none -> probe: answer ok, effect notdone, VM keeps running.
#           50/50 suspend done, 50/50 restore done with state_ok=yes, 0 hangs (70% confidence: the
#           feature is experimental; the most likely failure is a restore hang or a clock jump, not
#           silent memory corruption). Guest clock skew after restore ~ -(suspended seconds) unless bhyve
#           restores time (vm_restore_time) -- expect skew within -5..+1 s.
# CHANGES   Datasets zroot/yard/vm/sr3 (disk image + @prepared) and zroot/yard/data/vmsnap (quota 40G;
#           snapshot artifacts, encrypted per SR0 invariant 4; each cycle's files are deleted right after a
#           done restore, the rest at exit unless SR3_KEEP=yes). Interface $SR3_TAP (default tap93,
#           10.78.93.1/30), destroyed at exit if created here. If pf is enabled, anchor yard/sr3 gets one
#           rule passing ICMP on that tap (emptied at exit). /var/run/bhyve (bhyve's control-socket dir).
#           Results: ops/logs/sr3-30-<run>/ (cycles.csv, console and bhyve logs, summary.txt).
# UNDO      sudo sh sr3-30-cycles-undo.sh   (destroys the two datasets, tap, anchor; VM if left)
# RUNTIME   ~10-15 min for 50 cycles (first run adds ~2 min to decompress the image).
# RESTORE   bhyve without a bootrom only OPENS an existing VM (bhyverun.c do_open: "no bootrom was configured"
#           otherwise; first run 2026-10-07: every restore notdone in 24 ms). So in the default bhyveload mode
#           the VM is recreated with bhyveload (same -m, same disk) before `bhyve -r` (its own timed phase).
#           Source check (stable/15 fabb224f2f15): restore then (1) vm_setup_memory_domains on the existing
#           segments (as on every bhyveload boot), (2) restore_vm_mem reads ALL lowmem+highmem from the .ckp,
#           overwriting the loader's kernel image, env and bootinfo, (3) vm_restore_kern_structs restores
#           vm, vmcx (per-vCPU VMCS regs/descriptors/CRs/EFER/RIP/RSP + vmxctx GPRs, i.e. everything
#           bhyveload's vm_set_register/vm_set_desc set on the BSP), vlapic, vioapic, vatpic, vatpit, vhpet,
#           vpmtmr, vrtc. bhyveload's only other effect is reading /boot from the (stopped, consistent) disk.
#           After restore bhyve_init_platform_late rewrites the mptable/SMBIOS tables, which are
#           deterministic for the same config.
#           SR3_BOOT=uefi (optional, for later Linux guests): boots with -l bootrom,<BHYVE_UEFI.fd> and no
#           bhyveload; bhyve then creates the VM itself on restore. Needs the edk2-bhyve package (root step:
#           `pkg install edk2-bhyve`); the script refuses if the firmware file is missing.
# RUN 2     (2026-10-07, 145239Z bhyveload / 150153Z uefi) found three test defects, fixed here:
#           * net=FAIL after every restore: closing /dev/tapN (bhyve exit at suspend) runs if_purgeaddrs
#             (sys/net/if_tuntap.c tunclose, unless IFF_LINK0/vmnet), so the host address was gone; the
#             script only did `ifconfig tap up`. Now the address is re-set after every bhyve start, and
#             net is also checked after every cold boot (positive control).
#           * skew -14401 s already at cold boot: bhyve's RTC is localtime unless -u (host is
#             America/New_York, UTC-4) and the FreeBSD guest reads the RTC as UTC. Now -u. The extra
#             ~-1.35 s per cycle is real: vm_restore_time() re-bases the TSC offset so guest time does not
#             advance across the downtime (sys/amd64/vmm/vmm.c); reported as skew relative to cold boot.
#           * after the recovery limit the hung restored VM was left running and the live checkpoints ran
#             against it (all "unknown"). Now the VM is stopped before leaving the loop, and live cycles
#             start only on a ticking VM. On any hang the script records each vCPU's RIP/CR0/RFLAGS twice
#             1 s apart plus exit stats (diag-*.txt).
#           A GATE line (PASS/FAIL with reasons) ends the summary; the script exits 3 on FAIL.
#           "VM present after the process ended" is expected: on ACPI poweroff bhyve exits(1) without
#           vm_destroy unless -D (amd64/vmexit.c vmexit_suspend), so stop_vm destroys it.
# RUN 4     (sr3-uefi branch, 2026-10-07) UEFI restore hang explained: with a boot ROM bhyve leaves PCI BAR
#           decoding off at startup (pci.enable_bars defaults to false, commit e962b37bf0ff) and the
#           firmware assigns and enables the BARs; on restore pci_snapshot_pci_dev() copies the BAR
#           addresses and the command register back but never registers the I/O/MMIO handlers, so the
#           guest's virtio port writes hit bhyve's default handler and are dropped (disk I/O never
#           completes; the guest kernel idles with working timers). New knobs for the experiments:
#           SR3_RESTORE_OPTS  extra bhyve arguments for `bhyve -r` only, e.g. "-o pci.enable_bars=true"
#                             (workaround) or "-o pci.enable_bars=false" (bhyveload negative control).
#           SR3_VARIANT       run the patched bhyve from /usr/local/yard/bhyve-snap-<name> (sr3-lib.sh).
# VMGEN     (sr3-uefi, patch 0002 = variant p2) The agent (v2, prepared as @prepared2) adds to each tick
#             gen=<dev.vmgenc.0.guid, the guest's CACHED generation ID, hex> kr=<8 bytes of /dev/random>
#             vg=<number of devd ACPI VMGenerationCounter notifications so far>
#           After every done restore the script waits for one more tick and records gen=chg|same,
#           vgev=+<new notifications> and kr (the first post-restore kernel RNG read). Unpatched bhyve
#           writes a new ID into the page but never raises the GPE: predicted gen=same vgev=+0. With
#           SR3_VARIANT=p2 or later this is a gate item: every restore gen=chg and vgev>=1.
#           SR3_SAME_SNAP=yes replaces the N cycles: one suspend, then SR3_SAME_K (default 5) restores of
#           that SAME snapshot, each on the disk rolled back to the suspend point (zfs @same), each stopped
#           with SIGTERM (pwr=off if the guest powered off within 15 s, pwr=killed otherwise: unpatched
#           restored guests ignore the power button, pm.c state is not snapshotted). With p2+ the gate
#           also needs all K post-restore gen values and all K kr values distinct.
# RUN 5     (sr3-uefi, 2026-10-07 p1/p2 runs) Two harness defects and one kernel bug, fixed here / in 0003:
#           * False corruption (20261007T174412Z restores 17, 27: tok=BAD pid=BAD disk= log= kr=, skew
#             ~-1.79e9): bhyve's uart writes the guest's console output to the file one byte at a time and
#             the 50 ms poll read a half-written first tick ("SR3TICK n=68 p..."): n parsed, every other
#             field empty. (Their consoles also lack bhyve's "Pausing pci devs..." banner because that is
#             stdio-buffered and flushed only at exit, and these bhyves were SIGKILLed by the recovery
#             after SIGTERM did nothing.) last_tick now returns only newline-terminated lines and
#             wait_tick only a tick with all of n/pid/tok/t/disk/log; anything less keeps waiting up to
#             the same cap (then: unknown, hang). Restore rows record the parsed lines (raw1 = first tick,
#             raw2 = the next one, spaces as _). The same defect fits p2 bhyveload 20261007T180426Z
#             restore 3 (vgev=+-1: next tick without vg) and restore 10 (gen=chg vgev=+1: last tick before
#             the suspend cut short).
#           * 20261007T173757Z died after LIVE 1 with "595: Syntax error: end of file unexpected (expecting
#             "fi")" and no summary. The deployed file was identical to this one and parses; sh reads a
#             script 1024 bytes at a time while it runs, the next read was at byte 33792 (inside line
#             595), and the script on the NUC was overwritten in place mid-run by a deploy of a 32995-byte
#             older copy (the sr3/main/sr3-jail worktrees' version) -> EOF there. Now the whole body is one
#             { ... } group, parsed completely before it starts, deploy-sr3.sh replaces files by rename,
#             and the summary with its GATE line is written by the EXIT trap if the run aborts.
#           * p2 delivered the VM-generation SCI only on the first restore after a cold boot, and SIGTERM
#             never powered a restored guest off: with APICv the restored VM's VMCS EOI-exit bitmap is
#             empty, the guest's EOI of the level-triggered SCI never reaches the vioapic and Remote IRR
#             stays set (patch 0003, vmm.ko; variant p3 = 0001+0002+0003, kmod=own).
#           vgev is now judged on the first tick that shows the notification, up to 5 ticks after the
#           restore (devd runs the action asynchronously; p2 same-snapshot restore 4 read +0 one tick in).
#           With SR3_VARIANT=p3 or later the gate also needs SIGTERM to power the guest off: every
#           same-snapshot stop pwr=off, and in cycle mode the guest the N cycles ended with (restored
#           N times since its cold boot) is stopped with SIGTERM before the live phase (final_pwr=off).
#           p2 records final_pwr too but does not gate on it (known to fail: that is the 0003 bug).
#   vmm.ko  The loaded module must be the one this bhyve was built for: the variant's own vmm.ko for a
#           kmod=own variant (p3), the base snapshot module for the base build and kmod=base variants
#           (p1, p2). Any other pairing is refused. 0003 does not change the ioctl ABI, so the mixed pairs
#           would run, but their results would be labelled with the wrong variant (p2 bhyve on the p3
#           module IS p3; p3 bhyve on the base module IS p2).
#   load    SR3_LOAD=irq suspends a guest that is taking interrupts: a host ping flood (ping -f, 1400 B)
#           at the guest runs from 1 s before each suspend request until its answer, so a vCPU is
#           likely to have a virtio-net interrupt in service at the suspend point. Every run so far
#           (SR3_LOAD=none) suspended an idle guest. On 2026-10-07 14:41:51 a restore of a busy guest
#           panicked the NUC: "ISR and isrvec_stk out of sync" (vlapic.c:543). With APICv virtual
#           interrupt delivery the guest interrupt status (RVI/SVI) is not saved, so the restored
#           guest's EOI clears the wrong ISR bit and the next HLT trips that check (patch 0004,
#           vmm.ko; variant p4 = 0001-0004). WARNING: on any module without 0004 and with
#           hw.vmm.vmx.cap.virtual_interrupt_delivery=1 this mode can PANIC THE HOST; the script
#           refuses it unless the variant is p4 or later, or virtual interrupt delivery is off, or
#           SR3_LOAD_FORCE=yes.
#           APICv-off control (no 0003/0004 needed; prediction: GATE PASS under load):
#             sudo kenv hw.vmm.vmx.use_apic_vid=0 && sudo sh sr3-20-vmm-undo.sh && sudo sh sr3-20-vmm.sh
#             sysctl hw.vmm.vmx.cap.virtual_interrupt_delivery           # must print 0
#             sudo env SR3_LOAD=irq SR3_N=10 SR3_LIVE=0 sh sr3-30-cycles.sh
#             sudo kenv -u hw.vmm.vmx.use_apic_vid && sudo sh sr3-20-vmm-undo.sh && sudo sh sr3-20-vmm.sh
# KNOBS     SR3_BOOT(bhyveload|uefi) SR3_RESTORE_OPTS SR3_VARIANT SR3_SAME_SNAP SR3_SAME_K SR3_N SR3_LIVE SR3_MEM SR3_VM SR3_TAP SR3_KEEP SR3_PROBE_VCON SR3_DWELL SR3_XZ
#           SR3_LOAD(none|irq) SR3_LOAD_FORCE
#           SR3_SUSP_REQ_CAP SR3_SUSP_EXIT_CAP SR3_RESTORE_CAP SR3_BOOT_CAP SR3_LIVE_CAP SR3_MAX_RECOVER
#           (pass with: sudo env SR3_N=5 sh sr3-30-cycles.sh)
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-30-cycles "$0" "$@"
# The whole body is one { } group: sh parses it completely before running any of it, so a deploy
# that rewrites this file during a run cannot change what the run executes (RUN 5).
{

N=${SR3_N:-50}; LIVE=${SR3_LIVE:-5}; MEM=${SR3_MEM:-2560M}; CPUS=2
VM=${SR3_VM:-sr3-fbsd}; TAP=${SR3_TAP:-tap93}; HOSTIP=10.78.93.1; GUESTIP=10.78.93.2
DWELL=${SR3_DWELL:-2}
SUSP_REQ_CAP=${SR3_SUSP_REQ_CAP:-30}; SUSP_EXIT_CAP=${SR3_SUSP_EXIT_CAP:-120}
RESTORE_CAP=${SR3_RESTORE_CAP:-60}; BOOT_CAP=${SR3_BOOT_CAP:-180}; LIVE_CAP=${SR3_LIVE_CAP:-120}
MAX_RECOVER=${SR3_MAX_RECOVER:-5}
BOOT=${SR3_BOOT:-bhyveload}
FW=/usr/local/share/uefi-firmware/BHYVE_UEFI.fd
case $BOOT in
	bhyveload) BOOTARG= ;;
	uefi) [ -f "$FW" ] || die "SR3_BOOT=uefi needs $FW (package edk2-bhyve; as root: pkg install edk2-bhyve)"
		BOOTARG="-l bootrom,$FW" ;;
	*) die "SR3_BOOT must be bhyveload or uefi" ;;
esac
ROPTS=${SR3_RESTORE_OPTS:-}
SAME=${SR3_SAME_SNAP:-no}; SAME_K=${SR3_SAME_K:-5}
case $SAME in yes|no) ;; *) die "SR3_SAME_SNAP must be yes or no" ;; esac
# the VM-generation checks gate only for builds carrying patch 0002 (variant p2 or later)
case ${SR3_VARIANT:-} in p[2-9]|p[1-9][0-9]) GEN_GATE=yes ;; *) GEN_GATE=no ;; esac
# SIGTERM power-off gates only for builds carrying patch 0003 (variant p3 or later)
case ${SR3_VARIANT:-} in p[3-9]|p[1-9][0-9]) PWR_GATE=yes ;; *) PWR_GATE=no ;; esac
# suspend under interrupt load (see "load" above): refused where it can panic the host
LOAD=${SR3_LOAD:-none}
VID=$(sysctl -n hw.vmm.vmx.cap.virtual_interrupt_delivery 2>/dev/null || echo '?')
PI=$(sysctl -n hw.vmm.vmx.cap.posted_interrupts 2>/dev/null || echo '?')
case $LOAD in
	none) ;;
	irq) case ${SR3_VARIANT:-} in p[4-9]|p[1-9][0-9]) ;;
		*) [ "$VID" = 0 ] || [ "${SR3_LOAD_FORCE:-}" = yes ] ||
			die "SR3_LOAD=irq on variant '${SR3_VARIANT:-base}' with virtual_interrupt_delivery=$VID can panic the host (no patch 0004): use SR3_VARIANT=p4, turn APICv off, or set SR3_LOAD_FORCE=yes" ;;
		esac ;;
	*) die "SR3_LOAD must be none or irq" ;;
esac
PREP=prepared2   # guest prep version: v2 agent (gen/kr/vg); bump when the guest setup changes
XZ=${SR3_XZ:-$OWNER_HOME/yard-p0/dl/FreeBSD-15.1-RELEASE-amd64-ufs.raw.xz}
XZ_SHA=a8e2c0f8331be615ef008c167069076833a417e968ff6b7d8e83b4ac762e9409
VMDS=$YDS/vm/sr3; IMG=$YMNT/vm/sr3/disk.img
SNAPDS=$YDS/data/vmsnap; SNAPMNT=$YMNT/data/vmsnap
RUN=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$OPS/logs/sr3-30-$RUN; CSV=$OUT/cycles.csv
SD=$SNAPMNT/$RUN
case $MEM in
	*M) MEMB=$(( ${MEM%M} * 1048576 )) ;;
	*G) MEMB=$(( ${MEM%G} * 1073741824 )) ;;
	*) die "SR3_MEM must end in M or G" ;;
esac

# ---------------- preconditions (no changes yet)
[ -x "$SBHYVE" ] && [ -x "$SBHYVECTL" ] || die "snapshot bhyve/bhyvectl missing: run sr3-10-install.sh"
# the module must be the one this bhyve belongs to (see "vmm.ko" above)
if [ "$(vmm_path)" != "$SKO" ]; then
	if [ $KMOD_OWN = yes ]; then die "variant $VARIANT has its own vmm.ko ($SKO) but the loaded vmm is '$(vmm_path)': run sudo env SR3_VARIANT=$VARIANT sh sr3-20-vmm.sh"
	else die "this bhyve (${VARIANT:-base}) runs on $SKO but the loaded vmm is '$(vmm_path)': run sudo sh sr3-20-vmm.sh (no SR3_VARIANT)"; fi
fi
[ -f "$VMM_LOADED" ] || die "no $VMM_LOADED (load the module with sr3-20-vmm.sh)"
case " $(cat "$VMM_LOADED") " in *" path=$SKO sha256=$(sha256 -q "$SKO") "*) ;; *) die "$VMM_LOADED ($(cat "$VMM_LOADED")) does not match $SKO as it is on disk now; reload it with sr3-20-vmm.sh" ;; esac
if [ -e "/dev/vmm/$VM" ]; then
	say "VM $VM already exists (recorded here; a leftover of an earlier run?):"
	"$SBHYVECTL" --vm="$VM" --get-stats 2>/dev/null | head -3 || true
	[ "${SR3_DESTROY_STALE:-}" = yes ] || die "refusing; inspect it, or re-run with SR3_DESTROY_STALE=yes to destroy it"
	"$SBHYVECTL" --vm="$VM" --destroy; say "destroyed stale VM $VM"
fi
for p in $(bhyve_pids); do
	if ps -o args= -p "$p" | grep -q " $VM\$"; then die "a bhyve for $VM is running (pid $p)"; fi
done
[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"
ds_exists $YDS/vm || die "$YDS/vm missing (n0-10-zfs.sh)"
pg=$(sysctl -n hw.pagesize)
fr=$(( ( $(sysctl -n vm.stats.vm.v_free_count) + $(sysctl -n vm.stats.vm.v_inactive_count) ) * pg / 1048576 ))
[ "$fr" -ge $(( MEMB / 1048576 + 1024 )) ] || die "need $(( MEMB / 1048576 + 1024 )) MB free+inactive, have $fr"
command -v timeout >/dev/null || die "timeout(1) missing"

mkdir -p "$OUT"
say "run $RUN: N=$N LIVE=$LIVE MEM=$MEM ($MEMB B) VM=$VM TAP=$TAP BOOT=$BOOT bhyve=$SBHYVE restore_opts='$ROPTS' out=$OUT"
sed 's/^/  BUILDINFO /' "$SNAP/BUILDINFO"
say "vmm.ko loaded: $(cat "$VMM_LOADED")"
say "apicv: virtual_interrupt_delivery=$VID posted_interrupts=$PI; load=$LOAD"
[ "$(dirname "$SKO")" = "$SNAP" ] || sed 's/^/  vmm BUILDINFO /' "$(dirname "$SKO")/BUILDINFO"
say "script: $0 sha256 $(sha256 -q "$0")"

# ---------------- helpers
now() { date +%s.%N; }
el() { echo "$1 $2" | awk '{printf "%.3f", $2-$1}'; }
past() { echo "$1 $2" | awk '{exit !($2 >= $1)}'; }   # past DEADLINE NOW -> true when NOW >= DEADLINE
deadline() { echo "$1 $2" | awk '{printf "%.3f", $1+$2}'; }
fsize() { if [ -e "$1" ]; then stat -f %z "$1"; else echo -1; fi; }
falloc() { if [ -e "$1" ]; then du -k "$1" | awk '{print $1}'; else echo -1; fi; }
sha8() { if [ -s "$1" ]; then sha256 -q "$1" | cut -c1-12; else echo -; fi; }
vm_present() { [ -e "/dev/vmm/$VM" ] && echo yes || echo no; }
alive() { [ -n "${BPID:-}" ] && kill -0 "$BPID" 2>/dev/null; }
# last_tick CONLOG -> the last COMPLETE tick line. bhyve's uart writes the console one byte at a time, so
# the file's last line can be half-written; the '#EOF' appended to the same read marks it, and it is dropped.
last_tick() { { cat "$1" 2>/dev/null; echo '#EOF'; } | grep -a 'SR3TICK' | grep -av '#EOF' | tail -1 | tr -d '\r'; }
tf() { echo "$2" | sed -n "s/.*[ ]$1=\([^ ]*\).*/\1/p"; }   # tf FIELD LINE
# tick_ok LINE -- every field the restore checks read is there
tick_ok() { for _f in n pid tok t disk log; do [ -n "$(tf $_f "$1")" ] || return 1; done; }
# rawf LINE -> the line as one CSV-safe token (spaces -> _, commas -> ;), for the notes column
rawf() { if [ -n "$1" ]; then echo "$1" | tr ' ,' '_;'; else echo -; fi; }
row() { echo "$*" >>"$CSV"; }
echo "run,kind,i,answer,rc,t_answer,t_settle,t_total,proc_rc,class,ckp_bytes,ckp_alloc_k,meta_bytes,kern_bytes,kern_sha,meta_sha,vm_after,notes" >"$CSV"
ERR_BUT_DONE=0; OK_BUT_NOTDONE=0; VM_FOUND_BEFORE=0; RECOVERIES=0; CAPHITS=0
NET_BOOT_OK=0; NET_RESTORE_FAIL=0; BOOT_SKEW=0; BOOT_NET=-; STOPPED_EARLY=no; GEN_FAIL=0
corrupt=0; SAME_GENS=; SAME_KRS=; SAME_DONE=0; FINAL_PWR=na; CHAIN=0; REPORTED=no; ABORTED=

# wait_tick CONLOG NMIN CAP -> prints the first complete tick line (tick_ok) with n > NMIN; rc 1 on cap,
# 2 if bhyve died. A line that is not complete yet is never returned: no tick parsed = keep waiting.
wait_tick() {
	_dl=$(deadline "$(now)" "$3")
	while :; do
		_l=$(last_tick "$1")
		if [ -n "$_l" ]; then _n=$(tf n "$_l"); if [ -n "$_n" ] && [ "$_n" -gt "$2" ] && tick_ok "$_l"; then echo "$_l"; return 0; fi; fi
		alive || return 2
		past "$_dl" "$(now)" && return 1
		sleep 0.05
	done
}

# stop_vm REASON -- kill our bhyve (if any) and destroy the VM, recording what was there first
STOP_HOW=-
stop_vm() {
	STOP_HOW=-
	if alive; then kill -TERM "$BPID" 2>/dev/null; _d=$(deadline "$(now)" 15)
		while alive && ! past "$_d" "$(now)"; do sleep 0.1; done
		if alive; then STOP_HOW=killed; kill -9 "$BPID" 2>/dev/null; else STOP_HOW=off; fi
		wait "$BPID" 2>/dev/null || true
	fi
	BPID=
	if [ -e "/dev/vmm/$VM" ]; then say "stop_vm($1): VM $VM left after bhyve exited (expected after poweroff without -D); destroying"; "$SBHYVECTL" --vm="$VM" --destroy 2>/dev/null || true; fi
}

# check_no_vm LABEL -- the rule before every cold boot / restore: record, then destroy
check_no_vm() {
	if [ -e "/dev/vmm/$VM" ]; then
		VM_FOUND_BEFORE=$((VM_FOUND_BEFORE + 1))
		say "VM $VM PRESENT before $1 (recorded: count $VM_FOUND_BEFORE); destroying"
		row "$RUN,vm_present_before,$1,-,-,-,-,-,-,-,-,-,-,-,-,-,yes,destroyed"
		"$SBHYVECTL" --vm="$VM" --destroy 2>/dev/null || true
	fi
}

# load_vm LOG -- bhyveload mode: create+initialise the VM (bhyve without a bootrom only opens one)
load_vm() {
	bhyveload -m "$MEM" -d "$IMG" -e autoboot_delay=0 -e console=comconsole "$VM" </dev/null >"$1" 2>&1
}

# host_net -- (re)set the host end of the tap: tunclose() purges its addresses whenever bhyve exits
host_net() { ifconfig "$TAP" inet "$HOSTIP/30" up; }
# ping_guest -> "ok/<ms>ms" or FAIL
ping_guest() {
	_p=$(ping -c 1 -t 3 "$GUESTIP" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p')
	if [ -n "$_p" ]; then echo "ok/${_p}ms"; else echo FAIL; fi
}
# diag LABEL -- vCPU state twice, 1 s apart, plus exit stats (for hangs)
diag() {
	{
		echo "== $1 $(date -u +%H:%M:%SZ) vm_present=$(vm_present)"
		for k in 1 2; do
			for c in 0 1; do echo "-- cpu $c sample $k"; "$SBHYVECTL" --vm="$VM" --cpu=$c --get-rip --get-cr0 --get-rflags --get-cr3 2>&1; done
			"$SBHYVECTL" --vm="$VM" --get-active-cpus --get-suspended-cpus 2>&1
			[ $k = 1 ] && sleep 1
		done
		"$SBHYVECTL" --vm="$VM" --cpu=0 --get-stats 2>&1 | head -60
	} >"$OUT/diag-$1.txt" 2>&1
	say "diagnostics: $OUT/diag-$1.txt; cpu0 RIP $(grep -m2 -i 'rip' "$OUT/diag-$1.txt" | awk '{print $NF}' | tr '\n' ' ')"
}

DEV="$BOOTARG -u -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,$IMG -s 3:0,virtio-net,$TAP"
EXTRA=

# cold_boot LABEL -- fresh disk (rollback), bhyveload, bhyve; wait for login: and the first tick
cold_boot() {
	check_no_vm "boot-$1"
	zfs rollback -r "$VMDS@$PREP"
	CON=$OUT/console-boot-$1.log; : >"$CON"
	t0=$(now)
	if [ "$BOOT" = bhyveload ]; then
		load_vm "$OUT/bhyveload-$1.log" || { cat "$OUT/bhyveload-$1.log"; die "bhyveload failed"; }
	fi
	# shellcheck disable=SC2086
	"$SBHYVE" -c $CPUS -m "$MEM" $DEV $EXTRA -l com1,stdio "$VM" </dev/null >"$CON" 2>"$OUT/bhyve-boot-$1.err" &
	BPID=$!
	_dl=$(deadline "$t0" "$BOOT_CAP")
	while ! grep -aq 'login:' "$CON"; do
		alive || { cat "$OUT/bhyve-boot-$1.err"; tail -20 "$CON"; die "bhyve exited during boot $1"; }
		past "$_dl" "$(now)" && { tail -20 "$CON"; die "no login: after $BOOT_CAP s (boot $1)"; }
		sleep 0.1
	done
	t1=$(now)
	TICK=$(wait_tick "$CON" 0 60) || { tail -20 "$CON"; die "agent never ticked (boot $1)"; }
	t2=$(now)
	host_net
	BOOT_SKEW=$(( $(tf t "$TICK") - $(date +%s) ))
	BOOT_NET=$(ping_guest)
	[ "${BOOT_NET%%/*}" = ok ] && NET_BOOT_OK=$((NET_BOOT_OK + 1))
	say "BOOT $1: to login: $(el "$t0" "$t1") s, to first tick $(el "$t0" "$t2") s; net=$BOOT_NET skew_s=$BOOT_SKEW; $TICK"
	[ "$(tf disk "$TICK")" = ok ] || say "WARNING: agent disk check reports $(tf disk "$TICK") right after boot (dd iflag=direct unsupported?)"
	row "$RUN,boot,$1,-,-,$(el "$t0" "$t1"),$(el "$t1" "$t2"),$(el "$t0" "$t2"),-,done,-,-,-,-,-,-,yes,net=$BOOT_NET skew_s=$BOOT_SKEW"
}

# artifacts FILE -> sets A_OK A_CKP A_ALLOC A_META A_KERN A_KSHA A_MSHA
artifacts() {
	A_CKP=$(fsize "$1"); A_ALLOC=$(falloc "$1"); A_META=$(fsize "$1.meta"); A_KERN=$(fsize "$1.kern")
	A_KSHA=$(sha8 "$1.kern"); A_MSHA=$(sha8 "$1.meta")
	A_OK=no
	# the .meta JSON is finished only after memory and kernel state are written, so a closed .meta
	# plus non-empty .ckp/.kern means complete; the .ckp size is reported (predicted = guest RAM).
	if [ "$A_CKP" -gt 0 ] && [ "$A_KERN" -gt 0 ] && [ "$A_META" -gt 0 ] &&
		tail -c 16 "$1.meta" | tr -d ' \n\r\t' | grep -q '}$' &&
		[ "$(tr -cd '{' <"$1.meta" | wc -c)" -eq "$(tr -cd '}' <"$1.meta" | wc -c)" ]; then A_OK=yes; fi
}

# suspend_one KIND I [EXIT_CAP] -> sets S_CLASS, S_NLAST (last tick before the VM stopped)
suspend_one() {
	F=$SD/$1-$2.ckp
	pre=$(last_tick "$CON"); npre=$(tf n "$pre")
	FLOOD=
	if [ $LOAD = irq ]; then
		ping -f -q -s 1400 "$GUESTIP" >"$OUT/flood-$1-$2.log" 2>&1 &
		FLOOD=$!; sleep 1
	fi
	ta=$(now)
	timeout "$SUSP_REQ_CAP" "$SBHYVECTL" --vm="$VM" --suspend="$F" >"$OUT/bhyvectl-$1-$2.log" 2>&1; arc=$?
	tb=$(now)
	if [ -n "$FLOOD" ]; then kill "$FLOOD" 2>/dev/null; wait "$FLOOD" 2>/dev/null; FLOOD=; fi
	case $arc in 0) ans=ok ;; 124) ans=timeout ;; *) ans=err ;; esac
	# settle bound: the bhyve process exit (hard cap)
	_dl=$(deadline "$tb" "${3:-$SUSP_EXIT_CAP}"); capped=no
	while alive; do past "$_dl" "$(now)" && { capped=yes; break; }; sleep 0.02; done
	tc=$(now); prc=-
	if [ $capped = no ] && [ -n "${BPID:-}" ]; then wait "$BPID"; prc=$?; BPID=; fi
	[ $capped = yes ] && [ "$1" != probe-vcon ] && CAPHITS=$((CAPHITS + 1))
	artifacts "$F"
	vma=$(vm_present)
	S_LAST=$(last_tick "$CON"); S_NLAST=$(tf n "$S_LAST")
	notes="npre=$npre nlast=$S_NLAST capped=$capped"
	if [ $capped = no ] && [ $A_OK = yes ] && [ "$vma" = no ]; then S_CLASS=done
	elif [ $capped = yes ] && wait_tick "$CON" "${S_NLAST:-0}" 3 >/dev/null; then S_CLASS=notdone; notes="$notes still_running=yes"
	elif [ $capped = no ] && [ $A_OK = no ] && [ "$vma" = no ]; then S_CLASS=notdone; notes="$notes lost=yes"
	else S_CLASS=unknown; [ $capped = yes ] && notes="$notes hang=yes"
	fi
	if [ $ans != ok ] && [ $S_CLASS = done ]; then ERR_BUT_DONE=$((ERR_BUT_DONE + 1)); notes="$notes ERR_BUT_DONE"; fi
	if [ $ans = ok ] && [ $S_CLASS != done ]; then OK_BUT_NOTDONE=$((OK_BUT_NOTDONE + 1)); notes="$notes OK_BUT_NOTDONE"; fi
	row "$RUN,$1,$2,$ans,$arc,$(el "$ta" "$tb"),$(el "$tb" "$tc"),$(el "$ta" "$tc"),$prc,$S_CLASS,$A_CKP,$A_ALLOC,$A_META,$A_KERN,$A_KSHA,$A_MSHA,$vma,$notes"
	say "SUSPEND $1-$2: answer=$ans($arc) req->ans $(el "$ta" "$tb") s, ans->exit $(el "$tb" "$tc") s, proc_rc=$prc class=$S_CLASS ckp=$A_CKP (alloc ${A_ALLOC}K) meta=$A_META kern=$A_KERN vm_after=$vma $notes"
	[ $S_CLASS = done ] || { tail -5 "$OUT/bhyvectl-$1-$2.log" 2>/dev/null; }
}

# restore_one I [CKP] -> sets R_CLASS, R_GEN, R_KR (CKP given: same-snapshot mode, file kept)
restore_one() {
	F=${2:-$SD/s-$1.ckp}; R_GEN=-; R_KR=-
	check_no_vm "restore-$1"
	CON=$OUT/console-restore-$1.log; : >"$CON"
	tl0=$(now); lrc=-
	if [ "$BOOT" = bhyveload ]; then load_vm "$OUT/bhyveload-restore-$1.log"; lrc=$?; fi
	tr0=$(now)
	notes=; state_ok=-; prc=-
	if [ "$lrc" != - ] && [ "$lrc" != 0 ]; then
		vma=$(vm_present)
		R_CLASS=notdone; [ "$vma" = yes ] && R_CLASS=unknown
		notes="bhyveload_rc=$lrc"; tail -5 "$OUT/bhyveload-restore-$1.log"
		row "$RUN,restore,$1,-,-,$(el "$tl0" "$tr0"),-,-,-,$R_CLASS,-,-,-,-,-,-,$vma,$notes"
		say "RESTORE $1: bhyveload failed rc=$lrc class=$R_CLASS"
		R_STATE_OK=-; return
	fi
	# shellcheck disable=SC2086
	"$SBHYVE" -c $CPUS -m "$MEM" -r "$F" $DEV $EXTRA $ROPTS -l com1,stdio "$VM" </dev/null >"$CON" 2>"$OUT/bhyve-restore-$1.err" &
	BPID=$!
	TICK=$(wait_tick "$CON" "${S_NLAST:-0}" "$RESTORE_CAP"); wrc=$?
	tt=$(now); vma=$(vm_present)
	if [ $wrc = 0 ]; then
		R_CLASS=done
		d=$(( $(tf n "$TICK") - ${S_NLAST:-0} ))
		[ "$(tf tok "$TICK")" = "$TOK0" ] && tk=ok || tk=BAD
		[ "$(tf pid "$TICK")" = "$PID0" ] && pd=ok || pd=BAD
		[ "$d" -ge 1 ] && [ "$d" -le 2 ] && ct=ok || ct=BAD
		dk=$(tf disk "$TICK"); lg=$(tf log "$TICK")
		skew=$(( $(tf t "$TICK") - $(date +%s) ))
		host_net
		net=$(ping_guest)
		[ "$net" = FAIL ] && NET_RESTORE_FAIL=$((NET_RESTORE_FAIL + 1))
		state_ok=yes
		for x in "$tk" "$pd" "$ct" "$dk" "$lg"; do [ "$x" = ok ] || state_ok=NO; done
		notes="state_ok=$state_ok delta=$d tok=$tk pid=$pd counter=$ct disk=$dk log=$lg net=$net skew_s=$skew skew_vs_boot_s=$((skew - BOOT_SKEW))"
		# VM generation: judged on the NEXT tick (the ACPI notify is handled in a taskqueue); the devd
		# notification count (vg) may lag behind it, so where it gates (GEN_GATE) vgev takes the first of
		# up to 5 more ticks that shows it (vgev_ticks = how many it took)
		T2=$(wait_tick "$CON" "$(tf n "$TICK")" 5) || T2=
		g0=$(tf gen "$S_LAST"); v0=$(tf vg "$S_LAST")
		if [ -n "$T2" ] && [ -n "$(tf gen "$T2")" ]; then
			R_GEN=$(tf gen "$T2"); R_KR=$(tf kr "$TICK")
			[ "$R_GEN" != "$g0" ] && gc=chg || gc=same
			T3=$T2; vw=0
			vd=$(( $(tf vg "$T3") - ${v0:-0} ))
			while [ "$GEN_GATE" = yes ] && [ "$vd" -lt 1 ] && [ $vw -lt 5 ]; do
				T3=$(wait_tick "$CON" "$(tf n "$T3")" 3) || break
				vw=$((vw + 1)); vd=$(( $(tf vg "$T3") - ${v0:-0} ))
			done
			notes="$notes gen=$gc vgev=+$vd vgev_ticks=$vw kr=$R_KR"
			if [ "$GEN_GATE" = yes ] && { [ $gc != chg ] || [ "$vd" -lt 1 ]; }; then GEN_FAIL=$((GEN_FAIL + 1)); fi
		else
			notes="$notes gen=unobserved"
			[ "$GEN_GATE" = yes ] && GEN_FAIL=$((GEN_FAIL + 1))
		fi
		notes="$notes raw1=$(rawf "$TICK") raw2=$(rawf "$T2")"
	elif [ $wrc = 2 ]; then
		wait "$BPID"; prc=$?; BPID=; vma=$(vm_present)
		if [ "$vma" = no ]; then R_CLASS=notdone; else R_CLASS=unknown; notes="vm_left=yes"; fi
		tail -5 "$OUT/bhyve-restore-$1.err"
	else
		R_CLASS=unknown; notes="hang=yes (alive, no complete tick in $RESTORE_CAP s) last=$(rawf "$(last_tick "$CON")")"; CAPHITS=$((CAPHITS + 1))
		diag "restore-$1"
	fi
	# restore row: t_answer = bhyveload (VM recreate) time, t_settle = bhyve -r start -> first guest tick
	row "$RUN,restore,$1,-,-,$(el "$tl0" "$tr0"),$(el "$tr0" "$tt"),$(el "$tl0" "$tt"),$prc,$R_CLASS,-,-,-,-,-,-,$vma,$notes"
	say "RESTORE $1: bhyveload($BOOT) $(el "$tl0" "$tr0") s, bhyve -r start->first tick $(el "$tr0" "$tt") s, total $(el "$tl0" "$tt") s class=$R_CLASS $notes"
	if [ $R_CLASS = done ] && [ -z "${2:-}" ] && [ "${SR3_KEEP:-}" != yes ]; then rm -f "$F" "$F.meta" "$F.kern"; fi
	R_STATE_OK=$state_ok
}

# live_one J -- --checkpoint: VM must keep running; settle = artifacts complete (cap)
live_one() {
	F=$SD/l-$1.ckp
	pre=$(last_tick "$CON"); npre=$(tf n "$pre")
	ta=$(now)
	timeout "$SUSP_REQ_CAP" "$SBHYVECTL" --vm="$VM" --checkpoint="$F" >"$OUT/bhyvectl-l-$1.log" 2>&1; arc=$?
	tb=$(now)
	case $arc in 0) ans=ok ;; 124) ans=timeout ;; *) ans=err ;; esac
	_dl=$(deadline "$tb" "$LIVE_CAP"); capped=no
	while :; do artifacts "$F"; [ $A_OK = yes ] && break; alive || break; past "$_dl" "$(now)" && { capped=yes; break; }; sleep 0.02; done
	tc=$(now)
	[ $capped = yes ] && CAPHITS=$((CAPHITS + 1))
	tick=no; if alive && wait_tick "$CON" "${npre:-0}" 5 >/dev/null; then tick=yes; fi
	td=$(now)
	if alive && [ $tick = yes ] && [ $A_OK = yes ]; then L_CLASS=done
	elif alive && [ $tick = yes ]; then L_CLASS=notdone
	else L_CLASS=unknown; diag "live-$1"; fi
	if [ $ans != ok ] && [ $L_CLASS = done ]; then ERR_BUT_DONE=$((ERR_BUT_DONE + 1)); fi
	if [ $ans = ok ] && [ $L_CLASS != done ]; then OK_BUT_NOTDONE=$((OK_BUT_NOTDONE + 1)); fi
	row "$RUN,live,$1,$ans,$arc,$(el "$ta" "$tb"),$(el "$tb" "$tc"),$(el "$ta" "$tc"),-,$L_CLASS,$A_CKP,$A_ALLOC,$A_META,$A_KERN,$A_KSHA,$A_MSHA,$(vm_present),alive=$(alive && echo yes || echo no) ticking=$tick capped=$capped next_tick_after_s=$(el "$tc" "$td")"
	say "LIVE $1: answer=$ans req->ans $(el "$ta" "$tb") s, ans->artifacts $(el "$tb" "$tc") s class=$L_CLASS ckp=$A_CKP (alloc ${A_ALLOC}K) meta=$A_META kern=$A_KERN"
	# a live checkpoint is not restorable consistently later (the disk moved on); never kept
	rm -f "$F" "$F.meta" "$F.kern"
}

# ---------------- summary + gate (HARNESS SR3: any corruption or hang -> fallback is cold boot)
# report -- writes summary.txt ending in the GATE line; returns 3 on FAIL. Called once: at the end of the
# run, or by the EXIT trap when the run aborts (die, signal, shell error) with ABORTED set.
report() {
	REPORTED=yes
	{
		[ -z "$ABORTED" ] || echo "ABORTED ($ABORTED) before the run finished; counts below are what was recorded"
		echo "SR3 run $RUN  N=$N LIVE=$LIVE MEM=$MEM VM=$VM BOOT=$BOOT  ($(sed -n 1p "$SNAP/BUILDINFO"))"
		echo "bhyve=$SBHYVE restore_opts='$ROPTS' $(grep '^patches=' "$SNAP/BUILDINFO" || echo patches=none)"
		echo "vmm: $(cat "$VMM_LOADED" 2>/dev/null)"
		echo "classes (kind class count):"
		awk -F, 'NR>1 && $2!="boot" {c[$2" "$10]++} END {for (k in c) printf "  %-28s %d\n", k, c[k]}' "$CSV" | sort
		echo "  restores with state_ok=NO (corruption): $corrupt"
		echo "  answer=error but effect done: $ERR_BUT_DONE    answer=ok but effect not done: $OK_BUT_NOTDONE"
		echo "  VM found in /dev/vmm before boot/restore: $VM_FOUND_BEFORE    cap hits: $CAPHITS    recoveries (cold boots): $RECOVERIES"
		echo "timings, seconds (done outcomes only): p50 / p90 / max / n"
		for spec in "s:6:suspend req->answer" "s:7:suspend answer->exit" "s:8:suspend total" \
			"restore:6:restore bhyveload" "restore:7:restore start->first tick" "restore:8:restore total" \
			"live:6:live req->answer" "live:7:live answer->artifacts" "boot:8:cold boot->first tick"; do
			k=${spec%%:*}; r=${spec#*:}; c=${r%%:*}; lbl=${r#*:}
			awk -F, -v k="$k" -v c="$c" 'NR>1 && $2==k && $10=="done" {print $c}' "$CSV" | sort -n |
				awk -v l="$lbl" '{a[NR]=$1} END {if (NR==0) {printf "  %-28s n=0\n", l; exit}
					printf "  %-28s %.3f / %.3f / %.3f / %d\n", l, a[int((NR-1)*.5)+1], a[int((NR-1)*.9)+1], a[NR], NR}'
		done
		echo "artifact sizes (suspend, done): ckp bytes (RAM $MEMB) / ckp allocated KiB / meta / kern, min-max"
		awk -F, 'NR>1 && $2=="s" && $10=="done" {n++; if(!n1||$11<a1)a1=$11; if($11>b1)b1=$11; if(!n2||$12<a2)a2=$12; if($12>b2)b2=$12;
			if(!n3||$13<a3)a3=$13; if($13>b3)b3=$13; if(!n4||$14<a4)a4=$14; if($14>b4)b4=$14; n1=n2=n3=n4=1}
			END {printf "  ckp %s-%s  alloc %s-%s KiB  meta %s-%s  kern %s-%s  (n=%d)\n", a1,b1,a2,b2,a3,b3,a4,b4,n}' "$CSV"
		echo "restore checks (class: checks, count):"
		awk -F, '$2=="restore" {n=$18; sub(/ skew_s=.*/, "", n); sub(/ last=.*/, "", n); gsub(/ delta=[0-9-]*/, "", n); gsub(/net=ok\/[0-9.]*ms/, "net=ok", n);
			if (n == "") n = "(no checks: restore not done)"; c[$10": "n]++} END {for (k in c) printf "  %-90s %d\n", k, c[k]}' "$CSV" | sort
		sk=$(awk -F, '$2=="restore" {print $18}' "$CSV" | sed -n 's/.*skew_s=\([-0-9]*\).*/\1/p' | sort -n | awk 'NR==1{a=$1} {b=$1; n++} END {if (n) printf "min %s max %s (n=%d)", a, b, n}')
		echo "guest clock skew after restore, guest-host (s): ${sk:-(no done restores)}"
		echo "VM generation after restore (gen=chg|same vgev=+notifications): $(awk -F, '$2=="restore" {print $18}' "$CSV" | sed -n 's/.* \(gen=[a-z]*\)\( vgev=+[0-9-]*\)\{0,1\}.*/\1\2/p' | sort | uniq -c | tr '\n' ' ')"
		if [ "$SAME" = yes ]; then
			echo "same snapshot x$SAME_K: restores done $SAME_DONE; distinct gen $(echo $SAME_GENS | tr ' ' '\n' | sort -u | grep -c .), distinct kr $(echo $SAME_KRS | tr ' ' '\n' | sort -u | grep -c .); SIGTERM: $(awk -F, '$2=="same-stop" {print $18}' "$CSV" | sort | uniq -c | tr '\n' ' ')"
		else
			echo "SIGTERM to the guest the cycles ended with: final_pwr=$FINAL_PWR ($(awk -F, '$2=="final-stop" {print $18}' "$CSV"))"
		fi
		sv=$(awk -F, '$2=="restore" {print $18}' "$CSV" | sed -n 's/.*skew_vs_boot_s=\([-0-9]*\).*/\1/p' | awk 'NR==1{f=$1} {l=$1; n++} END {if (n) printf "first %s, last %s, over %d restores (%.2f s/restore)", f, l, n, (n>1)?(l-f)/(n-1):0}')
		echo "guest clock vs its cold-boot skew: ${sv:-(no done restores)}"
		echo "cold boots: $(awk -F, '$2=="boot" {print $18}' "$CSV" | sed 's/ skew_s=.*//; s/net=ok\/[0-9.]*ms/net=ok/' | sort | uniq -c | tr '\n' ' ')"
		echo "zfs: $(zfs get -H -o property,value compressratio,used "$SNAPDS" | tr '\n' ' ')"
		echo "csv: $CSV"
	} | tee "$OUT/summary.txt"
	# ---------------- gate (HARNESS SR3: any corruption or hang -> fallback is cold boot)
	cnt() { awk -F, -v k="$1" -v c="$2" 'NR>1 && $2==k && $10==c {n++} END {print n+0}' "$CSV"; }
	SD_DONE=$(cnt s done); RS_DONE=$(cnt restore done); LV_DONE=$(cnt live done)
	UNK=$(awk -F, 'NR>1 && ($2=="s" || $2=="restore" || $2=="live") && $10=="unknown" {n++} END {print n+0}' "$CSV")
	why=
	[ -z "$ABORTED" ] || why="$why aborted($ABORTED)"
	[ "$corrupt" -eq 0 ] || why="$why corruption=$corrupt"
	[ "$UNK" -eq 0 ] || why="$why unknown(hang)=$UNK"
	[ "$CAPHITS" -eq 0 ] || why="$why cap_hits=$CAPHITS"
	[ "$STOPPED_EARLY" = no ] || why="$why stopped_early"
	if [ "$SAME" = yes ]; then EXP_S=1; EXP_R=$SAME_K; else EXP_S=$N; EXP_R=$N; fi
	[ "$SD_DONE" -eq "$EXP_S" ] || why="$why suspend_done=$SD_DONE/$EXP_S"
	[ "$RS_DONE" -eq "$EXP_R" ] || why="$why restore_done=$RS_DONE/$EXP_R"
	if [ "$GEN_GATE" = yes ]; then
		[ "$GEN_FAIL" -eq 0 ] || why="$why vmgen_not_notified=$GEN_FAIL"
		if [ "$SAME" = yes ]; then
			dg=$(echo $SAME_GENS | tr ' ' '\n' | sort -u | grep -c .); dk=$(echo $SAME_KRS | tr ' ' '\n' | sort -u | grep -c .)
			[ "$dg" -eq "$SAME_DONE" ] || why="$why same_snap_gen_distinct=$dg/$SAME_DONE"
			[ "$dk" -eq "$SAME_DONE" ] || why="$why same_snap_kr_distinct=$dk/$SAME_DONE"
		fi
	fi
	if [ "$PWR_GATE" = yes ]; then
		if [ "$SAME" = yes ]; then
			po=$(awk -F, '$2=="same-stop" && $18=="pwr=off" {n++} END {print n+0}' "$CSV")
			[ "$po" -eq "$SAME_K" ] || why="$why same_snap_sigterm_off=$po/$SAME_K"
		elif [ "$N" -gt 0 ]; then
			[ "$FINAL_PWR" = off ] || why="$why final_sigterm=$FINAL_PWR"
		fi
	fi
	[ "$LV_DONE" -eq "$LIVE" ] || why="$why live_done=$LV_DONE/$LIVE"
	if [ "$NET_BOOT_OK" -gt 0 ]; then [ "$NET_RESTORE_FAIL" -eq 0 ] || why="$why net_fail_after_restore=$NET_RESTORE_FAIL"
	else say "WARNING: net never worked after a cold boot either (net check unusable; not counted against restore)"; fi
	if [ -z "$why" ]; then
		echo "GATE PASS: $EXP_R/$EXP_R restores ($EXP_S suspends) done with state intact, $LIVE/$LIVE live, 0 hangs, net ok, vmgen gate=$GEN_GATE, sigterm gate=$PWR_GATE final_pwr=$FINAL_PWR, same_snap=$SAME (BOOT=$BOOT VARIANT=${VARIANT:-none} RESTORE_OPTS='$ROPTS' LOAD=$LOAD VID=$VID)" | tee -a "$OUT/summary.txt"
	else
		echo "GATE FAIL:$why (BOOT=$BOOT VARIANT=${VARIANT:-none} RESTORE_OPTS='$ROPTS' LOAD=$LOAD VID=$VID)" | tee -a "$OUT/summary.txt"
		return 3
	fi
}

# ---------------- cleanup (always)
MD=; GM=; BPID=; TAP_CREATED=no; ANCHOR=no
cleanup() {
	set +e
	[ -n "${FLOOD:-}" ] && { kill "$FLOOD" 2>/dev/null; FLOOD=; }
	stop_vm cleanup
	[ -n "$GM" ] && mount | grep -q " $GM " && umount "$GM"
	[ -n "$MD" ] && mdconfig -d -u "$MD"
	[ "$ANCHOR" = yes ] && pfctl -a yard/sr3 -f /dev/null 2>/dev/null && say "pf anchor yard/sr3 emptied"
	[ "$TAP_CREATED" = yes ] && ifconfig "$TAP" destroy && say "destroyed $TAP"
	rm -f "/var/run/bhyve/$VM" /var/run/bhyve/sr3-vcon.sock
	if [ -d "$SD" ] && [ "${SR3_KEEP:-}" != yes ]; then rm -f "$SD"/*; rmdir "$SD"; fi
}
# on_exit -- an aborted run still gets its summary and GATE line (FAIL: aborted), then the cleanup
on_exit() {
	_rc=$?
	set +eu
	if [ "$REPORTED" = no ]; then
		ABORTED="rc=$_rc"
		say "run aborted (rc=$_rc); stopping the VM and writing the summary"
		stop_vm abort
		report
	fi
	cleanup
	exit "$_rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

# ---------------- datasets, image, network (idempotent)
if ! ds_exists "$SNAPDS"; then
	zfs create -o quota=40G -o exec=off -o setuid=off "$SNAPDS"
	echo "$SNAPDS" >>"$STATE/sr3-zfs-created"; say "created $SNAPDS"
fi
zfs get -H -o property,value encryption,encryptionroot,keystatus,compression "$SNAPDS" | tr '\n' ' '; echo
[ "$(zfs get -H -o value encryption "$SNAPDS")" != off ] || die "$SNAPDS is not encrypted"
mkdir -p "$SD"; chmod 0700 "$SNAPMNT" "$SD"
mkdir -p /var/run/bhyve

if ! zfs list -H -t snapshot "$VMDS@$PREP" >/dev/null 2>&1; then
	ds_exists "$VMDS" || { zfs create "$VMDS"; echo "$VMDS" >>"$STATE/sr3-zfs-created"; say "created $VMDS"; }
	# (an older @prepared stays; the image is rebuilt from the verified xz, never from it)
	[ -f "$XZ" ] || die "guest image $XZ missing"
	[ "$(sha256 -q "$XZ")" = "$XZ_SHA" ] || die "guest image checksum mismatch"
	t0=$(now); xz -dc "$XZ" >"$IMG.tmp"; mv "$IMG.tmp" "$IMG"; say "decompressed image in $(el "$t0" "$(now)") s"
	MD=$(mdconfig -a -t vnode -f "$IMG")
	PART=$(gpart show -p "$MD" | awk '$4=="freebsd-ufs"{print $3; exit}')
	[ -n "$PART" ] || die "no freebsd-ufs partition in $IMG"
	GM=$OUT/guestroot; mkdir -p "$GM"
	mount -o nosuid "/dev/$PART" "$GM"
	grep -q '^console="comconsole"' "$GM/boot/loader.conf" 2>/dev/null ||
		printf '%s\n' 'console="comconsole"' 'comconsole_speed="115200"' 'autoboot_delay="0"' >>"$GM/boot/loader.conf"
	grep -q '^# sr3 begin' "$GM/etc/rc.conf" 2>/dev/null || cat >>"$GM/etc/rc.conf" <<EOF
# sr3 begin
hostname="sr3"
ifconfig_vtnet0="inet $GUESTIP/30"
sendmail_enable="NONE"
sr3agent_enable="YES"
# sr3 end
EOF
	mkdir -p "$GM/usr/local/sbin" "$GM/usr/local/etc/rc.d"
	cat >"$GM/usr/local/sbin/sr3agent" <<'EOF'
#!/bin/sh
# sr3agent -- SR3 guest heartbeat on the serial console, once per second (see ops/sr3/sr3-30-cycles.sh).
PATH=/sbin:/bin:/usr/sbin:/usr/bin
tok=$(od -An -N8 -tx1 /dev/random | tr -d ' \n')
mkdir -p /var/sr3
touch /var/sr3/log
l0=$(wc -l </var/sr3/log | tr -d ' ')
n=0
while :; do
	n=$((n + 1))
	printf 'SR3BLK %d %s\n' "$n" "$tok" | dd of=/var/sr3/blk bs=4096 conv=sync 2>/dev/null
	fsync /var/sr3/blk
	rb=$(dd if=/var/sr3/blk bs=4096 count=1 iflag=direct 2>/dev/null | head -1)
	if [ "$rb" = "SR3BLK $n $tok" ]; then d=ok; else d=bad; fi
	echo "$n $tok" >>/var/sr3/log
	fsync /var/sr3/log
	l=$(wc -l </var/sr3/log | tr -d ' ')
	if [ "$l" -eq $((l0 + n)) ]; then lg=ok; else lg=bad; fi
	gen=$(sysctl -bn dev.vmgenc.0.guid 2>/dev/null | od -An -tx1 | tr -d ' \n'); [ -n "$gen" ] || gen=none
	kr=$(od -An -N8 -tx1 /dev/random | tr -d ' \n')
	vg=0; [ -f /var/sr3/vmgen.log ] && vg=$(wc -l </var/sr3/vmgen.log | tr -d ' ')
	printf 'SR3TICK n=%d pid=%d tok=%s t=%s disk=%s log=%s gen=%s kr=%s vg=%s\n' "$n" "$$" "$tok" "$(date +%s)" "$d" "$lg" "$gen" "$kr" "$vg" >/dev/console
	sleep 1
done
EOF
	cat >"$GM/usr/local/etc/rc.d/sr3agent" <<'EOF'
#!/bin/sh
# PROVIDE: sr3agent
# REQUIRE: LOGIN
# KEYWORD: nojail
. /etc/rc.subr
name=sr3agent
rcvar=sr3agent_enable
pidfile=/var/run/sr3agent.pid
command=/usr/sbin/daemon
command_args="-f -p ${pidfile} /usr/local/sbin/sr3agent"
load_rc_config $name
run_rc_command "$1"
EOF
	# every ACPI VM-generation notification (vmgenc(4) -> acpi_UserNotify -> devd) appends a line
	mkdir -p "$GM/usr/local/etc/devd"
	cat >"$GM/usr/local/etc/devd/sr3.conf" <<'EOF'
notify 100 {
	match "system"		"ACPI";
	match "subsystem"	"VMGenerationCounter";
	action "/usr/local/sbin/sr3vmgen";
};
EOF
	cat >"$GM/usr/local/sbin/sr3vmgen" <<'EOF'
#!/bin/sh
mkdir -p /var/sr3 && date +%s >>/var/sr3/vmgen.log && fsync /var/sr3/vmgen.log
EOF
	chmod 0555 "$GM/usr/local/sbin/sr3agent" "$GM/usr/local/etc/rc.d/sr3agent" "$GM/usr/local/sbin/sr3vmgen"
	umount "$GM"; GM=; mdconfig -d -u "$MD"; MD=
	zfs snapshot "$VMDS@$PREP"
	say "prepared $IMG and $VMDS@$PREP"
fi

if ! ifconfig "$TAP" >/dev/null 2>&1; then ifconfig "$TAP" create; TAP_CREATED=yes; say "created $TAP"; fi
host_net
if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
	echo "pass quick on $TAP inet proto icmp from $HOSTIP to $GUESTIP keep state" | pfctl -a yard/sr3 -f -
	ANCHOR=yes; say "pf enabled: anchor yard/sr3 passes ICMP $HOSTIP -> $GUESTIP on $TAP"
fi

# ---------------- cycles
set +e
cold_boot 0
TOK0=$(tf tok "$TICK"); PID0=$(tf pid "$TICK")
i=1
if [ "$SAME" = yes ]; then
	sleep "$DWELL"
	suspend_one s 1
	[ "$S_CLASS" = done ] || die "same-snapshot mode: the suspend was $S_CLASS"
	zfs snapshot "$VMDS@same"     # the disk as of the suspend; every restore starts from it
	k=1
	while [ $k -le "$SAME_K" ]; do
		zfs rollback -r "$VMDS@same"
		restore_one "same$k" "$SD/s-1.ckp"
		[ "${R_STATE_OK:-}" = NO ] && corrupt=$((corrupt + 1))
		if [ "$R_CLASS" = done ]; then SAME_DONE=$((SAME_DONE + 1)); SAME_GENS="$SAME_GENS $R_GEN"; SAME_KRS="$SAME_KRS $R_KR"; fi
		stop_vm "same$k"
		say "SAME $k: class=$R_CLASS gen=$R_GEN kr=$R_KR stop=$STOP_HOW (SIGTERM -> off = power button works)"
		row "$RUN,same-stop,$k,-,-,-,-,-,-,-,-,-,-,-,-,-,$(vm_present),pwr=$STOP_HOW"
		k=$((k + 1))
	done
	zfs destroy "$VMDS@same"
	N=0   # the regular cycles are replaced
fi
while [ $i -le "$N" ]; do
	sleep "$DWELL"
	suspend_one s "$i"
	if [ "$S_CLASS" = done ]; then
		restore_one "$i"
		[ "${R_STATE_OK:-}" = NO ] && corrupt=$((corrupt + 1))
		if [ "$R_CLASS" != done ] || [ "${R_STATE_OK:-}" = NO ]; then rec=yes; else rec=no; CHAIN=$((CHAIN + 1)); fi
	else
		rec=yes
	fi
	if [ $rec = yes ]; then
		RECOVERIES=$((RECOVERIES + 1))
		if [ $RECOVERIES -gt "$MAX_RECOVER" ]; then
			say "more than $MAX_RECOVER recoveries; stopping the cycles"; STOPPED_EARLY=yes
			stop_vm "recover-limit"; break
		fi
		say "recovering by cold boot ($RECOVERIES)"
		stop_vm "recover-$i"
		cold_boot "r$i"; TOK0=$(tf tok "$TICK"); PID0=$(tf pid "$TICK"); CHAIN=0
	fi
	i=$((i + 1))
done

# SIGTERM (ACPI power button -> SCI, level-triggered) to the guest the cycles ended with: it has been
# restored CHAIN times since its cold boot. A gate item for p3+ (patch 0003); the live phase cold boots.
if [ "$SAME" = no ] && [ "$N" -gt 0 ]; then
	if [ "$CHAIN" -gt 0 ] && alive; then
		stop_vm final-pwr; FINAL_PWR=$STOP_HOW
		say "FINAL SIGTERM after $CHAIN restores since the last cold boot: pwr=$FINAL_PWR (off = the guest powered off)"
		row "$RUN,final-stop,$CHAIN,-,-,-,-,-,-,-,-,-,-,-,-,-,$(vm_present),pwr=$FINAL_PWR"
	else
		say "FINAL SIGTERM check skipped: the cycles did not end on a restored, running guest"
	fi
fi

j=1
while [ $j -le "$LIVE" ]; do
	if ! alive || ! wait_tick "$CON" "$(tf n "$(last_tick "$CON")" | sed 's/^$/0/')" 3 >/dev/null; then
		stop_vm "live-precheck-$j"; cold_boot "live$j"; TOK0=$(tf tok "$TICK"); PID0=$(tf pid "$TICK")
	fi
	sleep "$DWELL"
	live_one "$j"
	j=$((j + 1))
done

if [ "${SR3_PROBE_VCON:-1}" = 1 ]; then
	stop_vm probe
	EXTRA="-s 4:0,virtio-console,port1=/var/run/bhyve/sr3-vcon.sock"
	cold_boot vcon
	sleep "$DWELL"
	suspend_one probe-vcon 1 20   # predicted not to exit: a short settle cap (the cap hit is expected)
	say "PROBE virtio-console: class=$S_CLASS (predicted notdone, VM still running); bhyve stderr:"
	tail -5 "$OUT/bhyve-boot-vcon.err"
	EXTRA=
fi
stop_vm end
report; exit $?
}
