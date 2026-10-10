#!/bin/sh
# sr3j-20-e2e.sh -- SR3J: bhyve runs unprivileged (one uid per VM, inside a jail), snapshot suspend/restore
#                   still works, and a host<->guest agent channel survives suspend/restore.
# PURPOSE   Root does setup only; every bhyveload/bhyve/bhyvectl and every channel client runs as the VM uid
#           2100000 inside jail sr3j_a (via sr3j-launch: jail_attach + setuid, nothing else inherited).
#   Setup   VM uid range 2100000-2109999 (A=2100000, B=2100001; gid = uid; never in /etc/passwd);
#           runtime devfs rulesets 2101 (jail A) / 2102 (jail B) -- kernel only, /etc/devfs.rules untouched;
#           jail A: allow.vmm, ip4.addr = host side of the VM link, devfs: null/zero/random/urandom/fd/std*,
#           vmmctl, vmm/sr3ja (+vmm.io/sr3ja.*), the VM's net device, nmdmsr3ja* -- owned by A, 0600.
#           (vmmctl is 0666 in jail A ONLY so uid B can attempt the ioctls there; production: A, 0600.)
#           jail B: allow.vmm + allow.socket_af (to probe netgraph privileges), devfs unhides vmm/*, tap*,
#           vmnet*, ngd*, nmdm* WITHOUT changing owners, so what B cannot see is hidden by the kernel.
#           Jail roots: read-only nullfs of /bin /lib /libexec /sbin /usr/{bin,lib,libexec,sbin,share},
#           /usr/local/yard/{bhyve-snap,sr3j}; /boot is a read-only tmpfs with copies of /boot/userboot*.so (bhyveload).
#           Disk: zfs clone of $BASEDS@agent-<sha> mounted at <jail>/vm (A, 0700; disk.img 0600).
#           Snapshots: $SNAPDS (encrypted, child of data/vmsnap) at <jail>/snap (A, 0700).
#           Guest: FreeBSD-15.1-RELEASE ufs image (the SR3 download), bhyveload, 2 vCPU, $SR3J_MEM,
#           com1 = console (stdio -> log), com2 = nmdmsr3jaA (UART channel), virtio-blk, virtio-net; bhyve -P
#           (every guest PAUSE is a VM exit to userland).
#           Guest agent: sr3j-chan agent on 10.78.94.2:7700 (TCP) and /dev/cuau1 (UART), SR3JTICK on console
#           (reopened after a write error: /etc/rc's exit revokes /dev/console), stderr in /var/log/sr3jagent.log.
#           Base snapshot @agent-<sr3j-chan sha12>-<rc script sha6>: a new binary or rc script re-bakes it.
#   Net     SR3J_NET (default vmnet):
#             tap    /dev/tap94: bhyve's open clears IFF_LINK0 (VMIO_SIOCSIFFLAGS), close purges the host
#                    address (tunclose) -> root must re-add it after every suspend (measured; the baseline).
#             vmnet  /dev/vmnet94: same driver, TUN_VMNET skips the purge -> address survives, no root step.
#             ngd    ng_eiface ngethN + ng_device /dev/ngdN on its ether hook (upstream bhyve "ngd" backend):
#                    bhyve opens a device node, no netgraph privilege, no patch; nodes outlive bhyve.
#             ngfd   ng_eiface ngethN + per-start ng_socket node made by sr3j-launch (root), data socket
#                    inherited as fd 3: patched bhyve `virtio-net,netgraph,datafd=3`.
#           pf anchor yard/sr3j-a on the host side: channel host->guest :7700 and ICMP pass, metadata
#           169.254.169.254/169.254.170.2:80 rdr to a fake broker on 10.78.94.1:8099, all else from the
#           guest blocked (egress, host sshd).
#   Steps   A boot (unprivileged), check uid/jail of bhyve, channel ping/exec over TCP and UART, pf checks,
#           throughput (TCP 256 MB each way, UART 64 KiB each way, then UART 16 KiB each way WITHOUT the
#           credit window as the positive control for the loss that stalled the first run), optionally the
#           UART capacity sweep (SR3J_UART_SWEEP=yes, section 2b), isolation probes (uid B in jail A and
#           in jail B), then SR3J_N suspend/restore cycles with three channel clients streaming
#           (r: TCP reconnect-on-silence, k: TCP keep-connection, u: UART), epoch bumped before each restore.
#   Classes (as SR3/SR0) suspend: done = bhyve exited, .ckp/.kern/.meta complete, VM gone; notdone = still
#           running or exited without artifacts; unknown = anything else. restore: done = new SR3JTICK within
#           the cap; harness = no tick but the TCP channel answers (guest alive: a tick defect, not a hang; the
#           cycles go on, the gate names it); notdone = bhyve exited, VM gone; unknown = alive, neither signal,
#           or VM left. Both signals are recorded per restore (restore i liveness).
#           Channel messages in flight at a suspend: done = delivered (agent's last_seq covers them, ACK
#           lost), notdone = not delivered (resent on the new connection), unknown = no reconnect in the cap.
#           Duplicates delivered to the agent must be 0 in every case.
# PREDICT   (2026-10-07, before any run; source reading in STATE.md SR3J)
#           unprivileged boot: done (75%; risks: a devfs rule detail, bhyveload's /boot in the jail);
#             bhyve uid 2100000 in jail sr3j_a; VSZ = guest RAM + 16..330 MB (guest RAM is mapped into bhyve;
#             2026-10-07 correction: run 202014Z had +54 MB, below the old fixed 1100 MB floor).
#           isolation, uid B in jail A: open /dev/vmm/sr3ja EACCES; VMMCTL_VM_DESTROY sr3ja EINVAL (cr_cansee,
#             see_other_uids=0); VMMCTL_VM_CREATE sr3ja EEXIST (name leak); sysctl hw.vmm.destroy EPERM;
#             kill bhyve ESRCH; control socket /var/run/bhyve/sr3ja EACCES; disk EACCES; nmdm B EACCES;
#             net device EACCES; netgraph control socket EPROTONOSUPPORT (jail socket_af). Needs ng_socket loaded
#             (now on every NET): without it every caller gets EAFNOSUPPORT before any jail or privilege check
#             (uipc_socket.c socreate; run 202014Z, vmnet, which had not loaded it).
#           uid B in jail B: /dev/vmm/sr3ja ENOENT (devfs prison check, despite unhide vmm/*); destroy EINVAL;
#             own VM sr3jb create+destroy OK (positive control); netgraph control socket EPERM
#             (PRIV_NETGRAPH_CONTROL); data socket to A's ng_socket node EADDRINUSE (ngfd); /dev/nmdmsr3jaB
#             ENOENT (tty created with A's cred); /dev/<net dev> EACCES (root 0600, host-made, devfs-only).
#           channel after boot: TCP ping < 5 ms, UART ping < 50 ms; TCP 150 MB/s down / 150 MB/s up (range
#             40-500); UART 40 KB/s down (10-150), 20 KB/s up (5-100): one VM exit per byte.
#           UART bulk (run 20261007T183613Z hung until timeout 300, no output): cause from source (sr3j-chan
#             main.go header): the emulated 16550 has no flow control; host->guest bytes past uart(4)'s
#             383-byte rx buffer are discarded in the guest (uart_dev_ns8250.c:1043-1071), guest->host bytes
#             are dropped when bhyve's non-blocking nmdm write fails (uart_backend.c:126-130, 224-228), and a
#             lost byte left a reader waiting for a frame that never completed. Since e228fdc the tty
#             transport runs a credit window (agent 320 B, host 1536 B) with fragmentation: the 64 KiB
#             each way completes, 0 bytes skipped after the HELLO on either side; the agent skips exactly
#             the client's 16-byte dial preamble before it (skipped_pre_hello 16). Positive control, -win 0 (old protocol), 16 KiB each way,
#             -deadline 20s: up loses bytes (agent acked < sent, or ok=false at the deadline; 85%), down
#             completes (70%: guest->host loss needs the nmdm swi task to fall 1920 B behind); the guest's
#             dev.uart.1.rx_overruns does not move (the software discard sets no LSR_OE).
#           UART sweep (SR3J_UART_SWEEP=yes; model from uart_emul.c/uart_backend.c and uart_dev_ns8250.c):
#             guest TX (down) per 16 bytes: LSR read + 16 THR writes + IER write, then the THRE interrupt:
#             IIR + IER + IIR = 21 inout exits, all to bhyve userland, each THR write one write(2) to the nmdm
#             -> 1.31 inout exits per wire byte; plus 2 per byte of the host's CREDITs (28 B per 768 B) ->
#             ~1.4 (1.2-1.8). Guest RX (up): DATA + LSR read per byte (uart_dev_ns8250.c:1058,1064) + ISR entry
#             (IIR, LSR, LSR, IIR) per FIFO run + 1.31 per byte of the guest's CREDITs (28 B per 160 B)
#             -> ~2.5 (2.1-3.5). All VM exits except PAUSE / inout 1.1-2 (HLT, external interrupts).
#             2026-10-07 corrections from run 202014Z's counters (sweep/*.st0/.st1): (a) with -P, PAUSE exits
#             are userland exits: the guest spin-waits on the ns8250 hwmtx, held across the 17 exits of each
#             transmit, and on adaptive mutexes; 2.6-3.2 per wire byte down, 0.6-3.2 up: the whole excess of
#             exits/B (4.2-4.8 down) and userspace/inout (2.8-3.2 down); userspace - inout - pause < 1%.
#             PAUSE exits are now reported (info) and the exit model is checked without them. (b) With
#             APICv virtual interrupt delivery the THRE interrupts are posted: interrupt-window exits 0
#             (predicted 0..1 when hw.vmm.vmx.cap.virtual_interrupt_delivery=1, else 20-150/KB down).
#             At ~7 us per userland exit round trip (vm_run return + handler + re-entry, N150): down ~80 KB/s
#             wire (25-250), up ~35 KB/s (10-120); flat in the chunk size: goodput = wire x chunk/(chunk +
#             20 x fragments), fragments of <= 748 B down / 140 B up (half the receiver's window), so chunk 64
#             gives 0.79 (down) / 0.88 (up) of chunk 1024's goodput and every chunk >= 1024 is within 2% of it.
#             bhyve CPU: ~1.8 cores down (1.0-2.2: one vCPU spins through UART exits, the other through
#             PAUSE exits waiting for it; was 0.6-1.6 without the PAUSE term, run 202014Z 1.74-1.91), ~1.3 up
#             (0.7-2.2: + the mevent thread re-armed per byte, uart_backend.c:153-155). vmm "vcpu total
#             runtime" 0.5-2.2 cores. Host client: down 0.1-0.8 core (bhyve writes each byte with its own
#             write(2), each wakes the reader: 1-4 bytes per read(2), client_bytes_per_read; was < 0.3,
#             run 202014Z 0.56-0.63), up < 0.3.
#             hw.broken_txfifo=1 in the guest (transmit drains LSR and schedules the swi itself, no THRE
#             interrupt; uart_dev_ns8250.c:1121-1131): 19 instead of 21 exits per 16 B (1.19/B) and one
#             interrupt less per 16 B: down x1.15 (1.0-1.5).
#             Message RTT, N=200 one at a time (UART: (size+20) B up at ~25 us/B + 20 B down + ~1 ms of
#             wakeups): 64 B p50 3.5 ms (1-15), 512 B 14 ms (4-60), 4 KiB 130 ms (40-500); TCP (virtio-net):
#             p50 0.1 ms (0.02-1) at every size.
#             Head-of-line under bulk (probe MSG every 100 ms): down, the ACK waits behind at most the host
#             window (1536 B) + one fragment (768 B) -> p50 ~20 ms (5-100), p99 ~35 ms (10-200); up, the
#             probe waits behind one 160 B fragment + the 320 B window -> p50 ~10 ms (3-60), p99 ~20 ms
#             (5-150); chunk 16384 vs 1024: same within x2 (fragmentation decouples HOL from chunk size).
#           suspend (1 GiB guest): done N/N, p50 0.4 s (0.2-0.9); .ckp = 1,073,741,824 B, written by uid A.
#           restore: done N/N (tick and channel), bhyveload ~0.13 s + start->first tick ~1.0 s (0.6-2).
#             Runs 183613Z/202014Z: unknown, no tick in 60 s although the TCP ping answered at 0.47 s:
#             the agent's console fd had been revoked at boot (tick n=1 only; fixed, see sr3j-chan ticker).
#           host address after suspend: tap gone (re-added by root), vmnet/ngd/ngfd kept.
#           ngfd: restore's NGM_CONNECT succeeds (the old socket node died with the old bhyve).
#           channel across suspend: r reconnects with the new epoch 0.2-1.5 s after the restore start
#             (prev_epoch = old); in-flight ~50 msgs at 100/s: mostly notdone (resent), 0-3 done; dups 0.
#             k: the same TCP connection resumes (same_conn) 0.5-4 s after restore (host RTO backoff), 0 lost.
#             u: reconnects 0.5-3 s after restore; in-flight mostly notdone; dups 0.
#           guest clock: stepped by -(suspended time) at each reconnect (-stepclock), skew after |x| < 0.1 s.
# CHANGES   (runtime; all removed on exit by sr3j_teardown) jails sr3j_a/sr3j_b, nullfs mounts, devfs rulesets
#           2101/2102, clone $DISKDS, $SNAPDS, VMs sr3ja/sr3jb, net device + ngeth/ngd nodes, pf anchor
#           yard/sr3j-a, fake broker process. (persistent, removed by undo) $VMDS (jail roots, base image +
#           snapshots), $SNAPPARENT if this script created it, kernel modules it loaded (nmdm, ng_socket on
#           every NET, ng_eiface/ng_device for ngd/ngfd), recorded in ops/state/sr3j-kld-loaded. Results: ops/logs/sr3j-20-<run>-<net>/.
# UNDO      sudo sh sr3j-20-e2e-undo.sh
# RUNTIME   first run + ~2 min (image decompress); then ~3-5 min for SR3J_N=5; SR3J_UART_SWEEP=yes adds ~5-15 min.
# KNOBS     SR3J_NET SR3J_N SR3J_MEM SR3J_DWELL SR3J_HOLD SR3J_KEEP SR3J_XZ SR3J_BULK_TCP SR3J_BULK_UART
#           SR3J_UART_SWEEP (yes: section 2b) SR3J_SWEEP_BYTES (per sweep point, default 262144; chunks < 1024
#           use a quarter) SR3J_SWEEP_CAP (s per point, default 180)
#           (sudo env SR3J_NET=ngfd SR3J_N=10 sh sr3j-20-e2e.sh; sudo env SR3J_UART_SWEEP=yes SR3J_N=1 sh sr3j-20-e2e.sh)
. "$(dirname "$0")/sr3j-lib.sh"
step_wrap sr3j-20-e2e "$0" "$@"

NET=${SR3J_NET:-vmnet}; N=${SR3J_N:-5}; MEM=${SR3J_MEM:-1024M}; CPUS=2
DWELL=${SR3J_DWELL:-3}; HOLD=${SR3J_HOLD:-2}
BULK_TCP=${SR3J_BULK_TCP:-268435456}; BULK_UART=${SR3J_BULK_UART:-65536}
SWEEP=${SR3J_UART_SWEEP:-no}; SWB=${SR3J_SWEEP_BYTES:-262144}; SWCAP=${SR3J_SWEEP_CAP:-180}
SUSP_EXIT_CAP=60; RESTORE_CAP=60; BOOT_CAP=180
XZ=${SR3J_XZ:-$OWNER_HOME/yard-p0/dl/FreeBSD-15.1-RELEASE-amd64-ufs.raw.xz}
XZ_SHA=a8e2c0f8331be615ef008c167069076833a417e968ff6b7d8e83b4ac762e9409
case $NET in
	tap|vmnet|ngd) BHYVE=$SNAP/bhyve; BHYVECTL=$SNAP/bhyvectl ;;
	ngfd) BHYVE=$INST/bhyve; BHYVECTL=$INST/bhyvectl ;;
	*) die "SR3J_NET must be tap, vmnet, ngd or ngfd" ;;
esac
[ "${SR3J_BHYVE:-}" = patched ] && { BHYVE=$INST/bhyve; BHYVECTL=$INST/bhyvectl; }
case $MEM in *M) MEMB=$(( ${MEM%M} * 1048576 )) ;; *G) MEMB=$(( ${MEM%G} * 1073741824 )) ;; *) die "SR3J_MEM must end in M or G" ;; esac
RUN=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$OPS/logs/sr3j-20-$RUN-$NET; CSV=$OUT/results.csv
TCPADDR=tcp:$GUESTIP:$CHAN_PORT; UARTADDR=tty:/dev/${NMDM}B

# ---------------- preconditions (no changes yet)
# vmm.ko: SR3's base snapshot module, or an SR3 variant module carrying patch 0004 (p4 or later; 0003/0004
# leave the ioctl ABI unchanged, so this spike's bhyve runs on it). With APICv virtual interrupt delivery
# the base module panics the host when a guest busy with interrupts is restored ("ISR and isrvec_stk out
# of sync", 2026-10-07 14:41:51, this script's first restore): the restore cycles below suspend a guest
# that is streaming on the channel, so they are refused on the base module unless APICv is off, N=0, or
# SR3J_UNSAFE_RESTORE=yes.
VMMKO=$(vmm_path); VID=$(sysctl -n hw.vmm.vmx.cap.virtual_interrupt_delivery 2>/dev/null || echo '?')
case $VMMKO in
	"$SNAP/vmm.ko") VMMFIX=no ;;
	"$SNAP"-p[4-9]/vmm.ko|"$SNAP"-p[1-9][0-9]/vmm.ko) VMMFIX=yes ;;
	*) die "loaded vmm is '$VMMKO', not $SNAP/vmm.ko or an SR3 p4+ variant (ops/sr3: sr3-20-vmm.sh)" ;;
esac
if [ $VMMFIX = no ] && [ "$VID" != 0 ] && [ "$N" -gt 0 ] && [ "${SR3J_UNSAFE_RESTORE:-}" != yes ]; then
	die "restores on $VMMKO with virtual_interrupt_delivery=$VID can panic the host (no patch 0004): load the SR3 p4 module (sudo env SR3_VARIANT=p4 sh ../sr3/sr3-20-vmm.sh), or SR3J_N=0 to skip the restore cycles"
fi
for f in bhyve bhyvectl sr3j-launch sr3j-probe sr3j-chan; do [ -x "$INST/$f" ] || die "$INST/$f missing: run sr3j-10-install.sh"; done
[ -x "$BHYVE" ] && [ -x "$BHYVECTL" ] || die "$BHYVE / $BHYVECTL missing"
[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"
ds_exists $YDS/vm || die "$YDS/vm missing (n0-10-zfs.sh)"
for j in $JA $JB; do [ -z "$(jid_of "$j")" ] || die "jail $j exists (leftover): run sr3j-20-e2e-undo.sh"; done
for v in $VM_A $VM_B; do [ ! -e "/dev/vmm/$v" ] || die "VM $v exists (leftover): run sr3j-20-e2e-undo.sh"; done
for u in $UA $UB; do
	pw usershow -u "$u" >/dev/null 2>&1 && die "uid $u is in /etc/passwd ($(pw usershow -u "$u" | cut -d: -f1)); VM uids must be unused"
	[ -z "$(pgrep -U "$u" 2>/dev/null)" ] || die "processes run as uid $u: $(pgrep -U "$u" | tr '\n' ' ')"
done
for rs in $RS_A $RS_B; do [ -z "$(devfs rule -s "$rs" show 2>/dev/null)" ] || die "devfs ruleset $rs is not empty (in use by something else?)"; done
for i in $TAP vmnet94; do ifconfig "$i" >/dev/null 2>&1 && die "interface $i exists (leftover?): run sr3j-20-e2e-undo.sh"; done
ds_exists "$DISKDS" && die "$DISKDS exists (leftover): run sr3j-20-e2e-undo.sh"
[ -s "$STATE/sr3j-net" ] && die "ops/state/sr3j-net lists network objects of an earlier run: run sr3j-20-e2e-undo.sh"
ds_exists "$SNAPDS" && die "$SNAPDS exists (leftover or SR3J_KEEP): run sr3j-20-e2e-undo.sh"
pg=$(sysctl -n hw.pagesize)
fr=$(( ( $(sysctl -n vm.stats.vm.v_free_count) + $(sysctl -n vm.stats.vm.v_inactive_count) ) * pg / 1048576 ))
[ "$fr" -ge $(( MEMB / 1048576 + 1024 )) ] || die "need $(( MEMB / 1048576 + 1024 )) MB free+inactive, have $fr"
command -v timeout >/dev/null || die "timeout(1) missing"
SOU=$(sysctl -n security.bsd.see_other_uids); SJP=$(sysctl -n security.bsd.see_jail_proc)

mkdir -p "$OUT"
say "run $RUN: NET=$NET N=$N MEM=$MEM bhyve=$BHYVE out=$OUT see_other_uids=$SOU see_jail_proc=$SJP vmm=$VMMKO vid=$VID"
sed 's/^/  BUILDINFO /' "$INST/BUILDINFO"

# ---------------- helpers
now() { date +%s.%N; }
el() { echo "$1 $2" | awk '{printf "%.3f", $2-$1}'; }
past() { echo "$1 $2" | awk '{exit !($2 >= $1)}'; }
deadline() { echo "$1 $2" | awk '{printf "%.3f", $1+$2}'; }
fsize() { if [ -e "$1" ]; then stat -f %z "$1"; else echo -1; fi; }
alive() { [ -n "${BPID:-}" ] && kill -0 "$BPID" 2>/dev/null; }
last_tick() { grep -a 'SR3JTICK' "$1" 2>/dev/null | tail -1 | tr -d '\r'; }
tf() { echo "$2" | sed -n "s/.*[ ]$1=\([^ ]*\).*/\1/p"; }
jf() { echo "$2" | sed -n "s/.*\"$1\":\"\{0,1\}\([^,\"}]*\).*/\1/p"; }   # jf KEY JSONLINE (flat JSON)
echo "kind,i,metric,actual,predicted,verdict,notes" >"$CSV"
MISMATCH=0
# rec KIND I METRIC ACTUAL PREDICTED [NOTES] -- verdict "ok" when ACTUAL matches PREDICTED (exact string,
# or "a..b" = numeric range, inclusive), "info" when PREDICTED is "-", else MISMATCH (counted; the run goes on)
rec() {
	_v=MISMATCH
	case $5 in
		*..*) if echo "$4 $5" | awk '{split($2, r, "[.][.]"); exit !($1 != "" && $1+0 >= r[1]+0 && $1+0 <= r[2]+0)}' 2>/dev/null; then _v=ok; fi ;;
		*) [ "$4" = "$5" ] && _v=ok ;;
	esac
	[ "$5" = "-" ] && _v=info
	[ $_v = MISMATCH ] && MISMATCH=$((MISMATCH + 1))
	echo "$1,$2,$3,$4,$5,$_v,${6:-}" >>"$CSV"
	say "$1 $2: $3 = $4 (predicted $5) $_v ${6:-}"
}
asA() { "$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / -- "$@"; }
asBA() { "$LAUNCH" -j "$JIDA" -u $UB -g $UB -d / -- "$@"; }
asBB() { "$LAUNCH" -j "$JIDB" -u $UB -g $UB -d / -- "$@"; }
probe() { # probe WHO(asBA|asBB|asA) OP ARG -> prints the result token
	_o=$($1 "$INST/sr3j-probe" "$2" "$3" 2>&1); _r=${_o##*-> }; echo "${_r%% *}"
}
gexec() { asA "$INST/sr3j-chan" client exec -addr "$TCPADDR" -stream x -wait 10s -- "$@"; }
tchan() { _t=$1; shift; timeout "$_t" "$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / -- "$INST/sr3j-chan" client "$@"; }   # tchan SECS CLIENT-ARGS
nocomma() { echo "$*" | tr ',' ';'; }
# vmstats FILE -- VM A's vmm counters (bhyvectl --get-stats, as uid A) summed over its vCPUs: "desc<TAB>value"
vmstats() {
	_v=0
	while [ $_v -lt $CPUS ]; do asA "$BHYVECTL" --vm=$VM_A --cpu=$_v --get-stats 2>/dev/null; _v=$((_v + 1)); done |
		awk -F'\t' 'NF == 2 && $2 ~ /^[0-9]+$/ {sub(/ +$/, "", $1); s[$1] += $2} END {for (k in s) print k "\t" s[k]}' >"$1"
}
sd() { awk -F'\t' -v k="$3" 'FNR == NR {if ($1 == k) b = $2; next} $1 == k {a = $2} END {printf "%.0f", a - b}' "$1" "$2"; }   # sd BEFORE AFTER DESC
# bcpu -> "all-threads-s vcpu-threads-s" CPU time of bhyve (ps -H: one line per thread, M:SS.ss)
bcpu() { ps -H -o time= -o tdname= -p "$BPID" 2>/dev/null | awk '{n = split($1, p, ":"); t = 0; for (i = 1; i <= n; i++) t = t * 60 + p[i]; s += t; if ($0 ~ /vcpu/) v += t} END {printf "%.2f %.2f", s, v}'; }

# ---------------- cleanup (always)
BPID=; CLIENTS=; BROKER_PGID=; JIDA=; JIDB=
cleanup() {
	set +e
	for p in $CLIENTS; do kill -TERM "$p" 2>/dev/null; done
	alive && kill -TERM "$BPID" 2>/dev/null
	sleep 1
	[ -n "$JIDA" ] && cp -p "$ROOT_A"/tmp/chan/*.log "$OUT"/ 2>/dev/null
	sr3j_teardown
	chown -R "$OWNER" "$OUT" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# ---------------- kernel modules (recorded for undo)
kld() { kldstat -q -m "$2" || kldstat -q -n "$1" || { kldload "$1" && echo "$1" >>"$STATE/sr3j-kld-loaded" && say "loaded $1"; }; }
kld nmdm nmdm
# ng_socket on every NET: without it PF_NETGRAPH is no registered domain and socket(2) fails EAFNOSUPPORT
# before the jail (prison_check_af -> EPROTONOSUPPORT) or privilege (EPERM) check is reached
# (sys/kern/uipc_socket.c socreate; vmnet run 20261007T202014Z: all three ngctl probes EAFNOSUPPORT), so the
# isolation probes need it loaded to test anything.
kld ng_socket ng_socket
case $NET in ngd|ngfd) kld ng_eiface ng_eiface; [ $NET = ngd ] && kld ng_device ng_device ;; esac
NGS=$(kldstat -q -m ng_socket && echo yes || echo no)

# ---------------- base image with the agent (persistent, idempotent)
# The guest's rc script for the agent. daemon -o: the agent's stderr (console tick errors) goes to
# /var/log/sr3jagent.log in the guest (read it with `client exec`).
RCAGENT=$(cat <<EOF
#!/bin/sh
# PROVIDE: sr3jagent
# REQUIRE: NETWORKING
# KEYWORD: nojail
. /etc/rc.subr
name=sr3jagent
rcvar=sr3jagent_enable
pidfile=/var/run/sr3jagent.pid
command=/usr/sbin/daemon
command_args="-f -r -o /var/log/sr3jagent.log -P \${pidfile} /usr/local/sbin/sr3j-chan agent -tcp $GUESTIP:$CHAN_PORT -tty /dev/cuau1 -console /dev/console -stepclock"
load_rc_config \$name
run_rc_command "\$1"
EOF
)
# snapshot name: the agent binary's sha (12) + the rc script's (6): a change to either re-bakes
AG=agent-$(sha256 -q "$INST/sr3j-chan" | cut -c1-12)-$(printf '%s\n' "$RCAGENT" | sha256 -q | cut -c1-6)
if ! ds_exists "$VMDS"; then zfs create -o mountpoint="$VMMNT" "$VMDS"; echo "$VMDS" >>"$STATE/sr3j-zfs-created"; say "created $VMDS"; fi
if ! zfs list -H -t snapshot "$BASEDS@raw" >/dev/null 2>&1; then
	ds_exists "$BASEDS" || zfs create "$BASEDS"
	[ -f "$XZ" ] || die "guest image $XZ missing"
	[ "$(sha256 -q "$XZ")" = "$XZ_SHA" ] || die "guest image checksum mismatch"
	t0=$(now); xz -dc "$XZ" >"$VMMNT/base/disk.img.tmp"; mv "$VMMNT/base/disk.img.tmp" "$VMMNT/base/disk.img"
	zfs snapshot "$BASEDS@raw"; say "decompressed the guest image in $(el "$t0" "$(now)") s; $BASEDS@raw"
fi
if ! zfs list -H -t snapshot "$BASEDS@$AG" >/dev/null 2>&1; then
	cl=$(zfs list -H -o name,origin -t filesystem -r "$VMDS" | awk -v b="$BASEDS@" 'index($2, b) == 1 {print $1}')
	[ -z "$cl" ] && zfs rollback -r "$BASEDS@raw" || die "clones of $BASEDS exist ($cl): run sr3j-20-e2e-undo.sh"
	MD=$(mdconfig -a -t vnode -f "$VMMNT/base/disk.img")
	PART=$(gpart show -p "$MD" | awk '$4=="freebsd-ufs"{print $3; exit}')
	GM=$OUT/guestroot; mkdir -p "$GM"
	[ -n "$PART" ] && mount -o nosuid "/dev/$PART" "$GM" || { mdconfig -d -u "$MD"; die "cannot mount the guest root"; }
	printf '%s\n' 'console="comconsole"' 'comconsole_speed="115200"' 'autoboot_delay="0"' >>"$GM/boot/loader.conf"
	cat >>"$GM/etc/rc.conf" <<EOF
# sr3j begin
hostname="sr3j"
ifconfig_vtnet0="inet $GUESTIP/$NETPFX"
defaultrouter="$HOSTIP"
sendmail_enable="NONE"
sr3jagent_enable="YES"
# sr3j end
EOF
	install -m 0555 "$INST/sr3j-chan" "$GM/usr/local/sbin/sr3j-chan"
	mkdir -p "$GM/usr/local/etc/rc.d"
	printf '%s\n' "$RCAGENT" >"$GM/usr/local/etc/rc.d/sr3jagent"
	chmod 0555 "$GM/usr/local/etc/rc.d/sr3jagent"
	umount "$GM"; mdconfig -d -u "$MD"; rmdir "$GM"
	zfs snapshot "$BASEDS@$AG"; say "prepared $BASEDS@$AG"
fi

# ---------------- network for VM A (host side)
case $NET in
	tap|vmnet)
		IFNAME=$TAP; [ $NET = vmnet ] && IFNAME=vmnet94
		ifconfig "$IFNAME" create >/dev/null; echo "tap:$IFNAME" >>"$STATE/sr3j-net"
		ifconfig "$IFNAME" inet "$HOSTIP/$NETPFX" up
		NETDEV=$IFNAME; NETARG=$IFNAME ;;
	ngd|ngfd)
		before=" $(ifconfig -l) "
		ngctl mkpeer . eiface sr3jtmp ether
		IFNAME=$(for i in $(ifconfig -l); do case $before in *" $i "*) ;; *) echo "$i" ;; esac; done | grep '^ngeth' | head -1)
		[ -n "$IFNAME" ] || die "no new ngeth interface after mkpeer eiface"
		echo "ngeth:$IFNAME" >>"$STATE/sr3j-net"
		ifconfig "$IFNAME" inet "$HOSTIP/$NETPFX" up
		if [ $NET = ngd ]; then
			dbefore=" $(ls /dev | grep '^ngd' | tr '\n' ' ') "
			ngctl mkpeer "$IFNAME:" device ether ether
			NETDEV=$(ls /dev | grep '^ngd' | while read -r d; do case $dbefore in *" $d "*) ;; *) echo "$d" ;; esac; done | head -1)
			[ -n "$NETDEV" ] || die "no new /dev/ngd* after mkpeer device"
			echo "ngd:$NETDEV" >>"$STATE/sr3j-net"; NETARG=$NETDEV
		else
			NETDEV=; NETARG="netgraph,datafd=3"
		fi ;;
esac
say "host side: $IFNAME $HOSTIP/$NETPFX (device ${NETDEV:-none: fd from sr3j-launch}); bhyve net arg $NETARG"

# pf anchor + fake broker
PF=no
if pf_on; then
	pfctl -a "$ANCHOR" -f - <<EOF
rdr pass on $IFNAME inet proto tcp from $GUESTIP to { 169.254.169.254, 169.254.170.2 } port 80 -> $HOSTIP port $BROKER_PORT
pass out quick on $IFNAME inet proto tcp from $HOSTIP to $GUESTIP port $CHAN_PORT keep state
pass out quick on $IFNAME inet proto icmp from $HOSTIP to $GUESTIP keep state
block drop in log quick on $IFNAME all
EOF
	PF=yes; say "pf anchor $ANCHOR loaded:"; pfctl -a "$ANCHOR" -s nat 2>/dev/null; pfctl -a "$ANCHOR" -s rules 2>/dev/null
	set -m
	( while :; do printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nyard-fake-broker\n' | nc -N -l "$HOSTIP" "$BROKER_PORT" >>"$OUT/broker.txt" 2>&1 || break; done ) </dev/null >/dev/null 2>&1 &
	BROKER_PGID=$!; set +m; echo "$BROKER_PGID" >"$STATE/sr3j-broker.pid"
else
	say "WARNING: pf not enabled: the channel is unfiltered and the pf checks are skipped"
fi

# ---------------- jail roots
mkroot() { # mkroot ROOT
	for d in bin lib libexec sbin usr/bin usr/lib usr/libexec usr/sbin usr/share usr/local/yard/bhyve-snap usr/local/yard/sr3j boot etc dev tmp var/run run; do
		mkdir -p "$1/$d"
	done
	chmod 1777 "$1/tmp"
	for d in /bin /lib /libexec /sbin /usr/bin /usr/lib /usr/libexec /usr/sbin /usr/share "$SNAP" "$INST"; do
		mount_nullfs -o ro "$d" "$1$d"
	done
	# bhyveload fdlopen()s /boot/userboot.so, which needs an exec mapping: the jail root's dataset is
	# exec=off (2026-10-07: "mmap of data failed: Permission denied"), so /boot is a small tmpfs holding
	# copies of the userboot modules, remounted read-only.
	mount -t tmpfs -o size=8m,mode=0755 tmpfs "$1/boot"
	cp -P /boot/userboot*.so "$1/boot/"
	mount -u -o ro "$1/boot"
}
mkroot "$ROOT_A"; mkroot "$ROOT_B"
zfs clone -o mountpoint="$ROOT_A/vm" "$BASEDS@$AG" "$DISKDS"
chown $UA:$UA "$ROOT_A/vm" "$ROOT_A/vm/disk.img"; chmod 0700 "$ROOT_A/vm"; chmod 0600 "$ROOT_A/vm/disk.img"
if ! ds_exists "$SNAPPARENT"; then
	zfs create -o quota=40G -o exec=off -o setuid=off "$SNAPPARENT"; echo "$SNAPPARENT" >>"$STATE/sr3j-zfs-created"; say "created $SNAPPARENT"
fi
[ "$(zfs get -H -o value encryption "$SNAPPARENT")" != off ] || die "$SNAPPARENT is not encrypted"
zfs create -o mountpoint="$ROOT_A/snap" -o quota=10G -o exec=off -o setuid=off "$SNAPDS"
chown $UA:$UA "$ROOT_A/snap"; chmod 0700 "$ROOT_A/snap"
mkdir -p "$ROOT_A/var/run/bhyve" "$ROOT_A/tmp/chan"
chown $UA:$UA "$ROOT_A/var/run/bhyve" "$ROOT_A/tmp/chan"; chmod 0700 "$ROOT_A/var/run/bhyve"; chmod 0755 "$ROOT_A/tmp/chan"
echo 1 >"$ROOT_A/run/epoch"; chmod 0644 "$ROOT_A/run/epoch"

# ---------------- devfs rulesets (kernel only)
dr() { devfs rule -s "$@"; }
for rs in $RS_A $RS_B; do
	dr "$rs" add hide
	for p in null zero random urandom fd 'fd/*' stdin stdout stderr; do dr "$rs" add path "$p" unhide; done
	dr "$rs" add path vmm unhide
	dr "$rs" add path vmm.io unhide
done
dr $RS_A add path vmmctl unhide mode 0666
dr $RS_A add path "vmm/$VM_A" unhide user $UA group $UA mode 0600
dr $RS_A add path "vmm.io/$VM_A.*" unhide user $UA group $UA mode 0600
dr $RS_A add path "${NMDM}*" unhide user $UA group $UA mode 0600
[ -n "$NETDEV" ] && dr $RS_A add path "$NETDEV" unhide user $UA group $UA mode 0600
dr $RS_B add path vmmctl unhide user $UB group $UB mode 0600
for p in 'vmm/*' 'vmm.io/*' 'tap*' 'vmnet*' 'ngd*' 'nmdm*'; do dr $RS_B add path "$p" unhide; done
dr $RS_B add path "vmm/$VM_B" unhide user $UB group $UB mode 0600
devfs rule -s $RS_A show | sed 's/^/  rs A: /'

# ---------------- jails
jail -c name=$JA path="$ROOT_A" host.hostname=$JA ip4.addr=$HOSTIP allow.vmm=1 mount.devfs devfs_ruleset=$RS_A \
	persist children.max=0 enforce_statfs=2 >/dev/null
jail -c name=$JB path="$ROOT_B" host.hostname=$JB ip4=disable allow.vmm=1 allow.socket_af=1 mount.devfs devfs_ruleset=$RS_B \
	persist children.max=0 enforce_statfs=2 >/dev/null
JIDA=$(jid_of $JA); JIDB=$(jid_of $JB)
say "jails: $JA jid $JIDA, $JB jid $JIDB; /dev in A: $(ls "$ROOT_A/dev" | tr '\n' ' ')"

# ---------------- boot / restore primitives (everything below runs as uid A in jail A)
DEV="-u -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,/vm/disk.img -s 3:0,virtio-net,$NETARG"
load_vm() { asA bhyveload -m "$MEM" -d /vm/disk.img -e autoboot_delay=0 -e console=comconsole $VM_A </dev/null >"$1" 2>&1; }
start_bhyve() { # start_bhyve LABEL [CKP]
	CON=$OUT/console-$1.log; : >"$CON"
	_ng=; [ $NET = ngfd ] && _ng="-n $IFNAME: -I $OUT/ngnode-$1.txt"
	# shellcheck disable=SC2086
	"$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / $_ng -- "$BHYVE" -c $CPUS -m "$MEM" $DEV ${2:+-r $2} \
		-l com1,stdio -l "com2,/dev/${NMDM}A" $VM_A </dev/null >"$CON" 2>"$OUT/bhyve-$1.err" &
	BPID=$!
}
wait_tick() { # wait_tick NMIN CAP -> first tick line with n > NMIN; rc 1 cap, 2 bhyve died
	_dl=$(deadline "$(now)" "$2")
	while :; do
		_l=$(last_tick "$CON")
		if [ -n "$_l" ]; then _n=$(tf n "$_l"); [ -n "$_n" ] && [ "$_n" -gt "$1" ] && { echo "$_l"; return 0; }; fi
		alive || return 2
		past "$_dl" "$(now)" && return 1
		sleep 0.05
	done
}
hostaddr() { ifconfig "$IFNAME" 2>/dev/null | grep -q "inet $HOSTIP " && echo kept || echo gone; }
# wait_alive NMIN CAP PINGPID PINGFILE -- after a restore start, wait for both liveness signals: a console
# tick with n > NMIN, and the TCP ping client (started before bhyve) exiting with ok=true. Once the channel
# has answered, the tick gets TICK_GRACE s more (it is once a second). Sets WT (tick line or empty), WTS (s
# to the tick or -), WCH (ok|fail|pending), WCS (s to the ping's exit or -); rc 2 if bhyve died.
TICK_GRACE=10
wait_alive() {
	_t0=$(now); _dl=$(deadline "$_t0" "$2"); WT=; WTS=-; WCH=pending; WCS=-; _gdl=
	while :; do
		if [ -z "$WT" ]; then
			_l=$(last_tick "$CON")
			if [ -n "$_l" ]; then _n=$(tf n "$_l"); [ -n "$_n" ] && [ "$_n" -gt "$1" ] && { WT=$_l; WTS=$(el "$_t0" "$(now)"); }; fi
		fi
		if [ $WCH = pending ] && ! kill -0 "$3" 2>/dev/null; then
			WCS=$(el "$_t0" "$(now)")
			[ "$(jf ok "$(cat "$4" 2>/dev/null)")" = true ] && WCH=ok || WCH=fail
			_gdl=$(deadline "$(now)" $TICK_GRACE)
		fi
		[ -n "$WT" ] && [ $WCH != pending ] && return 0
		alive || return 2
		past "$_dl" "$(now)" && return 1
		[ -n "$WT" ] || [ -z "$_gdl" ] || ! past "$_gdl" "$(now)" || return 1
		sleep 0.05
	done
}

set +e
# ================= 0. exec smoke: can the VM uid exec anything in jail A? (2026-10-07 runs: the launcher
# died with SIGSEGV still named sr3j-launch, i.e. execve failed in the kernel after the old image was gone.)
# On failure, trace one attempt from root's side (trace file outside the jail) and check exec as root in the jail.
_s=$(asA /bin/echo exec-ok 2>&1); _src=$?
rec boot 0 exec_smoke_rc "$_src" 0 "$(echo "$_s" | tail -1 | tr ',' ' ')"
if [ $_src != 0 ]; then
	ktrace -i -t cinsuw -f "$OUT/ktrace-smoke.out" "$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / -- /bin/echo exec-ok >/dev/null 2>&1
	kdump -f "$OUT/ktrace-smoke.out" >"$OUT/kdump-smoke.txt" 2>&1
	say "kdump of the failing exec (tail; full: $OUT/kdump-smoke.txt):"; tail -40 "$OUT/kdump-smoke.txt"
	rec boot 0 exec_smoke_root "$(jexec "$JIDA" /bin/echo exec-ok 2>&1 | tail -1)" exec-ok "root in jail A (jexec)"
	rec boot 0 exec_smoke_uid_host "$(su -m nobody -c '/bin/echo exec-ok' 2>&1 | tail -1)" exec-ok "an unprivileged uid on the host, no jail"
	for f in /libexec/ld-elf.so.1 /bin/echo /usr/sbin/bhyveload; do say "jail A view: $(ls -l "$ROOT_A$f" 2>&1)"; done
	say "mounts under jail A: $(mount -p | awk -v r="$ROOT_A" 'index($2, r) == 1 {print $2 "(" $3 "," $4 ")"}' | tr '\n' ' ')"
	die "exec as uid $UA in jail A fails (rc $_src); see kdump-smoke.txt"
fi

# ================= 1. unprivileged boot
t0=$(now)
load_vm "$OUT/bhyveload-boot.log"; lrc=$?
rec boot 0 bhyveload_rc "$lrc" 0 "$(tail -1 "$OUT/bhyveload-boot.log" | tr ',' ' ')"
[ $lrc = 0 ] || { cat "$OUT/bhyveload-boot.log"; die "bhyveload as uid $UA failed"; }
rec boot 0 vmm_node "$(stat -f '%u:%g %Lp' "$ROOT_A/dev/vmm/$VM_A" 2>&1)" "$UA:$UA 600" "jail A's devfs view (owner set by ruleset $RS_A; numeric: the VM uids have no passwd entry)"
rec boot 0 vmm_node_host "$(stat -f '%u:%g %Lp' "/dev/vmm/$VM_A" 2>&1)" "0:0 600" "host devfs view"
start_bhyve boot
while ! grep -aq 'login:' "$CON"; do
	alive || { cat "$OUT/bhyve-boot.err"; tail -20 "$CON"; die "bhyve (uid $UA, jail $JA) exited during boot"; }
	past "$(deadline "$t0" $BOOT_CAP)" "$(now)" && { tail -20 "$CON"; die "no login: after $BOOT_CAP s"; }
	sleep 0.1
done
TICK=$(wait_tick 0 60) || { tail -20 "$CON"; die "agent never ticked"; }
rec boot 0 boot_to_first_tick_s "$(el "$t0" "$(now)")" - "includes firstboot"
rec boot 0 bhyve_uid_jid "$(ps -o uid= -o jid= -p "$BPID" | awk '{print $1":"$2}')" "$UA:$JIDA"
# VSZ = the guest RAM mapping + bhyve's own text/libs/heap/stacks (run 202014Z: 1078 MB at 1024M = +54 MB;
# the old fixed 1100..1350 assumed a 76+ MB overhead)
rec boot 0 bhyve_vsz_mb "$(ps -o vsz= -p "$BPID" | awk '{printf "%d", $1/1024}')" "$((MEMB / 1048576 + 16))..$((MEMB / 1048576 + 330))" "guest RAM $MEM + bhyve itself"
[ $NET = tap ] && rec boot 0 hostaddr_after_bhyve_open "$(hostaddr)" kept "tunopen keeps addresses; only close purges"
TOK0=$(tf tok "$TICK"); PID0=$(tf pid "$TICK")
rec boot 0 ps_as_A_sees_bhyve "$(asA ps -ax -o pid= 2>/dev/null | grep -c "^ *$BPID\$")" 1

# ================= 2. channel after boot
P=$(asA "$INST/sr3j-chan" client ping -addr "$TCPADDR" -stream p -wait 20s)
rec chan 0 tcp_ping_ok "$(jf ok "$P")" true "$P"
rec chan 0 tcp_ping_ms "$(jf elapsed_s "$P" | awk '{printf "%.2f", $1*1000}')" "0..5"
P=$(asA "$INST/sr3j-chan" client ping -addr "$UARTADDR" -stream pu -wait 20s)
rec chan 0 uart_ping_ok "$(jf ok "$P")" true "$P"
rec chan 0 uart_ping_ms "$(jf elapsed_s "$P" | awk '{printf "%.2f", $1*1000}')" "0..50"
rec chan 0 guest_uname "$(gexec uname -sr | tr -d '\n')" "FreeBSD 15.1-RELEASE"
rec chan 0 guest_has_cuau1 "$(gexec ls /dev/cuau1 | tr -d '\n')" /dev/cuau1
B=$(timeout 180 "$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / -- "$INST/sr3j-chan" client bulk -addr "$TCPADDR" -stream b -down "$BULK_TCP" -up "$BULK_TCP")
rec chan 0 tcp_down_MBps "$(jf down_MBps "$B" | awk '{printf "%.1f", $1}')" "40..500" "$BULK_TCP B"
rec chan 0 tcp_up_MBps "$(jf up_MBps "$B" | awk '{printf "%.1f", $1}')" "40..500" "$BULK_TCP B"
# UART bulk. The first run (20261007T183613Z) hung here until timeout 300 with no output: bytes lost without
# flow control (header PREDICT). Since e228fdc the tty transport runs a credit window, and the client's own
# -deadline prints partial progress (ok=false, bytes moved, resync counts) before timeout(1) would kill it.
B=$(tchan 300 bulk -addr "$UARTADDR" -stream bu -chunk 1024 -down "$BULK_UART" -up "$BULK_UART" -deadline 240s); brc=$?
echo "$B" >"$OUT/uart-bulk.json"
rec chan 0 uart_bulk_ok "$(jf ok "$B")" true "rc=$brc $(nocomma "$(jf err "$B")") (uart-bulk.json)"
rec chan 0 uart_down_bytes "$(jf down_bytes "$B")" "$BULK_UART" "frames $(jf down_frames "$B")"
rec chan 0 uart_up_acked "$(jf up_bytes_acked "$B")" "$BULK_UART" "sent $(jf up_bytes_sent "$B"); agent frames $(jf up_agent_frames "$B")"
rec chan 0 uart_down_KBps "$(jf down_MBps "$B" | awk '{printf "%.1f", $1*1000}')" "10..150" "$BULK_UART B"
rec chan 0 uart_up_KBps "$(jf up_MBps "$B" | awk '{printf "%.1f", $1*1000}')" "5..100" "$BULK_UART B"
rec chan 0 uart_skipped_host_agent "$(jf skipped "$B")/$(jf up_agent_skipped "$B")" 0/0 "resync bytes (lost/corrupt frames) in this session; credit waits host $(jf credit_waits "$B") agent $(jf up_agent_credit_waits "$B")"
rec chan 0 uart_agent_skipped_pre_hello "$(jf up_agent_skipped_pre_hello "$B")" 16 "the dial preamble; agent tty lifetime total $(jf up_agent_skipped_total "$B")"
# Positive control for the stall cause: the old protocol (-win 0: no credit window, no fragments) on a short
# transfer with a 20 s deadline. Guest uart facts alongside (FIFO size found by the probe, the tunables).
rec chan 0 guest_uart1 "$(gexec grep -m1 '^uart1:' /var/run/dmesg.boot | sed -n 's/.*<\(.*\)>.*/\1/p')" "16550 or compatible" "FIFO probe: 16 (bhyve FIFOSZ, uart_backend.c:62)"
rec chan 0 guest_uart_tunables "$(gexec sysctl -n hw.broken_txfifo hw.uart_noise_threshold | tr '\n' '/')" "0/0/" "hw.broken_txfifo/hw.uart_noise_threshold"
ov0=$(gexec sysctl -n dev.uart.1.rx_overruns | tr -d '\n')
B=$(tchan 60 bulk -addr "$UARTADDR" -stream b0 -win 0 -chunk 1024 -down 16384 -up 16384 -deadline 20s); brc=$?
echo "$B" >"$OUT/uart-bulk-nowin.json"
ov1=$(gexec sysctl -n dev.uart.1.rx_overruns | tr -d '\n')
dl=$(jf down_bytes "$B"); ua=$(jf up_bytes_acked "$B"); us=$(jf up_bytes_sent "$B")
rec chan 0 nowin_down_complete "$([ "$dl" = 16384 ] && echo yes || echo no)" yes "down_bytes=$dl host_skipped=$(jf skipped "$B") rc=$brc $(nocomma "$(jf err "$B")")"
if [ -z "$us" ]; then ul=untested; elif [ "$(jf ok "$B")" = true ] && [ "$ua" = 16384 ]; then ul=no; else ul=yes; fi
rec chan 0 nowin_up_loss "$ul" yes "ok=$(jf ok "$B") sent=$us acked=$ua agent_frames=$(jf up_agent_frames "$B")/16 agent_skipped=$(jf up_agent_skipped "$B")"
rec chan 0 nowin_guest_rx_overruns_delta "$(echo "${ov0:-x} ${ov1:-y}" | awk '$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {print $2-$1; exit} {print "n/a"}')" 0 "the software rx-buffer discard sets no LSR_OE"
P=$(asA "$INST/sr3j-chan" client ping -addr "$UARTADDR" -stream pu -wait 20s)
rec chan 0 uart_ping_after_nowin "$(jf ok "$P")" true "the next HELLO resets the session (agent_win=$(jf agent_win "$P"))"

# ================= 2b. UART capacity sweep (SR3J_UART_SWEEP=yes). Predictions: header PREDICT "UART sweep".
# Expected bottleneck: bhyve's 16550 emulation. Every guest access to the UART's registers is an inout exit
# handled in bhyve userland (uart_emul.c:216-419, under the softc lock); THR writes are one write(2) each to
# the nmdm (uart_backend.c:126-130, 224-228); received bytes enter one read(2) at a time into a 16-byte FIFO
# (uart_backend.c:62, 113-124, 196-216), and every getchar from a full FIFO re-arms the mevent (:153-155),
# a pipe write to wake the mevent thread (mevent.c:119-130). The guest sees no line speed (bhyve ignores
# the divisor) and the nmdm simulates none (nmdm.c:327-331: rate simulation only with CDSR_OFLOW, which
# neither openTTY nor bhyve's cfmakeraw sets), so the 115200 baud setting only sizes tty buffers.
if [ "$SWEEP" = yes ]; then
	mkdir -p "$OUT/sweep"
	TSCF=$(sysctl -n machdep.tsc_freq)
	# upoint LABEL CAP CLIENT-BULK-ARGS... -- one UART bulk point with VM-exit and CPU accounting around it.
	# Sets PJ (client JSON; synthesized on timeout), PW wall s, PX/PIO/PUS/PIW/PEI/PHLT/PPAUSE exit counter deltas
	# (all vCPUs), PRUN vCPU runtime s, PBC/PVC bhyve CPU s (all threads / vCPU threads: these include guest time).
	upoint() {
		_l=$1; _cap=$2; shift 2
		_a=$OUT/sweep/$_l.st0; _b=$OUT/sweep/$_l.st1
		vmstats "$_a"; _c0=$(bcpu); _t0=$(now)
		PJ=$(tchan $((_cap + 30)) bulk -addr "$UARTADDR" -stream sw -deadline "${_cap}s" "$@"); _rc=$?
		_t1=$(now); _c1=$(bcpu); vmstats "$_b"
		[ -n "$PJ" ] || PJ="{\"ok\":false,\"err\":\"no output rc=$_rc\"}"
		echo "$PJ" >"$OUT/sweep/$_l.json"
		PW=$(el "$_t0" "$_t1")
		PX=$(sd "$_a" "$_b" "total number of vm exits"); PIO=$(sd "$_a" "$_b" "number of times in/out was intercepted")
		PUS=$(sd "$_a" "$_b" "number of vm exits handled in userspace"); PIW=$(sd "$_a" "$_b" "vm exits due to interrupt window opening")
		PEI=$(sd "$_a" "$_b" "vm exits due to external interrupt"); PHLT=$(sd "$_a" "$_b" "number of times hlt was intercepted")
		# (until 2026-10-07 "printf ..., $2 > 0 ? ..." -- awk reads "> 0" as an output redirection: syntax error,
		# PRUN empty, vcpu_runtime_cores 0.00 on every point)
		PRUN=$(echo "$(sd "$_a" "$_b" "vcpu total runtime") $TSCF" | awk '{printf "%.2f", ($2 > 0) ? $1/$2 : 0}')
		PPAUSE=$(sd "$_a" "$_b" "number of times pause was intercepted")
		PBC=$(echo "$_c0 $_c1" | awk '{printf "%.2f", $3-$1}'); PVC=$(echo "$_c0 $_c1" | awk '{printf "%.2f", $4-$2}')
	}
	# q A B [FMT] -> A/B (n/a when B is 0 or empty)
	q() { echo "${1:-0} ${2:-0}" | awk -v f="${3:-%.3f}" '{if ($2 + 0 > 0) printf f, $1/$2; else printf "n/a"}'; }
	# eff CHUNK MAXFRAG -> payload/wire for this chunk (fragments of at most MAXFRAG payload bytes, 20 B each)
	eff() { awk -v c="$1" -v m="$2" 'BEGIN {f = int((c + m - 1) / m); printf "%.4f", c / (c + 20 * f)}'; }
	scale() { awk -v e="$1" -v lo="$2" -v hi="$3" 'BEGIN {printf "%.1f..%.1f", lo * e, hi * e}'; }
	# srec DIR CHUNK LABEL -- the rows of one bulk point (prediction ranges per direction from the header)
	srec() {
		_d=$1; _c=$2; _i=$3
		if [ "$_d" = down ]; then _m=748; _wr="25 250"; _io=1.2..1.8; _ex=1.3..3.5; _cr=1.0..2.2; _cpm=2..65; _cc=0.1..0.8; _bpr=1..4
		else _m=140; _wr="10 120"; _io=2.1..3.5; _ex=2.3..7; _cr=0.7..2.2; _cpm=5..220; _cc=0..0.3; _bpr=-; fi
		_wb=$(jf ${_d}_wire_bytes "$PJ")
		rec sweep "$_i" ok "$(jf ok "$PJ")" true "$(nocomma "$(jf err "$PJ")") ${_d} chunk $_c ($_i.json)"
		_e=$(eff "$_c" $_m)
		# shellcheck disable=SC2086
		rec sweep "$_i" goodput_KBps "$(jf ${_d}_MBps "$PJ" | awk '{printf "%.1f", $1*1000}')" "$(scale "$_e" $_wr)" "payload/wire $_e"
		# shellcheck disable=SC2086
		rec sweep "$_i" wire_KBps "$(jf ${_d}_wire_MBps "$PJ" | awk '{printf "%.1f", $1*1000}')" "$(scale 1 $_wr)" "wire bytes $_wb in $(jf ${_d}_s "$PJ") s"
		rec sweep "$_i" inout_exits_per_wire_B "$(q "$PIO" "$_wb")" "$_io" "inout $PIO"
		# bhyve runs with -P: every PAUSE the guest executes is a VM exit to userland (vmx.c:2594-2597 ->
		# vmm.c:1216 default "handled in userland"; bhyve's vmexit_pause just resumes). The guest spins with
		# PAUSE (cpu_spinwait) on the UART's hwmtx spin lock, which ns8250_bus_transmit holds across 17
		# userland exits (uart_dev_ns8250.c:1107-1131) and ipend/receive take too (:796-837, :1040-1072),
		# and on adaptive mutexes whose owner sits in such exits. Run 202014Z: userspace - inout - pause
		# < 0.4% of userspace on every point; pause 0.6-3.2 per wire byte (the header's model had no PAUSE term).
		# So: the UART exit model is checked without PAUSE; PAUSE exits are reported, not predicted.
		rec sweep "$_i" exits_ex_pause_per_wire_B "$(q "$((PX - PPAUSE))" "$_wb")" "$_ex" "total $PX userspace $PUS pause $PPAUSE"
		rec sweep "$_i" pause_exits_per_wire_B "$(q "$PPAUSE" "$_wb")" - "guest spin-waits on locks held across UART exits (-P)"
		rec sweep "$_i" userspace_ex_pause_over_inout "$(q "$((PUS - PPAUSE))" "$PIO")" "0.95..1.1"
		# per 1000 wire bytes. Down: one THRE interrupt per 16 B, raised by the IER write inside the guest's
		# spin-locked transmit (interrupts off) -> ~62 interrupt-window exits; injected from the vCPU's own
		# thread, so no host IPI. Up: interrupts pulsed from the mevent thread (an IPI per pulse to a running
		# vCPU unless posted interrupts), up to one per FIFO refill. hlt: the idle vCPU, loosely bounded.
		# With APICv virtual interrupt delivery (VID=1) a LAPIC interrupt is posted (vmx_inject_pir) and the CPU
		# delivers it when the guest's IF opens: no interrupt-window exit at all; the window is only armed for
		# ExtINT or without VID (vmx.c:1545-1548). Run 202014Z (VID=1): 0 on every point.
		if [ "$VID" = 1 ]; then _iw=0..1; elif [ "$_d" = down ]; then _iw=20..150; else _iw=0..1000; fi
		if [ "$_d" = down ]; then _ei=0..50; else _ei=0..1000; fi
		rec sweep "$_i" iwin_exits_per_KB "$(q "$((PIW * 1000))" "$_wb" %.1f)" "$_iw" "virtual_interrupt_delivery=$VID"
		rec sweep "$_i" extint_exits_per_KB "$(q "$((PEI * 1000))" "$_wb" %.1f)" "$_ei"
		rec sweep "$_i" hlt_exits_per_KB "$(q "$((PHLT * 1000))" "$_wb" %.1f)" "0..200"
		rec sweep "$_i" bhyve_cores "$(q "$PBC" "$PW" %.2f)" "$_cr" "bhyve CPU $PBC s (vCPU threads $PVC s) in $PW s"
		rec sweep "$_i" bhyve_cpu_s_per_MB "$(q "$PBC" "$(echo "$_wb" | awk '{print $1/1e6}')" %.1f)" "$_cpm" "per wire MB"
		rec sweep "$_i" vcpu_runtime_cores "$(q "$PRUN" "$PW" %.2f)" "0.5..2.2" "vmm 'vcpu total runtime' $PRUN s (TSC $TSCF Hz)"
		# client CPU, down: bhyve writes each guest THR byte with its own write(2) to the nmdm
		# (uart_backend.c:126-130), each write wakes the nmdm swi task (nmdm.c:411-416), so the host client
		# wakes for 1-4 bytes at a time: one kevent + read(2) + EAGAIN read per wakeup, ~3-8 us, at ~100 KB/s
		# -> 0.1-0.8 core (run 202014Z: 0.56-0.63 vs the old 0..0.3, which assumed bulk reads). The read
		# counter tests the mechanism. Up: unchanged (only the guest's CREDIT frames are read).
		rec sweep "$_i" client_cores "$(echo "$(jf client_cpu_user_s "$PJ") $(jf client_cpu_sys_s "$PJ") $PW" | awk '{if ($3 > 0) printf "%.3f", ($1+$2)/$3; else print "n/a"}')" "$_cc"
		rec sweep "$_i" client_bytes_per_read "$(q "$(jf read_bytes "$PJ")" "$(jf reads "$PJ")" %.2f)" "$_bpr" "reads $(jf reads "$PJ")"
		if [ "$_d" = down ]; then rec sweep "$_i" skipped "$(jf skipped "$PJ")" 0 "host resync bytes"
		else
			# per session since 2026-10-07: before, the agent reported its tty reader's lifetime total, which grew
			# by 32 per up point = the 16-byte dial preambles of the down and the up client in between
			rec sweep "$_i" skipped "$(jf up_agent_skipped "$PJ")" 0 "agent resync bytes after HELLO; credit waits $(jf credit_waits "$PJ"); agent lifetime total $(jf up_agent_skipped_total "$PJ")"
			rec sweep "$_i" skipped_pre_hello "$(jf up_agent_skipped_pre_hello "$PJ")" 16 "the client's dial preamble (preambleLen)"
		fi
	}
	# 1. bulk vs frame payload size, each direction
	for c in 64 256 1024 4096 16384 65536; do
		nb=$SWB; [ "$c" -lt 1024 ] && nb=$((SWB / 4))
		for d in down up; do
			upoint "$d-$c" "$SWCAP" -chunk "$c" -$d "$nb"
			srec "$d" "$c" "$d-$c"
		done
	done
	# goodput relative to chunk 1024: the framing model alone (payload/wire), +-15%
	for d in down up; do
		[ $d = down ] && m=748 || m=140
		g0=$(awk -F, -v i="$d-1024" '$1=="sweep" && $2==i && $3=="goodput_KBps" {print $4}' "$CSV")
		for c in 64 256 4096 16384 65536; do
			g=$(awk -F, -v i="$d-$c" '$1=="sweep" && $2==i && $3=="goodput_KBps" {print $4}' "$CSV")
			r=$(awk -v a="$(eff "$c" $m)" -v b="$(eff 1024 $m)" 'BEGIN {printf "%.3f", a/b}')
			rec sweep "$d-$c" goodput_vs_1024 "$(q "$g" "$g0")" "$(awk -v r="$r" 'BEGIN {printf "%.2f..%.2f", r*0.85, r*1.15}')" "framing model $r"
		done
	done
	# 3. head-of-line: a probe MSG every 100 ms during each direction, chunk 1024 vs 16384
	for c in 1024 16384; do
		upoint "probe-$c" "$SWCAP" -chunk "$c" -down $((SWB / 2)) -up $((SWB / 2)) -probe 100ms
		rec sweep "probe-$c" ok "$(jf ok "$PJ")" true "$(nocomma "$(jf err "$PJ")") (probe-$c.json)"
		for d in down up; do
			if [ $d = down ]; then p50=5..100; p99=10..200; else p50=3..60; p99=5..150; fi
			rec sweep "probe-$c" ${d}_probe_p50_ms "$(jf ${d}_probe_p50_ms "$PJ")" "$p50" "n=$(jf ${d}_probe_n "$PJ") p90 $(jf ${d}_probe_p90_ms "$PJ") max $(jf ${d}_probe_max_ms "$PJ")"
			rec sweep "probe-$c" ${d}_probe_p99_ms "$(jf ${d}_probe_p99_ms "$PJ")" "$p99"
			rec sweep "probe-$c" ${d}_probe_lost "$(jf ${d}_probe_lost "$PJ")" 0
			rec sweep "probe-$c" ${d}_goodput_KBps "$(jf ${d}_MBps "$PJ" | awk '{printf "%.1f", $1*1000}')" - "throughput with probes"
		done
	done
	for d in down up; do
		a=$(awk -F, -v m="${d}_probe_p99_ms" '$1=="sweep" && $2=="probe-1024" && $3==m {print $4}' "$CSV")
		b=$(awk -F, -v m="${d}_probe_p99_ms" '$1=="sweep" && $2=="probe-16384" && $3==m {print $4}' "$CSV")
		rec sweep probe ${d}_p99_16384_over_1024 "$(q "$b" "$a" %.2f)" "0.5..2" "fragments bound HOL, not the chunk"
	done
	# variant: guest hw.broken_txfifo=1 (no THRE interrupt per 16 bytes), down only; restored afterwards
	rec sweep txfifo set "$(gexec sysctl -n hw.broken_txfifo=1 >/dev/null 2>&1; gexec sysctl -n hw.broken_txfifo | tr -d '\n')" 1 "runtime tunable (CTLFLAG_RWTUN)"
	for c in 1024 16384; do
		upoint "txfifo-down-$c" "$SWCAP" -chunk "$c" -down "$SWB"
		srec down "$c" "txfifo-down-$c"
		g0=$(awk -F, -v i="down-$c" '$1=="sweep" && $2==i && $3=="goodput_KBps" {print $4}' "$CSV")
		g=$(awk -F, -v i="txfifo-down-$c" '$1=="sweep" && $2==i && $3=="goodput_KBps" {print $4}' "$CSV")
		rec sweep "txfifo-down-$c" goodput_vs_default "$(q "$g" "$g0" %.2f)" "1.0..1.5" "19 vs 21 inout exits per 16 B + one interrupt less"
	done
	rec sweep txfifo restored "$(gexec sysctl -n hw.broken_txfifo=0 >/dev/null 2>&1; gexec sysctl -n hw.broken_txfifo | tr -d '\n')" 0
	# 2 + 5. message rate and RTT, one message at a time, UART and TCP
	for s in 64 512 4096; do
		case $s in 64) up50=1..15; up99=1..60; um=66..1000 ;; 512) up50=4..60; up99=4..200; um=16..250 ;; 4096) up50=40..500; up99=40..1500; um=2..25 ;; esac
		for t in uart tcp; do
			[ $t = uart ] && a=$UARTADDR || a=$TCPADDR
			R=$(tchan $((SWCAP + 30)) rtt -addr "$a" -stream rt$t -n 200 -size "$s" -stall 5s)
			echo "$R" >"$OUT/sweep/rtt-$t-$s.json"
			if [ $t = uart ]; then p50=$up50; p99=$up99; mps=$um; else p50=0.02..1; p99=0.02..5; mps=1000..50000; fi
			rec sweep "rtt-$t-$s" ok "$(jf ok "$R")" true "acked $(jf acked "$R")/200 $(nocomma "$(jf err "$R")")"
			rec sweep "rtt-$t-$s" msgs_per_s "$(jf msgs_per_s "$R" | awk '{printf "%.1f", $1}')" "$mps"
			rec sweep "rtt-$t-$s" rtt_p50_ms "$(jf rtt_p50_ms "$R")" "$p50" "p90 $(jf rtt_p90_ms "$R") mean $(jf rtt_mean_ms "$R")"
			rec sweep "rtt-$t-$s" rtt_p99_ms "$(jf rtt_p99_ms "$R")" "$p99" "max $(jf rtt_max_ms "$R")"
		done
	done
	{
		echo "UART sweep (payload KB/s goodput / wire KB/s; inout exits per wire byte; bhyve cores):"
		for d in down up; do
			for c in 64 256 1024 4096 16384 65536; do
				awk -F, -v i="$d-$c" '$1=="sweep" && $2==i {v[$3]=$4} END {printf "  %-12s %8s / %8s KB/s  inout/B %6s  exits-pause/B %6s  pause/B %6s  bhyve %5s cores  %s s/MB\n", i, v["goodput_KBps"], v["wire_KBps"], v["inout_exits_per_wire_B"], v["exits_ex_pause_per_wire_B"], v["pause_exits_per_wire_B"], v["bhyve_cores"], v["bhyve_cpu_s_per_MB"]}' "$CSV"
			done
		done
		for c in 1024 16384; do
			awk -F, -v i="probe-$c" '$1=="sweep" && $2==i {v[$3]=$4} END {printf "  HOL chunk %-6s probe RTT down p50/p99 %s/%s ms, up p50/p99 %s/%s ms (lost %s/%s)\n", substr(i, 7), v["down_probe_p50_ms"], v["down_probe_p99_ms"], v["up_probe_p50_ms"], v["up_probe_p99_ms"], v["down_probe_lost"], v["up_probe_lost"]}' "$CSV"
		done
		for c in 1024 16384; do
			awk -F, -v i="txfifo-down-$c" '$1=="sweep" && $2==i {v[$3]=$4} END {printf "  broken_txfifo=1 down chunk %-6s %s KB/s (x%s of default), inout/B %s\n", substr(i, 13), v["goodput_KBps"], v["goodput_vs_default"], v["inout_exits_per_wire_B"]}' "$CSV"
		done
		for s in 64 512 4096; do
			awk -F, -v s="$s" '$1=="sweep" && ($2=="rtt-uart-" s || $2=="rtt-tcp-" s) {v[$2 ":" $3]=$4} END {printf "  RTT %4s B: UART p50 %s p99 %s ms (%s msg/s) | TCP p50 %s p99 %s ms (%s msg/s)\n", s, v["rtt-uart-" s ":rtt_p50_ms"], v["rtt-uart-" s ":rtt_p99_ms"], v["rtt-uart-" s ":msgs_per_s"], v["rtt-tcp-" s ":rtt_p50_ms"], v["rtt-tcp-" s ":rtt_p99_ms"], v["rtt-tcp-" s ":msgs_per_s"]}' "$CSV"
		done
	} >"$OUT/sweep/summary.txt"
	while IFS= read -r l; do say "$l"; done <"$OUT/sweep/summary.txt"
fi

# ================= 3. pf on the VM link (guest-side commands over the channel)
if [ $PF = yes ]; then
	rec pf 0 metadata_rdr "$(gexec fetch -T 5 -qo - http://169.254.169.254/latest/meta-data/ 2>&1 | tr -d '\n')" yard-fake-broker
	rec pf 0 ecs_rdr "$(gexec fetch -T 5 -qo - http://169.254.170.2/v2/credentials/x 2>&1 | tr -d '\n')" yard-fake-broker
	gexec fetch -T 3 -qo /dev/null http://1.1.1.1/ >/dev/null 2>&1 && b=no || b=yes; rec pf 0 internet_blocked $b yes
	gexec nc -z -w 3 $HOSTIP 22 >/dev/null 2>&1 && b=no || b=yes; rec pf 0 host_sshd_blocked $b yes
	rec pf 0 host_ping_guest "$(ping -c 1 -t 3 $GUESTIP >/dev/null 2>&1 && echo ok || echo FAIL)" ok
fi

# ================= 4. isolation
NODE=$(cat "$OUT/ngnode-boot.txt" 2>/dev/null | tr -d '\n')
iso() { rec iso "$1" "$2 $3" "$(probe "$4" "$2" "$3")" "$5" "${6:-}"; }
iso BinA open "/dev/vmm/$VM_A" asBA EACCES
iso BinA vmdestroy "$VM_A" asBA EINVAL "cr_cansee: see_other_uids=$SOU"
iso BinA vmcreate "$VM_A" asBA EEXIST "VM names are global: existence leaks"
iso BinA sysctl-destroy "$VM_A" asBA EPERM
iso BinA kill "$BPID" asBA ESRCH
iso BinA unix "/var/run/bhyve/$VM_A" asBA EACCES "bhyvectl control socket"
iso BinA read /vm/disk.img asBA EACCES
iso BinA open "/dev/${NMDM}B" asBA EACCES
[ -n "$NETDEV" ] && iso BinA open "/dev/$NETDEV" asBA EACCES
# ngctl: with ng_socket loaded the jail check (prison_check_af) and the privilege check are what answer;
# without it every caller gets EAFNOSUPPORT and the positive control below tests nothing (NGS=no is then
# itself recorded as a MISMATCH).
rec iso 0 ng_socket_loaded "$NGS" yes "PF_NETGRAPH registered: the ngctl probes reach the jail/privilege checks"
if [ "$NGS" = yes ]; then NGA=EPROTONOSUPPORT; NGB=EPERM; else NGA=EAFNOSUPPORT; NGB=EAFNOSUPPORT; fi
iso BinA ngctl - asBA $NGA "jail A has no allow.socket_af"
asBA "$BHYVECTL" --vm=$VM_A --destroy >"$OUT/bhyvectl-B-destroy.log" 2>&1
rec iso BinA "bhyvectl --destroy rc" "$?" 1 "$(tr '\n' ' ' <"$OUT/bhyvectl-B-destroy.log")"
iso AinA ngctl - asA $NGA "the VM uid cannot make netgraph sockets in its jail"
asA "$BHYVECTL" --vm=$VM_A --get-stats >/dev/null 2>&1; rec iso AinA "bhyvectl --get-stats rc" "$?" 0 "positive control: A controls its own VM"
iso BinB open "/dev/vmm/$VM_A" asBB ENOENT "devfs prison check (si_cred = A's cred), despite unhide vmm/*"
iso BinB vmdestroy "$VM_A" asBB EINVAL
iso BinB vmcreate "$VM_B" asBB OK "positive control"
iso BinB vmdestroy "$VM_B" asBB OK "positive control"
iso BinB kill "$BPID" asBB ESRCH
iso BinB open "/dev/${NMDM}B" asBB ENOENT "tty created with A's cred"
[ -n "$NETDEV" ] && iso BinB open "/dev/$NETDEV" asBB EACCES "host-made node: only devfs rules + root 0600 protect it"
iso BinB ngctl - asBB $NGB "PRIV_NETGRAPH_CONTROL (positive control that netgraph privilege is withheld; allow.socket_af=1 passes the jail check)"
[ -n "$NODE" ] && iso BinB ngdata "$NODE" asBB EADDRINUSE "A's ng_socket node already has bhyve's data socket"
[ $NET = ngd ] || [ $NET = ngfd ] && iso BinB ngdata "$IFNAME:" asBB EINVAL "not a socket node"
TICK=$(wait_tick "$(tf n "$(last_tick "$CON")")" 5); rec iso after VM_A_still_ticking "$([ -n "$TICK" ] && echo yes || echo no)" yes "$(nocomma "$TICK")"
rec iso after VM_A_channel_alive "$(jf ok "$(asA "$INST/sr3j-chan" client ping -addr "$TCPADDR" -stream p -wait 10s)")" true "liveness independent of the console tick"

# ================= 5. channel clients + suspend/restore cycles
for s in r k u; do
	case $s in
		r) a="-addr $TCPADDR -rate 100" ;;
		k) a="-addr $TCPADDR -rate 100 -keep -keepmax 120s" ;;
		u) a="-addr $UARTADDR -rate 20 -silence 1500ms" ;;
	esac
	# shellcheck disable=SC2086
	"$LAUNCH" -j "$JIDA" -u $UA -g $UA -d / -- "$INST/sr3j-chan" client stream $a -stream $s -epochfile /run/epoch -log /tmp/chan/$s.log \
		</dev/null >"$OUT/client-$s.out" 2>&1 &
	CLIENTS="$CLIENTS $!"
done
sleep 2
: >"$OUT/restores.txt"
i=1
while [ $i -le "$N" ]; do
	sleep "$DWELL"
	npre=$(tf n "$(last_tick "$CON")")
	F=/snap/s-$i.ckp; HF=$ROOT_A$F
	ta=$(now)
	asA "$BHYVECTL" --vm=$VM_A --suspend=$F >"$OUT/bhyvectl-s-$i.log" 2>&1; arc=$?
	tb=$(now); capped=no
	while alive; do past "$(deadline "$tb" $SUSP_EXIT_CAP)" "$(now)" && { capped=yes; break; }; sleep 0.02; done
	tc=$(now); prc=-
	[ $capped = no ] && { wait "$BPID"; prc=$?; BPID=; }
	ck=$(fsize "$HF"); kn=$(fsize "$HF.kern"); mt=$(fsize "$HF.meta")
	own=$(stat -f '%u' "$HF" 2>/dev/null)
	vma=$([ -e "/dev/vmm/$VM_A" ] && echo yes || echo no)
	if [ $capped = no ] && [ "$ck" -gt 0 ] && [ "$kn" -gt 0 ] && [ "$mt" -gt 0 ] && tail -c 16 "$HF.meta" | tr -d ' \n\r\t' | grep -q '}$' && [ $vma = no ]; then sc=done
	elif [ $capped = yes ]; then sc=notdone
	elif [ "$ck" -le 0 ] && [ $vma = no ]; then sc=notdone
	else sc=unknown; fi
	rec suspend $i class $sc done "answer rc=$arc proc_rc=$prc req->ans $(el "$ta" "$tb") s ans->exit $(el "$tb" "$tc") s npre=$npre"
	rec suspend $i total_s "$(el "$ta" "$tc")" "0.2..0.9"
	rec suspend $i ckp_bytes "$ck" "$MEMB" "kern=$kn meta=$mt"
	rec suspend $i ckp_owner "$own" "$UA"
	ha=$(hostaddr)
	if [ $NET = tap ]; then rec suspend $i hostaddr "$ha" gone "tunclose purge: root re-adds it"; ifconfig "$IFNAME" inet "$HOSTIP/$NETPFX" up
	else rec suspend $i hostaddr "$ha" kept; fi
	[ $sc = done ] || { say "suspend $i not done; stopping the cycles"; break; }
	echo $((i + 1)) >"$ROOT_A/run/epoch"          # yard-ctl bumps the resume epoch before resuming
	sleep "$HOLD"
	tl=$(now)
	load_vm "$OUT/bhyveload-r$i.log"; lrc=$?
	tr0=$(now); echo "$i $tr0" >>"$OUT/restores.txt"
	[ $lrc = 0 ] || { rec restore $i class notdone done "bhyveload rc=$lrc: $(tail -1 "$OUT/bhyveload-r$i.log")"; break; }
	asA "$INST/sr3j-chan" client ping -addr "$TCPADDR" -stream p -epochfile /run/epoch -wait 60s >"$OUT/ping-r$i.json" 2>&1 &
	PINGP=$!
	start_bhyve "r$i" "$F"
	wait_alive "${npre:-0}" $RESTORE_CAP $PINGP "$OUT/ping-r$i.json"; wrc=$?
	wait $PINGP; P=$(cat "$OUT/ping-r$i.json")
	# class from both liveness signals (until 2026-10-07 the tick alone: a mute agent made a live guest
	# "unknown" after 60 s). harness = the channel works (the guest runs, new epoch seen) but no tick: a
	# defect of the tick, not a hang; the cycles go on and the gate reports it separately.
	if [ $wrc = 2 ]; then wait "$BPID"; BPID=; rc_=$([ -e "/dev/vmm/$VM_A" ] && echo unknown || echo notdone); tail -5 "$OUT/bhyve-r$i.err"
	elif [ -n "$WT" ]; then rc_=done
	elif [ $WCH = ok ]; then rc_=harness
	else rc_=unknown; fi
	rec restore $i class $rc_ done "bhyveload $(el "$tl" "$tr0") s; start->tick $WTS s; start->channel $WCS s ($WCH)"
	rec restore $i liveness "tick=$([ -n "$WT" ] && echo yes || echo no) chan=$WCH" "tick=yes chan=ok" "console tick and TCP ping are independent"
	rec restore $i start_to_tick_s "$WTS" "0.6..2"
	case $rc_ in done|harness) ;; *) say "restore $i not done; stopping the cycles"; break ;; esac
	if [ -n "$WT" ]; then tk_=$(tf tok "$WT"); pd_=$(tf pid "$WT"); else tk_=$(jf token "$P"); pd_=$(jf pid "$P"); fi
	st=yes; [ "$tk_" = "$TOK0" ] && [ "$pd_" = "$PID0" ] || st=NO
	rec restore $i agent_same_tok_pid $st yes "from the $([ -n "$WT" ] && echo tick || echo ping)"
	rec restore $i bhyve_uid_jid "$(ps -o uid= -o jid= -p "$BPID" | awk '{print $1":"$2}')" "$UA:$JIDA"
	rec restore $i tcp_reconnect_s "$(jf elapsed_s "$P")" "0.2..1.5" "from restore start; $P"
	rec restore $i new_epoch_seen "$(jf epoch "$P")" $((i + 1))
	rec restore $i exec_after "$(gexec echo ok | tr -d '\n')" ok
	[ $PF = yes ] && rec restore $i metadata_rdr "$(gexec fetch -T 5 -qo - http://169.254.169.254/ 2>&1 | tr -d '\n')" yard-fake-broker
	rec restore $i hostaddr_after_restore "$(hostaddr)" kept
	rm -f "$HF" "$HF.kern" "$HF.meta"
	i=$((i + 1))
done
sleep 5     # let the stream clients settle after the last restore
for p in $CLIENTS; do kill -TERM "$p" 2>/dev/null; done
for p in $CLIENTS; do wait "$p"; done
CLIENTS=
cp -p "$ROOT_A"/tmp/chan/*.log "$OUT"/

# ================= 6. channel outcomes across the suspends (from the client logs)
for s in r k u; do
	L=$OUT/$s.log
	[ -f "$L" ] || { rec stream $s log missing present; continue; }
	# every reconnect ("up" with down_for_s) and every same-connection resume, matched to the latest restore start
	grep -E '"ev":"(up|same_conn)"' "$L" | grep -E 'down_for_s|same_conn' | while read -r e; do
		t=$(jf t "$e")
		ri=$(awk -v t="$t" '$2 <= t {i=$1; r=$2} END {print i" "r}' "$OUT/restores.txt")
		lat=$(echo "$t ${ri#* }" | awk '{printf "%.3f", $1-$2}')
		case $e in
			*same_conn*) echo "stream,$s,${ri%% *},same_conn,lat_s=$lat silent_for_s=$(jf silent_for_s "$e")" ;;
			*) echo "stream,$s,${ri%% *},up,lat_s=$lat epoch=$(jf epoch "$e") prev_epoch=$(jf prev_epoch "$e") inflight=$(jf inflight_at_down "$e") done=$(jf delivered_unacked "$e") notdone=$(jf lost_resent "$e") dups=$(jf dups "$e") stale=$(jf stale "$e") superseded=$(jf superseded "$e") skew_s=$(jf skew_s "$e") stepped_s=$(jf stepped_s "$e")" ;;
		esac
	done >>"$OUT/stream-events.csv"
	F=$(grep '"ev":"final"' "$L" | tail -1)
	ups=$(jf ups "$F"); same=$(jf same_conn "$F")
	if [ $s = k ]; then rec stream $s same_conn_resumes "$same" "$N" "$F"
	else rec stream $s reconnects "$((ups - 1))" "$N" "$F"; fi
	rec stream $s dups_at_agent "$(grep '"ev":"up"' "$L" | tail -1 | sed -n 's/.*"dups":\([0-9]*\).*/\1/p')" 0
done
[ -f "$OUT/stream-events.csv" ] && sed 's/^/  /' "$OUT/stream-events.csv"

# ================= summary
{
	echo "SR3J run $RUN NET=$NET N=$N MEM=$MEM bhyve=$BHYVE ($(sed -n 4p "$INST/BUILDINFO"))"
	echo "verdicts: $(awk -F, 'NR>1 {c[$6]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$CSV")"
	echo "mismatches:"; awk -F, 'NR>1 && $6=="MISMATCH" {printf "  %s %s %s: actual %s, predicted %s  %s\n", $1, $2, $3, $4, $5, $7}' "$CSV"
	echo "suspend classes: $(awk -F, '$1=="suspend" && $3=="class" {c[$4]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$CSV")"
	echo "restore classes: $(awk -F, '$1=="restore" && $3=="class" {c[$4]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$CSV")"
	for m in suspend:total_s restore:start_to_tick_s restore:tcp_reconnect_s; do
		awk -F, -v k="${m%%:*}" -v n="${m#*:}" '$1==k && $3==n && $4 ~ /^[0-9.]+$/ {print $4}' "$CSV" | sort -n |
			awk -v l="$m" '{a[NR]=$1} END {if (NR) printf "  %-26s p50 %.3f max %.3f n=%d\n", l, a[int((NR-1)/2)+1], a[NR], NR}'
	done
	[ -f "$OUT/sweep/summary.txt" ] && cat "$OUT/sweep/summary.txt"
	echo "stream events (per restore): $OUT/stream-events.csv"
	echo "csv: $CSV"
} | tee "$OUT/summary.txt"
SD=$(awk -F, '$1=="suspend" && $3=="class" && $4=="done"' "$CSV" | wc -l | tr -d ' ')
RD=$(awk -F, '$1=="restore" && $3=="class" && $4=="done"' "$CSV" | wc -l | tr -d ' ')
RH=$(awk -F, '$1=="restore" && $3=="class" && $4=="harness"' "$CSV" | wc -l | tr -d ' ')
ISO=$(awk -F, '$1=="iso" && $6=="MISMATCH"' "$CSV" | wc -l | tr -d ' ')
why=
[ "$SD" -eq "$N" ] || why="$why suspend_done=$SD/$N"
[ "$RD" -eq "$N" ] || why="$why restore_done=$RD/$N"
[ "$RH" -eq 0 ] || why="$why restore_harness=$RH(channel alive, no console tick: a harness defect, not a hang)"
[ "$ISO" -eq 0 ] || why="$why isolation_mismatches=$ISO"
awk -F, '$1=="stream" && $3=="dups_at_agent" && $4!="0"' "$CSV" | grep -q . && why="$why duplicate_delivery"
if [ -z "$why" ]; then echo "GATE PASS: unprivileged bhyve ($NET) $N/$N suspend+restore done, isolation as predicted, 0 duplicate deliveries ($MISMATCH other mismatches)" | tee -a "$OUT/summary.txt"
else echo "GATE FAIL:$why (NET=$NET; $MISMATCH mismatches)" | tee -a "$OUT/summary.txt"; exit 3; fi
