# sr3j-lib.sh -- shared settings for the SR3J root scripts (unprivileged jailed bhyve + agent channel).
# Sourced, never run. Sources ../lib.sh (step_wrap, say, die, ds_exists); logs/state go to ops/logs, ops/state.
# Does not touch ops/sr3 (another branch edits it); only reads /usr/local/yard/bhyve-snap (SR3's install).
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
SJ=$YARD_OPS/sr3j
INST=/usr/local/yard/sr3j             # this spike's build (sr3j-10-install.sh), root-owned
SNAP=/usr/local/yard/bhyve-snap       # SR3's snapshot build: vmm.ko (loaded), unpatched bhyve/bhyvectl
LAUNCH=$INST/sr3j-launch
OWNER_HOME=$(pw usershow -n "$OWNER" | cut -d: -f9)
STAGE=${SR3J_STAGE:-$OWNER_HOME/yard-sr3j/stage$INST}

# --- identities: VM uids are their own range, separate from task uids (2000000-2099999, n0-30)
VMUID_MIN=2100000; VMUID_MAX=2109999
UA=2100000            # VM A's bhyve/bhyveload/bhyvectl/client uid (gid = uid)
UB=2100001            # the "other VM" uid used for the isolation checks
VM_A=sr3ja            # VM A
VM_B=sr3jb            # a VM uid B creates and destroys itself (positive control)
JA=sr3j_a; JB=sr3j_b  # jails
RS_A=2101; RS_B=2102  # runtime devfs rulesets (kernel only, never written to /etc/devfs.rules)

# --- storage
VMDS=$YDS/vm/sr3j                 # unencrypted container (like vm/sr3): jail roots + base image
VMMNT=$YMNT/vm/sr3j
BASEDS=$VMDS/base                 # disk.img + @raw + @agent-<sha12>
ROOT_A=$VMMNT/a/root; ROOT_B=$VMMNT/b/root
DISKDS=$VMDS/a-disk               # per-run clone of base@agent-*, mounted at $ROOT_A/vm
SNAPPARENT=$YDS/data/vmsnap       # encrypted (SR0 invariant 4); SR3 created it
SNAPDS=$SNAPPARENT/sr3j-a         # owned by uid A, mounted at $ROOT_A/snap

# --- network
TAP=tap94; HOSTIP=10.78.94.1; GUESTIP=10.78.94.2; NETPFX=30
ANCHOR=yard/sr3j-a
BROKER_PORT=8099; CHAN_PORT=7700
NMDM=nmdm${VM_A}                  # nmdmsr3jaA (bhyve com2) / nmdmsr3jaB (host client)

# vmm_path -- the file the loaded vmm module came from, or empty
vmm_path() { kldstat -v 2>/dev/null | awk '$5 == "vmm.ko" { p = $6; gsub(/[()]/, "", p); print p; exit }'; }
jid_of() { jls -j "$1" jid 2>/dev/null || true; }
pf_on() { pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; }
# ngeth/ngd names this spike created are recorded in $STATE/sr3j-net (kind:name per line)
net_recorded() { grep "^$1:" "$STATE/sr3j-net" 2>/dev/null | cut -d: -f2 | tail -1; }

# sr3j_teardown -- remove every runtime object of a run (idempotent; used by the e2e trap and by undo).
# Never touches the base image dataset, the installed build or loaded modules (undo does those).
sr3j_teardown() {
	set +e
	# processes: anything running as the two VM uids (bhyve, clients, probes)
	for u in $UA $UB; do
		for p in $(pgrep -U "$u" 2>/dev/null); do kill -TERM "$p" 2>/dev/null; done
	done
	sleep 1
	for u in $UA $UB; do
		for p in $(pgrep -U "$u" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
	done
	[ -n "${BROKER_PGID:-}" ] && kill -TERM -- "-$BROKER_PGID" 2>/dev/null
	if [ -f "$STATE/sr3j-broker.pid" ]; then kill -TERM -- "-$(cat "$STATE/sr3j-broker.pid")" 2>/dev/null; rm -f "$STATE/sr3j-broker.pid"; fi
	# VMs (host root sees every VM: cr_cansee from prison0 with PRIV_SEEOTHERUIDS)
	for v in $VM_A $VM_B; do
		[ -e "/dev/vmm/$v" ] && { "$SNAP/bhyvectl" --vm="$v" --destroy 2>/dev/null; say "teardown: destroyed VM $v"; }
	done
	# jails (removing kills anything left inside)
	for j in $JA $JB; do
		[ -n "$(jid_of "$j")" ] && { jail -r "$j" >/dev/null 2>&1; say "teardown: removed jail $j"; }
	done
	# mounts under the jail roots, deepest first
	for r in "$ROOT_A" "$ROOT_B"; do
		mount -p | awk -v r="$r" '$2 == r || index($2, r "/") == 1 {print $2}' | sort -r | while read -r m; do
			case $m in "$ROOT_A/vm"|"$ROOT_A/snap") zfs unmount "$m" 2>/dev/null || umount -f "$m" ;; *) umount -f "$m" ;; esac
		done
	done
	# datasets of the run
	ds_exists "$DISKDS" && { zfs destroy -r "$DISKDS" && say "teardown: destroyed $DISKDS"; }
	if ds_exists "$SNAPDS"; then
		if [ "${SR3J_KEEP:-}" = yes ]; then say "teardown: SR3J_KEEP=yes: kept $SNAPDS"; else zfs destroy -r "$SNAPDS" && say "teardown: destroyed $SNAPDS"; fi
	fi
	# devfs rulesets (runtime only)
	for rs in $RS_A $RS_B; do devfs rule -s "$rs" delset 2>/dev/null; done
	# rctl rules on the VM uids
	for u in $UA $UB; do rctl -r "user:$u" 2>/dev/null; done
	# pf anchor
	pf_on && pfctl -a "$ANCHOR" -f /dev/null 2>/dev/null
	# network objects recorded by this spike
	if [ -f "$STATE/sr3j-net" ]; then
		while IFS=: read -r kind n; do
			case $kind in
				tap) ifconfig "$n" >/dev/null 2>&1 && ifconfig "$n" destroy && say "teardown: destroyed $n" ;;
				ngd) ngctl shutdown "$n:" 2>/dev/null && say "teardown: shut down ng_device $n" ;;
				ngeth) ngctl shutdown "$n:" 2>/dev/null && say "teardown: shut down ng_eiface $n" ;;
			esac
		done <"$STATE/sr3j-net"
		: >"$STATE/sr3j-net"
	fi
	rm -rf "${ROOT_A:?}/var/run/bhyve" 2>/dev/null
	return 0
}
