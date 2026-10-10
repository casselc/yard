# sr3-lib.sh -- shared settings for the SR3 root scripts (bhyve snapshot spike). Sourced, never run.
# Sources ../lib.sh (step_wrap, say, die, ds_exists); logs and state go to ops/logs and ops/state.
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
SR3=$YARD_OPS/sr3
SNAP=/usr/local/yard/bhyve-snap         # installed snapshot build (root-owned); nothing in base
SBHYVE=$SNAP/bhyve
SBHYVECTL=$SNAP/bhyvectl
SKO=$SNAP/vmm.ko
# home of the user who owns ops/ (the build stages there as that user)
OWNER_HOME=$(pw usershow -n "$OWNER" | cut -d: -f9)
STAGE=${SR3_STAGE:-$OWNER_HOME/yard-sr3/stage$SNAP}

# vmm_path -- the file the loaded vmm module came from, or empty if vmm is not loaded.
vmm_path() {
	kldstat -v 2>/dev/null | awk '$5 == "vmm.ko" { p = $6; gsub(/[()]/, "", p); print p; exit }'
}
# vms -- names of existing VMs (empty if none or vmm is not loaded)
vms() { ls /dev/vmm 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
# bhyve_pids -- pids of any running bhyve process (base or ours)
bhyve_pids() { pgrep -x bhyve 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true; }
