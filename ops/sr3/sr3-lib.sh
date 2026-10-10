# sr3-lib.sh -- shared settings for the SR3 root scripts (bhyve snapshot spike). Sourced, never run.
# Sources ../lib.sh (step_wrap, say, die, ds_exists); logs and state go to ops/logs and ops/state.
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
SR3=$YARD_OPS/sr3
SNAP0=/usr/local/yard/bhyve-snap        # installed snapshot build (root-owned); nothing in base
# SR3_VARIANT=<name> selects a patched build installed beside it (sr3-00-build.sh with SR3_PATCHES,
# staged and installed as /usr/local/yard/bhyve-snap-<name>). A variant whose patches touch only
# bhyve/bhyvectl/libvmmapi runs on SNAP0's vmm module; one whose patches touch sys/ (BUILDINFO line
# kmod=own, e.g. p3 = 0001+0002+0003) ships its own vmm.ko, and SKO is then that file.
VARIANT=${SR3_VARIANT:-}
case $VARIANT in *[!a-z0-9]*) echo "SR3_VARIANT must be [a-z0-9]+"; exit 1 ;; esac
SNAP=$SNAP0${VARIANT:+-$VARIANT}
SBHYVE=$SNAP/bhyve
SBHYVECTL=$SNAP/bhyvectl
KMOD_OWN=no
if [ -n "$VARIANT" ] && grep -qx 'kmod=own' "$SNAP/BUILDINFO" 2>/dev/null; then KMOD_OWN=yes; fi
SKO=$SNAP0/vmm.ko
[ $KMOD_OWN = no ] || SKO=$SNAP/vmm.ko
# what sr3-20-vmm.sh loaded (path, sha256, variant), for the run logs
VMM_LOADED=$STATE/sr3-vmm.loaded
# home of the user who owns ops/ (the build stages there as that user)
OWNER_HOME=$(pw usershow -n "$OWNER" | cut -d: -f9)
STAGE=${SR3_STAGE:-$OWNER_HOME/yard-sr3/stage$SNAP}

# vmm_path -- the file the loaded vmm module came from, or empty if vmm is not loaded.
vmm_path() {
	kldstat -v 2>/dev/null | awk '$5 == "vmm.ko" { p = $6; gsub(/[()]/, "", p); print p; exit }'
}
# ours_ko PATH -- true if PATH is a vmm.ko installed by sr3-10-install.sh (base snapshot build or a variant)
ours_ko() { case $1 in "$SNAP0"/vmm.ko|"$SNAP0"-*/vmm.ko) return 0 ;; *) return 1 ;; esac; }
# vms -- names of existing VMs (empty if none or vmm is not loaded)
vms() { ls /dev/vmm 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
# bhyve_pids -- pids of any running bhyve process (base or ours)
bhyve_pids() { pgrep -x bhyve 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true; }
