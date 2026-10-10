#!/bin/sh
# sr3-20-vmm.sh -- SR3: replace the running vmm module with the BHYVE_SNAPSHOT build, until reboot.
# PURPOSE   kldload /usr/local/yard/bhyve-snap/vmm.ko by full path. If base vmm.ko is loaded it is
#           unloaded first, but ONLY when no VM exists (/dev/vmm empty) and no bhyve process runs.
#           The previous state (base loaded / not loaded) is recorded in ops/state/sr3-vmm.prev for undo.
#           loader.conf / rc.conf are NOT changed: after a reboot the base vmm.ko (or none) is back.
#           Once ours is loaded, base bhyve's `kldload vmm` finds the module "vmm" already present, so
#           base bhyve would also run on the snapshot module (same ioctl ABI; nothing on this box runs
#           base bhyve today).
# PREDICT   < 1 s. On 2026-10-07 vmm was not loaded at all (Phase 0's 99-cleanup unloaded it), so this
#           is a plain kldload. Afterwards `kldstat -v` shows vmm.ko (/usr/local/yard/bhyve-snap/vmm.ko),
#           hw.vmm.vmx.initialized=1 and dmesg has no vmm error. Module size ~520 KB (base 547 KB).
# CHANGES   The loaded kernel module set, until reboot. Nothing on disk except ops/state/sr3-vmm.prev.
# UNDO      sudo sh sr3-20-vmm-undo.sh   (unloads ours; reloads /boot/kernel/vmm.ko if it was loaded before)
# VARIANT   SR3_VARIANT=<name> loads that variant's own vmm.ko (/usr/local/yard/bhyve-snap-<name>/vmm.ko)
#           when its BUILDINFO says kmod=own (patches under sys/, e.g. p3); for a kmod=base variant it
#           loads the base snapshot module as without SR3_VARIANT. Switching between snapshot modules
#           (base <-> variant) unloads the loaded one under the same rules (no VM, no bhyve) and keeps
#           the recorded pre-SR3 state, so sr3-20-vmm-undo.sh still returns to it; running this script
#           again without SR3_VARIANT goes back to the base snapshot module. The loaded module's path,
#           sha256 and variant are written to ops/state/sr3-vmm.loaded (sr3-30-cycles.sh prints it).
# RISKS     kldunload of base vmm fails with EBUSY if anything still holds it (then nothing changed);
#           a kernel/module mismatch would show as a kldload error (link_elf: symbol ... undefined) --
#           sr3-00-build.sh checked that every undefined symbol of the module is exported by this kernel.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-20-vmm "$0" "$@"

[ -z "$VARIANT" ] || [ -f "$SNAP/BUILDINFO" ] || die "variant $VARIANT is not installed ($SNAP): run sr3-10-install.sh with SR3_VARIANT=$VARIANT"
[ -f "$SKO" ] || die "$SKO missing: run sr3-10-install.sh first"
KD=$(dirname "$SKO")
(cd "$KD" && grep ' vmm.ko$' SHA256 | { read -r h f; [ "$(sha256 -q vmm.ko)" = "$h" ]; }) || die "$SKO does not match $KD/SHA256"
[ -z "$VARIANT" ] || say "variant $VARIANT: kmod=$([ $KMOD_OWN = yes ] && echo own || echo base) -> $SKO"
cur=$(vmm_path)
say "vmm now: ${cur:-not loaded}; VMs: $(vms); bhyve pids: $(bhyve_pids)"
record_loaded() {
	echo "path=$SKO sha256=$(sha256 -q "$SKO") variant=${VARIANT:-base} kmod_own=$KMOD_OWN loaded=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$VMM_LOADED"
	say "recorded in $VMM_LOADED: $(cat "$VMM_LOADED")"
}
if [ "$cur" = "$SKO" ]; then say "already loaded from $SKO; nothing to do"; record_loaded; exit 0; fi

if [ -n "$cur" ]; then
	[ -z "$(vms)" ] || die "VMs exist ($(vms)); refusing to unload vmm. Stop them first."
	[ -z "$(bhyve_pids)" ] || die "bhyve is running (pids $(bhyve_pids)); refusing to unload vmm."
	# record before acting so undo knows what to restore even if we die half-way. Only the state
	# before the first sr3-20 counts: switching between our modules keeps it.
	if ours_ko "$cur"; then [ -f "$STATE/sr3-vmm.prev" ] || echo "unknown:" >"$STATE/sr3-vmm.prev"
	else [ -f "$STATE/sr3-vmm.prev" ] || echo "loaded:$cur" >"$STATE/sr3-vmm.prev"; fi
	kldunload vmm || die "kldunload vmm failed (still in use?); nothing changed"
	rm -f "$VMM_LOADED"
	say "unloaded $cur"
else
	[ -f "$STATE/sr3-vmm.prev" ] || echo "unloaded:" >"$STATE/sr3-vmm.prev"
fi
say "recorded previous state: $(cat "$STATE/sr3-vmm.prev")"

if ! kldload "$SKO"; then
	say "kldload $SKO failed; dmesg tail:"; dmesg | tail -8
	# put back what was loaded a moment ago (the pre-SR3 module, or another of ours)
	if [ -n "$cur" ]; then kldload "$cur" && say "restored $cur" || say "could not reload $cur"; fi
	ours_ko "$cur" || rm -f "$STATE/sr3-vmm.prev"
	die "snapshot vmm.ko did not load"
fi
[ "$(vmm_path)" = "$SKO" ] || die "vmm loaded but from $(vmm_path), not $SKO"
record_loaded
kldstat -v | grep -E 'vmm\.ko|^Id'
sysctl hw.vmm.vmx.initialized hw.vmm.vmx.cap.unrestricted_guest 2>/dev/null || true
dmesg | tail -4
say "OK (until reboot); next: sudo ${VARIANT:+env SR3_VARIANT=$VARIANT }sh sr3-30-cycles.sh"
