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
# RISKS     kldunload of base vmm fails with EBUSY if anything still holds it (then nothing changed);
#           a kernel/module mismatch would show as a kldload error (link_elf: symbol ... undefined) --
#           sr3-00-build.sh checked that every undefined symbol of the module is exported by this kernel.
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-20-vmm "$0" "$@"

[ -f "$SKO" ] || die "$SKO missing: run sr3-10-install.sh first"
(cd "$SNAP" && grep ' vmm.ko$' SHA256 | { read -r h f; [ "$(sha256 -q vmm.ko)" = "$h" ]; }) || die "$SKO does not match $SNAP/SHA256"
cur=$(vmm_path)
say "vmm now: ${cur:-not loaded}; VMs: $(vms); bhyve pids: $(bhyve_pids)"
if [ "$cur" = "$SKO" ]; then say "already loaded from $SKO; nothing to do"; exit 0; fi

if [ -n "$cur" ]; then
	[ -z "$(vms)" ] || die "VMs exist ($(vms)); refusing to unload vmm. Stop them first."
	[ -z "$(bhyve_pids)" ] || die "bhyve is running (pids $(bhyve_pids)); refusing to unload vmm."
	# record before acting so undo knows what to restore even if we die half-way
	[ -f "$STATE/sr3-vmm.prev" ] || echo "loaded:$cur" >"$STATE/sr3-vmm.prev"
	kldunload vmm || die "kldunload vmm failed (still in use?); nothing changed"
	say "unloaded $cur"
else
	[ -f "$STATE/sr3-vmm.prev" ] || echo "unloaded:" >"$STATE/sr3-vmm.prev"
fi
say "recorded previous state: $(cat "$STATE/sr3-vmm.prev")"

if ! kldload "$SKO"; then
	say "kldload $SKO failed; dmesg tail:"; dmesg | tail -8
	prev=$(cat "$STATE/sr3-vmm.prev")
	case $prev in
		loaded:*) kldload "${prev#loaded:}" && say "restored ${prev#loaded:}" || say "could not reload ${prev#loaded:}" ;;
	esac
	rm -f "$STATE/sr3-vmm.prev"
	die "snapshot vmm.ko did not load"
fi
[ "$(vmm_path)" = "$SKO" ] || die "vmm loaded but from $(vmm_path), not $SKO"
kldstat -v | grep -E 'vmm\.ko|^Id'
sysctl hw.vmm.vmx.initialized hw.vmm.vmx.cap.unrestricted_guest 2>/dev/null || true
dmesg | tail -4
say "OK (until reboot); next: sudo sh sr3-30-cycles.sh"
