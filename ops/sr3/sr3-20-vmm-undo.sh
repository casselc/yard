#!/bin/sh
# sr3-20-vmm-undo.sh -- undo sr3-20-vmm.sh: unload the snapshot vmm.ko and restore the previous state.
# SAFETY    Refuses while any VM exists or any bhyve runs. Unloads whichever of our modules is loaded (the
#           base snapshot build or a variant's own, any SR3_VARIANT). If base vmm.ko was loaded before the
#           first sr3-20, it is loaded again by full path (/boot/kernel/vmm.ko); if vmm was not loaded, it
#           stays unloaded. (To go back from a variant's module to the base snapshot module instead, run
#           sr3-20-vmm.sh without SR3_VARIANT.)
#           A reboot also undoes sr3-20 (nothing persistent was changed).
# RUNTIME   seconds. Idempotent.
. "$(dirname "$0")/sr3-lib.sh"
step_wrap sr3-20-vmm-undo "$0" "$@"
cur=$(vmm_path)
prev=$(cat "$STATE/sr3-vmm.prev" 2>/dev/null || echo "unknown:")
say "vmm now: ${cur:-not loaded}; recorded previous state: $prev"
if [ -n "$cur" ] && ours_ko "$cur"; then
	[ -z "$(vms)" ] || die "VMs exist ($(vms)); refusing to unload vmm"
	[ -z "$(bhyve_pids)" ] || die "bhyve is running (pids $(bhyve_pids)); refusing to unload vmm"
	kldunload vmm || die "kldunload vmm failed"
	rm -f "$VMM_LOADED"
	say "unloaded $cur"
elif [ -n "$cur" ]; then
	say "loaded vmm is $cur, not ours; leaving it"
	rm -f "$STATE/sr3-vmm.prev"; exit 0
fi
case $prev in
	loaded:*)
		p=${prev#loaded:}
		if [ -z "$(vmm_path)" ]; then kldload "$p" || die "could not reload $p"; say "reloaded $p"; fi ;;
	unloaded:) say "vmm was not loaded before sr3-20; leaving it unloaded" ;;
	*) say "no record of the previous state; leaving vmm unloaded (base loads on demand: kldload vmm)" ;;
esac
rm -f "$STATE/sr3-vmm.prev"
kldstat -v | grep -E 'vmm\.ko' || say "vmm not loaded"
say "OK"
