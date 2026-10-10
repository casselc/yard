#!/bin/sh
# Diagnose mount-induced physical drift on an isolated clone of the SR1 test
# base, never on the failed session's checkpoint. Run as root after the kept
# SR1 diagnostic run: its sr1p project key must already be available.
# Requires DTrace providers loaded by the user (kldload dtraceall). Creates
# one throwaway clone; runs yard-devsrv there to produce fsync+rename state
# saves; stops it before snapshot; traces only mount+sync. No key bytes are
# extracted, no production drift rule changes, and no resume is forced.
# Logs: ops/logs/sr1-mount-<UTC>/; clone destroyed on exit unless
# SR1_DRIFT_KEEP=yes. DTrace/CTF availability is checked before clone creation.
. "$(dirname "$0")/sr1-lib.sh"
step_wrap sr1-11-mount-drift "$0" "$@"
RUN=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$OPS/logs/sr1-mount-$RUN
TRACE=$OPS/sr1/sr1-mount-drift.d
DS=$PROJDS/mountprobe-$RUN
MNT=$WSMNT/$PROJECT/mountprobe-$RUN
SNAP=$DS@before-mount
CREATED=no; DEV_PID=
mkdir -p "$OUT"
[ -x "$DEVSRV" ] || die "missing $DEVSRV"
[ -f "$TRACE" ] || die "missing $TRACE"
grep -Fqx "$PROJDS" "$ZCREATED" || die "$PROJDS is not recorded as the SR1 test project"
ds_exists "$PROJDS@base-1" || die "SR1 test base snapshot missing"
[ "$(zfs get -H -o value keystatus "$PROJDS")" = available ] || die "test project key not available; run the kept SR1 drift diagnostic first"
ds_exists "$DS" && die "$DS already exists"
if jls -n name 2>/dev/null | grep -q "^name=ysbx_$SBX\.s"; then die "SR1 service instances still exist; probe only the suspended test project"; fi

# Missing probes or CTF types must not turn into a successful-looking trace.
if ! dtrace -l -n 'fbt::zil_destroy:entry' >"$OUT/probes.txt" 2>"$OUT/probes.err"; then
	die "DTrace unavailable; load dtraceall as root; see $OUT/probes.err"
fi
awk 'NR > 1 {n++} END {exit (n == 0)}' "$OUT/probes.txt" || die "zil_destroy probe unavailable"
if ! dtrace -e -s "$TRACE" -c '/usr/bin/true' >"$OUT/compile.txt" 2>&1; then
	die "DTrace/CTF compilation failed; see $OUT/compile.txt"
fi

cleanup() {
	rc=$?
	if [ -n "$DEV_PID" ]; then kill -TERM "$DEV_PID" 2>/dev/null || true; wait "$DEV_PID" 2>/dev/null || true; fi
	if [ "$CREATED" = yes ]; then
		if [ "${SR1_DRIFT_KEEP:-no}" = yes ]; then say "kept throwaway clone $DS"
		else zfs destroy -r "$DS" || say "cleanup failed for $DS"; fi
	fi
	say "diagnostic exit $rc; results $OUT"
	exit "$rc"
}
trap cleanup EXIT
zfs clone -o mountpoint="$MNT" -o atime=off "$PROJDS@base-1" "$DS"
CREATED=yes

# Reuse the exact fsync/atomic-rename workload from the SR1 service, without
# a jail/VM or any request to another service. Only a loopback ephemeral port.
"$DEVSRV" -listen 127.0.0.1:0 -state "$MNT/.mount-probe/state.json" >"$OUT/service.txt" 2>&1 &
DEV_PID=$!
i=0
while ! grep -q 'listening' "$OUT/service.txt"; do
	kill -0 "$DEV_PID" 2>/dev/null || die "fixture exited before ready; see $OUT/service.txt"
	i=$((i + 1)); [ "$i" -lt 100 ] || die "fixture startup timeout"
	sleep 0.05
done
kill -TERM "$DEV_PID"
if ! wait "$DEV_PID"; then DEV_PID=; die "fixture failed to stop cleanly"; fi
DEV_PID=
zpool sync "${YDS%%/*}"
zfs snapshot "$SNAP"
zpool sync "${YDS%%/*}"
zfs get -Hp -o name,property,value written@before-mount "$DS" >"$OUT/written-before.txt"
OBJSET=$(zfs get -Hp -o value objsetid "$DS")
HEX=$(printf '%x' "$OBJSET")
KSTATS=kstat.zfs.${YDS%%/*}.dataset.objset-0x$HEX

# Hashes + visible metadata: strip only mtree's variable comment header.
mtree -x -c -p "$MNT" -k type,uid,gid,mode,size,time,link,sha256digest >"$OUT/tree-before.raw"
sed '/^#/d' "$OUT/tree-before.raw" >"$OUT/tree-before.txt"
sysctl "$KSTATS" >"$OUT/kstats-before-unmount.txt" 2>&1 || say "dataset counters unavailable; see kstats-before-unmount.txt"
zfs unmount "$DS"
zpool sync "${YDS%%/*}"
zfs get -Hp -o name,property,value written@before-mount "$DS" >"$OUT/written-unmounted.txt"

# Keep sync inside the traced command's lifetime. This still does not trace
# asynchronous workers; call stacks identify what the mount thread submits.
cat >"$OUT/mount.sh" <<EOF
#!/bin/sh
set -eu
/sbin/zfs mount '$DS'
/sbin/zpool sync '${YDS%%/*}'
EOF
if ! dtrace -s "$TRACE" -c "/bin/sh $OUT/mount.sh" >"$OUT/trace.txt" 2>"$OUT/trace.err"; then
	die "mount trace failed; see $OUT/trace.txt and trace.err"
fi
if grep -q 'TRACE ERROR' "$OUT/trace.txt"; then die "DTrace reported an attribution error; see $OUT/trace.txt"; fi
[ "$(zfs get -H -o value mounted "$DS")" = yes ] || die "trace command did not mount the clone"
zpool sync "${YDS%%/*}"
zfs get -Hp -o name,property,value written@before-mount "$DS" >"$OUT/written-remounted.txt"
sysctl "$KSTATS" >"$OUT/kstats-remounted.txt" 2>&1 || say "dataset counters unavailable; see kstats-remounted.txt"
zfs diff -H "$SNAP" "$DS" >"$OUT/filesystem-diff.txt" 2>"$OUT/filesystem-diff.err" || die "zfs diff failed"
mtree -x -c -p "$MNT" -k type,uid,gid,mode,size,time,link,sha256digest >"$OUT/tree-after.raw"
sed '/^#/d' "$OUT/tree-after.raw" >"$OUT/tree-after.txt"
if diff -u "$OUT/tree-before.txt" "$OUT/tree-after.txt" >"$OUT/tree-diff.txt"; then say "visible metadata and content hashes unchanged"
else say "visible tree differences: $OUT/tree-diff.txt"; fi

# Positive control: verify that the logical diff detector sees a real edit.
printf 'positive-control\n' >"$MNT/.mount-probe/added-after-snapshot"
zpool sync "${YDS%%/*}"
zfs diff -H "$SNAP" "$DS" >"$OUT/positive-diff.txt" 2>"$OUT/positive-diff.err" || die "positive-control diff failed"
[ -s "$OUT/positive-diff.txt" ] || die "positive control not detected"
say "positive-control file edit detected"
for stage in before unmounted remounted; do say "written $stage: $(cat "$OUT/written-$stage.txt")"; done
BEFORE=$(awk '{print $NF}' "$OUT/written-before.txt")
AFTER=$(awk '{print $NF}' "$OUT/written-remounted.txt")
if [ "$BEFORE" = "$AFTER" ]; then
	say "Fixture did not reproduce mount drift; this is inconclusive for the jailed/nullfs/key-cycle path."
fi
say "kernel paths/object numbers: $OUT/trace.txt; logical changes: filesystem-diff.txt; hashes/metadata: tree-diff.txt"
say "This attributes mount-thread activity; it is not a passed SR1 lifecycle gate."
