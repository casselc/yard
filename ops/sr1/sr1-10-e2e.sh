#!/bin/sh
# sr1-10-e2e.sh -- SR1: a dev-server service jail suspended and resumed through the SR0 lifecycle, measured.
# PURPOSE   HARNESS.md SR1 exit test. A service (yard-devsrv, a small Go HTTP server deployed with the
#           other binaries) is declared as a spec (argv, env, cwd, ports, readiness probe) and runs as the
#           task uid in a child jail of a broker sandbox, on its own workspace clone. yard-svc drives
#           lifecycle.Machine (the SR0 state machine, SQLite store) with the service backend
#           (internal/service). Every command is one Machine incarnation.
#   Layout  (decided 2026-10-07) zroot/yard/ws: its own encryption root (key file on the data root),
#           exec=on setuid=off compression=zstd atime=off. ws/sr1p: the test project, an encryption root
#           with a raw key held by the key service (internal/wskey: wrapped AES-256-GCM in the lifecycle
#           db on zroot/yard/data/keys -- its own dataset, never snapshotted or backed up (n0-70-keys.sh) --
#           under a TEST KEK FILE, kek.test on data/sr1, never the TPM here); its base @base-1 holds
#           the devsrv binary; the sessions web, kill, hang are clones of it (refquota 2G) mounted at
#           /yard/ws/sr1p/<session>; suspend snapshots are taken on the clone.
#   Suspend Quiesce: SIGTERM every process of the instance's jail (SIGCONT to stopped ones), SIGKILL after
#           the grace period, verify none is left. Checkpoint: zfs snapshot <clone>@ysr1-web-g<gen>-c<op>
#           + the spec artifact (digested, create-only) on zroot/yard/data/sr1. Destroy: jail_remove,
#           wait until its processes are gone, unmount, rmdir. Commit: suspended, one-shot token, credential
#           epoch bumped. Then, if no session of the project is active: unmount its datasets, unload-key.
#   Resume  The token consume (one conditional UPDATE); load only the project key (zfs load-key from stdin).
#           Restore: sync/read drift BEFORE mounting (mount itself dirties the ZIL); refuse if changed (written@snap > 0)
#           unless -force (decision 2), else mount the clone and create a new jail ysbx_sr1e2e.sweb-<gen> through yard-spawn's own
#           path from the artifact's spec, wait for readiness (HTTP GET /healthz from the host via the
#           sandbox's exposed port); mint (stand-in: an epoch file); complete; the owed delete removes the
#           snapshot and the artifact. The jail runs ON its clone: the clone is nullfs-mounted as the jail's
#           /workspace; suspend = stop -> snapshot -> jail_remove + wait for its processes -> unmount the jail's
#           view -> unmount the clone -> unload the key (last session); resume = load key -> mount clone ->
#           jail with the clone as /workspace -> start -> readiness.
#   Checks  0: the layout's properties (encryption roots, exec, setuid, compression, atime, refquota,
#             origins, mountpoints), ws-init/base/clone times.
#           per cycle: after suspend no instance jail, no process of the task uid, one ysr1 snapshot, the
#           port refuses, the project key unavailable and the clone unmounted; after resume the key
#           available, one jail, the devsrv's workspace state continued (starts = cycle+1, stops = cycle),
#           the marker the SERVICE wrote inside its jail before the suspend (GET /mark, fsync; on the host it is
#           the clone's file, owned by the task uid; the jail's /workspace is a nullfs view of the clone) is read
#           back by the service after the resume, no view of the clone survives the suspend, 0 bytes of drift,
#           the epoch file
#           = generation+1, no snapshot or artifact left.
#           D drift refusal (decision 2): web suspended, its clone mounted by hand (ws-load) and written: the
#             resume is refused (Drift recorded, back to Suspended, fresh token, no jail, the key unloaded
#             again); resume -force resumes it on the changed workspace (the devsrv sees the new marker).
#           R per-session rekey probe (measured, not used): zfs change-key on a throwaway clone: allowed or
#             refused, time, encryptionroot after (STATE.md: it does not change the master key).
#           (round 2) down -> Removed in the lifecycle: the last session's down unloads the project key (L).
#           K escalation: a service that ignores SIGTERM: grace + SIGKILL, nothing left; the key stays loaded
#             while web is active.
#           T readiness timeout: the second start never listens: the resume is observed not done, removes its
#             jail, returns to Suspended with a fresh token; the next resume works.
#           P pause tier: SIGSTOP (all processes T, the port hangs), a message wakes it, paused again,
#             suspended straight from Paused (graceful).
#           X dead instance (decision 3): probes find web alive for 300 ms; its jail is removed behind the
#             lifecycle's back; the next probes fail it (fact lost) within a few probe intervals.
#           L leftovers after `yard-svc down`: no service jail, snapshot, artifact, mount or process.
#           S crypto-shred: ws-shred unmounts, unloads, deletes the wrapped key and destroys ws/sr1p; a
#             later ws-load fails.
#   Outcome classes (SR0): every step's answer is done, refused (decision 2, definite) or an error; an
#           error is unknown until the lifecycle resolves it by observation (instance by jail name and its
#           processes, artifact digest + snapshot, artifact/snapshot absence, keystatus/mounted) once no copy
#           can land (the op's flock, held by its zfs and shim children). Counted per command (outcomes).
# PREDICT   (2026-10-07, before any run. Hypothesis: every step is a few syscalls and forks; zfs txg syncs
#           dominate snapshot/clone/create; load-key of a raw key is no PBKDF, two zfs processes and a mount;
#           lifecycle commits are fsyncs on an encrypted dataset, ~1-3 ms each.)
#           0: ws-init (key create + wrap + insert, zfs create of an encryption root, mount) p50 60 ms (25-200);
#             ws-base (unmount + snapshot) 60 ms (20-200); ws-clone 50 ms (20-150) each.
#           stop (quiesce) p50 20 ms (8-50); zfs snapshot 40 ms (15-120); whole checkpoint 55 ms (25-150);
#             remove (destroy) 6 ms (2-20).
#           unmount (the clone) p50 15 ms (5-60); unload-key 10 ms (3-40); load-key + mount 25 ms (8-80).
#           start-to-ready (restore: artifact, zfs get written@, spawn setup, devsrv) p50 30 ms (15-80);
#             its "ready" step 20 ms (8-60).
#           suspend decision->commit p50 100 ms (50-250); resume consume->complete 75 ms (35-180).
#             Command wall: suspend p50 175 ms (90-450) (+ unmount/unload), resume 115 ms (50-300) (+ load).
#             HARNESS exit: p50 suspend+resume well under 1 s + the service's own start time (95%).
#           drift 0 B every cycle; state continued and marker kept N/N; key unavailable after every suspend;
#           0 leftovers.
#           D: refused, answered by the restore (restore_refused=1), wall < 400 ms; forced resume ok.
#           R: change-key on a clone refused by ZFS 40% / done in 30-150 ms 60% (then encryptionroot = clone).
#           K: stop = grace 1 s + 10-60 ms, escalated. T: resume fails after 2.0-2.3 s, Suspended, no jail,
#           snapshot kept; a retry refuses the failed start's workspace writes; explicit forced retry ok.
#           P: pause/unpause p50 8 ms (3-30), suspend from Paused graceful.
#           X: 0 lost while alive; after the jail is removed, Failed within 20-150 ms of the probe start.
#           S: shred p50 80 ms (30-250); ws-load afterwards fails.
#           GATE PASS 65% (new code on the host: zfs key handling from Go, clone mountpoints, pf expose rule).
# CHANGES   Datasets zroot/yard/data/sr1 (db, state, artifacts, kek.test; emptied at the start of every run),
#           zroot/yard/ws (only if absent; key /yard/data/yard/keys/ws.key) and zroot/yard/ws/sr1p with its
#           clones (re-created every run: its key lives in the db), listed in ops/state/sr1-zfs-created.
#           Task sr1e2e (a task uid + its rctl user: rules), sandbox sr1e2e (VNET, epair, pf anchor
#           yard/sbx-sr1e2e with the expose rule), service jails under it, ysr1 snapshots. All of these
#           except the datasets are removed at exit (SR1_KEEP=yes keeps them); S destroys ws/sr1p.
#           Results: ops/logs/sr1-10-<run>/ (results.csv, cycles.csv, every command's JSON, summary.txt).
# UNDO      sudo sh sr1-10-e2e-undo.sh   (sessions, sandbox, task, snapshots, then the datasets it created)
# KNOBS     SR1_N=10 cycles; SR1_GRACE=5s (web's stop grace); SR1_START_DELAY=0s (devsrv's own start
#           time, added before it listens); SR1_SUBNET=211; SR1_KEEP=no; SR1_SKIP=  (any of D R K T P X S).
#           SR1_DIAG_DRIFT=yes: sync/read written@snap after suspend; on a definite drift refusal,
#           load/mount the suspended test clone for zfs diff. This does not force a resume. Use
#           SR1_KEEP=yes to keep the failed test state; these are diagnostic, not timing-gate runs.
# RUNTIME   ~25 s for 10 cycles (+3 s for K and T, +1 s for D, X, S).
. "$(dirname "$0")/sr1-lib.sh"
step_wrap sr1-10-e2e "$0" "$@"
N=${SR1_N:-10}; GRACE=${SR1_GRACE:-5s}; SDELAY=${SR1_START_DELAY:-0s}; KEEP=${SR1_KEEP:-no}; SKIP=${SR1_SKIP:-}
DIAG_DRIFT=${SR1_DIAG_DRIFT:-no}
case $DIAG_DRIFT in yes|no) ;; *) die "SR1_DIAG_DRIFT must be yes or no" ;; esac
case $N in ''|*[!0-9]*) die "SR1_N must be a number" ;; esac
RUN=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$OPS/logs/sr1-10-$RUN; CSV=$OUT/results.csv; CYC=$OUT/cycles.csv
mkdir -p "$OUT"
for b in "$SP" "$SVC" "$DEVSRV" "$BIN/yard-exec-shim"; do [ -x "$b" ] || die "missing $b (run tools/deploy-nuc.sh)"; done
[ -f /yard/tmpl/base/.yard-template-ok ] || die "template missing: run n0-40-template.sh"
[ -f /usr/local/etc/yard/tasks.conf ] || die "tasks.conf missing: run n0-30-tasks.sh"
[ "$(sysctl -n kern.racct.enable)" = 1 ] || die "kern.racct.enable=0"
pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || die "pf not enabled (n0-50-pf.sh): the readiness probe needs the anchor's expose rule"
[ "$(zfs get -H -o value keystatus $YDS/data)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"
ds_exists "$KEYSDS" || die "$KEYSDS missing: run n0-70-keys.sh dataset"
[ "$(zfs get -H -o value com.sun:auto-snapshot "$KEYSDS")" = false ] || die "$KEYSDS has a snapshot policy: run n0-70-keys.sh dataset"
if ds_exists "$WSROOT"; then
	[ "$(zfs get -H -o value keystatus "$WSROOT")" = available ] || die "$WSROOT is locked: run yard-unlock.sh"
fi
say "run $RUN revision $(cat $BIN/REVISION 2>/dev/null) N=$N grace=$GRACE start_delay=$SDELAY host $(uname -r)"

FAILS=0
pass() { say "PASS $*"; }
miss() { say "MISMATCH $*"; FAILS=$((FAILS+1)); }
expect() { if [ "$2" = "$3" ]; then pass "$1: $3"; else miss "$1: want '$2', got '$3'"; fi; }
rec() { echo "$1,$2,$3,$4,$5,$6" >>"$CSV"; }     # phase,item,metric,value,predicted,note
kv() { echo "$2" | tr ' ' '\n' | sed -n "s/^$1=//p" | tail -1; }
inrange() { awk -v v="$1" -v r="$2" 'BEGIN { split(r, a, /\.\./); exit !(v != "" && v+0 >= a[1]+0 && v+0 <= a[2]+0) }'; }
pct() { sort -n | awk -v q="$1" '{a[NR]=$1} END {if (NR == 0) print "-"; else print a[int((NR-1)*q)+1]}'; }
skip() { case " $SKIP " in *" $1 "*) return 0 ;; esac; return 1; }
svc() { # svc NAME CMD [args] -- one yard-svc command; JSON in $OUT/NAME.json, SUM = its SR1SUM line, SVCRC = exit
	n=$1; shift
	if $SVC "$@" $SVCARGS >"$OUT/$n.json" 2>"$OUT/$n.err"; then SVCRC=0; else SVCRC=$?; fi
	SUM=$(grep '^SR1SUM' "$OUT/$n.json" || true)
	[ -n "$SUM" ] || SUM="SR1SUM ok=0 err=no-summary rc=$SVCRC"
}
get() { fetch -q -T "${2:-2}" -o - "http://$JADDR:$1/" 2>/dev/null; }
mark() { fetch -q -T 2 -o - "http://$JADDR:$1/mark?v=$2" 2>/dev/null; }   # the service writes its marker
views() { mount -p | awk -v s="$(wsmnt "$1")" '$1 == s {print $2}'; }       # nullfs views of a clone
jf() { echo "$2" | sed -n "s/.*\"$1\":\"\{0,1\}\([^,\"}]*\).*/\1/p"; }
ujail() { jls -n name 2>/dev/null | grep -c "^name=ysbx_$SBX\.s$1-" || true; }
uprocs() { ps -ax -o uid= | awk -v u="$U" '$1 == u' | wc -l | tr -d ' '; }
usnaps() { zfs list -H -t snapshot -o name -d 1 "$PROJDS/$1" | grep -c "@ysr1-$1-" || true; }
keyst() { zfs get -H -o value keystatus "$PROJDS"; }
mnted() { zfs get -H -o value mounted "$PROJDS/$1"; }
uarts() { ls "$SR1ROOT/art/$1" 2>/dev/null | wc -l | tr -d ' '; }
jidof() { jls -j "ysbx_$SBX.s$1-$2" jid 2>/dev/null || true; }

# Native drift diagnostics: account separately for teardown/unmount and resume
# mounting. Read physical written@ without loading the key at after_suspend.
drift_probe() {
	stage=$1; ds=$PROJDS/web
	if ! snaps=$(zfs list -H -t snapshot -o name -d 1 "$ds"); then
		say "drift $stage: could not list snapshots"; return 1
	fi
	DIAG_SNAP=$(printf '%s\n' "$snaps" | awk '/@ysr1-web-/ {n++; s=$0} END {if (n == 1) print s}')
	[ -n "$DIAG_SNAP" ] || { say "drift $stage: expected exactly one suspend snapshot"; return 1; }
	if ! zpool sync "${YDS%%/*}"; then say "drift $stage: pool sync failed"; return 1; fi
	if ! zfs get -Hp -o name,property,value "written@${DIAG_SNAP#*@}" "$ds" >"$OUT/drift-$stage.txt"; then
		say "drift $stage: written@ read failed"; return 1
	fi
	say "drift $stage: $(cat "$OUT/drift-$stage.txt")"
}

# Only a definite drift refusal enters this path: no new service is started,
# and no force override is sent. The clone is mounted for inspection.
diagnose_refused_resume() {
	saved_sum=$SUM; saved_rc=$SVCRC
	svc diag-ws-load ws-load -project "$PROJECT" -sess web
	if [ "$SVCRC" = 0 ]; then
		if drift_probe after_refusal_mount; then
			if zfs diff -H "$DIAG_SNAP" "$PROJDS/web" >"$OUT/drift-zfs-diff.txt" 2>"$OUT/drift-zfs-diff.err"; then
				if [ -s "$OUT/drift-zfs-diff.txt" ]; then
					say "drift: filesystem changes are in $OUT/drift-zfs-diff.txt"
				else say "drift: zfs diff is empty (no reported namespace/file changes)"; fi
			else say "drift: zfs diff failed; see $OUT/drift-zfs-diff.err"; fi
		fi
	else say "drift: inspection mount failed; see $OUT/diag-ws-load.err"; fi
	SUM=$saved_sum; SVCRC=$saved_rc
}

cleanup() {
	rc=$?
	if [ "$KEEP" = yes ]; then say "SR1_KEEP=yes: sessions, sandbox $SBX and task $TASK kept (sr1-10-e2e-undo.sh removes them)"
	else sr1_teardown; fi
	[ -f "$OUT/summary.txt" ] || say "no summary (aborted, rc=$rc)"
	exit $rc
}
trap cleanup EXIT
sr1_teardown

say "=== 0 datasets, the workspace tree and the test project"
mk() { d=$1; shift
	if ds_exists "$d"; then
		grep -qx "$d" "$ZCREATED" 2>/dev/null || die "$d exists but was not created by sr1; refusing to use it"
		say "exists: $d"
	else zfs create "$@" "$d"; echo "$d" >>"$ZCREATED"; say "created $d"; fi
}
mk $SR1DS
rm -rf "$SR1ROOT/lifecycle.db" "$SR1ROOT/lifecycle.db-wal" "$SR1ROOT/lifecycle.db-shm" "$SR1ROOT/lifecycle.db.lock" \
	"$SR1ROOT/state" "$SR1ROOT/art"
rm -f "$KEYSDB" "$KEYSDB-wal" "$KEYSDB-shm"   # this run's project is new; so is its key
if [ ! -s "$KEK" ]; then   # the TEST KEK: wraps the project key in the db; the TPM is never used here
	( umask 077; dd if=/dev/random of="$KEK.tmp" bs=32 count=1 2>/dev/null ); chmod 0400 "$KEK.tmp"; mv "$KEK.tmp" "$KEK"
	say "generated the test KEK $KEK"
fi
if ! ds_exists "$WSROOT"; then
	encroot_create "$WSROOT" "$KEYDIR/ws.key" -o exec=on -o setuid=off -o compression=zstd -o atime=off
	echo "$WSROOT" >>"$ZCREATED"
else
	say "exists: $WSROOT ($(zfs get -H -o value encryptionroot,exec,setuid,compression "$WSROOT" | tr '\n' ' '))"
fi
if ds_exists "$PROJDS"; then   # an earlier run's project: its key went with that run's db
	grep -qx "$PROJDS" "$ZCREATED" 2>/dev/null || die "$PROJDS exists but was not created by sr1; refusing"
	for m in $(zfs list -H -r -o name,mounted "$PROJDS" | awk '$2 == "yes" {print $1}' | sort -r); do zfs unmount "$m"; done
	zfs destroy -R "$PROJDS"; say "destroyed the earlier run's $PROJDS"
fi
grep -vx "$PROJDS" "$ZCREATED" >"$ZCREATED.tmp" 2>/dev/null || true; mv "$ZCREATED.tmp" "$ZCREATED"

say "=== 1 task uid, project, clones, sandbox"
U=$($SP task-begin -task $TASK)
[ -n "$U" ] || die "task-begin gave no uid"
G=$(sed -n 's/^task_gid=//p' /usr/local/etc/yard/tasks.conf); G=${G:-2000000}
svc ws-init ws-init -project $PROJECT
[ $SVCRC = 0 ] || die "ws-init: $(cat "$OUT/ws-init.err") $SUM"
echo "$PROJDS" >>"$ZCREATED"
rec ws "$PROJECT" init_ms "$(kv ws_create_ms "$SUM")" 25..200 "key create $(kv ws_key_create_ms "$SUM") ms"
BASE=$WSMNT/$PROJECT/.base
mkdir -p "$BASE/.bin"; cp "$DEVSRV" "$BASE/.bin/yard-devsrv"; chmod 0755 "$BASE/.bin" "$BASE/.bin/yard-devsrv"
chown -R "$U:$G" "$BASE"
svc ws-base ws-base -project $PROJECT
[ $SVCRC = 0 ] || die "ws-base: $(cat "$OUT/ws-base.err")"
expect "base generation" 1 "$(kv ws_gen "$SUM")"
rec ws "$PROJECT" base_ms "$(kv ws_snapshot_ms "$SUM")" 20..200 ""
for s in $SESSIONS; do
	svc ws-clone-$s ws-clone -project $PROJECT -sess $s -refquota 2G
	[ $SVCRC = 0 ] || die "ws-clone $s: $(cat "$OUT/ws-clone-$s.err")"
	rec ws "$s" clone_ms "$(kv ws_clone_ms "$SUM")" 20..150 ""
done
zfs get -H -o name,property,value encryption,encryptionroot,keyformat,keylocation,keystatus,exec,setuid,compression,atime,canmount,mountpoint,origin,refquota \
	$WSROOT $PROJDS $PROJDS/web | sed 's/^/  /' | tee "$OUT/layout.txt"
expect "ws root is its own encryption root" "$WSROOT" "$(zfs get -H -o value encryptionroot $WSROOT)"
expect "project is its own encryption root" "$PROJDS" "$(zfs get -H -o value encryptionroot $PROJDS)"
expect "project key format/location" "raw prompt" "$(zfs get -H -o value keyformat,keylocation $PROJDS | tr '\n' ' ' | sed 's/ $//')"
expect "clone inherits the project key" "$PROJDS" "$(zfs get -H -o value encryptionroot $PROJDS/web)"
expect "clone exec/setuid/compression/atime" "on off zstd off" "$(zfs get -H -o value exec,setuid,compression,atime $PROJDS/web | tr '\n' ' ' | sed 's/ $//')"
expect "clone origin" "$PROJDS@base-1" "$(zfs get -H -o value origin $PROJDS/web)"
expect "clone refquota" 2G "$(zfs get -H -o value refquota $PROJDS/web)"
expect "clone mountpoint" "$(wsmnt web)" "$(zfs get -H -o value mountpoint $PROJDS/web)"
expect "data root still exec=off" off "$(zfs get -H -o value exec $YDS/data)"
# the sandbox's own workspace is a plain directory: a nullfs mount of a session clone there would hold it
# (an unmount for the key unload would be EBUSY); every instance mounts its session's clone itself
$SP sbx-create -id $SBX -net broker -subnet $SUB -broker-port 8099 -expose 8080,8081,8082 -owner $U \
	>"$OUT/sbx-create.json"
say "task uid $U; sandbox $(cat "$OUT/sbx-create.json")"
pfctl -a yard/sbx-$SBX -s rules | sed 's/^/  anchor: /'

spec() { # spec NAME PORT GRACE START_TIMEOUT [devsrv flags]
	n=$1 p=$2 g=$3 st=$4; shift 4
	a=""; for x in "$@"; do a="$a, \"$x\""; done
	cat <<EOF
{"name": "devsrv-$n",
 "argv": ["/workspace/.bin/yard-devsrv", "-listen", ":$p", "-state", "/workspace/.devsrv/$n.json", "-start-delay", "$SDELAY"$a],
 "env": ["SR1_SESSION=$n"], "cwd": "/workspace", "ports": [$p],
 "ready": {"kind": "http", "port": $p, "path": "/healthz", "interval": "10ms", "timeout": "1s"},
 "start_timeout": "$st", "stop_grace": "$g", "kill_wait": "2s", "pause_wait": "1s"}
EOF
}
spec web 8080 "$GRACE" 30s >"$OUT/web.spec.json"
spec kill 8081 1s 30s -ignore-term >"$OUT/kill.spec.json"
spec hang 8082 5s 2s -hang-on-start 2 >"$OUT/hang.spec.json"

say "=== 2 web up"
svc up-web up -sess web -sbx $SBX -task $TASK -spec "$OUT/web.spec.json" -project $PROJECT
[ $SVCRC = 0 ] || die "up web: $(cat "$OUT/up-web.err") $SUM"
say "up: $(kv up_ms "$SUM") ms (ready step $(kv up_ready_ms "$SUM") ms, probes $(kv up_probes "$SUM"))"
R=$(get 8080)
expect "up state starts" 1 "$(jf starts "$R")"
rec up web up_ms "$(kv up_ms "$SUM")" "" "probes $(kv up_probes "$SUM")"

say "=== 3 $N suspend/resume cycles"
echo "cycle,suspend_ok,resume_ok,stop_ms,escalated,snapshot_ms,checkpoint_ms,remove_ms,unmount_ms,unload_ms,suspend_fact_ms,suspend_wall_ms,load_ms,restore_ms,ready_ms,jail_ms,resume_fact_ms,resume_wall_ms,delete_ms,drift_bytes,ckpt_bytes,starts,stops,marker,key_suspended,key_resumed" >"$CYC"
i=1
while [ $i -le $N ]; do
	# the service writes its marker inside its jail, on its clone
	mark 8080 "cycle-$i" >/dev/null || miss "cycle $i: the service could not write its marker"
	[ "$(cat "$(wsmnt web)/marker" 2>/dev/null)" = "cycle-$i" ] || miss "cycle $i: the marker is not in the clone"
	[ "$(stat -f %u "$(wsmnt web)/marker" 2>/dev/null)" = "$U" ] || miss "cycle $i: the marker is not the service uid's"
	case "$(views web)" in */workspace) ;; *) miss "cycle $i: the jail's /workspace is not a view of the clone ($(views web))" ;; esac
	get 8080 >/dev/null || miss "cycle $i: web not answering before suspend"
	svc s$i suspend -sess web; SS=$SUM
	sok=$(kv ok "$SS")
	[ "$sok" = 1 ] || die "cycle $i suspend: $(cat "$OUT/s$i.err") $SS"
	[ "$(ujail web)" = 0 ] || miss "cycle $i: instance jail left after suspend"
	[ "$(uprocs)" = 0 ] || miss "cycle $i: $(uprocs) processes of uid $U after suspend"
	[ "$(usnaps web)" = 1 ] || miss "cycle $i: $(usnaps web) snapshots after suspend (want 1)"
	if get 8080 1 >/dev/null; then miss "cycle $i: port answers while suspended"; fi
	[ -z "$(views web)" ] || miss "cycle $i: a view of the clone survived the suspend: $(views web)"
	ks=$(keyst); mw=$(mnted web)
	[ "$ks $mw" = "unavailable no" ] || miss "cycle $i: after suspend key $ks, clone mounted $mw (want unavailable no)"
	if [ "$DIAG_DRIFT" = yes ]; then drift_probe after_suspend || say "drift: after-suspend probe failed"; fi
	svc r$i resume -sess web; RS=$SUM
	rok=$(kv ok "$RS")
	if [ "$rok" != 1 ]; then
		if [ "$DIAG_DRIFT" = yes ] && [ "$(kv restore_refused "$RS")" = 1 ]; then diagnose_refused_resume; fi
		die "cycle $i resume failed: $(cat "$OUT/r$i.err") $RS; artifacts in $OUT"
	fi
	kr=$(keyst)
	[ "$kr $(mnted web)" = "available yes" ] || miss "cycle $i: after resume key $kr, clone mounted $(mnted web)"
	R=$(get 8080)
	starts=$(jf starts "$R"); stops=$(jf stops "$R"); marker=$(jf marker "$R")
	[ "$starts" = $((i + 1)) ] || miss "cycle $i: starts $starts (want $((i + 1)))"
	[ "$stops" = $i ] || miss "cycle $i: graceful stops $stops (want $i)"
	[ "$marker" = "cycle-$i" ] || miss "cycle $i: marker '$marker' (want cycle-$i)"
	[ "$(jf gen "$R")" = $i ] || miss "cycle $i: devsrv gen $(jf gen "$R")"
	[ "$(ujail web)" = 1 ] || miss "cycle $i: $(ujail web) instance jails after resume"
	[ "$(usnaps web)" = 0 ] || miss "cycle $i: $(usnaps web) snapshots after resume (want 0: delete owed and done)"
	[ "$(uarts web)" = 0 ] || miss "cycle $i: $(uarts web) artifact files after resume"
	[ "$(cat "$SR1ROOT/state/svc/web/epoch" 2>/dev/null)" = $((i + 1)) ] || miss "cycle $i: epoch $(cat "$SR1ROOT/state/svc/web/epoch" 2>/dev/null) (want $((i + 1)))"
	drift=$(kv restore_drift_bytes "$RS")
	[ "$drift" = 0 ] || miss "cycle $i: workspace drift $drift B since the snapshot"
	echo "$i,$sok,$rok,$(kv quiesce_ms "$SS"),$(kv quiesce_escalated "$SS"),$(kv checkpoint_snapshot_ms "$SS"),$(kv checkpoint_ms "$SS"),$(kv destroy_ms "$SS"),$(kv unmount_ms "$SS"),$(kv unload_key_ms "$SS"),$(kv fact_suspend_ms "$SS"),$(kv wall_ms "$SS"),$(kv load_key_ms "$RS"),$(kv restore_ms "$RS"),$(kv restore_ready_ms "$RS"),$(kv restore_jail_ms "$RS"),$(kv fact_resume_ms "$RS"),$(kv wall_ms "$RS"),$(kv delete_ms "$RS"),$drift,$(kv fact_suspend_bytes "$SS"),$starts,$stops,$marker,$ks,$kr" >>"$CYC"
	say "cycle $i: stop $(kv quiesce_ms "$SS") snap $(kv checkpoint_snapshot_ms "$SS") remove $(kv destroy_ms "$SS") unmount $(kv unmount_ms "$SS") unload $(kv unload_key_ms "$SS") | suspend $(kv fact_suspend_ms "$SS")/$(kv wall_ms "$SS") ms || load $(kv load_key_ms "$RS") start-to-ready $(kv restore_ms "$RS") (ready $(kv restore_ready_ms "$RS")) | resume $(kv fact_resume_ms "$RS")/$(kv wall_ms "$RS") ms; starts=$starts stops=$stops"
	i=$((i + 1))
done
col() { awk -F, -v c="$1" 'NR == 1 {for (k = 1; k <= NF; k++) if ($k == c) n = k; next} $n != "" {print $n}' "$CYC"; }
pstat() { # pstat COLUMN PREDICTED_P50_RANGE LABEL
	p50=$(col "$1" | pct 0.5); p90=$(col "$1" | pct 0.9); mx=$(col "$1" | pct 1)
	if inrange "$p50" "$2"; then v=in; else v=OUT; fi
	rec cycles "$1" p50 "$p50" "$2" "p90 $p90 max $mx n=$(col "$1" | wc -l | tr -d ' ') $v"
	printf '  %-18s p50 %9s  p90 %9s  max %9s   predicted p50 %-9s %s\n' "$3" "$p50" "$p90" "$mx" "$2" "$v" >>"$OUT/summary.txt"
}
nok=$(awk -F, 'NR > 1 && $2 == 1 && $3 == 1' "$CYC" | wc -l | tr -d ' ')
expect "cycles done (suspend and resume)" "$N" "$nok"
expect "graceful stops (no escalation)" 0 "$(col escalated | grep -c 1 || true)"

if ! skip D; then
	say "=== D drift refusal (decision 2) on web"
	svc d-suspend suspend -sess web
	expect "D suspend ok, key unloaded" "1 unavailable" "$(kv ok "$SUM") $(keyst)"
	svc d-load ws-load -project $PROJECT -sess web       # something mounts the clone by hand ...
	[ $SVCRC = 0 ] || miss "D ws-load: $(cat "$OUT/d-load.err")"
	rec D web ws_load_ms "$(kv ws_load_ms "$SUM")" 8..80 "by hand"
	printf "drift-$RUN" >"$(wsmnt web)/marker"; chown "$U:$G" "$(wsmnt web)/marker"   # ... and writes to it
	# (no sync here: the restore's own `zpool sync` must make the write visible to written@snap)
	svc d-resume1 resume -sess web
	expect "D resume refused" "0 Suspended 1 1" "$(kv ok "$SUM") $(kv state "$SUM") $(kv drift "$SUM") $(kv restore_refused "$SUM")"
	rec D web refused_wall_ms "$(kv wall_ms "$SUM")" 0..400 "drift_bytes $(kv restore_drift_bytes "$SUM") outcomes $(sed -n 1p "$OUT/d-resume1.json" | sed -n 's/.*"outcomes":\({[^}]*}\).*/\1/p' | tr ',' ' ')"
	expect "D no jail after the refusal" 0 "$(ujail web)"
	expect "D key unloaded again" unavailable "$(keyst)"
	tok=$(kv token "$SUM"); [ -n "$tok" ] && [ "$tok" != 0 ] && pass "D fresh token" || miss "D token '$tok'"
	svc d-resume2 resume -sess web -force
	expect "D forced resume ok" "1 Active 0" "$(kv ok "$SUM") $(kv state "$SUM") $(kv drift "$SUM")"
	rec D web forced_restore_ms "$(kv restore_ms "$SUM")" 15..80 "force $(kv restore_force "$SUM") drift_bytes $(kv restore_drift_bytes "$SUM")"
	expect "D the service sees the changed workspace" "drift-$RUN" "$(jf marker "$(get 8080)")"
	RS=$SUM
fi

if ! skip R; then
	say "=== R per-session rekey probe (zfs change-key on a throwaway clone; measured, not used)"
	svc r-clone ws-clone -project $PROJECT -sess rk
	if [ $SVCRC = 0 ]; then
		t0=$(date +%s.%N)
		if dd if=/dev/random bs=32 count=1 2>/dev/null | zfs change-key -o keyformat=raw -o keylocation=prompt "$PROJDS/rk" >"$OUT/rekey.out" 2>&1; then rk=done; else rk=refused; fi
		t1=$(date +%s.%N)
		rkms=$(echo "$t0 $t1" | awk '{printf "%.1f", ($2-$1)*1000}')
		er=$(zfs get -H -o value encryptionroot "$PROJDS/rk")
		say "R change-key on a clone: $rk in $rkms ms; encryptionroot now $er; $(tr '\n' ' ' <"$OUT/rekey.out")"
		rec R rk change_key_ms "$rkms" 30..150 "$rk encryptionroot=$er"
		zfs destroy -r "$PROJDS/rk" && say "R destroyed $PROJDS/rk"
	else miss "R clone: $(cat "$OUT/r-clone.err")"; fi
fi

if ! skip K; then
	say "=== K escalation: a service that ignores SIGTERM"
	# Earlier project-wide unloads also unmounted the unused pre-created clones.
	# Initial Up requires its workspace mounted; this is not a checkpoint resume.
	svc k-load ws-load -project $PROJECT -sess kill
	[ $SVCRC = 0 ] || die "K workspace load: $(cat "$OUT/k-load.err") $SUM"
	svc up-kill up -sess kill -sbx $SBX -task $TASK -spec "$OUT/kill.spec.json" -project $PROJECT
	[ $SVCRC = 0 ] || die "K up: $(cat "$OUT/up-kill.err") $SUM"
	svc k-suspend suspend -sess kill
	expect "K suspend ok" 1 "$(kv ok "$SUM")"
	expect "K escalated" 1 "$(kv quiesce_escalated "$SUM")"
	k=$(kv quiesce_ms "$SUM")
	if inrange "$k" 1000..1060; then pass "K stop $k ms (grace 1 s + kill)"; else miss "K stop $k ms (want 1000-1060)"; fi
	rec K kill quiesce_ms "$k" 1010..1060 "escalated $(kv quiesce_escalated "$SUM") term $(kv quiesce_term_ms "$SUM") kill $(kv quiesce_kill_ms "$SUM")"
	expect "K jail gone" 0 "$(ujail kill)"
	expect "K key stays loaded (web active)" available "$(keyst)"
	svc k-resume resume -sess kill
	expect "K resume ok" 1 "$(kv ok "$SUM")"
	R=$(get 8081)
	expect "K starts/stops (never graceful)" "2/0" "$(jf starts "$R")/$(jf stops "$R")"
	svc k-down down -sess kill
	[ $SVCRC = 0 ] || miss "K down: $(cat "$OUT/k-down.err")"
fi

if ! skip T; then
	say "=== T readiness timeout: the second start never listens"
	svc t-load ws-load -project $PROJECT -sess hang
	[ $SVCRC = 0 ] || die "T workspace load: $(cat "$OUT/t-load.err") $SUM"
	svc up-hang up -sess hang -sbx $SBX -task $TASK -spec "$OUT/hang.spec.json" -project $PROJECT
	[ $SVCRC = 0 ] || die "T up: $(cat "$OUT/up-hang.err") $SUM"
	svc t-suspend suspend -sess hang
	expect "T suspend ok" 1 "$(kv ok "$SUM")"
	tok1=$(jf Token "$(sed -n 1p "$OUT/t-suspend.json")")
	svc t-resume1 resume -sess hang
	expect "T resume not done" "0 Suspended" "$(kv ok "$SUM") $(kv state "$SUM")"
	t=$(kv restore_ms "$SUM")
	if inrange "$t" 2000..2300; then pass "T gave up after $t ms (start timeout 2 s)"; else miss "T restore $t ms (want 2000-2300)"; fi
	rec T hang restore_ms "$t" 2000..2300 "probes $(kv restore_probes "$SUM") outcomes $(sed -n 1p "$OUT/t-resume1.json" | sed -n 's/.*"outcomes":\({[^}]*}\).*/\1/p' | tr ',' ' ')"
	expect "T no jail left" 0 "$(ujail hang)"
	expect "T snapshot kept" 1 "$(usnaps hang)"
	tok2=$(jf Token "$(sed -n 1p "$OUT/t-resume1.json")")
	[ -n "$tok2" ] && [ "$tok2" != "$tok1" ] && [ "$tok2" != 0 ] && pass "T fresh token" || miss "T token $tok1 -> $tok2"
	svc t-resume2 resume -sess hang
	expect "T retry refuses failed-start workspace writes" "0 Suspended 1 1" "$(kv ok "$SUM") $(kv state "$SUM") $(kv drift "$SUM") $(kv restore_refused "$SUM")"
	expect "T retry refusal leaves no jail" 0 "$(ujail hang)"
	svc t-resume3 resume -sess hang -force
	expect "T explicit forced retry ok" 1 "$(kv ok "$SUM")"
	expect "T starts" 3 "$(jf starts "$(get 8082)")"
	svc t-down down -sess hang
	[ $SVCRC = 0 ] || miss "T down: $(cat "$OUT/t-down.err")"
fi

if ! skip P; then
	say "=== P pause tier on web"
	g=$(kv gen "$RS")
	svc p-pause pause -sess web
	expect "P pause ok" "1 Paused" "$(kv ok "$SUM") $(kv state "$SUM")"
	pz=$(kv pause_ms "$SUM")
	rec P web pause_ms "$pz" 3..30 "procs $(kv pause_procs "$SUM")"
	J=$(jidof web "$g")
	nst=$(ps -ax -o jid= -o stat= | awk -v j="$J" '$1 == j && $2 !~ /^T/' | wc -l | tr -d ' ')
	nall=$(ps -ax -o jid= -o stat= | awk -v j="$J" '$1 == j' | wc -l | tr -d ' ')
	[ "$nst" = 0 ] && [ "$nall" -gt 0 ] && pass "P all $nall processes stopped" || miss "P $nst of $nall not stopped"
	if get 8080 1 >/dev/null; then miss "P port answers while paused"; else pass "P port does not answer while paused"; fi
	svc p-unpause unpause -sess web
	expect "P unpause ok" 1 "$(kv ok "$SUM")"
	rec P web unpause_ms "$(kv unpause_ms "$SUM")" 3..30 ""
	get 8080 >/dev/null && pass "P port answers after unpause" || miss "P port after unpause"
	stops0=$(jf stops "$(get 8080)")
	svc p-pause2 pause -sess web
	svc p-suspend suspend -sess web
	expect "P suspend from Paused ok, not escalated" "1 0" "$(kv ok "$SUM") $(kv quiesce_escalated "$SUM")"
	rec P web quiesce_ms_from_paused "$(kv quiesce_ms "$SUM")" 8..50 "escalated $(kv quiesce_escalated "$SUM")"
	svc p-resume resume -sess web
	expect "P resume ok" 1 "$(kv ok "$SUM")"
	expect "P graceful stop counted" $((stops0 + 1)) "$(jf stops "$(get 8080)")"
fi

if ! skip X; then
	say "=== X dead instance while active (decision 3)"
	svc x-alive probe -sess web -for 300ms
	expect "X alive: not failed" "1 0" "$(kv ok "$SUM") $(echo "$SUM" | grep -c fact_lost_ms || true)"
	g=$(kv gen "$SUM"); j=ysbx_$SBX.sweb-$g
	if jls -j "$j" jid >/dev/null 2>&1; then
		jail -r "$j" && say "X removed $j behind the lifecycle's back"
		svc x-dead probe -sess web -for 3s
		expect "X detected: Failed" "Failed 1" "$(kv state "$SUM") $(echo "$SUM" | grep -c fact_lost_ms || true)"
		rec X web detect_ms "$(kv cmd_ms "$SUM")" 20..150 "probe every 20 ms; lost counted $(sed -n 1p "$OUT/x-dead.json" | grep -o '"probe/lost":[0-9]*')"
	else miss "X no jail $j for web"; fi
fi

say "=== L leftovers"
svc l-down down -sess web
[ $SVCRC = 0 ] || miss "L down web: $(cat "$OUT/l-down.err")"
expect "L service jails" 0 "$(jls -n name | grep -c "^name=ysbx_$SBX\.s" || true)"
expect "L ysr1 snapshots" 0 "$(zfs list -H -t snapshot -o name -r $PROJDS | grep -c '@ysr1-' || true)"
expect "L artifacts" 0 "$(find "$SR1ROOT/art" -type f 2>/dev/null | wc -l | tr -d ' ')"
expect "L task processes" 0 "$(uprocs)"
expect "L service mounts" 0 "$(mount -p | awk '{print $2}' | grep -c "^/yard/jails/$SBX/root/.yard/svc/" || true)"
expect "L every session Removed or Failed: the project key unloaded" "unavailable no" "$(keyst) $(mnted web)"
expect "L down is Removed in the lifecycle" Removed "$(kv state "$SUM")"

if ! skip S; then
	say "=== S crypto-shred of the project"
	for s in kill hang; do $SVC down -sess $s $SVCARGS >/dev/null 2>&1 || true; done
	svc s-shred ws-shred -project $PROJECT
	expect "S shred ok" 1 "$(kv ok "$SUM")"
	rec S $PROJECT shred_ms "$(kv ws_shred_ms "$SUM")" 30..250 ""
	if ds_exists "$PROJDS"; then miss "S $PROJDS still exists"; else pass "S $PROJDS destroyed"; fi
	svc s-load ws-load -project $PROJECT -sess web
	expect "S a load after the shred fails" 1 "$([ $SVCRC != 0 ] && echo 1 || echo 0)"
fi

{
	echo "SR1 e2e $RUN N=$N grace=$GRACE start_delay=$SDELAY revision $(cat $BIN/REVISION 2>/dev/null)"
	echo "per cycle (ms; predicted p50 ranges stated in the header before any run):"
} >"$OUT/summary.txt"
pstat stop_ms 8..50 "stop (quiesce)"
pstat snapshot_ms 15..120 "zfs snapshot"
pstat checkpoint_ms 25..150 "checkpoint"
pstat remove_ms 2..20 "remove (destroy)"
pstat unmount_ms 5..60 "unmount (clone)"
pstat unload_ms 3..40 "unload-key"
pstat load_ms 8..80 "load-key + mount"
pstat suspend_fact_ms 50..250 "suspend (lifecycle)"
pstat suspend_wall_ms 90..450 "suspend wall"
pstat restore_ms 15..80 "start-to-ready"
pstat ready_ms 8..60 "  ready step"
pstat jail_ms 1..10 "  jail setup"
pstat resume_fact_ms 35..180 "resume (lifecycle)"
pstat resume_wall_ms 50..300 "resume wall"
pstat delete_ms 5..60 "delete (owed)"
awk -F, 'NR > 1 {print $12 + $18}' "$CYC" >"$OUT/cycle_wall.txt"
cw=$(pct 0.5 <"$OUT/cycle_wall.txt"); rd=$(col ready_ms | pct 0.5)
if inrange "$cw" "0..$(awk -v r="$rd" 'BEGIN {print 1000 + r}')"; then v=PASS; else v=FAIL; miss "HARNESS bound: suspend+resume wall p50 $cw ms"; fi
echo "  suspend+resume wall p50 $cw ms; HARNESS bound 1000 ms + service ready step $rd ms: $v" >>"$OUT/summary.txt"
rec cycles suspend_resume_wall p50 "$cw" "0..1000+ready" "$v"
[ $FAILS = 0 ] && gate=PASS || gate=FAIL
echo "GATE $gate ($FAILS mismatches); results $CSV, cycles $CYC" >>"$OUT/summary.txt"
cat "$OUT/summary.txt"
[ $FAILS = 0 ] || die "$FAILS check(s) did not match"
say "OK"
