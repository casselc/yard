# sr1-lib.sh -- shared settings for the SR1 root scripts (service jails suspend/resume). Sourced, never run.
# Sources ../lib.sh (step_wrap, say, die, ds_exists); logs and state go to ops/logs and ops/state.
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
BIN=$YARD_OPS/../bin
SP=$BIN/yard-spawn
SVC=$BIN/yard-svc
DEVSRV=$BIN/yard-devsrv
SBX=sr1e2e                              # yard-spawn sandbox id (broker/VNET, ports exposed to the host)
TASK=sr1e2e                             # task id -> task uid (yard-spawn task-begin)
SUB=${SR1_SUBNET:-211}                  # sandbox /30: host 10.77.$SUB.1, sandbox 10.77.$SUB.2
JADDR=10.77.$SUB.2
SR1DS=$YDS/data/sr1                     # lifecycle db (+ the key service's wskeys table), service state, artifacts
SR1ROOT=$YMNT/data/sr1
# Workspaces (layout decided 2026-10-07): $WSROOT is its own encryption root (lib.sh); the test project is an
# encryption root of its own whose raw key the key service holds, wrapped under a TEST KEK file (a 32-byte file
# on data/sr1, never the TPM); the sessions are clones of its @base-<n>.
PROJECT=sr1p
PROJDS=$WSROOT/$PROJECT
KEK=$SR1ROOT/kek.test
SVCARGS="-root $SR1ROOT -artifact-ds $SR1DS -ws-root $WSROOT -ws-mnt $WSMNT -kek file:$KEK"
SESSIONS="web kill hang"
ZCREATED=$STATE/sr1-zfs-created
wsmnt() { echo "$WSMNT/$PROJECT/$1"; }   # a session clone's mountpoint

# sr1_teardown -- remove the run's sessions, sandbox, task uid and snapshots (not the datasets, not the project).
# Idempotent.
sr1_teardown() {
	set +e
	if [ -x "$SVC" ] && [ -f "$SR1ROOT/lifecycle.db" ]; then
		for s in $SESSIONS; do
			[ -f "$SR1ROOT/state/svc/$s/session.json" ] || continue
			$SVC down -sess $s $SVCARGS >/dev/null 2>&1 && say "session $s down" || say "session $s: down failed (sandbox removal below kills it anyway)"
		done
	fi
	if [ -f "/yard/jails/$SBX/sandbox.json" ]; then
		$SP sbx-destroy -id $SBX -purge && say "sandbox $SBX destroyed"
	fi
	for j in $(jls -n name 2>/dev/null | sed -n "s/^name=\(ysbx_$SBX\(\..*\)\{0,1\}\)$/\1/p"); do
		jls -j "$j" jid >/dev/null 2>&1 && jail -r "$j" && say "removed leftover jail $j"
	done
	for s in $SESSIONS; do
		ds_exists "$PROJDS/$s" || continue
		for n in $(zfs list -H -t snapshot -o name -d 1 "$PROJDS/$s" | grep '@ysr1-'); do zfs destroy "$n" && say "destroyed $n"; done
	done
	ds_exists "$PROJDS/rk" && zfs destroy -r "$PROJDS/rk" && say "destroyed the rekey probe clone $PROJDS/rk"
	if [ -x "$SP" ]; then $SP task-end -task $TASK >/dev/null 2>&1; fi
	set -e
}
