# lib.sh -- shared helpers for the yard N0 root scripts. Sourced by each script; never run directly.
#
# Conventions (same as the Phase 0 spikes):
#   * Run as root: `sudo sh <script> [args]`. Nothing here escalates by itself.
#   * Each script re-execs itself through a timestamping tee into $OPS/logs/<name>.log and chowns
#     logs/state back to the owner of the ops directory at the end.
#   * Idempotent: re-running a finished step reports "already done" and changes nothing.
#   * Every step has an -undo.sh twin. State the step needs for undo lives in $OPS/state/.
#   * rc.conf / loader.conf changes go through sysrc only.

export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
# OPS = the directory holding these scripts (no hard-coded home directory).
# Scripts in a subdirectory (tests/) export YARD_OPS before sourcing this file.
OPS=${YARD_OPS:-$(cd "$(dirname "$0")" && pwd)}
STATE=$OPS/state
OWNER=$(stat -f %Su "$OPS")
POOL=zroot
YDS=$POOL/yard          # top of the yard dataset tree
YMNT=/yard              # its mountpoint
ETC=/usr/local/etc/yard # installed yard config (tasks.conf, ...)

# step_wrap NAME "$0" "$@" -- call first thing in each script.
step_wrap() {
	NAME=$1; shift
	LOG=$OPS/logs/$NAME.log
	if [ -z "${YARD_OPS_INNER:-}" ]; then
		if [ "$(id -u)" != 0 ]; then echo "$NAME: must run as root (sudo sh $1)"; exit 1; fi
		mkdir -p "$OPS/logs" "$STATE"
		st=$STATE/.$NAME.rc
		echo "===== $NAME start $(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname) $(freebsd-version -ku | tr '\n' ' ') args=$*" >>"$LOG"
		( YARD_OPS_INNER=1 sh "$@"; echo $? >"$st" ) 2>&1 |
			while IFS= read -r l; do printf '%s %s\n' "$(date -u +%H:%M:%S)" "$l"; done | tee -a "$LOG"
		rc=$(cat "$st" 2>/dev/null || echo 99); rm -f "$st"
		echo "===== $NAME end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$LOG"
		chown -R "$OWNER" "$OPS/logs" "$STATE" 2>/dev/null || true
		echo "$NAME: exit $rc; log $LOG"
		exit "$rc"
	fi
	set -eu
}

say() { echo "[$NAME] $*"; }
die() { echo "[$NAME] FATAL: $*"; exit 1; }

# backup_once FILE -- keep the pre-yard copy of FILE as $STATE/orig/<path>; records absence too.
backup_once() {
	b=$STATE/orig$1
	[ -e "$b" ] || [ -e "$b.absent" ] && return 0
	mkdir -p "$(dirname "$b")"
	if [ -e "$1" ]; then cp -p "$1" "$b"; say "backed up $1 -> $b"; else : >"$b.absent"; say "recorded that $1 did not exist"; fi
}

# restore_orig FILE -- undo helper: put back the backed-up copy (or remove FILE if it did not exist).
restore_orig() {
	b=$STATE/orig$1
	if [ -e "$b" ]; then cp -p "$b" "$1"; rm -f "$b"; say "restored $1"
	elif [ -e "$b.absent" ]; then rm -f "$1" "$b.absent"; say "removed $1 (did not exist before)"
	else say "no backup of $1; left as is"; fi
}

# rc_set VAR VALUE [FILE] -- sysrc, remembering the previous value for undo ($STATE/rc.prev).
rc_set() {
	f=${3:-/etc/rc.conf}
	key="$f:$1"
	if ! grep -q "^$key=" "$STATE/rc.prev" 2>/dev/null; then
		# only a value literally in $f counts as "set" (sysrc would also report /etc/defaults values)
		if [ -f "$f" ] && grep -Eq "^[[:space:]]*$1=" "$f" && old=$(sysrc -f "$f" -n "$1" 2>/dev/null); then echo "$key=set:$old" >>"$STATE/rc.prev"
		else echo "$key=unset:" >>"$STATE/rc.prev"; fi
	fi
	sysrc -f "$f" "$1=$2"
}

# rc_restore VAR [FILE] -- undo helper for rc_set.
rc_restore() {
	f=${2:-/etc/rc.conf}
	key="$f:$1"
	line=$(grep "^$key=" "$STATE/rc.prev" 2>/dev/null | head -1) || true
	[ -n "$line" ] || { say "rc: $1 in $f was not changed by yard; left as is"; return 0; }
	v=${line#"$key="}
	case $v in
		unset:*) sysrc -f "$f" -x "$1" 2>/dev/null || true; say "rc: removed $1 from $f" ;;
		set:*) sysrc -f "$f" "$1=${v#set:}"; say "rc: restored $1=${v#set:} in $f" ;;
	esac
	grep -v "^$key=" "$STATE/rc.prev" >"$STATE/rc.prev.tmp" || true
	mv "$STATE/rc.prev.tmp" "$STATE/rc.prev"
}

ds_exists() { zfs list -H -o name "$1" >/dev/null 2>&1; }
