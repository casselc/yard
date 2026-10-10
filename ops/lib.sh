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
# Encryption roots besides $YDS/data (decided 2026-10-07; CONTROL-PLANE.md "Workspace layout"). Their raw keys
# are files on the data encryption root, so one passphrase (yard-unlock.sh) opens all three.
WSROOT=$YDS/ws          # workspaces: ws/<project> (own encryption root, raw key held by yard-ctl), session clones
WSMNT=$YMNT/ws
VMROOT=${YARD_VMROOT:-$YDS/vmx}   # VM disks (n0-60-vmx.sh); YARD_VMROOT=$YDS/vm selects the old unencrypted tree
VMROOTMNT=$YMNT/${VMROOT#"$YDS"/}
KEYDIR=$YMNT/data/yard/keys       # 0700 root: ws.key, vmx.key (32 raw bytes, 0400)

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

# encroot_create DS KEYFILE [zfs create args...] -- a new encryption root with a raw key file on the data root.
# The key file is made once (32 bytes from /dev/random, 0400) and never overwritten. Idempotent: an existing DS
# must already be an encryption root.
encroot_create() {
	_d=$1 _k=$2; shift 2
	if ds_exists "$_d"; then
		[ "$(zfs get -H -o value encryptionroot "$_d")" = "$_d" ] || die "$_d exists but is not an encryption root"
		say "exists: $_d (encryption root, keystatus $(zfs get -H -o value keystatus "$_d"))"
		return 0
	fi
	[ "$(zfs get -H -o value keystatus $YDS/data 2>/dev/null)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"
	case $_k in "$KEYDIR"/*) ;; *) die "key file $_k is not under $KEYDIR" ;; esac
	[ -d "$KEYDIR" ] || { mkdir -p "$KEYDIR"; say "created $KEYDIR"; }
	chown root:wheel "$KEYDIR"; chmod 0700 "$KEYDIR"
	if [ ! -e "$_k" ]; then
		( umask 077; dd if=/dev/random of="$_k.tmp" bs=32 count=1 2>/dev/null ) || die "cannot write $_k"
		[ "$(stat -f %z "$_k.tmp")" = 32 ] || die "$_k.tmp is not 32 bytes"
		chmod 0400 "$_k.tmp"; mv "$_k.tmp" "$_k"; say "generated raw key $_k"
	fi
	[ "$(stat -f %z "$_k")" = 32 ] || die "$_k is not 32 raw bytes"
	zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation="file://$_k" "$@" "$_d"
	say "created encryption root $_d (key $_k)"
}

# encroot_load DS -- load DS's key from its keylocation if it exists, is encrypted and is not loaded yet.
encroot_load() {
	ds_exists "$1" || { say "$1 does not exist; nothing to load"; return 0; }
	[ "$(zfs get -H -o value encryption "$1")" != off ] || { say "$1 is not encrypted"; return 0; }
	if [ "$(zfs get -H -o value keystatus "$1")" = available ]; then say "$1: key already loaded"
	else zfs load-key "$1"; say "$1: key loaded from $(zfs get -H -o value keylocation "$1")"; fi
}

# vmroot_ready -- the precondition of the VM scripts: $VMROOT exists and, if encrypted, is unlocked.
vmroot_ready() {
	ds_exists "$VMROOT" || die "$VMROOT missing: run n0-60-vmx.sh (or YARD_VMROOT=$YDS/vm for the old tree)"
	if [ "$(zfs get -H -o value encryption "$VMROOT")" != off ]; then
		[ "$(zfs get -H -o value keystatus "$VMROOT")" = available ] || die "$VMROOT is locked: run yard-unlock.sh"
	fi
	[ "$(zfs get -H -o value mounted "$VMROOT")" = yes ] || die "$VMROOT is not mounted: run yard-unlock.sh"
}

# ---- dataset copy between encryption domains (n0-60-vmx.sh and its undo)
# ds_copy SRC DST TAG -- copy SRC (every snapshot, plus its current head as @TAG) to the new dataset DST with a
# NON-raw, non-replicated send: no properties travel, so DST inherits encryption, mountpoint, exec, ... from its
# new parent (a raw or -R/-p stream would carry encryption=off and local mountpoints). Full send of the oldest
# snapshot, then one -I incremental to @TAG. DST is mounted afterwards (at its inherited mountpoint).
ds_copy() {
	_s=$1 _t=$2 _g=$3
	ds_exists "$_t" && die "$_t exists already"
	zfs snapshot "$_s@$_g"
	_first=$(zfs list -H -t snapshot -o name -s createtxg -d 1 "$_s" | head -1)
	_first=${_first#*@}
	_t0=$(date +%s)
	zfs send "$_s@$_first" | zfs recv -u "$_t"
	[ "$_first" = "$_g" ] || zfs send -I "@$_first" "$_s@$_g" | zfs recv -u "$_t"
	zfs mount "$_t"
	say "copied $_s -> $_t ($(zfs get -H -o value used "$_s") used at the source, $(( $(date +%s) - _t0 )) s; target $(zfs get -H -o value encryption,encryptionroot,mountpoint "$_t" | tr '\n' ' '))"
}

# ds_manifest MOUNTPOINT TAG -- the tree of snapshot @TAG: every path with type, mode, owner, size, and the
# sha256 of every regular file (sparse files are hashed over their full apparent size).
ds_manifest() {
	( cd "$1/.zfs/snapshot/$2" && find . -exec stat -f '%HT %Sp %u %g %z %N' {} + | sort &&
		find . -type f -exec sha256 -r {} + | sort -k 2 )
}

# ds_verify SRC DST TAG -- same snapshot names (in creation order), same tree and contents at @TAG.
ds_verify() {
	_s=$1 _t=$2 _g=$3
	_a=$(zfs list -H -t snapshot -o name -s createtxg -d 1 "$_s" | sed 's/.*@//' | tr '\n' ' ')
	_b=$(zfs list -H -t snapshot -o name -s createtxg -d 1 "$_t" | sed 's/.*@//' | tr '\n' ' ')
	[ "$_a" = "$_b" ] || { say "snapshots differ: $_s [$_a] vs $_t [$_b]"; return 1; }
	_t0=$(date +%s)
	_ms=$(ds_manifest "$(zfs get -H -o value mountpoint "$_s")" "$_g") || { say "cannot read $_s@$_g"; return 1; }
	_mt=$(ds_manifest "$(zfs get -H -o value mountpoint "$_t")" "$_g") || { say "cannot read $_t@$_g"; return 1; }
	if [ "$_ms" != "$_mt" ]; then
		say "contents differ between $_s@$_g and $_t@$_g:"
		printf '%s\n' "$_ms" >"$STATE/.vmx-manifest.src"; printf '%s\n' "$_mt" >"$STATE/.vmx-manifest.dst"
		diff "$STATE/.vmx-manifest.src" "$STATE/.vmx-manifest.dst" | head -20
		return 1
	fi
	say "verified $_s == $_t: snapshots [$_a], $(printf '%s\n' "$_ms" | grep -c '^Regular') files hashed in $(( $(date +%s) - _t0 )) s"
}

# vm_quiet ROOTMNT -- refuse while a VM runs or anything but ZFS is mounted below ROOTMNT (jail roots in use).
vm_quiet() {
	[ -z "$(ls /dev/vmm 2>/dev/null)" ] || die "VMs exist (/dev/vmm: $(ls /dev/vmm | tr '\n' ' ')); stop them first"
	pgrep -x bhyve >/dev/null 2>&1 && die "a bhyve process runs"
	_m=$(mount -p | awk -v r="$1/" 'index($2, r) == 1 && $3 != "zfs" {print $2}')
	[ -z "$_m" ] || die "non-ZFS mounts below $1 (a jail in use?): $_m"
	return 0
}
