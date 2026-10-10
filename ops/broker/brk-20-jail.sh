#!/bin/sh
# brk-20-jail.sh -- run yard-broker B0 in the yard-brk jail on the NUC.
# USAGE     sudo sh ops/broker/brk-20-jail.sh start | sync | stop | status
# PURPOSE   yard-brk is a NON-VNET jail (decision for the user: CONTROL-PLANE puts services in VNET jails, but
#           the broker must bind the host side of every sandbox epair, which lives in the host's stack; pf's
#           per-sandbox rdr already targets those addresses). Its ip4.addr is the broker address
#           10.77.255.253 plus the host-side address of each link in links.json that exists on the host;
#           it can bind nothing else. Root: /yard/jails/brk/root (etc/ copies only), /.yard = the binary dir
#           (nullfs ro), /workspace = /yard/data/brk (nullfs rw). No devfs, securelevel 3, allow.* off.
#           The broker runs as _yardbrk via `jexec -u`, supervised by the HOST's daemon(8) (-r restarts),
#           stdout/stderr to /yard/data/brk/logs/broker.log.
#           A host daemon(8) also runs brk-40-registry.sh heartbeat (the snapshot lease is 30 s).
#   sync    recomputes ip4.addr from links.json (`jail -m`) and publishes a new snapshot; yard-spawn and
#           yard-ctl will do both per sandbox in B1.
# PREDICT   start: `jls -j yard-brk ip4.addr` -> 10.77.255.253[,10.77.N.1...]; broker.log shows no error;
#           `sockstat -4 -j yard-brk` lists a listener per link address present; under 2 s.
# UNDO      sudo sh ops/broker/brk-20-jail.sh stop
YARD_OPS=$(cd "$(dirname "$0")/.." && pwd); export YARD_OPS
. "$YARD_OPS/lib.sh"
step_wrap brk-20-jail "$0" "$@"
ACT=${1:-status}
D=$YMNT/data/brk
JR=$YMNT/jails/brk/root
BRK_ADDR=10.77.255.253
PIDF=$STATE/brk-daemon.pid

addrs() {
	list=$BRK_ADDR
	for a in $(grep -o '"addr": *"[0-9.]*:[0-9]*"' $D/etc/links.json 2>/dev/null | sed 's/.*"\([0-9.]*\):[0-9]*"/\1/' | sort -u); do
		if ifconfig -a inet | grep -q "inet $a "; then list="$list,$a"
		else say "link address $a not on any interface yet (sandbox not up): skipped"; fi
	done
	echo "$list"
}

mounted() { mount -p | awk '{print $2}' | grep -qx "$1"; }

case $ACT in
start)
	[ -x /usr/local/libexec/yard-brk/yard-broker ] || die "run brk-10-install.sh first"
	jls -j yard-brk jid >/dev/null 2>&1 && die "yard-brk already running"
	mounted $JR/.yard || mount -t nullfs -o ro /usr/local/libexec/yard-brk $JR/.yard
	mounted $JR/workspace || mount -t nullfs -o rw $D $JR/workspace
	jail -c name=yard-brk path=$JR host.hostname=yard-brk ip4.addr="$(addrs)" ip6=disable \
		securelevel=3 enforce_statfs=2 children.max=0 persist
	say "jail yard-brk jid $(jls -j yard-brk jid) ip4 $(jls -j yard-brk ip4.addr)"
	daemon -f -r -P $STATE/brk-beat.pid sh "$OPS/broker/brk-40-registry.sh" heartbeat
	daemon -f -r -P $PIDF -o $D/logs/broker.log \
		jexec -u _yardbrk yard-brk /.yard/yard-broker -config /workspace/etc/broker.json
	sleep 1
	tail -n 5 $D/logs/broker.log
	sockstat -4 -j yard-brk -l || true
	;;
sync)
	jls -j yard-brk jid >/dev/null 2>&1 || die "yard-brk not running"
	jail -m name=yard-brk ip4.addr="$(addrs)"
	BRK_ETC=$D/etc sh "$OPS/broker/brk-40-registry.sh" publish
	say "ip4.addr now $(jls -j yard-brk ip4.addr) (the broker binds new links at its next sync)"
	;;
stop)
	if [ -f $PIDF ]; then kill "$(cat $PIDF)" 2>/dev/null || true; sleep 1; rm -f $PIDF; say "stopped daemon"; fi
	if [ -f $STATE/brk-beat.pid ]; then kill "$(cat $STATE/brk-beat.pid)" 2>/dev/null || true; rm -f $STATE/brk-beat.pid; say "stopped registry heartbeat"; fi
	jls -j yard-brk jid >/dev/null 2>&1 && { jail -r yard-brk; say "removed jail"; }
	for m in $JR/workspace $JR/.yard; do mounted $m && umount $m; done
	say "stopped"
	;;
status)
	jls -j yard-brk jid name ip4.addr 2>/dev/null || say "yard-brk not running"
	[ -f $PIDF ] && say "daemon pid $(cat $PIDF)"
	sockstat -4 -j yard-brk -l 2>/dev/null || true
	tail -n 5 $D/logs/broker.log 2>/dev/null || true
	;;
*) die "usage: start | sync | stop | status" ;;
esac
