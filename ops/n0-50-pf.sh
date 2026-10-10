#!/bin/sh
# n0-50-pf.sh -- N0: persistent pf with a dead-man rollback timer (CONTROL-PLANE §4).
# USAGE     sudo sh n0-50-pf.sh apply [MINUTES]   load + enable the ruleset NOW (runtime only), start a
#                                                 rollback timer (default 5 min)
#           sudo sh n0-50-pf.sh confirm           from a NEW ssh session: stop the timer, install /etc/pf.conf,
#                                                 sysrc pf_enable/pflog_enable (persistent from here on)
#           sudo sh n0-50-pf.sh status            show timer, pf state, rule counters
#           sudo sh n0-50-pf.sh rollback          revert to the pre-yard pf state now (what the timer does)
# PURPOSE   Base ruleset (pf/pf.conf.in): skip lo0 + tailscale0; on the LAN interface allow inbound SSH
#           from the LAN network, Tailscale direct UDP, DHCP, ICMP and ICMPv6; all host egress stateful;
#           everything else blocked and logged; nat for jail/VM nets; rdr-anchor/nat-anchor/anchor "yard/*".
#           The LAN interface is taken from the default route (expected igc0, 192.168.1.72/22) and the
#           ruleset is syntax-checked with `pfctl -nf` before anything is loaded.
# SAFETY    Lockout guards: (1) tailscale0 is skipped, so Tailscale SSH cannot be filtered; (2) LAN SSH is
#           allowed with sloppy state so an already-open LAN session survives; (3) `apply` changes no
#           file and no rc.conf setting -- a reboot reverts it; (4) a detached daemon(8) timer reverts pf
#           to its previous state after MINUTES unless `confirm` runs first. Confirm from a NEW session
#           (ideally one over the LAN and one over Tailscale) to prove new connections still work.
# PREDICT   apply: pfctl -nf passes; pf Enabled; `pfctl -sr` shows 7 filter rules + anchor "yard/*"; this SSH
#           session survives; a new `ssh chuck@100.64.0.10` works (tailscale0 skipped) and LAN ssh to
#           192.168.1.72 works. 80%: `pfctl -s info` shows a few blocked packets within minutes (LAN
#           broadcast/mDNS noise). confirm: rc.conf pf_enable=YES pf_rules=/etc/pf.conf pflog_enable=YES.
# CHANGES   apply: loads pf.ko (+pflog.ko at confirm), enables pf with the yard ruleset. confirm: writes
#           /etc/pf.conf (none existed: recorded), rc.conf pf_enable/pf_rules/pflog_enable.
# UNDO      sudo sh n0-50-pf-undo.sh   (rollback + remove /etc/pf.conf + restore rc.conf values)
# RUNTIME   seconds (+ the timer).
. "$(dirname "$0")/lib.sh"
step_wrap n0-50-pf "$0" "$@"
ACT=${1:-status}
REND=$STATE/pf.conf.rendered
PIDF=$STATE/pf-timer.pid
TS_PORT=$(sysrc -n tailscaled_port 2>/dev/null || echo 41641)

render() {
	EXT=$(route -n get -inet default 2>/dev/null | awk '/interface:/{print $2}')
	[ -n "$EXT" ] || die "no IPv4 default route; cannot pick the LAN interface"
	ifconfig "$EXT" >/dev/null || die "default-route interface $EXT not found"
	case $EXT in tailscale*|lo*|epair*|tap*|bridge*) die "default route is via $EXT, expected a physical NIC" ;; esac
	ADDR=$(ifconfig "$EXT" inet | awk '/inet /{print $2"/"$4; exit}')
	say "LAN interface $EXT ($ADDR), tailscaled port $TS_PORT"
	[ "$EXT" = igc0 ] || say "WARNING: expected igc0 (inspected 2026-10-07); continuing with $EXT"
	sed -e "s/@EXT_IF@/$EXT/" -e "s/@TS_PORT@/$TS_PORT/" "$OPS/pf/pf.conf.in" >"$REND"
}

timer_alive() { [ -f "$PIDF" ] && pgrep -F "$PIDF" >/dev/null 2>&1; }

rollback() {
	# Revert to the state recorded by `apply` before it touched pf.
	prev=$(cat "$STATE/pf-prev" 2>/dev/null || echo "unknown")
	say "rolling back pf (previous state: $prev)"
	case $prev in
		enabled-with-etc-pf.conf) if pfctl -f "$STATE/orig/etc/pf.conf"; then say "reloaded the previous /etc/pf.conf"; else pfctl -q -d || true; say "previous ruleset failed to load: pf DISABLED"; fi ;;
		*) pfctl -q -d 2>/dev/null || true; pfctl -q -F all 2>/dev/null || true; say "pf disabled and flushed" ;;
	esac
	if grep -q '^pf$' "$STATE/kld-loaded" 2>/dev/null && [ "$prev" != enabled-with-etc-pf.conf ]; then
		kldunload pf 2>/dev/null && { say "unloaded pf.ko"; sed -i '' '/^pf$/d' "$STATE/kld-loaded"; }
	fi
	rm -f "$STATE/pf-applied"
}

case $ACT in
apply)
	MIN=${2:-5}
	[ ! -f "$STATE/pf-confirmed" ] || { say "already confirmed and persistent; re-apply = edit pf/pf.conf.in, then: pfctl -nf + pfctl -f /etc/pf.conf"; }
	timer_alive && die "a rollback timer is already running (pid $(cat $PIDF)); confirm or rollback first"
	render
	if [ ! -f "$STATE/pf-prev" ]; then
		if kldstat -q -m pf && pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
			[ -f /etc/pf.conf ] || die "pf is enabled with a ruleset that is not /etc/pf.conf; not touching it"
			backup_once /etc/pf.conf; echo enabled-with-etc-pf.conf >"$STATE/pf-prev"
		else echo disabled >"$STATE/pf-prev"; fi
	fi
	say "previous pf state: $(cat "$STATE/pf-prev")"
	kldstat -q -m pf || { kldload pf && echo pf >>"$STATE/kld-loaded"; say "loaded pf.ko"; }
	pfctl -nf "$REND" || die "ruleset failed pfctl -nf; nothing loaded"
	say "ruleset syntax OK"
	# arm the dead-man timer BEFORE loading, detached from this session
	daemon -f -p "$PIDF" sh -c "sleep $((MIN * 60)); [ -f '$STATE/pf-confirmed' ] || YARD_OPS_INNER=1 sh '$OPS/n0-50-pf.sh' _timer-fired >>'$OPS/logs/n0-50-pf.log' 2>&1"
	sleep 1; timer_alive || die "could not start the rollback timer; nothing loaded"
	say "rollback timer armed: pid $(cat $PIDF), fires in $MIN min"
	pfctl -f "$REND"
	pfctl -s info | grep -q 'Status: Enabled' || pfctl -e
	date -u +%FT%TZ >"$STATE/pf-applied"
	pfctl -s info | head -3
	pfctl -sr
	say "APPLIED (runtime only). Now open a NEW ssh session (Tailscale and, if you can, LAN 192.168.1.72)"
	say "and run: sudo sh $OPS/n0-50-pf.sh confirm   -- within $MIN minutes, or pf rolls back."
	;;
confirm)
	[ -f "$STATE/pf-applied" ] || die "nothing applied (or already rolled back); run apply first"
	if timer_alive; then pkill -P "$(cat "$PIDF")" 2>/dev/null || true; kill "$(cat "$PIDF")" 2>/dev/null || true; fi
	touch "$STATE/pf-confirmed"; rm -f "$PIDF"
	say "rollback timer stopped"
	backup_once /etc/pf.conf
	install -m 0600 -o root -g wheel "$REND" /etc/pf.conf
	pfctl -nf /etc/pf.conf
	rc_set pf_enable YES
	rc_set pf_rules /etc/pf.conf
	rc_set pflog_enable YES
	service pflog start 2>/dev/null || service pflog restart
	say "persistent: /etc/pf.conf installed, pf_enable/pflog_enable set. Blocked packets: tcpdump -n -e -ttt -i pflog0"
	;;
_timer-fired)
	NAME=n0-50-pf; say "$(date -u +%FT%TZ) rollback timer fired without confirm"
	rollback; rm -f "$PIDF"
	;;
rollback)
	if timer_alive; then pkill -P "$(cat "$PIDF")" 2>/dev/null || true; kill "$(cat "$PIDF")" 2>/dev/null || true; rm -f "$PIDF"; fi
	[ -f "$STATE/pf-confirmed" ] && say "note: pf was confirmed; this reverts runtime only -- use n0-50-pf-undo.sh to undo persistently"
	rollback
	;;
status)
	if timer_alive; then say "rollback timer running: pid $(cat $PIDF)"; else say "no rollback timer"; fi
	[ -f "$STATE/pf-confirmed" ] && say "confirmed (persistent)" || say "not confirmed"
	pfctl -s info 2>/dev/null | head -12 || say "pf not loaded"
	pfctl -v -s rules 2>/dev/null | grep -A1 -E '^(block|pass)' | head -40 || true
	;;
*) die "unknown action $ACT (apply|confirm|status|rollback)" ;;
esac
say "OK"
