#!/bin/sh
# brk-40-registry.sh -- the B0 stand-in for yard-ctl's registry writer (NUC or Halo).
# USAGE     sudo sh brk-40-registry.sh publish      publish links.json as a new snapshot (serial + 1, issued now)
#           sudo sh brk-40-registry.sh heartbeat    re-publish every BRK_BEAT seconds (default 10) until killed;
#                                                   run it under daemon(8) / systemd beside the broker
#           sudo sh brk-40-registry.sh show
# WHY       The broker applies a snapshot only if its serial is higher than every one applied before (persisted
#           floors) and refuses everything once the newest snapshot is older than its lease (30 s): a writer that
#           stops or a file restored from a backup stops authorization instead of silently keeping or rolling it
#           back. links.json is the hand-maintained source: a JSON array of links, each with addr, incarnation
#           (32 lowercase hex = 128 random bits, NEW for every allocation of an address:
#           `openssl rand -hex 16`), peers, workload, epoch (never lowered), class.
# ENV       BRK_ETC (default /yard/data/brk/etc; Halo: /var/lib/yard-broker), BRK_USER (default _yardbrk;
#           Halo: yard-broker), BRK_BEAT.
# WRITES    $BRK_ETC/registry.json by rename (0600, BRK_USER); never edits links.json.
set -eu
ETC=${BRK_ETC:-/yard/data/brk/etc}
USR=${BRK_USER:-_yardbrk}
BEAT=${BRK_BEAT:-10}
REG=$ETC/registry.json
LINKS=$ETC/links.json
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -f "$LINKS" ] || { echo "$LINKS missing"; exit 1; }

publish() {
	cur=0
	[ -f "$REG" ] && cur=$(sed -n 's/.*"serial": *\([0-9][0-9]*\).*/\1/p' "$REG" | head -n 1)
	next=$(( ${cur:-0} + 1 ))
	tmp=$(mktemp "$ETC/.registry.XXXXXX")
	{ printf '{"serial": %s, "issued": "%s", "links": ' "$next" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; cat "$LINKS"; printf '}\n'; } >"$tmp"
	chown "$USR" "$tmp"
	chmod 0600 "$tmp"
	mv "$tmp" "$REG"
}

case ${1:-show} in
publish) publish; echo "published serial $(sed -n 's/.*"serial": *\([0-9][0-9]*\).*/\1/p' "$REG" | head -n 1)" ;;
heartbeat) while :; do publish; sleep "$BEAT"; done ;;
show) cat "$REG" ;;
*) echo "usage: publish | heartbeat | show"; exit 1 ;;
esac
