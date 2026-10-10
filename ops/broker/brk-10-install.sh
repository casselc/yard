#!/bin/sh
# brk-10-install.sh -- Broker B0 on the NUC: account, data dataset, binary, config, broker address.
# USAGE     sudo sh ops/broker/brk-10-install.sh          (after tools/deploy-nuc.sh copied bin/yard-broker)
# PURPOSE   Prepares the yard-brk jail's pieces (brk-20-jail.sh creates and runs it):
#             account   _yardbrk uid/gid 832 (after _sign 830, _yard 831), nologin, no home
#             dataset   zroot/yard/data/brk (inherits the data root's encryption; exec=off) at /yard/data/brk:
#                       etc/ (broker.json, links.json, registry.json), secrets/ (one 0600 file per key), logs/, state/
#                       (floors.json: the broker's persisted serial/epoch/incarnation floors) -- all 0700 _yardbrk
#             binary    /usr/local/libexec/yard-brk/yard-broker (root 0555; nullfs'd read-only into the jail)
#             address   lo1 alias 10.77.255.253/32: the broker jail's own (first) address, the source of its
#                       outbound connections (NATed by the base ruleset's yard_nets rule). Link listeners bind
#                       the sandboxes' host-side epair addresses, added to the jail by brk-20-jail.sh sync.
#             jail root /yard/jails/brk/root with etc/{resolv.conf,hosts,ssl/cert.pem} copied from the host
#                       (a static Go binary needs nothing else: no shell, no devfs).
# PREDICT   `id _yardbrk` uid 832; `zfs get -H encryptionroot zroot/yard/data/brk` -> zroot/yard/data;
#           `/usr/local/libexec/yard-brk/yard-broker -check -config /yard/data/brk/etc/broker.json` fails only on
#           the in-jail paths (it is meant to run inside the jail); under 5 s.
# CHANGES   /etc/master.passwd + /etc/group (one account), one dataset, one directory tree, lo1 (runtime only:
#           re-run after a reboot until yard-ctl owns this), /usr/local/libexec/yard-brk.
# UNDO      sudo sh ops/broker/brk-10-install-undo.sh   (BRK_DESTROY_DATA=yes also destroys the dataset)
# NOTHING   is started here. No secret is written here (brk-30-secret.sh does that, from stdin).
YARD_OPS=$(cd "$(dirname "$0")/.." && pwd); export YARD_OPS
. "$YARD_OPS/lib.sh"
step_wrap brk-10-install "$0" "$@"
BIN_SRC=$OPS/../bin/yard-broker
LIBX=/usr/local/libexec/yard-brk
DDS=$YDS/data/brk; D=$YMNT/data/brk
JR=$YMNT/jails/brk/root
BRK_ADDR=10.77.255.253

[ -x "$BIN_SRC" ] || die "$BIN_SRC missing: run tools/deploy-nuc.sh on the Halo first"
[ "$(zfs get -H -o value keystatus $YDS/data 2>/dev/null)" = available ] || die "$YDS/data is locked: run yard-unlock.sh"

if id _yardbrk >/dev/null 2>&1; then say "account _yardbrk present (uid $(id -u _yardbrk))"
else
	pw groupadd _yardbrk -g 832
	pw useradd _yardbrk -u 832 -g 832 -d /nonexistent -s /usr/sbin/nologin -c "yard broker"
	say "created _yardbrk uid 832"
fi

ds_exists $DDS || { zfs create -o exec=off -o setuid=off $DDS; say "created $DDS"; }
for d in etc secrets logs state; do install -d -m 0700 -o _yardbrk -g _yardbrk $D/$d; done
if [ ! -e $D/etc/broker.json ]; then
	install -m 0600 -o _yardbrk -g _yardbrk "$OPS/broker/broker.nuc.json.in" $D/etc/broker.json
	say "installed $D/etc/broker.json (halo_url empty: halo routes off until G7 + B1 mTLS; halo_secret name: halo)"
else say "$D/etc/broker.json kept"; fi
if [ ! -e $D/etc/links.json ]; then
	printf '[]\n' >$D/etc/links.json; chown _yardbrk:_yardbrk $D/etc/links.json; chmod 0600 $D/etc/links.json
	say "installed an empty $D/etc/links.json"
fi
BRK_ETC=$D/etc sh "$OPS/broker/brk-40-registry.sh" publish

install -d -m 0755 -o root -g wheel $LIBX
install -m 0555 -o root -g wheel "$BIN_SRC" $LIBX/yard-broker
say "installed $LIBX/yard-broker ($(sha256 -q $LIBX/yard-broker | cut -c1-16))"
# floors: created ONCE for a new install; a missing file later means recovery, not first boot
if [ ! -e $D/state/floors.json ]; then
	tmpcfg=$(mktemp)
	printf '{"trust_domain":"home.arpa","floors_file":"%s"}\n' "$D/state/floors.json" >"$tmpcfg"
	$LIBX/yard-broker -config "$tmpcfg" -init-floors
	rm -f "$tmpcfg"
	chown _yardbrk:_yardbrk $D/state/floors.json
	say "initialised $D/state/floors.json"
else say "$D/state/floors.json kept (never re-initialised)"; fi

ifconfig lo1 >/dev/null 2>&1 || { ifconfig lo1 create; say "created lo1"; }
if ifconfig lo1 inet | grep -q "inet $BRK_ADDR "; then say "lo1 has $BRK_ADDR"
else ifconfig lo1 inet $BRK_ADDR/32 alias; say "lo1 alias $BRK_ADDR/32"; fi

install -d -m 0755 $JR $JR/etc $JR/etc/ssl $JR/.yard $JR/workspace $JR/tmp
cp /etc/resolv.conf /etc/hosts $JR/etc/
cp /etc/ssl/cert.pem $JR/etc/ssl/cert.pem
say "jail root $JR ready ($(ls $JR/etc | tr '\n' ' '))"
say "next: brk-30-secret.sh <name> < keyfile (anthropic, openai), then brk-20-jail.sh start"
