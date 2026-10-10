#!/bin/sh
# halo-10-install.sh -- Broker B0 on the Halo (Linux, per node): a hardened systemd service.
# USAGE     cd <yard checkout> && . ./env.sh && CGO_ENABLED=0 go build -trimpath -o out/yard-broker ./cmd/yard-broker
#           sudo sh ops/broker/halo-10-install.sh [out/yard-broker]
# PURPOSE   The Halo's sandboxes (Firecracker taps, SR2; none exist yet) reach their node's broker only. halo_serve
#           stays on 127.0.0.1:8080 and only this broker reaches it from sandboxes.
#             user      yard-broker (system, nologin), the only reader of /var/lib/yard-broker/secrets (0700)
#             files     /usr/local/libexec/yard-broker (root 0555), /etc/yard/broker.json (root:yard-broker 0640),
#                       /var/lib/yard-broker/{links.json,secrets/,logs/}
#             unit      yard-broker.service: NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp,
#                       PrivateDevices, no capabilities (listeners use ports > 1024), AF_INET/AF_INET6/AF_UNIX only,
#                       SystemCallFilter=@system-service, MemoryMax=512M, Restart=on-failure.
#           Link addresses are the host side of each sandbox tap; the per-tap DNAT of 169.254.169.254 and
#           169.254.170.2 port 80 to <tap host addr>:8099 belongs to yard-node (nftables, REPORT 5.4), not here.
# PREDICT   `systemctl is-active yard-broker` -> active; journal shows no listener (links.json is empty).
# UNDO      sudo sh ops/broker/halo-10-install-undo.sh   (keeps /var/lib/yard-broker unless BRK_DESTROY_DATA=yes)
# NOTHING   here reads, writes or prints a key; use brk-30-secret.sh with BRK_SECRETS/BRK_USER (header there).
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/../../out/yard-broker}
[ -x "$BIN" ] || { echo "$BIN missing: build it first (see USAGE)"; exit 1; }
id yard-broker >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin yard-broker
install -d -m 0755 /usr/local/libexec /etc/yard
install -m 0555 -o root -g root "$BIN" /usr/local/libexec/yard-broker
install -d -m 0700 -o yard-broker -g yard-broker /var/lib/yard-broker /var/lib/yard-broker/secrets /var/lib/yard-broker/logs /var/lib/yard-broker/state
[ -e /etc/yard/broker.json ] || install -m 0640 -o root -g yard-broker "$HERE/broker.halo.json.in" /etc/yard/broker.json
[ -e /var/lib/yard-broker/links.json ] || { printf '[]\n' >/var/lib/yard-broker/links.json; chown yard-broker:yard-broker /var/lib/yard-broker/links.json; chmod 0600 /var/lib/yard-broker/links.json; }
install -m 0555 -o root -g root "$HERE/brk-40-registry.sh" /usr/local/libexec/yard-broker-registry.sh
BRK_ETC=/var/lib/yard-broker BRK_USER=yard-broker sh /usr/local/libexec/yard-broker-registry.sh publish
cat >/etc/systemd/system/yard-broker-registry.service <<'UNIT'
[Unit]
Description=yard-broker B0 registry heartbeat (stand-in for yard-ctl's writer)
Before=yard-broker.service

[Service]
Environment=BRK_ETC=/var/lib/yard-broker BRK_USER=yard-broker BRK_BEAT=10
ExecStart=/bin/sh /usr/local/libexec/yard-broker-registry.sh heartbeat
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/yard-broker.service <<'UNIT'
[Unit]
Description=yard-broker B0 (per-node egress and credential broker)
After=network-online.target
Wants=network-online.target

[Service]
User=yard-broker
Group=yard-broker
ExecStart=/usr/local/libexec/yard-broker -config /etc/yard/broker.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
ReadWritePaths=/var/lib/yard-broker
UMask=0077
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
# floors: created ONCE for a new install; a missing file later means recovery, not first boot
[ -e /var/lib/yard-broker/state/floors.json ] || runuser -u yard-broker -- /usr/local/libexec/yard-broker -config /etc/yard/broker.json -init-floors
/usr/local/libexec/yard-broker -config /etc/yard/broker.json -check >/dev/null || { echo "config check failed"; exit 1; }
systemctl enable --now yard-broker-registry yard-broker
sleep 1
systemctl --no-pager --lines=5 status yard-broker || true
