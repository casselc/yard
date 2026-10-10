#!/bin/sh
# halo-10-install-undo.sh -- undo halo-10-install.sh. Keeps /var/lib/yard-broker (secrets, audit) unless
# BRK_DESTROY_DATA=yes.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
systemctl disable --now yard-broker yard-broker-registry 2>/dev/null || true
rm -f /etc/systemd/system/yard-broker.service /etc/systemd/system/yard-broker-registry.service /usr/local/libexec/yard-broker-registry.sh
systemctl daemon-reload
rm -f /usr/local/libexec/yard-broker /etc/yard/broker.json
rmdir /etc/yard 2>/dev/null || true
if [ "${BRK_DESTROY_DATA:-no}" = yes ]; then rm -rf /var/lib/yard-broker; echo "removed /var/lib/yard-broker"; else echo "kept /var/lib/yard-broker"; fi
id yard-broker >/dev/null 2>&1 && userdel yard-broker
echo "yard-broker removed"
