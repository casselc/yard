#!/bin/sh
# brk-30-secret.sh -- install one broker secret from stdin (NUC or Halo). The value is never echoed,
# logged or passed as an argument.
# USAGE     NUC:  sudo sh ops/broker/brk-30-secret.sh anthropic < /path/to/key
#           Halo: sudo BRK_SECRETS=/var/lib/yard-broker/secrets BRK_USER=yard-broker sh brk-30-secret.sh openai < key
# CHECKS    name [a-z0-9][a-z0-9._-]{0,63}; one non-empty line; written 0600 to a temp file in the same
#           directory and renamed (never a partial file); owner BRK_USER. Prints only the name and the size.
# UNDO      rm <secrets dir>/<name>
set -eu
umask 077
NAME=${1:-}
DIR=${BRK_SECRETS:-/yard/data/brk/secrets}
USR=${BRK_USER:-_yardbrk}
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
echo "$NAME" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,63}$' || { echo "bad secret name"; exit 1; }
[ -d "$DIR" ] || { echo "$DIR missing (install step first)"; exit 1; }
[ -t 0 ] && { echo "pipe the secret on stdin"; exit 1; }
tmp=$(mktemp "$DIR/.tmp.XXXXXX")
trap 'rm -f "$tmp"' EXIT
head -c 65536 >"$tmp"
lines=$(grep -c '' "$tmp" || true)
[ "$lines" -le 1 ] && [ -s "$tmp" ] || { echo "secret must be one non-empty line"; exit 1; }
chown "$USR" "$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$DIR/$NAME"
trap - EXIT
echo "installed secret $NAME ($(wc -c <"$DIR/$NAME" | tr -d ' ') bytes) in $DIR"
