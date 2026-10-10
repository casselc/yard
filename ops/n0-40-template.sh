#!/bin/sh
# n0-40-template.sh -- N0: the read-only jail base template (pkgbase) at zroot/yard/tmpl/base.
# PURPOSE   yard jails and per-call child jails nullfs-mount this template read-only as their root.
#           It is installed with pkg -r from the SAME pkgbase repo the host tracks (base_latest), pinned
#           to the host's OSVERSION, so template userland matches the 15.1-STABLE kernel. Adds the two
#           empty mountpoints yard-spawn needs inside every root: /.yard (tmpfs, per-call roots) and
#           /workspace (task workspace).
#           Phase 0 traps carried over: with -r, pkg resolves `fingerprints` inside the rootdir (keys are
#           copied in), and a forced ABI makes pkg guess OSVERSION (so OSVERSION is passed explicitly).
# PREDICT   ~48 packages, ~25 MiB download, ~120-130 MiB installed, 40-120 s (Phase 0 spike 20 measured
#           the 15.1-p4 equivalent). USERLAND_VERSION reports 15.1-STABLE. Snapshot @base, readonly=on.
# CHANGES   Dataset zroot/yard/tmpl/base (+@base). Writes ops/state/pkgbase-repo/base.conf. Nothing is
#           installed on the host itself. Needs network to pkg.FreeBSD.org.
# UNDO      sudo sh n0-40-template-undo.sh   (destroys zroot/yard/tmpl/base)
# RUNTIME   1-3 min.
. "$(dirname "$0")/lib.sh"
step_wrap n0-40-template "$0" "$@"
ds_exists $YDS/tmpl || die "$YDS/tmpl missing: run n0-10-zfs.sh first"
TDS=$YDS/tmpl/base; T=$YMNT/tmpl/base
if [ -f $T/.yard-template-ok ]; then say "template present: $(cat $T/.yard-template-ok)"; exit 0; fi
ds_exists $TDS || zfs create -o setuid=off $TDS
zfs set readonly=off $TDS
OSV=$(uname -U)
R=$STATE/pkgbase-repo; mkdir -p $R
cat >$R/base.conf <<'CONF'
FreeBSD-base: {
  url: "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/base_latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
CONF
mkdir -p $T/usr/share/keys
cp -R /usr/share/keys/pkg $T/usr/share/keys/
t0=$(date +%s)
pkg -R $R -r $T -o ABI=FreeBSD:15:amd64 -o OSVERSION=$OSV -o ASSUME_ALWAYS_YES=yes \
	install -y -r FreeBSD-base FreeBSD-set-minimal-jail
say "pkg install took $(( $(date +%s) - t0 )) s"
UV=$(sed -n 's/^USERLAND_VERSION="\(.*\)"/\1/p' $T/bin/freebsd-version)
say "template userland: $UV (host kernel $(freebsd-version -k))"
for f in /usr/bin/true /bin/sh /bin/sleep /bin/dd /usr/bin/id /usr/bin/fetch /sbin/ifconfig; do
	[ -e $T$f ] && say "has $f" || say "MISSING $f"
done
mkdir -p $T/.yard $T/workspace $T/dev $T/tmp
chmod 0700 $T/.yard
touch $T/etc/rc.conf
echo "pkgbase base_latest OSVERSION=$OSV $UV $(date -u +%FT%TZ) pkgs=$(pkg -r $T info 2>/dev/null | wc -l | tr -d ' ')" >$T/.yard-template-ok
zfs snapshot $TDS@base
zfs set readonly=on $TDS
zfs list -o name,used,refer,compressratio,readonly $TDS $TDS@base
say "OK"
