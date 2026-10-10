#!/bin/sh
# sr3j-00-build.sh -- SR3J: build the spike's userland as the UNPRIVILEGED user (refuses root).
# PURPOSE   Stage everything sr3j-10-install.sh installs under /usr/local/yard/sr3j:
#           * bhyve + bhyvectl with BHYVE_SNAPSHOT and ops/sr3j/patches/*.diff applied (today one patch:
#             netgraph backend option datafd=N, an inherited, already-connected ng_socket data socket),
#             linked to a private static libvmmapi.a. Same source rules as ops/sr3/sr3-00-build.sh
#             (copied here from branch sr3-uefi, trimmed: no vmm.ko -- the snapshot vmm.ko from
#             /usr/local/yard/bhyve-snap stays the loaded module; same source tree, same ioctl ABI):
#             /usr/src must be the FreeBSD-src package of the running kernel; patched directories are
#             copied into a shadow tree $R/src (everything else symlinks to /usr/src), never patched in place.
#           * sr3j-launch (root helper: jail_attach + drop to the VM uid, optional netgraph data socket as fd 3)
#             and sr3j-probe (isolation probes), from ops/sr3j/src, cc -Werror.
#           * sr3j-chan (Go, host client + guest agent), cross-built on the Halo by tools/deploy-sr3j.sh and
#             copied to ops/sr3j/bin/sr3j-chan; only checked and staged here.
#           Output: $R/stage/usr/local/yard/sr3j (+ BUILDINFO, SHA256). $R defaults to ~/yard-sr3j.
# PREDICT   < 1 min (SR3 measured bhyve ~3 s, bhyvectl < 1 s, libvmmapi < 1 s with -j4). The patched bhyve's
#           usage text is unchanged; `bhyve -s 3,virtio-net,netgraph,datafd=1 x` must refuse fd 1 (< 3).
# CHANGES   Only files under $R. No root.
# UNDO      rm -rf ~/yard-sr3j
set -eu
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
[ "$(id -u)" != 0 ] || { echo "sr3j-00-build: run as the unprivileged user, not root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${SR3J_SRC:-/usr/src}
R=${SR3J_ROOT:-$HOME/yard-sr3j}
O=$R/obj
J=${SR3J_JOBS:-4}
ST=$R/stage/usr/local/yard/sr3j
L=$R/logs
mkdir -p "$O" "$R/lib" "$L"
say() { echo "[sr3j-00-build] $*"; }
die() { echo "[sr3j-00-build] FATAL: $*"; exit 1; }
now() { date +%s.%N; }
dt() { echo "$1 $2" | awk '{printf "%.1f", $2-$1}'; }

KVER=$(uname -v)
SRCV=$(pkg query %v FreeBSD-src 2>/dev/null || true)
KPV=$(pkg query %v FreeBSD-kernel-generic 2>/dev/null || true)
say "running kernel: $KVER; FreeBSD-src $SRCV, FreeBSD-kernel-generic $KPV"
if [ -z "$SRCV" ] || [ "$SRCV" != "$KPV" ]; then
	[ "${SR3J_FORCE_SRC:-}" = yes ] || die "source package '$SRCV' != kernel package '$KPV' (SR3J_FORCE_SRC=yes to override)"
fi
[ -x "$HERE/bin/sr3j-chan" ] || [ -f "$HERE/bin/sr3j-chan" ] || die "$HERE/bin/sr3j-chan missing (tools/deploy-sr3j.sh copies it)"
file "$HERE/bin/sr3j-chan" | grep -q 'FreeBSD' || die "$HERE/bin/sr3j-chan is not a FreeBSD binary: $(file "$HERE/bin/sr3j-chan")"

M="MAKEOBJDIRPREFIX=$O WITH_BHYVE_SNAPSHOT=yes WITHOUT_TESTS=yes"

# --- shadow source tree with the patches applied
PATCHES=$(ls "$HERE"/patches/*.diff 2>/dev/null || true)
[ -n "$PATCHES" ] || die "no patches in $HERE/patches"
USRC=$R/src
rm -rf "$USRC"; mkdir -p "$USRC"
pdirs=
for p in $PATCHES; do
	for f in $(sed -n 's|^+++ b/\([^[:space:]]*\).*|\1|p' "$p"); do
		case $f in
			usr.sbin/bhyve/*) d=usr.sbin/bhyve ;;
			usr.sbin/bhyvectl/*) d=usr.sbin/bhyvectl ;;
			lib/libvmmapi/*) d=lib/libvmmapi ;;
			*) die "patch $p touches $f (only usr.sbin/bhyve, usr.sbin/bhyvectl, lib/libvmmapi allowed)" ;;
		esac
		case " $pdirs " in *" $d "*) ;; *) pdirs="$pdirs $d" ;; esac
	done
done
for d in $pdirs; do
	parent=${d%/*}
	[ -d "$USRC/$parent" ] || {
		mkdir -p "$USRC/$parent"
		for e in "$SRC/$parent"/* "$SRC/$parent"/.[!.]*; do
			[ -e "$e" ] || continue
			b=${e##*/}; [ -e "$USRC/$parent/$b" ] || ln -s "$e" "$USRC/$parent/$b"
		done
	}
	rm -f "$USRC/$d"; cp -R "$SRC/$d" "$USRC/$d"
done
for e in "$SRC"/* "$SRC"/.[!.]*; do
	[ -e "$e" ] || continue
	b=${e##*/}; [ -e "$USRC/$b" ] || ln -s "$e" "$USRC/$b"
done
PINFO=
for p in $PATCHES; do
	patch -s -p1 -d "$USRC" -i "$p" || die "patch $p does not apply"
	PINFO="$PINFO ${p##*/}:$(sha256 -q "$p" | cut -c1-12)"
done
find "$USRC" -name '*.orig' -delete
PINFO=${PINFO# }
say "shadow source $USRC: patched$pdirs with $PINFO"

# --- libvmmapi.a (static, PIE-compatible)
t0=$(now)
make -C "$USRC/lib/libvmmapi" $M cleandir >/dev/null 2>&1 || true
env CFLAGS=-fPIE make -j"$J" -C "$USRC/lib/libvmmapi" $M libvmmapi.a >"$L/libvmmapi-build.log" 2>&1 || { tail -30 "$L/libvmmapi-build.log"; die "libvmmapi.a build failed"; }
cp "$(make -C "$USRC/lib/libvmmapi" $M -V .OBJDIR)/libvmmapi.a" "$R/lib/libvmmapi.a"
say "libvmmapi.a built in $(dt "$t0" "$(now)") s"

# --- bhyve, bhyvectl (CFLAGS/LDFLAGS via the environment, see ops/sr3/sr3-00-build.sh)
for d in bhyve bhyvectl; do
	t0=$(now)
	make -C "$USRC/usr.sbin/$d" $M SUBDIR= cleandir >/dev/null 2>&1 || true
	env CFLAGS="-I$USRC/lib/libvmmapi" LDFLAGS="-L$R/lib" make -j"$J" -C "$USRC/usr.sbin/$d" $M SUBDIR= >"$L/$d-build.log" 2>&1 ||
		{ tail -30 "$L/$d-build.log"; die "$d build failed"; }
	say "$d built in $(dt "$t0" "$(now)") s"
done
BH=$(make -C "$USRC/usr.sbin/bhyve" $M SUBDIR= -V .OBJDIR)/bhyve
BC=$(make -C "$USRC/usr.sbin/bhyvectl" $M SUBDIR= -V .OBJDIR)/bhyvectl
"$BC" 2>&1 | grep -q -- '--suspend' || die "bhyvectl usage lacks --suspend"
"$BH" -h 2>&1 | grep -q -- '-r file' || die "bhyve usage lacks -r"
for b in "$BH" "$BC"; do ldd "$b" | grep -q vmmapi && die "$b links base libvmmapi.so dynamically"; done
strings "$BH" | grep -q 'datafd excludes' || die "patched bhyve lacks the datafd option"

# --- C helpers
for p in sr3j-launch sr3j-probe; do
	lib=; [ $p = sr3j-launch ] && lib=-lnetgraph
	cc -O2 -Wall -Wextra -Werror -o "$R/$p" "$HERE/src/$p.c" $lib || die "$p failed to compile"
done
say "sr3j-launch, sr3j-probe compiled"

# --- stage
rm -rf "$ST"; mkdir -p "$ST"
install -m 0555 "$BH" "$ST/bhyve"
install -m 0555 "$BC" "$ST/bhyvectl"
install -m 0555 "$R/sr3j-launch" "$ST/sr3j-launch"
install -m 0555 "$R/sr3j-probe" "$ST/sr3j-probe"
install -m 0555 "$HERE/bin/sr3j-chan" "$ST/sr3j-chan"
{
	echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname) user=$(id -un)"
	echo "kernel=$KVER"
	echo "src_pkg=FreeBSD-src-$SRCV kernel_pkg=FreeBSD-kernel-generic-$KPV"
	echo "patches=$PINFO"
	echo "sr3j-chan=$(sha256 -q "$HERE/bin/sr3j-chan" | cut -c1-12) $(cat "$HERE/bin/sr3j-chan.rev" 2>/dev/null || echo rev=?)"
	echo "options=WITH_BHYVE_SNAPSHOT=yes; static libvmmapi; vmm.ko NOT built (the loaded /usr/local/yard/bhyve-snap/vmm.ko is used)"
	echo "cc=$(cc --version | head -1)"
} >"$ST/BUILDINFO"
(cd "$ST" && sha256 -r bhyve bhyvectl sr3j-launch sr3j-probe sr3j-chan BUILDINFO) >"$ST/SHA256"
cat "$ST/SHA256"
say "staged in $ST; next (root): cd ~/yard/ops/sr3j && sudo sh sr3j-10-install.sh"
