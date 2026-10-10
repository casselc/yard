#!/bin/sh
# sr3-00-build.sh -- SR3: build snapshot-capable vmm.ko, bhyve, bhyvectl and a static libvmmapi.
# PURPOSE   HARNESS.md "SR3: bhyve snapshot on the NUC". Runs as the UNPRIVILEGED user (refuses root).
#           Source: /usr/src from the FreeBSD-src pkgbase package, which must carry the same snapshot
#           version as the running FreeBSD-kernel-generic package (checked here). On 2026-10-07 the
#           relevant 600 files (sys/amd64/vmm, sys/dev/vmm, sys/modules/vmm, sys/conf, sys/amd64/include,
#           share/mk, usr.sbin/bhyve{,ctl}, lib/libvmmapi) were byte-identical to git fabb224f2f15
#           (the commit in `uname -v`).
#           * vmm.ko: a private kernel config "include GENERIC + options BHYVE_SNAPSHOT" is run through
#             config(8) only to get GENERIC's opt_*.h (plus opt_bhyve_snapshot.h); the module is then
#             built tied to it (KERNBUILDDIR), so opt_global.h matches GENERIC and kmod.mk adds
#             vmm_snapshot.c via KERN_OPTS. No kernel is built.
#           * libvmmapi: static archive only (-fPIE so it links into PIE executables); the amd64
#             Makefile.inc already defines WITH_VMMAPI_SNAPSHOT.
#           * bhyve, bhyvectl: WITH_BHYVE_SNAPSHOT=yes (-DBHYVE_SNAPSHOT, snapshot.c, libucl/libxo),
#             linked against the private libvmmapi.a (no runtime dependency on base libvmmapi.so).
#             bhyve's slirp helper subdir is skipped (SUBDIR=).
#           Output is staged at $HOME/yard-sr3/stage/usr/local/yard/bhyve-snap (+ BUILDINFO, SHA256)
#           for sr3-10-install.sh. Objects go to $HOME/yard-sr3/obj (MAKEOBJDIRPREFIX).
# PATCHES   SR3_PATCHES="<diff> ..." (unified diffs against fabb224f2f15, -p1 paths, e.g. ops/sr3/patches/*.diff)
#           with SR3_VARIANT=<name> (required then): the patched directories are copied into a shadow
#           source tree $HOME/yard-sr3/src-<name> (every other top-level entry is a symlink to /usr/src, so
#           SRCTOP stays /usr/src; checked 2026-10-07) and patched there; /usr/src is never modified. Only
#           usr.sbin/bhyve, usr.sbin/bhyvectl, lib/libvmmapi, sys/amd64/vmm and sys/dev/vmm may be patched.
#           Output is staged at $HOME/yard-sr3/stage/usr/local/yard/bhyve-snap-<name>, BUILDINFO lists the
#           patches + sha256 and says where the variant's vmm.ko comes from:
#           * kmod=base: no patch touches sys/; vmm.ko is built from /usr/src unchanged, and the variant
#             runs on the base build's module (/usr/local/yard/bhyve-snap/vmm.ko; this copy is unused).
#           * kmod=own: a patch touches sys/amd64/vmm or sys/dev/vmm (e.g. 0003, variant p3). vmm.ko is
#             built the same way (GENERIC + BHYVE_SNAPSHOT opt headers) from the shadow tree, with
#             SRCTOP/SYSDIR set to it (share/mk would resolve SRCTOP back to /usr/src) and its own object
#             dir $HOME/yard-sr3/obj-<name>; the build checks that make resolved both to the shadow tree
#             and that every patched .c file was compiled from there. sr3-20-vmm.sh with the same
#             SR3_VARIANT loads it, and sr3-30-cycles.sh then runs only on it.
# PREDICT   < 1 min on the N150 (measured 2026-10-07: vmm 3 s, libvmmapi <1 s, bhyve ~3 s, bhyvectl <1 s
#           with -j4 from a warm cache).
# CHANGES   Only files under $HOME/yard-sr3. No root, nothing outside the home directory.
# UNDO      rm -rf "$HOME/yard-sr3"
# RUNTIME   about a minute.
set -eu
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
[ "$(id -u)" != 0 ] || { echo "sr3-00-build: run as the unprivileged user, not root"; exit 1; }
SRC=${SR3_SRC:-/usr/src}
R=${SR3_ROOT:-$HOME/yard-sr3}
O=$R/obj
KB=$R/kbuild/GENERIC-SNAP
VARIANT=${SR3_VARIANT:-}
PATCHES=${SR3_PATCHES:-}
case $VARIANT in *[!a-z0-9]*) echo "[sr3-00-build] FATAL: SR3_VARIANT must be [a-z0-9]+"; exit 1 ;; esac
if [ -n "$PATCHES" ] && [ -z "$VARIANT" ]; then echo "[sr3-00-build] FATAL: SR3_PATCHES needs SR3_VARIANT"; exit 1; fi
ST=$R/stage/usr/local/yard/bhyve-snap${VARIANT:+-$VARIANT}
L=$R/logs${VARIANT:+-$VARIANT}
J=${SR3_JOBS:-4}
mkdir -p "$R/conf" "$R/kbuild" "$O" "$R/lib" "$L"
say() { echo "[sr3-00-build] $*"; }
die() { echo "[sr3-00-build] FATAL: $*"; exit 1; }
now() { date +%s.%N; }
dt() { echo "$1 $2" | awk '{printf "%.1f", $2-$1}'; }

# --- source must match the running kernel
KVER=$(uname -v)
SRCV=$(pkg query %v FreeBSD-src 2>/dev/null || true)
KPV=$(pkg query %v FreeBSD-kernel-generic 2>/dev/null || true)
say "running kernel: $KVER"
say "FreeBSD-src $SRCV, FreeBSD-src-sys $(pkg query %v FreeBSD-src-sys 2>/dev/null || true), FreeBSD-kernel-generic $KPV"
if [ -z "$SRCV" ] || [ "$SRCV" != "$KPV" ]; then
	[ "${SR3_FORCE_SRC:-}" = yes ] || die "source package version '$SRCV' != kernel package version '$KPV' (SR3_FORCE_SRC=yes to override)"
fi
[ -f "$SRC/sys/amd64/vmm/vmm_snapshot.c" ] || die "$SRC has no sys/amd64/vmm/vmm_snapshot.c"

M="MAKEOBJDIRPREFIX=$O WITH_BHYVE_SNAPSHOT=yes WITHOUT_TESTS=yes"

# --- source: /usr/src, or a shadow tree with the patched directories copied (SR3_PATCHES)
USRC=$SRC
PINFO=none
KPATCH=no; kfiles=
if [ -n "$PATCHES" ]; then
	USRC=$R/src-$VARIANT
	rm -rf "$USRC"; mkdir -p "$USRC"
	pdirs=
	for p in $PATCHES; do
		[ -f "$p" ] || die "patch $p not found"
		for f in $(sed -n 's|^+++ b/\([^[:space:]]*\).*|\1|p' "$p"); do
			case $f in
				usr.sbin/bhyve/*) d=usr.sbin/bhyve ;;
				usr.sbin/bhyvectl/*) d=usr.sbin/bhyvectl ;;
				lib/libvmmapi/*) d=lib/libvmmapi ;;
				sys/amd64/vmm/*) d=sys/amd64/vmm; KPATCH=yes; kfiles="$kfiles $f" ;;
				sys/dev/vmm/*) d=sys/dev/vmm; KPATCH=yes; kfiles="$kfiles $f" ;;
				*) die "patch $p touches $f (only usr.sbin/bhyve, usr.sbin/bhyvectl, lib/libvmmapi, sys/amd64/vmm, sys/dev/vmm allowed)" ;;
			esac
			case " $pdirs " in *" $d "*) ;; *) pdirs="$pdirs $d" ;; esac
		done
	done
	[ -n "$pdirs" ] || die "no '+++ b/' paths in $PATCHES"
	# shadow: every top-level entry is a symlink into /usr/src; each directory on the path to a patched
	# dir becomes a real directory of symlinks (any depth: usr.sbin, sys, sys/amd64, ...); the patched
	# dir itself is copied
	for e in "$SRC"/* "$SRC"/.[!.]*; do
		[ -e "$e" ] || continue
		ln -s "$e" "$USRC/${e##*/}"
	done
	for d in $pdirs; do
		a=
		for c in $(echo "${d%/*}" | tr / ' '); do
			a=$a${a:+/}$c
			[ -L "$USRC/$a" ] || continue
			rm "$USRC/$a"; mkdir "$USRC/$a"
			for e in "$SRC/$a"/* "$SRC/$a"/.[!.]*; do
				[ -e "$e" ] || continue
				ln -s "$e" "$USRC/$a/${e##*/}"
			done
		done
		rm -f "$USRC/$d"; cp -R "$SRC/$d" "$USRC/$d"
	done
	PINFO=
	for p in $PATCHES; do
		patch -s -p1 -d "$USRC" -i "$(cd "$(dirname "$p")" && pwd)/${p##*/}" || die "patch $p does not apply"
		PINFO="$PINFO ${p##*/}:$(sha256 -q "$p" | cut -c1-12)"
	done
	find "$USRC" -name '*.orig' -delete
	PINFO=${PINFO# }
	say "shadow source $USRC: patched$pdirs with $PINFO"
fi

# --- vmm.ko (kmod=own: from the shadow tree; the opt headers come from /usr/src's GENERIC either way)
printf '%s\n' "include \"$SRC/sys/amd64/conf/GENERIC\"" "ident GENERIC-SNAP" "options BHYVE_SNAPSHOT" >"$R/conf/GENERIC-SNAP"
t0=$(now)
(cd "$SRC/sys/amd64/conf" && config -s "$SRC/sys" -d "$KB" "$R/conf/GENERIC-SNAP") >"$L/config.log" 2>&1 || { cat "$L/config.log"; die "config failed"; }
grep -q '^#define BHYVE_SNAPSHOT 1' "$KB/opt_bhyve_snapshot.h" || die "opt_bhyve_snapshot.h lacks BHYVE_SNAPSHOT"
KM="KERNBUILDDIR=$KB MAKEOBJDIRPREFIX=$O"; KMOD=base
if [ $KPATCH = yes ]; then
	KM="KERNBUILDDIR=$KB MAKEOBJDIRPREFIX=$R/obj-$VARIANT SRCTOP=$USRC SYSDIR=$USRC/sys"; KMOD=own
	mkdir -p "$R/obj-$VARIANT"
	# sys/conf/config.mk finds the *_if.m interface files with a plain find(1) under SYSDIR, which does
	# not follow the shadow tree's symlinks (sys/dev -> /usr/src/sys/dev): "don't know how to make
	# acpi_if.h". config.mk skips its find when __MPATH is already set, so list them here with -L.
	__MPATH=$(find -L "$USRC/sys/" -name '*_if.m' | tr '\n' ' '); export __MPATH
	[ -n "$__MPATH" ] || die "no *_if.m under $USRC/sys"
	[ "$(make -C "$USRC/sys/modules/vmm" $KM -V SRCTOP)" = "$USRC" ] || die "make does not take SRCTOP=$USRC"
	[ "$(make -C "$USRC/sys/modules/vmm" $KM -V SYSDIR)" = "$USRC/sys" ] || die "make does not take SYSDIR=$USRC/sys"
fi
make -C "$USRC/sys/modules/vmm" $KM cleandir >/dev/null 2>&1 || true
make -j"$J" -C "$USRC/sys/modules/vmm" $KM >"$L/vmm-build.log" 2>&1 || { tail -30 "$L/vmm-build.log"; die "vmm.ko build failed"; }
# every patched kernel .c file must have been compiled from the shadow tree, not /usr/src
for f in $kfiles; do
	case $f in *.c) grep -q -- "$USRC/$f" "$L/vmm-build.log" || die "$f was not compiled from $USRC (see $L/vmm-build.log)" ;; esac
done
say "vmm.ko (kmod=$KMOD) built in $(dt "$t0" "$(now)") s"
KO=$(make -C "$USRC/sys/modules/vmm" $KM -V .OBJDIR)/vmm.ko
[ -f "$KO" ] || die "no $KO"

# --- libvmmapi.a (static, PIE-compatible)
t0=$(now)
LIBD=$R/lib${VARIANT:+-$VARIANT}; mkdir -p "$LIBD"
make -C "$USRC/lib/libvmmapi" $M cleandir >/dev/null 2>&1 || true
env CFLAGS=-fPIE make -j"$J" -C "$USRC/lib/libvmmapi" $M libvmmapi.a >"$L/libvmmapi-build.log" 2>&1 || { tail -30 "$L/libvmmapi-build.log"; die "libvmmapi.a build failed"; }
# (an unpatched dir in the shadow tree is a symlink; make's .CURDIR resolves it, so ask make for .OBJDIR)
cp "$(make -C "$USRC/lib/libvmmapi" $M -V .OBJDIR)/libvmmapi.a" "$LIBD/libvmmapi.a"
say "libvmmapi.a built in $(dt "$t0" "$(now)") s"

# --- bhyve, bhyvectl. CFLAGS/LDFLAGS go through the environment: on the make command line they would
# replace the Makefiles' own CFLAGS+= instead of adding to them. -L$R/lib holds only the .a, so
# -lvmmapi resolves to the static archive.
for d in bhyve bhyvectl; do
	t0=$(now)
	make -C "$USRC/usr.sbin/$d" $M SUBDIR= cleandir >/dev/null 2>&1 || true
	env CFLAGS="-I$USRC/lib/libvmmapi" LDFLAGS="-L$LIBD" make -j"$J" -C "$USRC/usr.sbin/$d" $M SUBDIR= >"$L/$d-build.log" 2>&1 ||
		{ tail -30 "$L/$d-build.log"; die "$d build failed"; }
	say "$d built in $(dt "$t0" "$(now)") s"
done
BH=$(make -C "$USRC/usr.sbin/bhyve" $M SUBDIR= -V .OBJDIR)/bhyve
BC=$(make -C "$USRC/usr.sbin/bhyvectl" $M SUBDIR= -V .OBJDIR)/bhyvectl

# --- checks
nm "$KO" | grep -q ' vm_snapshot_req$' || die "vmm.ko lacks vm_snapshot_req"
nm "$KO" | grep -q ' vm_restore_time$' || die "vmm.ko lacks vm_restore_time"
"$BC" 2>&1 | grep -q -- '--checkpoint' || die "bhyvectl usage lacks --checkpoint"
"$BC" 2>&1 | grep -q -- '--suspend' || die "bhyvectl usage lacks --suspend"
"$BH" -h 2>&1 | grep -q -- '-r file' || die "bhyve usage lacks -r"
for b in "$BH" "$BC"; do ldd "$b" | grep -q vmmapi && die "$b links base libvmmapi.so dynamically"; done
# every undefined symbol of the module must be exported by the running kernel
readelf -Ws --dyn-syms /boot/kernel/kernel | awk '{print $8}' | sort -u >"$R/kernel.syms"
miss=$(nm -u "$KO" | awk '{print $2}' | sort -u | comm -23 - "$R/kernel.syms")
[ -z "$miss" ] || die "vmm.ko needs symbols the running kernel lacks: $miss"
say "checks OK: snapshot symbols in vmm.ko ($(nm "$KO" | grep -ci snapshot) matches), --checkpoint/--suspend in bhyvectl, -r in bhyve, static libvmmapi, $(nm -u "$KO" | wc -l | tr -d ' ') undefined symbols all exported by the kernel"

# --- stage
rm -rf "$ST"; mkdir -p "$ST"
install -m 0444 "$KO" "$ST/vmm.ko"
install -m 0555 "$BH" "$ST/bhyve"
install -m 0555 "$BC" "$ST/bhyvectl"
{
	echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname) user=$(id -un)"
	echo "kernel=$KVER"
	echo "src_pkg=FreeBSD-src-$SRCV kernel_pkg=FreeBSD-kernel-generic-$KPV"
	echo "src_commit=fabb224f2f15 (checked 2026-10-07 against git for the vmm/bhyve/libvmmapi/sys-conf/share-mk files)"
	echo "patches=$PINFO"
	echo "kmod=$KMOD"
	echo "options=GENERIC+BHYVE_SNAPSHOT (module tied to config(8) opt headers); WITH_BHYVE_SNAPSHOT=yes; static libvmmapi"
	echo "cc=$(cc --version | head -1)"
} >"$ST/BUILDINFO"
(cd "$ST" && sha256 -r vmm.ko bhyve bhyvectl BUILDINFO) >"$ST/SHA256"
cat "$ST/SHA256"
say "staged in $ST; next (root): cd ~/yard/ops/sr3 && sudo ${VARIANT:+env SR3_VARIANT=$VARIANT }sh sr3-10-install.sh"
