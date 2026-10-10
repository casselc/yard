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
ST=$R/stage/usr/local/yard/bhyve-snap
L=$R/logs
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

# --- vmm.ko
printf '%s\n' "include \"$SRC/sys/amd64/conf/GENERIC\"" "ident GENERIC-SNAP" "options BHYVE_SNAPSHOT" >"$R/conf/GENERIC-SNAP"
t0=$(now)
(cd "$SRC/sys/amd64/conf" && config -s "$SRC/sys" -d "$KB" "$R/conf/GENERIC-SNAP") >"$L/config.log" 2>&1 || { cat "$L/config.log"; die "config failed"; }
grep -q '^#define BHYVE_SNAPSHOT 1' "$KB/opt_bhyve_snapshot.h" || die "opt_bhyve_snapshot.h lacks BHYVE_SNAPSHOT"
make -C "$SRC/sys/modules/vmm" KERNBUILDDIR="$KB" MAKEOBJDIRPREFIX="$O" cleandir >/dev/null 2>&1 || true
make -j"$J" -C "$SRC/sys/modules/vmm" KERNBUILDDIR="$KB" MAKEOBJDIRPREFIX="$O" >"$L/vmm-build.log" 2>&1 || { tail -30 "$L/vmm-build.log"; die "vmm.ko build failed"; }
say "vmm.ko built in $(dt "$t0" "$(now)") s"
KO=$O$SRC/sys/modules/vmm/vmm.ko

# --- libvmmapi.a (static, PIE-compatible)
t0=$(now)
make -C "$SRC/lib/libvmmapi" $M cleandir >/dev/null 2>&1 || true
env CFLAGS=-fPIE make -j"$J" -C "$SRC/lib/libvmmapi" $M libvmmapi.a >"$L/libvmmapi-build.log" 2>&1 || { tail -30 "$L/libvmmapi-build.log"; die "libvmmapi.a build failed"; }
cp "$O$SRC/lib/libvmmapi/libvmmapi.a" "$R/lib/libvmmapi.a"
say "libvmmapi.a built in $(dt "$t0" "$(now)") s"

# --- bhyve, bhyvectl. CFLAGS/LDFLAGS go through the environment: on the make command line they would
# replace the Makefiles' own CFLAGS+= instead of adding to them. -L$R/lib holds only the .a, so
# -lvmmapi resolves to the static archive.
for d in bhyve bhyvectl; do
	t0=$(now)
	make -C "$SRC/usr.sbin/$d" $M SUBDIR= cleandir >/dev/null 2>&1 || true
	env CFLAGS="-I$SRC/lib/libvmmapi" LDFLAGS="-L$R/lib" make -j"$J" -C "$SRC/usr.sbin/$d" $M SUBDIR= >"$L/$d-build.log" 2>&1 ||
		{ tail -30 "$L/$d-build.log"; die "$d build failed"; }
	say "$d built in $(dt "$t0" "$(now)") s"
done
BH=$O$SRC/usr.sbin/bhyve/bhyve
BC=$O$SRC/usr.sbin/bhyvectl/bhyvectl

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
	echo "options=GENERIC+BHYVE_SNAPSHOT (module tied to config(8) opt headers); WITH_BHYVE_SNAPSHOT=yes; static libvmmapi"
	echo "cc=$(cc --version | head -1)"
} >"$ST/BUILDINFO"
(cd "$ST" && sha256 -r vmm.ko bhyve bhyvectl BUILDINFO) >"$ST/SHA256"
cat "$ST/SHA256"
say "staged in $ST; next (root): cd ~/yard/ops/sr3 && sudo sh sr3-10-install.sh"
