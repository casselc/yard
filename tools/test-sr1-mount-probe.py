"""Exercise probe orchestration/error isolation with stubbed privileged tools.

This does not validate FreeBSD DTrace/CTF compilation or kernel behavior.
"""
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "ops/sr1/sr1-11-mount-drift.sh"
for mode in ("ok", "compile-fail", "trace-fail", "trace-error"):
    with tempfile.TemporaryDirectory(prefix="sr1-mount-test-") as directory:
        base = Path(directory)
        ops = base / "ops"
        (ops / "sr1").mkdir(parents=True)
        (ops / "state").mkdir()
        (ops / "state/sr1-zfs-created").write_text("zroot/yard/ws/sr1p\n")
        (ops / "sr1/sr1-mount-drift.d").write_text((root / "ops/sr1/sr1-mount-drift.d").read_text())
        fixture = base / "fixture.sh"
        fixture.write_text("""#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  if [ "$1" = -state ]; then state=$2; shift 2; else shift; fi
done
mkdir -p "$(dirname "$state")"
printf '{}\n' >"$state"
trap 'exit 0' TERM
printf 'listening\n'
while :; do sleep 0.05; done
""")
        fixture.chmod(0o700)
        lib = f"""
OPS={shlex.quote(str(ops))}
WSMNT={shlex.quote(str(base / 'ws'))}
DEVSRV={shlex.quote(str(fixture))}
YDS=zroot/yard; PROJDS=zroot/yard/ws/sr1p; PROJECT=sr1p; SBX=sr1e2e
ZCREATED=$OPS/state/sr1-zfs-created
step_wrap() {{ :; }}
say() {{ printf '%s\n' "$*"; }}
die() {{ printf '%s\n' "$*" >&2; exit 1; }}
ds_exists() {{ [ "$1" = "$PROJDS@base-1" ]; }}
jls() {{ :; }}
zpool() {{ [ "$*" = 'sync zroot' ]; }}
sysctl() {{ printf '%s\n' "$*"; }}
zfs() {{
  printf '%s\n' "$*" >>"$OPS/calls.txt"
  case $1 in
    clone) mkdir -p "$MNT" ;;
    snapshot|unmount) : ;;
    mount) MOUNTED=yes ;;
    get)
      case $* in
        *keystatus*) printf 'available\n' ;;
        *objsetid*) printf '42\n' ;;
        *mounted*) printf 'yes\n' ;;
        *written@*) [ "${{MOUNTED:-no}}" = yes ] && printf '8192\n' || printf '0\n' ;;
        *) return 99 ;;
      esac ;;
    diff) [ ! -f "$MNT/.mount-probe/added-after-snapshot" ] || printf '+ positive-control\n' ;;
    destroy) rm -rf "$MNT" ;;
    *) return 99 ;;
  esac
}}
mtree() {{
  while [ "$1" != -p ]; do shift; done
  shift
  find "$1" -type f -exec sha256sum '{{}}' +
}}
dtrace() {{
  case $1 in
    -e) [ '{mode}' != compile-fail ] ;;
    -l) printf 'ID PROVIDER MODULE FUNCTION NAME\n1 fbt zfs zil_destroy entry\n' ;;
    *) [ '{mode}' != trace-fail ] || return 1
       zfs mount "$DS"
       if [ '{mode}' = trace-error ]; then printf 'TRACE ERROR: attribution is incomplete\n'
       else printf 'stub mount trace\n'; fi ;;
  esac
}}
"""
        (ops / "sr1/sr1-lib.sh").write_text(lib)
        copy = ops / "sr1/sr1-11-mount-drift.sh"
        copy.write_text(source.read_text())
        result = subprocess.run(["sh", str(copy)], capture_output=True, text=True, timeout=15)
        calls_file = ops / "calls.txt"
        calls = calls_file.read_text().splitlines() if calls_file.exists() else []
        if mode == "ok":
            assert result.returncode == 0, result.stderr + result.stdout
            out = next((ops / "logs").iterdir())
            assert out.joinpath("written-before.txt").read_text().strip() == "0"
            assert out.joinpath("written-unmounted.txt").read_text().strip() == "0"
            assert out.joinpath("written-remounted.txt").read_text().strip() == "8192"
            assert not out.joinpath("filesystem-diff.txt").read_text()
            assert not out.joinpath("tree-diff.txt").read_text()
            assert out.joinpath("positive-diff.txt").read_text()
        else:
            assert result.returncode != 0, result.stdout
        clones = [call for call in calls if call.startswith("clone ")]
        destroys = [call for call in calls if call.startswith("destroy ")]
        if mode == "compile-fail":
            assert not clones and not destroys, calls
        else:
            assert len(clones) == len(destroys) == 1, calls
            assert destroys[0].startswith("destroy -r zroot/yard/ws/sr1p/mountprobe-"), destroys
        assert not any(call == "destroy -r zroot/yard/ws/sr1p" for call in calls)
print("PASS: mount probe records controls, aborts before clone creation on compile failure, and cleans only its own clone")
