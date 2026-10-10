"""Run the actual SR1 diagnostic helpers with stubbed ZFS/service commands."""
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

script = Path(__file__).resolve().parents[1] / "ops/sr1/sr1-10-e2e.sh"
source = script.read_text()
helpers = "\n".join(re.search(r"^" + name + r"\(\) \{\n.*?^\}", source,
                               re.M | re.S).group(0)
                    for name in ("drift_probe", "diagnose_refused_resume"))
for diff_error in (0, 1):
    with tempfile.TemporaryDirectory(prefix="sr1-drift-") as directory:
        program = f"""
set -eu
OUT={shlex.quote(directory)}
PROJDS=zroot/yard/ws/sr1p; PROJECT=sr1p; YDS=zroot/yard
SUM='SR1SUM ok=0 restore_refused=1'; SVCRC=1
say() {{ printf '%s\n' "$*"; }}
zpool() {{ [ "$*" = 'sync zroot' ]; }}
zfs() {{
  case $1 in
    list) printf '%s\n' 'zroot/yard/ws/sr1p/web@ysr1-web-g1-c2' ;;
    get) printf 'zroot/yard/ws/sr1p/web\twritten@ysr1-web-g1-c2\t8192\n' ;;
    diff) [ '{diff_error}' = 0 ] || {{ printf 'diff unavailable\n' >&2; return 1; }} ;;
    *) return 99 ;;
  esac
}}
svc() {{ printf '%s\n' "$*" >>"$OUT/calls.txt"; SVCRC=0; SUM=inspection; }}
{helpers}
drift_probe after_suspend
diagnose_refused_resume
[ "$SUM" = 'SR1SUM ok=0 restore_refused=1' ] && [ "$SVCRC" = 1 ]
"""
        result = subprocess.run(["sh", "-c", program], check=True, capture_output=True, text=True)
        output = Path(directory)
        assert output.joinpath("calls.txt").read_text().splitlines() == [
            "diag-ws-load ws-load -project sr1p -sess web"]
        for stage in ("after_suspend", "after_refusal_mount"):
            assert "8192" in output.joinpath(f"drift-{stage}.txt").read_text()
        if diff_error:
            assert "zfs diff failed" in result.stdout
            assert "diff unavailable" in output.joinpath("drift-zfs-diff.err").read_text()
        else:
            assert "zfs diff is empty" in result.stdout
print("PASS: native probe records both stages, preserves refusal, and distinguishes empty diff from diff failure")
