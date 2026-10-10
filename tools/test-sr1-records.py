"""Check SR1's six-field recorder without running privileged setup."""
import csv
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


script = Path(__file__).resolve().parents[1] / "ops/sr1/sr1-10-e2e.sh"
lines = script.read_text().splitlines()
recorder = next(line for line in lines if line.startswith("rec()"))
calls = [(number, line.strip()) for number, line in enumerate(lines, 1)
         if re.match(r"\s*rec\s+", line)]
for number, call in calls:
    args = shlex.split(call, comments=True, posix=True)
    assert len(args) == 7, f"{script}:{number}: rec expects six arguments: {call}"

# Exercise the actual recorder and workspace call sites under nounset. Stub
# only the metric lookup, so no ZFS, jail or yard-svc command can run here.
workspace_calls = [call for _, call in calls if call.startswith("rec ws ")]
assert len(workspace_calls) == 3, "expected init/base/clone workspace records"
with tempfile.TemporaryDirectory(prefix="sr1-records-") as directory:
    output = Path(directory) / "results.csv"
    program = "\n".join([
        "set -eu", f"CSV={shlex.quote(str(output))}",
        "PROJECT=sr1p; s=web; SUM=fixture", "kv() { printf '7\\n'; }",
        recorder, *workspace_calls,
    ])
    subprocess.run(["sh", "-c", program], check=True)
    with output.open(newline="") as source:
        rows = list(csv.reader(source))
    assert len(rows) == 3 and all(len(row) == 6 for row in rows), rows
    assert [row[:3] for row in rows] == [
        ["ws", "sr1p", "init_ms"], ["ws", "sr1p", "base_ms"],
        ["ws", "web", "clone_ms"],
    ], rows
print(f"PASS: {len(calls)} recorder call sites have six arguments; workspace rows run under sh -eu")
