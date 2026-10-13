#!/usr/bin/env python3
"""mutants.py: plant each mutant in a table, run the package's tests, report caught / survived.
   tools/mutants.py tools/mutants/<name>.json [only-name]     (from the repo root, after `. ./env.sh`)
A table is {"package": "./internal/x/", "mutants": [{"name", "file", "old", "new"}...]}; `old` must occur. A mutant
may instead list "edits": [{"file", "old", "new"}...], all planted together."""
import json, subprocess, sys
table = json.load(open(sys.argv[1])); only = sys.argv[2] if len(sys.argv) > 2 else None
caught = total = 0
for m in table["mutants"]:
    if only and m["name"] != only: continue
    total += 1
    edits = m.get("edits") or [{"file": m["file"], "old": m["old"], "new": m["new"]}]
    origs = {e["file"]: open(e["file"]).read() for e in edits}
    missing = False
    for e in edits:
        if e["old"] not in origs[e["file"]]:
            missing = True
    if missing:
        print("PATTERN-MISSING", m["name"]); continue
    try:
        cur = dict(origs)
        for e in edits:
            cur[e["file"]] = cur[e["file"]].replace(e["old"], e["new"], 1)
        for f, text in cur.items():
            open(f, "w").write(text)
        r = subprocess.run(["go", "test", "-count=1", table["package"]], capture_output=True, text=True, timeout=900)
        out = r.stdout + r.stderr
        if r.returncode == 0: print("SURVIVED ", m["name"])
        elif "build failed" in out or "[setup failed]" in out: print("BUILD-FAIL", m["name"])
        else: print("caught   ", m["name"]); caught += 1
    except subprocess.TimeoutExpired:
        print("caught    %s (timeout)" % m["name"]); caught += 1
    finally:
        for f, text in origs.items():
            open(f, "w").write(text)
print("caught %d of %d" % (caught, total)); sys.exit(0 if caught == total else 1)
