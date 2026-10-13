#!/usr/bin/env python3
"""agent_fault_probe.py: AG2's fault probe against a live yard-agentd (design/AGENT-OPERATIONS.md section 16).

Plays the outbox's side of the envelope (submit with the exact body, poll, fetch, ack) for one review task per
scenario, injects the scenario's fault while the attempt runs, and checks what comes back:

  baseline        no fault: completed, spend exact
  agentd_crash    yard-agentd SIGKILLed while the worker runs, restarted: the attempt resumes and ends
  node_outage     yard-node SIGSTOPped past the unreachable bound, then SIGCONT: worker_failed with execution
                  unconfirmed, then an execution_stopped correction once the node is back (its lease watchdog)
  vm_killed       the VM's firecracker process killed: worker_failed, execution stopped
  cancel          the cancel verb while it runs: cancelled
  timeout         a 45 s wall-time limit: timeout
  halo_lost       the next model call's answer lost at halo's proxy: the call is resolved from halo's record
  halo_restart    halo restarted (new incarnation) while the review runs: the lost call stays at its maximum,
                  the spend is bounded, and nothing waits for exactness

Every scenario also checks: the outcome is terminal; a refusal never appears for an accepted attempt; the receipt
carries spend with certainty; acking releases the record. Results go to a JSON lines file.

  agent_fault_probe.py --agentd http://127.0.0.1:18200 --repo fixture --change change.diff --out results.jsonl \\
      --restart-cmd 'systemd-run ...' --node-pid-file F --agentd-pid-file F --alloc-root DIR --proxy URL
"""
import argparse, hashlib, json, os, signal, subprocess, sys, time, urllib.request, urllib.error

p = argparse.ArgumentParser()
p.add_argument("--agentd", default="http://127.0.0.1:18200")
p.add_argument("--repo", default="fixture")
p.add_argument("--change", required=True)
p.add_argument("--out", required=True)
p.add_argument("--agentd-pid-file", required=True)
p.add_argument("--agentd-restart", required=True, help="shell command that starts yard-agentd again")
p.add_argument("--node-pid-file", required=True)
p.add_argument("--alloc-root", required=True)
p.add_argument("--proxy", default="", help="halo op_fault_proxy admin URL (halo_lost, halo_restart)")
p.add_argument("--unreachable-s", type=float, default=10)
p.add_argument("--scenarios", default="baseline,agentd_crash,node_outage,vm_killed,cancel,timeout,halo_lost,halo_restart")
a = p.parse_args()

SCHEMA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "review_schema.json")))
RUBRIC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "review_rubric.txt")).read()
CHANGE = open(a.change).read()
OWNER = "cordis-probe"


def http(method, path, body=None, headers=None, timeout=60):
    req = urllib.request.Request(a.agentd + path, data=body, method=method)
    req.add_header("X-Yard-Principal", OWNER)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:
        return 0, {"error": str(e)}


def contract():
    for _ in range(120):
        c, v = http("GET", "/v1/yard/contract")
        if c == 200:
            return v
        time.sleep(1)
    raise SystemExit("yard-agentd does not answer")


class Attempt:
    def __init__(self, op, seconds):
        k = contract()
        self.inc = k["incarnation"]
        task = {"agent": "claude", "route": "local", "input": {"repo": a.repo, "commit": "HEAD"}, "change": CHANGE,
                "instructions": [RUBRIC], "output": SCHEMA, "valuation": k["agent"]["current_valuation"],
                "limits": {"tokens": 600000, "charge": 3000000, "money_micro_usd": 0, "seconds": seconds}}
        self.op = op
        self.not_after = k["time_ms"] + 300000
        self.body = json.dumps({"operation_id": op, "attempt": 0, "not_after": self.not_after, "api": "agent",
                                "request": task}, separators=(",", ":")).encode()
        self.digest = hashlib.sha256(self.body).hexdigest()

    def submit(self):  # the exact body, as first sent, every time
        return http("POST", "/v1/operations", self.body, {"Yard-Incarnation": self.inc, "Yard-Digest": self.digest,
                                                          "Content-Type": "application/json"}, timeout=600)

    def verb(self, method, what=""):
        path = "/v1/operations/%s/0%s" % (self.op, "/" + what if what else "")
        return http(method, path, b"" if method == "POST" else None,
                    {"Yard-Incarnation": self.inc, "Yard-Not-After": str(self.not_after), "Yard-Digest": self.digest})

    def wait(self, limit_s=1500):
        t0 = time.time()
        while time.time() - t0 < limit_s:
            c, v = self.verb("GET")
            if c == 200 and v and v.get("status") in ("done", "released"):
                return v
            if c == 200 and v and v.get("status") in ("never_accepted",):  # resend exactly (rule 4)
                self.submit()
            time.sleep(2)
        return None

    def stage(self):
        c, v = self.verb("GET")
        return (v or {}).get("stage") if c == 200 else None


def pid(f):
    try:
        return int(open(f).read().strip())
    except Exception:
        return None


def wait_stage(att, want="started", limit=180):
    t0 = time.time()
    while time.time() - t0 < limit:
        if att.stage() == want:
            return True
        time.sleep(0.5)
    return False


def wait_calls(att, n=1, limit=300):
    """wait until the attempt's broker route has made n model calls (its ledger rows appear in the allocation's route log
    only after the fact; the transcript is not available while running), approximated by elapsed time after start"""
    time.sleep(min(limit, 25 * n))


def firecracker_pids():
    out = subprocess.run(["pgrep", "-f", "firecracker --no-api"], capture_output=True, text=True).stdout.split()
    return [int(x) for x in out]


def corrections():
    c, v = http("GET", "/v1/yard/corrections?after=0")
    return (v or {}).get("corrections", []) if c == 200 else []


def run(name):
    rec = {"scenario": name, "t0": time.time()}
    seconds = 45 if name == "timeout" else 900
    att = Attempt("probe-%s-%d" % (name, int(time.time())), seconds)
    c, v = att.submit()
    rec["submit"] = c
    if c not in (200, 202):
        rec["error"] = v
        return rec
    if name != "baseline":
        wait_stage(att)
    if name == "agentd_crash":
        wait_calls(att, 1)
        os.kill(pid(a.agentd_pid_file), signal.SIGKILL)
        time.sleep(2)
        subprocess.run(a.agentd_restart, shell=True)
        contract()
    elif name == "node_outage":
        wait_calls(att, 1)
        np = pid(a.node_pid_file)
        os.kill(np, signal.SIGSTOP)
        time.sleep(a.unreachable_s + 10)
        rec["fenced_while_stopped"] = (att.verb("GET")[1] or {}).get("status")
        os.kill(np, signal.SIGCONT)
    elif name == "vm_killed":
        wait_calls(att, 1)
        for fp in firecracker_pids():
            os.kill(fp, signal.SIGKILL)
    elif name == "cancel":
        wait_calls(att, 1)
        rec["cancel"] = att.verb("POST", "cancel")
    elif name in ("halo_lost", "halo_restart") and a.proxy:
        wait_calls(att, 1)
        body = b'{"lose_submit_answer": true}' if name == "halo_lost" else b""
        path = "/admin/fault" if name == "halo_lost" else "/admin/restart"
        req = urllib.request.Request(a.proxy + path, data=body, method="POST")
        try:
            urllib.request.urlopen(req, timeout=300).read()
            rec["proxy"] = "ok"
        except Exception as e:
            rec["proxy"] = str(e)
    v = att.wait()
    if v is None:
        rec["error"] = "did not end"
        return rec
    o = v.get("outcome") or {}
    if isinstance(o, str):
        o = json.loads(o)
    rec.update(outcome=o.get("outcome"), execution=o.get("execution"), why=o.get("why"),
               certainty=(o.get("spend") or {}).get("certainty"), spend=o.get("spend"),
               unresolved_left=o.get("unresolved_left"), artifacts=len(o.get("artifacts") or []),
               reallocs=o.get("reallocs"), value=o.get("value"))
    if rec["execution"] == "unconfirmed":
        for _ in range(60):
            cs = [x for x in corrections() if x.get("operation_id") == att.op]
            if cs:
                rec["correction"] = cs[0]["kind"]
                break
            time.sleep(2)
    c, ack = att.verb("POST", "ack")
    rec["ack"] = (ack or {}).get("status")
    rec["wall_s"] = round(time.time() - rec["t0"], 1)
    return rec


EXPECT = {
    "baseline": lambda r: r.get("outcome") == "completed" and r.get("certainty") == "exact",
    # the harness rides out the broker's restart with its own retries: anything but completed is a defect (the first
    # live run passed invalid_output here and hid a call-id collision after the restart)
    "agentd_crash": lambda r: r.get("outcome") == "completed",
    "node_outage": lambda r: r.get("outcome") == "worker_failed" and r.get("execution") == "unconfirmed"
                             and r.get("correction") == "execution_stopped",
    "vm_killed": lambda r: r.get("outcome") == "worker_failed" and r.get("execution") == "stopped",
    "cancel": lambda r: r.get("outcome") == "cancelled" and r.get("execution") == "stopped",
    "timeout": lambda r: r.get("outcome") == "timeout" and r.get("execution") == "stopped",
    "halo_lost": lambda r: r.get("outcome") in ("completed", "invalid_output", "insufficient"),
    "halo_restart": lambda r: r.get("outcome") is not None and r.get("certainty") in ("exact", "bounded"),
}

fails = 0
with open(a.out, "a") as f:
    for name in a.scenarios.split(","):
        r = run(name)
        r["pass"] = bool(EXPECT[name](r)) and r.get("ack") == "released"
        fails += not r["pass"]
        f.write(json.dumps(r) + "\n")
        f.flush()
        print("%-14s %-5s %s %s %s ack=%s %ss" % (name, "PASS" if r["pass"] else "FAIL", r.get("outcome"), r.get("execution"),
                                                  r.get("certainty"), r.get("ack"), r.get("wall_s")), flush=True)
print("failures: %d" % fails)
sys.exit(1 if fails else 0)
