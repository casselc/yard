#!/bin/sh
# sr1-mutants.sh -- the planted mutants of SR1 (internal/service, and the lifecycle's pause tier and retry
# rule): each is one exact-text change applied with `go test -overlay` (the tree is never edited), and the
# named tests must FAIL with it. Prints one row per mutant; exits 1 if any mutant survives.
# usage: tools/sr1-mutants.sh            (Halo; Go from env.sh, no network)
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
. "$R/env.sh"
cd "$R"
exec python3 -I - "$R" <<'PY'
import json, os, subprocess, sys, tempfile
root = sys.argv[1]
S, L = "internal/service/backend.go", "internal/lifecycle/transitions.go"
ST = "internal/service/store.go"
W, K, MC = "internal/service/workspace.go", "internal/wskey/wskey.go", "internal/lifecycle/machine.go"
M = [
 # name, file, old, new, package, tests
 ("stop-no-cont", S, 'return b.signal(tg, "CONT", stopped)', 'return nil',
  "./internal/service", "TestQuiescePausedIsGraceful|TestLifecyclePauseTier"),
 ("no-kill-escalation", S, 'if err := b.signal(tg, "KILL", pids); err != nil {', 'if err := b.signal(tg, "TERM", nil); err != nil {',
  "./internal/service", "TestQuiesceEscalatesToKill"),
 ("stop-no-verify", S, '\tdeadline := b.now().Add(spec.StopGrace.D())\n\tfor {\n\t\tif err := term(ps); err != nil {',
  '\tdeadline := b.now().Add(spec.StopGrace.D())\n\treturn term(ps)\n\tfor {\n\t\tif err := term(ps); err != nil {',
  "./internal/service", "TestQuiesceEscalatesToKill|TestQuiesceCatchesLateChildren"),
 ("term-first-listing-only", S, '\tfor {\n\t\tif err := term(ps); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := b.sleep(ctx, b.Poll)',
  '\tif err := term(ps); err != nil {\n\t\treturn err\n\t}\n\tfor {\n\t\tif err := b.sleep(ctx, b.Poll)',
  "./internal/service", "TestQuiesceCatchesLateChildren"),
 ("unkillable-claims-done", S, 'return fmt.Errorf("%d process(es) still in jail %d %s after SIGKILL", len(ps), jid, spec.KillWait.D())', 'return nil',
  "./internal/service", "TestQuiesceUnkillableIsNotDone"),
 ("probe-attempt-unbounded", S, 'actx, cancel := context.WithTimeout(ctx, at)', 'actx, cancel := context.WithCancel(ctx); _ = at',
  "./internal/service", "TestRestoreHangingProbeIsBounded"),
 ("exit-not-watched", S, '\t\tselect {\n\t\tcase <-ref.exited:\n\t\t\tt.info("probes", n)',
  '\t\tselect {\n\t\tcase <-make(chan struct{}):\n\t\t\tt.info("probes", n)',
  "./internal/service", "TestRestoreExitBeforeReady"),
 ("unready-restore-left", S, 'if rerr := b.remove(context.WithoutCancel(ctx), c, st.JID, spec, t); rerr != nil {', 'if rerr := error(nil); rerr != nil {',
  "./internal/service", "TestRestoreReadinessTimeout|TestLifecycleResumeReadinessTimeoutAborts"),
 ("restore-not-create-only", S, 'if _, err := b.OS.JID(jailName(sbx, sess, gen)); err == nil {\n\t\tt.info("existed", true)',
  'if false {\n\t\tt.info("existed", true)', "./internal/service", "TestRestoreCreateOnly"),
 ("destroy-no-wait", S, 'if err := b.waitGone(ctx, jid, spec.KillWait.D()); err != nil {', 'if err := error(nil); err != nil {',
  "./internal/service", "TestDestroyWaitsForProcesses"),
 ("inflight-ignores-lock", S, 'return b.lockHeld(op.ID)', 'return false, nil',
  "./internal/service", "TestInFlightLock"),
 ("pause-single-pass", S, '\t\tif n == 0 {\n\t\t\treturn len(ps), nil', '\t\tif true {\n\t\t\treturn len(ps), nil',
  "./internal/service", "TestPauseUnpause"),
 ("snapshot-name-no-ckpt", ST, 'return fmt.Sprintf("%s@ysr1-%s-g%d-c%d", dataset, sess, gen, ckpt)', 'return fmt.Sprintf("%s@ysr1-%s-g%d-c%d", dataset, sess, gen, 0)',
  "./internal/service", "TestCheckpointFailures"),
 ("artifact-digest-unchecked", ST, 'if a.Digest != a.digest() || a.Session != sess || a.Ckpt != ckpt {', 'if a.Session != sess || a.Ckpt != ckpt {',
  "./internal/service", "TestPartialAndEditedArtifact"),
 ("unpause-before-pause-settles", L, 'c.resolved(r.Op) && wake && c.opsLeft(1)', 'wake && c.opsLeft(1)',
  "./internal/lifecycle", "TestUnpauseWaitsForPauseResolution"),
 ("retry-superseded-op", L, '(c.Cfg.MaxAttempts == 0 || o.Attempts < c.Cfg.MaxAttempts) && c.opCurrent(o)', '(c.Cfg.MaxAttempts == 0 || o.Attempts < c.Cfg.MaxAttempts)',
  "./internal/lifecycle", "TestOpRetryOnlyCurrent"),
 # ---- 2026-10-07: workspace keys (layout D), drift refusal (decision 2), liveness (decision 3)
 ("unload-under-active", L, 'c.resolved(pr.Op) && idle); err != nil {', 'c.resolved(pr.Op) && (idle || true)); err != nil {',
  "./internal/lifecycle", "TestKeyUnloadOnlyWhenNoSessionActive"),
 ("load-during-unload", L, 'c.opsLeft(1) && pr.Phase == KNone && c.resolved(pr.Op)); err != nil {', 'c.opsLeft(1) && (pr.Phase == KNone || true)); err != nil {',
  "./internal/lifecycle", "TestResumeLoadWaitsForUnload"),
 ("resume-without-key", L, '\tif r.Project != "" {\n\t\tr.Phase, r.Op = PKey, 0', '\tif false {\n\t\tr.Phase, r.Op = PKey, 0',
  "./internal/lifecycle", "TestResumeLoadWaitsForUnload"),
 ("refusal-taken-as-unknown", L, '\tcase AnsRefused:\n\t\to.St = Refused', '\tcase AnsRefused:\n\t\to.St = Unknown',
  "./internal/lifecycle", "TestResumeRefusedDrift"),
 ("probe-timeout-is-dead", L, 'p.Pending, p.Answered, p.Alive = false, false, false', 'p.Pending, p.Answered, p.Alive = false, true, false',
  "./internal/lifecycle", "TestLostDetect"),
 ("stale-probe", L, 'p.Answered && !p.Alive && p.Inst == r.Inst && p.Gen == r.Gen', 'p.Answered && !p.Alive',
  "./internal/lifecycle", "TestLostDetectStale"),
 ("auto-resume-after-refusal", MC, 'if r.Inbox > 0 && !r.Drift {', 'if r.Inbox > 0 {',
  "./internal/service", "TestLifecycleDriftRefusedThenForced"),
 ("drift-not-refused", S, 'if n > 0 && !force {', 'if false {',
  "./internal/service", "TestRestoreRefusesDrift|TestLifecycleDriftRefusedThenForced"),
 ("drift-read-without-sync", S, 'if err := b.OS.ZpoolSync(ctx, pool); err != nil {', 'if err := error(nil); err != nil && pool != "" {',
  "./internal/service", "TestRestoreRefusesDrift"),
 ("drift-unreadable-goes-ahead", S, '\tif err != nil {\n\t\treturn fmt.Errorf("workspace drift of %s: %w", s.Dataset, err)\n\t}\n\tn, err := strconv',
  '\tif err != nil {\n\t\tout = "0"\n\t}\n\tn, err := strconv', "./internal/service", "TestRestoreDriftUnreadableIsUnknown"),
  ("restore-unmounted-clone", S, '\t\tif err := b.checkDataset(ctx, s, sbx); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tt.step("artifact")',
   '\t\tt.step("artifact")', "./internal/service", "TestRestoreNeedsMountedClone"),
 ("unmount-forced", W, 'if _, err := w.Z.Zfs(ctx, lock, "unmount", ds); err != nil {', 'if _, err := w.Z.Zfs(ctx, lock, "unmount", "-f", ds); err != nil {',
  "./internal/service", "TestWorkspaceKeyCycle|TestWorkspaceShred"),
 ("retire-destroys-with-clones", W, '_, err := w.Z.Zfs(ctx, nil, "destroy", "-d", snap)', '_, err := w.Z.Zfs(ctx, nil, "destroy", snap)',
  "./internal/service", "TestWorkspaceRetireBase"),
 ("promote-any-generation", W, 'if len(gens) == 0 || gens[0] != gen {', 'if len(gens) < 0 {',
  "./internal/service", "TestWorkspacePromote"),
 ("destroy-promoted-in-place", W, 'if strings.HasPrefix(porigin, ds+"@") {', 'if porigin == "\\x00" {',
  "./internal/service", "TestWorkspacePromote"),
 ("shred-before-unmount", W, '\tif err := w.Unmount(ctx, nil, p); err != nil {\n\t\treturn err\n\t}\n\tif err := w.UnloadKey(ctx, nil, p)',
  '\tif err := sh.Shred(wskey.ConsumerZFS, p, now); err != nil {\n\t\treturn err\n\t}\n\tif err := w.Unmount(ctx, nil, p); err != nil {\n\t\treturn err\n\t}\n\tif err := w.UnloadKey(ctx, nil, p)',
  "./internal/service", "TestWorkspaceShred"),
 ("base-generation-reused", W, 'if v, err := w.get(ctx, "yard:basegen", ds); err == nil {', 'if v, err := "", errors.New("x"); err == nil {',
  "./internal/service", "TestWorkspaceRetireBase"),
 ("wrap-unbound", K, 'return []byte(consumer + "|" + subject + "|" + strconv.FormatInt(version, 10))', 'return []byte(strconv.Itoa(0))',
  "./internal/wskey", "TestWrapBindsIdentity"),
 # ---- round 2: jail on its clone, Removed
 ("unload-before-destroy-done", L, '(r.Op != 0 && c.opSt(r.Op) != Done)', '(r.Op != 0 && !c.resolved(r.Op))',
  "./internal/lifecycle", "TestRemovedDestroyNotDoneKeepsKey"),
 ("removed-blocks-unload", L, 'var keyIdle = []State{Suspended, Expired, Failed, Removed}', 'var keyIdle = []State{Suspended, Expired, Failed}',
  "./internal/lifecycle", "TestRemoveUnblocksKeyUnload"),
 ("remove-while-resuming", L, 'r.State != Removed && quiet && len(c.Drivers[s]) == 0); err != nil {', 'r.State != Removed && (quiet || true)); err != nil {',
  "./internal/lifecycle", "TestRemoveGuard"),
 ("destroy-keeps-jail-view", S, '\tif err := b.Spawn.Teardown(c); err != nil {\n\t\treturn err\n\t}\n\tt.step("teardown")',
  '\tt.step("teardown")', "./internal/service", "TestJailRunsOnCloneAndReleasesIt"),
 ("shred-leaves-wal", K, '_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)', '_, err := s.db.Exec(`SELECT 1`)',
   "./internal/wskey", "TestCreateKeyShred"),
 # ---- 2026-10-08: check drift before writable mount/ZIL housekeeping
 ("key-load-mounts-before-drift", S, 'return w.LoadProjectKey(ctx, lock, s.Project)',
   'return w.LoadKey(ctx, lock, s.Project, sess)', "./internal/service",
    "TestResumeChecksDriftBeforeMountMetadataWrites|TestLoadOrderRuntimeConformance"),
 ("cleanup-retires-record-early", S, 'return errors.Join(errs...)',
   'return errors.Join(errors.Join(errs...), os.Remove(filepath.Join(b.sessDir(sess), "session.json")))',
   "./internal/service", "TestRemovalProjectFailureRetainsRecordForRetry"),
]
tmp = tempfile.mkdtemp(prefix="sr1mut.")
survived = 0
print("%-30s %-8s %s" % ("mutant", "result", "tests"))
for name, f, old, new, pkg, tests in M:
    src = open(os.path.join(root, f)).read()
    if src.count(old) != 1:
        print("%-30s %-8s %s" % (name, "STALE", "the text to mutate is not in %s exactly once" % f)); survived += 1; continue
    mf = os.path.join(tmp, name + ".go")
    open(mf, "w").write(src.replace(old, new))
    ov = os.path.join(tmp, name + ".json")
    json.dump({"Replace": {os.path.join(root, f): mf}}, open(ov, "w"))
    p = subprocess.run(["go", "test", "-count=1", "-overlay", ov, "-run", tests, "-timeout", "120s", pkg],
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    if p.returncode == 0:
        res = "SURVIVED"; survived += 1
    elif "build failed" in out or "[setup failed]" in out:
        res = "NOBUILD"; survived += 1
    else:
        res = "caught"
    failed = sorted({l.split()[2] for l in out.splitlines() if l.startswith("--- FAIL")})
    print("%-30s %-8s %s" % (name, res, " ".join(failed) or out.strip().splitlines()[-1][:100]))
print("%d mutants, %d survived" % (len(M), survived))
sys.exit(1 if survived else 0)
PY
