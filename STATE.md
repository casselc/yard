# yard Phase 1 (stream Y): durable state

Resume from here. Design docs: /work/research/agent-platform/{CONTROL-PLANE,HARNESS,IDENTITY}.md.
Build/deploy: `. ./env.sh` (Halo), `tools/deploy-nuc.sh` (builds FreeBSD binaries + test binaries, copies them,
ops/ and the shim source to the NUC ~/yard as chuck, compiles the shim there with cc).

## Status (2026-10-07)
- [x] repo, module `yard`; internal/sts + internal/tpmkey copied from nuc/src/signer (thread-locked TPM transport)
- [x] N0 root scripts in ops/ (mirrored to NUC ~/yard/ops): n0-10-zfs, n0-20-audit, n0-30-tasks,
      n0-40-template, n0-50-pf (+ -undo for each, yard-unlock.sh). NOT RUN: waiting on the user.
- [x] yard-ctl: internal/{keyring,issuer,jwks,frontend,ctl}, cmd/yard-ctl. Unit tests pass on Linux (-race)
      and on the NUC (FreeBSD peercred path). Soft-key smoke on the NUC as chuck: init/serve/mint/verify/
      rotate/auto-retire all worked (50 CLI mints in 0.47 s incl. process start).
- [x] yard-spawn J0: internal/{jail,rctl,mount,pfanchor,spawn}, cmd/yard-spawn, shim/yard-exec-shim.c
      (builds -Werror on the NUC). Unit tests (fake Sys) pass on Linux and the NUC.
- [x] user ran N0 scripts 1-8 (2026-10-07): all OK; pf persistent (n0-50 confirm 13:44Z); final t20 rc=0 13:51Z
- [x] logs read, predicted-vs-actual below; three defects found by the runs and fixed:
  - n0-20-audit (0e1427d): auditd keeps `current` at the fixed /var/audit/current (OpenBSM
    AUDIT_CURRENT_LINK), not under dir:; the check now reads it, falling back to the newest open trail.
  - rctl (7568ba2): the kernel parses rule amounts with strtoul (kern_rctl.c str2int64) and rejects
    k/m/g suffixes with EINVAL; rctl(8) expands them in userland. We now expand to digits (powers of
    1024) before rctl_add_rule. t20 now stops if task-begin yields no uid.
  - anchor flush (402e041): `pfctl -a <anchor> -F all` fails with ENODEV on 15.1-STABLE before
    flushing anything (it flushes the anchor's eth rules and tables first); now an empty load
    (`-f /dev/null`). t20's fake broker runs in its own process group (an orphaned `nc` loop held the
    log pipe and hung the wrapper); t20 G checks the anchor is empty after destroy.

## Root run order (user: `cd ~/yard/ops && sudo sh <script>`)
1. n0-10-zfs.sh        (passphrase prompt twice)
2. n0-20-audit.sh
3. n0-30-tasks.sh
4. n0-40-template.sh   (network: pkg.FreeBSD.org)
5. tests/t10-ctl-tpm.sh
6. tests/t20-spawn-j0.sh   (F audit runs; G broker SKIPs until pf)
7. n0-50-pf.sh apply 5  -> new ssh session -> n0-50-pf.sh confirm
8. tests/t20-spawn-j0.sh   again (G broker check now runs)

## Predictions (stated before any run)
- t10: prod keys sign p50 19-21 ms; scratch init 3-6 s; retire 1.5-3 s; handle set unchanged.
- t20 H: per-call total p50 ~2.0 ms (1.5-3.5), p99 < 6 ms; +0.1 ms with -mem.
- t20 C: timeout exit 124 after 2.0-2.5 s; 0 leftover processes/dying jails.
- n0-50: 7 filter rules + anchor; existing SSH survives; 80% some blocked LAN noise within minutes.

## Actual (2026-10-07)
- t10: sign p50 19.62 ms (max 19.88, n=10); scratch init 1.95 s (predicted 3-6, faster); retire 1.15 s
  (predicted 1.5-3, faster); rotation cycle PASS.
- t20 H: total p50 2.46-2.52 ms, p99 3.5-4.0 ms (in range); 360-400 calls/s; -mem adds ~0.1-0.2 ms setup.
- t20 C: exit 124 after 2.02 s; 0 leftover processes, 0 dying jails.
- t20 D/E/F/G: 100M denied under a 64M call rule; user: accounting maxproc=51 across child jails;
  7 audit records carry zone ysbx_j0a.caud1; metadata rdr to the broker works for IMDS and ECS,
  internet and host sshd blocked, net=none child has no network, anchor empty after destroy.
- n0-50: existing SSH survived; persistent after confirm.

## NUC facts (read-only inspection, 2026-10-07)
- 15.1-STABLE n285848; LAN igc0 192.168.1.72/22 (DHCP), gw 192.168.1.1; tailscale0 100.64.0.10.
- pf not loaded, no /etc/pf.conf. auditd not enabled. kern.racct.enable=1. securelevel -1.
- zroot/yard-p0 destroyed by 99-cleanup (no template left). TPM keys kept at 0x81010010/11.
- /dev/tpm0 root:wheel 0600; chuck cannot open it, so TPM tests run as root.
- User jails: zroot/jails/* (ubuntu-noble on igc0 alias 192.168.2.242, not running). Do not touch.
- zroot/home/user already uses keyformat=passphrase keylocation=prompt (precedent for zroot/yard/data).
- linux64 is loaded on the host (linux_enable=YES), contrary to the "linux64 off" decision for the jailhost VM.

## Forward compatibility (lead, 2026-10-07; HARNESS.md "Milestones: suspend and resume", NOT in scope)
- SR1: long-running jails must be expressible as a service spec (command, env, cwd, ports, readiness probe).
  Today spawn.Call already carries argv/env/cwd/net/limits and spawn.Sandbox persists as versionable JSON
  (sandbox.json); a ServiceSpec = Call fields + ports + probe, with a Start/Stop path beside the synchronous
  Run (which requires a timeout). Nothing built here blocks that.
- SR0: yard-ctl has no session store yet (only keyring.json with "version" and the hash-chained mint log).
  The session table, when added, needs a lifecycle state field and a one-shot resume token consumed atomically
  (SQLite). Keep the mint log separate from it.
