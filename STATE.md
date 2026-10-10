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

## SR3 spike: bhyve snapshot/restore (branch sr3, 2026-10-07) -- scripts written, NOT RUN as root
- Source: NUC /usr/src = pkgbase FreeBSD-src 15.snap20261006235134, same snapshot as the running
  FreeBSD-kernel-generic; the 600 relevant files (sys/amd64/vmm, sys/dev/vmm, sys/modules/vmm, sys/conf,
  sys/amd64/include, share/mk, usr.sbin/bhyve{,ctl}, lib/libvmmapi) are byte-identical to git fabb224f2f15
  (= `uname -v`). No separate checkout needed.
- Build (ops/sr3/sr3-00-build.sh, as chuck, ~9 s total): config(8) on "include GENERIC + options
  BHYVE_SNAPSHOT" for the opt_*.h only, vmm.ko tied to it (KERNBUILDDIR) -> vmm_snapshot.c included;
  libvmmapi.a static (-fPIE); bhyve/bhyvectl WITH_BHYVE_SNAPSHOT=yes linked to it. Checks pass:
  vm_snapshot_req/vm_restore_time in vmm.ko, --checkpoint/--suspend in bhyvectl, -r in bhyve, no
  libvmmapi.so dependency, all 233 undefined module symbols exported by the running kernel.
  Gotchas: CFLAGS/LDFLAGS on the make command line replace the Makefiles' CFLAGS+= (pass via env);
  libvmmapi.so fails to link with -fPIE (TLS relocs) -> build only the libvmmapi.a target.
- Source facts: bhyvectl --suspend/--checkpoint only delivers the request over /var/run/bhyve/<vm>
  (answer != effect); with suspend bhyve writes .ckp/.kern/.meta then vm_destroy + exit(5). A device
  without pe_snapshot (virtio-console, virtio-9p, virtio-scsi, nvme, hda, passthru, virtio-input) makes
  the checkpoint fail with ENOTSUP AFTER the full memory write, and the VM resumes. virtio-console is
  the planned runner transport (CONTROL-PLANE §5) -> probe in sr3-30.
- Root run order (user, `cd ~/yard/ops/sr3 && sudo sh <script>`): sr3-10-install.sh, sr3-20-vmm.sh,
  sr3-30-cycles.sh. Undo: sr3-30-cycles-undo.sh, sr3-20-vmm-undo.sh (or reboot), sr3-10-install-undo.sh.
- Predictions (before any run): .ckp = guest RAM exactly (2,684,354,560 B for 2560M), 0.2-0.7 GB
  allocated on lz4; .kern 20-200 KB; .meta 5-30 KB. Suspend req->answer < 50 ms, answer->exit 2.0 s (1-5).
  Restore start->first tick 1.5 s (0.7-4). Live checkpoint pause ~2 s (1-5). 50/50 done, state intact,
  0 hangs (70%). virtio-console probe: answer ok, effect notdone, VM keeps running. Guest clock skew
  after restore -5..+1 s.
- First runs (user, 2026-10-07, 143348Z N=5 and 143825Z N=50 stopped after 6 recoveries): install and
  vmm swap OK. Suspend: 11/11 done, proc rc 5, req->answer 4 ms, answer->exit 1.28 s (predicted 2.0,
  1-5); .ckp 2,684,354,560 B = guest RAM as predicted, but only ~38-45 MB allocated (predicted 0.2-0.7 GB;
  lz4 on mostly-zero pages, compressratio 8.8x); .kern 88,025 B, .meta 1,384 B (below the predicted
  5-30 KB). Live checkpoint 7/7 done, 0.86-1.33 s. virtio-console probe: answer ok, effect notdone, as
  predicted. Restore: 11/11 notdone in 24 ms -- defect in sr3-30: "bhyve: no bootrom was configured"
  (without a bootrom bhyve only opens a VM bhyveload created; the suspend destroyed it). Fixed: the VM is
  recreated with bhyveload before `bhyve -r` (timed separately); optional SR3_BOOT=uefi. Cold boot to
  first tick is 17 s, not 4 s: every cold boot rolls back to @prepared, so firstboot runs each time.
- Run 2 (user, 145239Z bhyveload N=50; 150153Z uefi): bhyveload suspend 50/50 + restore 50/50 done,
  state intact (tok/pid/counter/disk/log), 0 hangs; suspend p50 0.78 s, restore = bhyveload 0.136 s +
  start->first tick 1.43 s. Three TEST defects (fixed in sr3-30): net=FAIL 50/50 because tunclose()
  purges the tap's host address when bhyve exits; skew -14401 s from the localtime RTC (no -u; host is
  UTC-4); after the recovery limit the hung VM was left running and the live checkpoints ran on it.
  Real finding: guest time does not advance across the downtime (vm_restore_time re-bases the TSC),
  -1.35 s per cycle -> a resumed guest needs a clock step (as SR2 plans). UEFI: 6/6 suspends done, 6/6
  restores hang (bhyve alive, no tick, no stderr). The snapshot saves only lowmem+highmem
  (vm_get_guestmem_from_ctx); the VM_BOOTROM devmem segment and the CFI flash variable state
  (bootrom.c `var`) have no snapshot hook -- suspected cause, unconfirmed; the rerun captures vCPU
  RIP/CR0 on hang.
- Rerun predictions: bhyveload GATE PASS, net ok 50/50 (and after every cold boot), cold-boot skew 0..-1 s,
  skew vs boot ~-1.35 s per restore (about -68 s by cycle 50). uefi: restores still hang (75%); the RIP
  samples either do not move (vCPU stuck/halted) or sit in the firmware's runtime region.
