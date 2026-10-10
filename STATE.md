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

## SR0: session suspend/resume lifecycle (branch sr0, 2026-10-07)
Design + code only; nothing run on the NUC. Spec: spec/sr0/README.md (scope, assumptions, register of
external calls, mutant results, Quint -> Go mapping, what SR1-SR5 must provide).
- [x] Quint model spec/sr0/lifecycle.qnt (quint 0.32; typecheck/run/test, no verify): states active, idle,
      suspending, suspended, resuming, expired, failed; suspend record (kind, checkpoint/artifact, ZFS
      snapshot, token, credential epoch); every external call (quiesce, checkpoint, destroy, unquiesce,
      restore, STS mint, artifact delete) is request/effect/answer with lost request, late effect, lost
      answer, duplicate (retry, replay after restart), per casselc/observability otel-chdb/model/TEMPLATE.md;
      clock, op timeouts, slow activity observation, yard-ctl crash/restart at any step.
- [x] Invariants I1-I7 (resumed at most once, no acked write lost, no pre-suspend credential, artifacts
      encrypted and accounted, resume keeps its artifact, suspend only when idle, no held message dropped).
      Design and design2 hold at seed 0x5eed (3000 samples x 100 steps); 12 mutants each break their
      invariant, 7 in random simulation and all 12 in scripted counterexamples (lifecycle_test.qnt).
- [x] internal/lifecycle: pure Ctl (one method per Quint action), SQLite Store (modernc.org/sqlite v1.46.1,
      pure Go, builds for freebsd; token consume and expiry are single conditional UPDATEs, other commits
      CAS on the row), Machine (executor, clock, facts, recovery on Start: CtlRestart, RecoverOps, Adopt),
      Backend/Minter/ArtifactStore/ActivitySource/FactSink interfaces (SR1-SR4 implement).
- [x] Tests: 18 per-transition unit tests, 10 Machine/Store tests (double-resume race 32 callers -> 1 winner;
      16 store handles + an expiry on one token -> 1 winner; restart mid-resume; checkpoint timeout landing
      late; activity abort; message wake; expiry; unencrypted dataset refused), ITF replay of 189 traces
      (spec/sr0/gen_traces.sh) comparing Go to the model after every step; -race clean.
- Module: modernc.org/sqlite and deps came from the shared module cache under platform/go/cache/mod via
  GOPROXY=file://...; GOSUMDB was off for that one `go get` (go.sum hashes are the cached zips').
- Open: Deliver (message payload to the harness) is atomic in the model; instance loss while Active is not
  detected (SR1/SR2 health); a per-unknown-class production counter (AMBIGUITY rule 5); the broker and STS
  must enforce the epoch (I3); one yard-ctl process per database (A3).
- Decisions 2026-10-07 (user accepted the lead's recommendations; spec/sr0/README.md "Decisions"):
  - go.sum: the lead verifies online.
  - Message queue: yard-ctl owns it beside the lifecycle store. SR5 modelling item: delivery becomes
    request/effect/answer (message ids, harness dedupe, remove only on Done).
  - Credential epoch: implemented in internal/issuer (yard_sess/yard_epoch claims; mint refused unless
    current; VerifyEpoch for the broker side). Machine implements issuer.EpochSource.
  - One yard-ctl per database: lifecycle.OpenOwned (flock on <db>.lock, fail fast with ErrOwned).
  - SR1/SR2 requirement: health checks detect a dead instance while Active; model it first.
  - Metrics: lifecycle.OutcomeCounter hook on the fact sink; export as OTel counters when backends are real.
  - Focused simulation instances for the 5 mutants plain random runs missed (spec/sr0 README table).

## SR3 spike: bhyve snapshot/restore (branch sr3, 2026-10-07) -- bhyveload GATE PASS; UEFI restore hang explained (bhyve bug, patch on sr3-uefi)
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
- Run 3 (user, 2026-10-07): bhyveload 154337Z N=50: GATE PASS. Suspend 50/50 (total p50 0.784 s),
  restore 50/50 (bhyveload 0.136 + start->first tick 1.384 = p50 1.521 s, max 1.583), live 5/5 (p50
  0.72 s), state intact incl. net 50/50 and at both cold boots, 0 unknown, 0 cap hits, ckp allocated
  43.5-52.5 MB of 2.5 GB (compressratio 8.11x). Skew: cold boot -1 s, then -1.35 s per restore (-67 s
  after 50), as predicted. uefi 155438Z N=3: GATE FAIL, 3/3 restores hang. Diagnostics contradict the
  firmware-memory hypothesis: both vCPUs run in the guest KERNEL (RIP 0xffffffff81..., changing between
  samples, not halted) with RFLAGS 0x46 (IF=0): the kernel resumed and spins with interrupts off,
  likely waiting for an interrupt/IPI that never arrives. Leading hypothesis (unconfirmed): x2APIC mode
  under UEFI vs xAPIC under bhyveload, with x2APIC state not restored. Decision: suspend/resume uses
  bhyveload FreeBSD guests; UEFI/Linux guests are cold-boot-only until this is explained.
- UEFI hang analysis (branch sr3-uefi, 2026-10-07, source + logs only, no new run yet):
  * Symbols (15.1-RELEASE kernel.txz, the guest's kernel: console shows releng/15.1-n283562-96841ea08dcf):
    8115fdb8/8115fde6 = lapic_et_start just after the xAPIC MMIO writes of LVT-timer/initial-count,
    8105acfa = cpu_idle_acpi right after `sti; hlt`, 81070120 = Xtimerint_pti, 80b983dc = binuptime,
    80b99d86 = tc_ticktock. Not a spin: both vCPUs idle in hlt and take LAPIC timer interrupts (582 in
    60 s, idle ticks ~60k). The kernel is alive; every thread is blocked. No x2APIC in this guest
    (Features2 has no x2APIC, x2apic_mode=0 paths taken), so the x2APIC hypothesis is out.
  * Boot-log diff bhyveload vs UEFI: the firmware reassigns the virtio MMIO BARs (blk 0xc0000000 ->
    0xc0002000, net the reverse), INTx 16/17 -> 23/16 (fixed bootrom mapping in ioapic.c), efirtc0, ACPI
    from the firmware's copy. I/O BARs 0x2000/0x2080 identical.
  * Root cause (bhyve, unfixed on main as of b27a221ef79d): with a boot ROM, pci.enable_bars defaults to
    false (e962b37bf0ff), so bhyve registers no BAR handlers at startup and the firmware's command-register
    write registers them. On restore pci_snapshot_pci_dev() (pci_emul.c) copies pi_bar[].addr and the
    whole config space (decode bits set) but never calls register_bar: the restored guest has NO I/O or
    MMIO handlers for any PCI device. virtio-blk queue notifies go to the default inout handler and are
    dropped -> the agent's write/fsync never completes -> no SR3TICK, ever (consistent with only 17
    in/out exits in 60 s). bhyveload works only because bhyve's own BAR assignment is registered at
    startup and the guest never moved it.
  * Latent, same mechanism: without a boot ROM a guest that moved a BAR also resumes with handlers at
    the old address. Also: bhyve_init_platform_late() rewrites mptable/SMBIOS/ACPI into guest RAM AFTER
    restore_vm_mem (deterministic content in a reserved range: harmless here).
  * vmgenc (coordinator question): present in BOTH boot modes (acpi_tables defaults to true on amd64;
    both boot logs show vmgenc0), so not UEFI-specific and not the cause. Its UUID page is bootrom_alloc'd
    in the bootrom devmem segment, outside lowmem/highmem, so it is NOT in the snapshot: restore's
    vmgenc_init writes a NEW random UUID, but the GPE that would notify the guest is `#if 0` ("XXX When
    we have suspend/resume/rollback"), so the guest never re-reads it and does not reseed. Consequence
    for yard: a restored guest (and every clone of one snapshot) keeps its pre-snapshot RNG state ->
    SR2 resume must reseed explicitly (write fresh entropy to /dev/random in the guest) or we patch
    bhyve to raise GPE_VMGENC after restore (guest vmgenc_notify -> random_harvest_direct reseed).
  * Patch: ops/sr3/patches/0001-bhyve-snapshot-restore-reregisters-pci-bars.diff (userland bhyve only,
    syntax-checked with the NUC's cc -Wall -Werror): on restore, clear the decode bits and let
    pci_emul_cmd_changed() unregister the pre-restore BARs, read the state, then let it register the
    restored BARs whose decoding is enabled. Build: sr3-00-build.sh SR3_PATCHES/SR3_VARIANT (shadow
    source tree, /usr/src untouched), installed beside the base build as bhyve-snap-<variant>.
  * No-build workaround (diagnostic only): `bhyve -r ... -o pci.enable_bars=true` registers bhyve's
    default BARs; correct for the I/O BARs here, but the MSI-X MMIO handlers then sit at the swapped
    addresses (a guest MSI-X table access would hit the wrong device / assert). Not for production.
  * Experiments and predictions (stated before the runs): A (unpatched, SR3_BOOT=uefi N=3,
    SR3_RESTORE_OPTS="-o pci.enable_bars=true"): 3/3 restores done, state intact (80%). B (negative
    control, unpatched, bhyveload N=3, "-o pci.enable_bars=false"): 3/3 restores hang like UEFI, same
    idle/timer RIPs (85%). C (SR3_VARIANT=p1, uefi N=50): GATE PASS, restore start->first tick ~1.4 s as
    bhyveload (75%). D (p1, bhyveload N=50): GATE PASS, no regression (90%). E (p1, bhyveload N=3 with
    "-o pci.enable_bars=false"): 3/3 done (85%). If A and B come out as predicted but C fails, the
    patch is wrong, not the diagnosis.
  * Upstream: report warranted (draft in ops/sr3/patches/UPSTREAM-PR-draft.txt, not filed).
- VM generation ID on restore (user approved the patch, 2026-10-07; patch 0002, variant p2 = 0001+0002):
  * Source facts: amd64/pm.c (PM1 enable/status/control, GPE0 enable/status, sci_active) has NO
    snapshot hook -> after restore GPE0_EN=0, so raising the vmgenc GPE alone would never reach the
    guest; and the SIGTERM power-button mevent (installed on the guest's ACPI-enable write) is missing,
    so `kill -TERM` does not power a restored guest off (stop path for yard: bhyvectl/kill -9 or p2).
    The SCI pin itself (vatpic ELCR, vioapic rtbl+acnt) IS in the kernel snapshot.
  * 0002: pm_snapshot() as device "pm" (restore tolerates older snapshots without it; re-installs the
    power-button handler when SCI_EN was set); vmgenc_restore() runs in bhyverun.c after
    vm_restore_devices/vm_restore_kern_structs/vm_resume_devices and before vm_resume_cpu: fresh ID
    into the page + acpi_raise_gpe(GPE_VMGENC). Not called by --checkpoint (running VM keeps its ID).
    Syntax-checked on the NUC (cc -Wall; only the two pre-existing snapshot.c -Wpointer-sign hits).
  * Guest side: FreeBSD vmgenc(4) on notify 0x80 compares the page with its cache, then
    random_harvest_direct(RANDOM_PURE_VMGENID) into Fortuna pool 0 (reseed at the next /dev/random read
    once pool 0 has >= 64 B and >= 100 ms since the last reseed -- not a forced immediate reseed),
    EVENTHANDLER acpi_vmgenc_event (no in-tree listener), devd ACPI/VMGenerationCounter; no counter,
    but sysctl dev.vmgenc.0.guid shows the cached ID. Userland arc4random state in long-lived processes
    is NOT reseeded on FreeBSD (no userland hook). Linux vmgenid (ACPI ids VMGENCTR/VM_GEN_COUNTER, ADDR
    package, notify 0x80) -> add_vmfork_randomness(): immediate crng reseed + vDSO getrandom generation
    bump + uevent NEW_VMGENID=1; bhyve's _CID "VM_Gen_Counter" evidently matches FreeBSD's uppercase id,
    the same match should hold for Linux -- verify with the first Linux guest.
  * sr3-30: agent v2 (@prepared2; first run re-prepares the image, ~2 min) prints gen/kr/vg; after each
    restore gen=chg|same and vgev=+n are recorded; SR3_SAME_SNAP=yes restores one snapshot SR3_SAME_K
    times (disk rolled back to @same each time) and records pwr=off|killed for SIGTERM. Gate items only
    with SR3_VARIANT=p2+.
  * Predictions: unpatched (A-D runs): gen=same, vgev=+0 on every restore (95%); unpatched same-snap:
    pwr=killed every time (90%), kr distinct anyway (60%: host RDSEED/interrupt entropy reaches pool 0
    before the agent's first read), so kr alone does not discriminate. p2 uefi N=50 and bhyveload
    N=50: GATE PASS with gen=chg vgev=+1 on all 50 (80%). p2 same-snap K=5: 5/5 done, 5 distinct gen,
    5 distinct kr, pwr=off 5/5 (75%).
- Runs 2026-10-07 (A/B/p1/p2) and the vmm bug they exposed (patch 0003, variant p3 = 0001+0002+0003):
  * A (uefi, -o pci.enable_bars=true) 3/3 PASS; B (bhyveload, =false) 3/3 hang as predicted; p1
    bhyveload 50/50 PASS; p1 uefi 50/50 done but 2 "corrupt" = harness defect (half-written console line
    parsed; fixed in sr3-30, RUN 5). p2: only the first restore after a cold boot gets the vmgen notify,
    and a restored guest never powers off on SIGTERM.
  * Cause (source-checked): APICv EOI virtualization. The VMCS EOI-exit bitmap is set only by
    vioapic_update_tmr() on a guest redirection-table write; a restored VM starts with it zeroed and
    nothing rebuilds it, so the guest's EOI of the level SCI never reaches the vioapic (Remote IRR stays
    1, pin wedged; later snapshots carry RIRR=1). 0003 (vmm.ko) rebuilds it in vm_snapshot_req() after
    the vioapic and vlapic restores. Old wedged snapshots stay wedged (disposable).
  * Build/install: a variant with sys/ patches builds its own vmm.ko (BUILDINFO kmod=own); sr3-20-vmm.sh
    with SR3_VARIANT loads it, sr3-30 refuses any other bhyve/vmm pairing. sr3-30 RUN 5 also fixes the
    mid-run overwrite abort (whole body parsed up front, rename deploy, summary from the EXIT trap).
  * Predictions for p3: uefi N=50 and bhyveload N=50 GATE PASS with gen=chg vgev>=1 on all 50 and
    final_pwr=off (80%); same-snap K=5 pwr=off 5/5 (85%); p1 uefi false corruption gone (95%).
    Control without the patch: p2 with kenv hw.vmm.vmx.use_apic_vid=0 behaves like p3 (75%).

## SR3 host panic on restore under APICv (2026-10-07) -- patch 0004 written, untested

- 14:41:51 EDT the NUC panicked: "ISR and isrvec_stk out of sync" (/var/crash/info.1, vmcore.1). It was 2 s
  after the first restore in the SR3J e2e (sr3j-20-20261007T183613Z), of a guest that was busy (its UART
  bulk test had stalled; it had stopped ticking) on the base snapshot vmm.ko with APICv on.
- Cause (source): vmx_vcpu_snapshot() saves neither VMCS_GUEST_INTR_STATUS (RVI/SVI) nor the PIR
  descriptor, so an in-service vector at suspend stays in service after restore (SVI = 0). The next HLT
  reaches vlapic_update_ppr()'s always-on check (vlapic.c:543) via vm_handle_hlt() (vmm.c:779).
  Every SR3 cycle so far suspended an idle guest, which is why the gate never saw it.
- Patch 0004 (vmx.c, vlapic.c, vlapic_priv.h): flush PIR -> IRR before the save; recompute RVI/SVI from
  IRR/ISR after the restore. Variant p4 = 0001-0004 (kmod=own). It applies cleanly; not yet compiled.
- sr3-30-cycles.sh SR3_LOAD=irq: ping flood during each suspend. It refuses pre-p4 modules while virtual
  interrupt delivery is on, unless SR3_LOAD_FORCE=yes. The run header and GATE line record VID and LOAD.
- Standalone reproducer for the report: ops/sr3/repro/apicv-restore-panic.sh (REPRO_ACK=panic-the-host).
- Predictions:
  - p4 + SR3_LOAD=irq, N=50: GATE PASS, both boots.
  - APICv off + base module + SR3_LOAD=irq: GATE PASS.
  - p3 + SR3_LOAD_FORCE=yes: host panic, or guest wedge, within a few cycles.
- Until p4 passes, never suspend a busy guest on base/p1-p3 with APICv on.

## SR3J spike: unprivileged jailed bhyve + snapshot-safe agent channel (branch sr3-jail, 2026-10-07)
Scripts in ops/sr3j/ (nothing run on the NUC yet; all root steps are the user's). Source: NUC /usr/src
(15.1-STABLE fabb224f2f15, = running kernel; same tree SR3 built from).
- Source findings (sys/dev/vmm/vmm_dev.c, libvmmapi, bhyve, if_tuntap.c, nmdm.c, ng_socket.c, ng_device.c, devfs):
  - No privilege check anywhere on the vmm path except `vmm_priv_check` = "jailed => allow.vmm". Access is
    file permissions: /dev/vmmctl (root:wheel 0600, open needs FWRITE) and /dev/vmm/<name> (made root:wheel
    0600, si_cred = creator's cred). vmmdev_open/ioctl/mmap use si_drv1 directly: WHOEVER CAN OPEN
    /dev/vmm/<name> CONTROLS THE VM -- the devfs node's owner/mode is the whole access control.
  - Names are global. VMMCTL_VM_DESTROY/hw.vmm.destroy look up by name with cr_cansee(caller, creator):
    prison_check + see_other_uids/gids + see_jail_proc. With see_other_uids=0 another uid gets EINVAL even in
    the same jail; another jail gets EINVAL; host root sees all. VMMCTL_VM_CREATE of an existing name by an
    uid that cannot see it returns EEXIST (from make_dev's duplicate-name check): existence leaks, names can
    be squatted (DoS), and the half-created VM is briefly first in the list, so the owner's own by-name lookup
    can fail transiently. Mitigation: host-assigned, unguessable VM names.
  - devfs hides /dev/vmm/<name> from other jails by si_cred (devfs_prison_check), independent of rules.
    Rules (`user`/`mode`) apply to nodes created later in a mount, so a runtime ruleset can hand
    vmm/<name> (and vmm.io/<name>.*) to the VM uid before the VM exists.
  - Guest memory: VM_ALLOC_MEMSEG is an OBJT_SWAP object with no cred (not charged to the uid); bhyve maps it,
    so the bhyve process VSZ includes guest RAM (rctl user:<vmuid>:vmemoryuse caps it only if nothing else
    runs as that uid). `-S` wiring is VM_MAP_WIRE_USER on the guest vmspace: global vm.max_user_wired, no
    per-uid RLIMIT_MEMLOCK -> do not allow -S for VM uids. A compromised bhyve (= the VM uid) can create
    more VMs/memsegs not charged to anything: cap with VM count checks in yard (risk, no kernel knob).
  - bhyve/bhyveload need no root: modfind("vmm") works unprivileged (kldload is skipped when loaded);
    bhyveload reads userboot*.so from the jail's /boot; bhyve opens the disk, tap/vmnet/ngd, nmdm, binds
    /var/run/bhyve/<vm> (jail path; bhyvectl connects to the same fixed path, so bhyvectl runs in the jail as
    the VM uid), then caph_enter. Snapshots: bhyvectl sends a DIRECTORY FD + basename over that socket and
    bhyve openat()s the files with its own cred -> .ckp/.kern/.meta owned by the VM uid; restore opens the
    files before cap mode. Anyone who can connect to the socket can suspend the VM -> dir 0700.
  - tap: opening an existing /dev/tapN needs only file permission (net.link.tap.user_open only gates devfs
    cloning). BUT bhyve's VMIO_SIOCSIFFLAGS at open resets if_flags (clears IFF_LINK0) and tunclose purges the
    host address -> after every suspend root must re-add it. vmnetN (same driver, TUN_VMNET) skips the purge:
    use `ifconfig vmnetN create` + bhyve `virtio-net,vmnetN`.
  - netgraph: upstream bhyve already has an `ngd` backend: ng_device(4) node -> /dev/ngdN, which bhyve opens
    like a tap (no netgraph privilege, no patch). ng_device + ng_eiface outlive bhyve; packets for a suspended
    VM queue in the device (net.link.ifqmaxlen=50). The `netgraph` backend itself calls NgMkSockNode
    (PRIV_NETGRAPH_CONTROL; in a non-VNET jail also blocked by allow.socket_af=0 -> EPROTONOSUPPORT).
    ng_socket DATA sockets need NO privilege and may connect(2) to ANY ng_socket node by name/[id] that has no
    data socket yet (no prison check) -> a privileged helper must hand bhyve a node whose data socket it
    already holds (NgMkSockNode makes both at once; a race loser gets EADDRINUSE, never a hijack).
  - UART backends: stdio, tty (nmdm), tcp=addr:port (listens; no unix socket). nmdm pairs can be created
    by any uid (tty_makedevf with the opener's cred: owner = opener, visible only in its prison).
- Decisions: VM uids 2100000-2109999 (own range, gid = uid): bhyve is infrastructure, not task code; a
  task uid's user: rctl caps (vmemoryuse 8g, maxproc) would also count guest RAM; audit/accounting
  distinguishes VM monitors; one uid per VM so cr_cansee and file modes separate VMs. One jail per VM
  (allow.vmm, ip4.addr = host side of the VM link, devfs ruleset per VM). Launch via sr3j-launch (root: optional
  netgraph socket, jail_attach, setgroups/setgid/setuid, refuses if root can be regained, closefrom, exec).
  Exec-with-inherited-fd rather than SCM_RIGHTS to a running launcher: no privileged daemon, no peer auth,
  the fd only ever exists in the helper and then in bhyve (same process).
- Channel: framed (magic, type, len, seq, CRC32), host-driven resume epoch in HELLO, agent answers
  WELCOME{last_seq}, host resends from last_seq+1 -> exactly-once per stream; a HELLO with an older
  connection generation is refused (found in the local test: queued HELLOs from abandoned attempts stole
  the stream); MSGs from a superseded connection are dropped (stale). -stepclock steps the guest clock to
  the host time in HELLO (restored guests lose the downtime). cmd/sr3j-chan (Go, one binary: agent/client).
  Recommendation (to be confirmed by the run): TCP over the VM link (vmnet or ngd) as primary: throughput
  for tool I/O, usable by any process in the jail with the jail's IP, pf-guarded; a TCP connection even
  survives a short suspend (host retransmits). UART via nmdm as fallback/bootstrap: no network config, no
  pf, survives snapshot (uart_emul has snapshot support) but ~10-100 KB/s and one opener at a time.
  virtio-console is excluded (no snapshot support, SR3 probe).
- bhyve patch ops/sr3j/patches/0001-bhyve-netgraph-datafd.diff: `virtio-net,netgraph,datafd=N` uses an
  inherited ng_socket data socket (checked: SO_DOMAIN PF_NETGRAPH, SO_PROTOCOL NG_DATA, fd >= 3, excludes
  path/socket), keeps the CAP_EVENT|READ|WRITE limit. bhyve has no closefrom, so fd 3 survives exec; each
  bhyve start (boot, every restore) gets a new socket node from sr3j-launch; the eiface persists.
  Upstream? Weak case: `ngd` already gives unprivileged bhyve netgraph access through devfs without a helper.
  datafd's only extra is that the node dies with bhyve (no stale queue, exclusive by construction).
  Draft (not sent): "bhyve: netgraph backend: accept an inherited data socket (datafd=N). Lets a privileged
  parent create and connect the ng_socket node (PRIV_NETGRAPH_CONTROL) and run bhyve unprivileged or in a
  non-VNET jail; bhyve only reads/writes the data socket, rights-limited as today. Alternative to ngd(4)
  when the node should live exactly as long as the bhyve process."
- Run order (user): Halo `tools/deploy-sr3j.sh`; NUC as chuck `sh ~/yard/ops/sr3j/sr3j-00-build.sh`;
  root `cd ~/yard/ops/sr3j && sudo sh sr3j-10-install.sh`; then (snapshot vmm.ko must be loaded:
  ops/sr3 sr3-20-vmm.sh) `sudo sh sr3j-20-e2e.sh` (default SR3J_NET=vmnet), then
  `sudo env SR3J_NET=ngd sh sr3j-20-e2e.sh`, `sudo env SR3J_NET=ngfd sh sr3j-20-e2e.sh`,
  `sudo env SR3J_NET=tap sh sr3j-20-e2e.sh` (baseline: address purge). Undo: sr3j-20-e2e-undo.sh,
  sr3j-10-install-undo.sh, rm -rf ~/yard-sr3j. Note: ops/sr3 sr3-30-cycles-undo.sh destroys
  zroot/yard/data/vmsnap with -r (it would take a kept sr3j-a child with it).
- Predictions (before any run): in the header of sr3j-20-e2e.sh (per-check expected values are also the
  `predicted` column of results.csv).

### SR3J outcome (2026-10-07, p4 vmm.ko): GATE PASS on all four backends
- vmnet 20261007T204214Z (with SR3J_UART_SWEEP), tap 204924Z, ngd 205101Z, ngfd 205240Z: 5/5 unprivileged jailed
  suspend+restore each, isolation as predicted, 0 duplicate deliveries; tap/ngd/ngfd 0 mismatches.
- UART with the credit window: ~100 KB/s guest->host, 60-67 host->guest, 1.8-2.2 bhyve cores saturated (PAUSE
  exits from the guest's UART spin lock); control frames under bulk p99 15-27 ms; RTT 64 B 1.35 ms, 4 KiB 67 ms
  (TCP 0.07-0.14 ms). The UART is the control path only; bulk goes over TCP (250-420 MB/s).
- Restore start -> channel ~0.55 s, -> tick ~1.1 s; the resume epoch reaches the guest on every restore.

## SR1: service jails suspend/resume (branch sr1-service-jails, 2026-10-07) -- code + model done; e2e NOT RUN (user); decisions of 2026-10-07 built
HARNESS.md "SR1: jails on the NUC/jailhost". SR1 is a client of the SR0 lifecycle: kind "service" is a
lifecycle.Backend (+ Pauser, + ArtifactStore) in internal/service; yard-svc drives lifecycle.Machine.
- Spec (internal/service/spec.go): name, argv, env, cwd, ports, readiness probe (tcp | http GET from the host
  through the sandbox's exposed port | cmd in the service's jail, exit 0), start_timeout, stop_grace, kill_wait,
  pause_wait, mem, tmp. Validated against the sandbox (network probe => broker sandbox exposing that port).
- Mapping onto the SR0 ops: Quiesce = stop (SIGTERM once per process + SIGCONT to stopped ones, re-scan for new
  ones, SIGKILL after the grace, verify none left; jail kept); Checkpoint = `zfs snapshot
  <ws-dataset>@ysr1-<sess>-g<gen>-c<ckpt>` + spec artifact (sha256-digested, create-only via link(2)) on the
  encrypted dataset; Destroy = jail_remove + wait for its processes + unmount + rmdir; Restore = new jail
  <sbx>.s<sess>-<gen> through spawn.Start (yard-spawn's per-call setup path), wait for readiness, on failure
  remove it (=> observed not done => ResumeAbort, fresh token); create-only by jail name. Unquiesce (abort) =
  SIGCONT or start again in the same jail. Pause/Unpause = SIGSTOP/SIGCONT until all processes are T / none is.
- Signals are sent FROM INSIDE the jail as the service uid (yard-exec-shim + /bin/kill pid...): the kernel's
  prison/cred check confines them. NUC fact: kern.randompid=1023, so the pid space (pid_max 99999) wraps every
  ~200 forks; host-side kill-by-pid (pkill -j style) could hit a reused host pid. Listing is `ps -ax -o jid=
  -o pid= -o stat=` (NUC gotcha: `-o jid=,pid=` makes ",pid=" the header of jid; `ps -J` refuses a dying jail).
- Settle bound (A1): each op copy holds flock <state>/ops/<id>.lock, inherited by its zfs and shim children (the
  shim closes it at closefrom just before exec), so InFlight sees an earlier incarnation's child.
- Workspace = its own dataset zroot/yard/data/ws/<sbx> (encrypted via data, exec=on setuid=off), sandbox
  -workspace; not rolled back at resume (nothing writes while suspended); restore records written@snap (drift).
- Model (spec/sr0): pause tier added (state Paused, phases PPause/PUnpause, ops OPause/OUnpause, Inst.frozen,
  policy pause/suspendHold, invariant I8 noFrozenAwake) with mutant unpauseBeforePauseSettles. Modelling found a
  latent SR0 defect: OpRetry resent ANY not-done retryable op, also after the row moved on (a lost SIGSTOP resent
  while the SIGCONT is out; in SR0 a superseded quiesce could kill the service after an abort). New rule
  RETRY_CURRENT (deletes/mints always; stop/start/pause ops only while row.op is theirs), mutant
  retrySupersededOp; Go Ctl.OpRetry fixed. Also: recoverAssumesNotDoneFocus's "breaks (~570)" was seed luck
  (old model, 0/9000 at 3 other seeds); new focused step stepCrashCkpt (crash only with a checkpoint in flight)
  breaks it in ~80 traces. Machine no longer commits memory-only steps (each commit was an fsync).
- Model results (run_models.sh, 0x5eed): designPause/design/design2 hold I1-I8; unpauseBeforePauseSettles breaks
  (~277), retrySupersededOp (~1074); 17 scripted modules 0 failing; replay 222 traces, 18389 steps.
- Tests: internal/service unit tests on a fake OS (signals with stopped/TERM-pending semantics, lingering
  processes, unkillable, forks on TERM/STOP, zfs fail / lost answer, hanging probes) + Machine integration
  (3 cycles, readiness-timeout abort, pause tier); -race clean. tools/sr1-mutants.sh: 16 planted mutants via
  `go test -overlay`, all caught.
- Root run (user): Halo `tools/deploy-nuc.sh`; NUC `cd ~/yard/ops && sudo sh yard-unlock.sh`, then
  `cd ~/yard/ops/sr1 && sudo sh sr1-10-e2e.sh` (knobs SR1_N=10, SR1_GRACE, SR1_START_DELAY, SR1_KEEP,
  SR1_SKIP); undo `sudo sh sr1-10-e2e-undo.sh`. VM disks: `sudo sh n0-60-vmx.sh` (undo n0-60-vmx-undo.sh).
- Predictions (before any run; also in the script header): stop p50 20 ms (8-50); zfs snapshot 40 ms (15-120);
  checkpoint 55 ms (25-150); remove 6 ms (2-20); start-to-ready 30 ms (15-80); suspend decision->commit 100 ms
  (50-250), wall 150 ms; resume consume->complete 50 ms (25-150), wall 90 ms; p50 suspend+resume << 1 s +
  service start (95%); drift 0, state continued, 0 leftovers; K: stop = 1 s grace + 10-60 ms escalated;
  T: resume not done after 2.0-2.3 s, back to Suspended; P: pause/unpause 3-30 ms. GATE PASS 70%.
- Open: message delivery stays atomic (X12); a restore whose cleanup fails leaves an unready instance that is
  observed done (the liveness probe now fails it once it has no process).

### SR1 decisions of 2026-10-07 (user) -- built; model + tests done; e2e NOT RUN (user)
- Layout (CONTROL-PLANE.md "Workspace layout"): zroot/yard/ws is its own encryption root (raw key file
  /yard/data/yard/keys/ws.key on the data root, loaded by yard-unlock.sh), exec=on setuid=off compression=zstd
  atime=off (FreeBSD has no `devices` property; devfs rulesets govern device nodes). ws/<project> is an
  encryption root with a raw key (keylocation=prompt) held by the key service; it holds the base
  (canmount=noauto, /yard/ws/<p>/.base, snapshots @base-<n>, n never reused: user property yard:basegen);
  sessions are clones ws/<p>/<s> (refquota, /yard/ws/<p>/<s>); suspend snapshots on the clone. Data root and
  data/sr1 stay exec=off. internal/service/workspace.go: CreateProject, SnapshotBase, CloneSession,
  DestroySession (promotes the project back if the session was promoted), RetireBase (no clones: destroy;
  clones: `destroy -d` deferred, or promote the newest clone, oldest generation only), LoadKey/Unmount/
  UnloadKey (+ observations), ShredProject. yard-svc ws-init/ws-base/ws-clone/ws-load/ws-destroy/ws-retire/
  ws-shred, up -project, -kek file:PATH|tpm:HANDLE.
- Keys (internal/wskey; IDENTITY.md "Workspace and spill keys" joint section with SE's "Spill keys"): KEK =
  HKDF of a deterministic RSASSA-PKCS1-v1_5 signature by a dedicated TPM key 0x81010012 (not built on the NUC:
  the handle must be created by the user; tests and the e2e use a 32-byte KEK file); data keys 32 random
  bytes, AES-256-GCM-wrapped (AAD consumer|subject|version) in the lifecycle db table wskeys, secure_delete
  on; Shred NULLs the wrapped key and truncates the WAL. Lifecycle: resume phase PKey (ResumeLoadKey behind
  KEY_FENCE, ResumeKeyDone), project records (Ctl.Projects, SQLite table projects) with KeyUnloadBegin
  (KEY_GUARD: every session of the project Suspended/Expired/Failed, no driver, no load unresolved) ->
  OUnmount -> OUnloadKey -> KeyUnloadDone, KeyUnloadAbort, RecoverProjOps; Router.Keys = the service backend.
- Per-session rekey (designed, measured by e2e step R, not built): `zfs change-key` on a clone only rewraps
  the project's master key ("newly-written data will continue to be encrypted with the same master key",
  zfs-change-key(8)); it neither isolates the session nor breaks clone sharing, and destroying the session's
  key shreds nothing. Real per-session keys need a non-clone copy (send|recv into a new encryption root,
  one full copy of the base per session).
- Decision 2: Restore runs `zpool sync` (written@ counts only synced data: a write in the open txg read 0),
  then refuses written@snap > 0 without the override: lifecycle.ErrRefused -> op Refused (definite) ->
  ResumeAbort records Drift (fact resume_refused_drift), fresh token; a held message does not auto-resume a
  Drift row; `yard-svc resume -force` (ResumeConsumeForce, Op.Force) resumes on the changed workspace. An
  unreadable drift is an error (unknown); Restore also refuses an unmounted clone (fail closed).
- Decision 3: Machine probes awake sessions every Config.ProbeEvery (Instance: jail exists with a process);
  a timeout is unknown; LostDetect (Failed, fact lost) only for an answer about the row's current instance and
  generation (a suspend attempt bumps it). `yard-svc probe -sess S -for D`.
- Decision 4: per-call jail sessions (kind "jail") have no suspend backend: nothing to suspend (a call runs to
  completion or its timeout); their rows only ever go Active -> Idle; a suspend would need a backend first.
- Model (spec/sr0): constants PROJECT, DRIFT_REFUSE, KEY_GUARD, KEY_FENCE, RESUME_LOADS, PROBE_CURRENT,
  PROBE_TIMEOUT_UNKNOWN; invariants I9 noSilentDrift, I10 noLiveFailed, I11 keyUnderActive; instance
  designKeys (2 sessions, 1 project), design2's s1 has a project; mutants resumeIgnoresDrift, deadOnProbeTimeout,
  staleProbe, unloadUnderActive, loadDuringUnload, resumeWithoutKey (+ focused rows); stepCore (step without
  the SR1 actions) for the three older mutants whose random detection the new actions diluted.
  Results and the separate key-service model (spec/keys): spec/sr0/README.md "SR1 decisions of 2026-10-07".
- Tests: lifecycle sr1_test.go (unload guard, load fence, refusal, probes, store fields), service
  workspace_test.go on a fake zfs with clone/key rules (zfs_fake_test.go), sr1dec_test.go (drift refused and
  forced, zpool sync before the read, unmounted clone refused, key cycle / drift / lost through the Machine);
  replay 361 traces, 31253 steps; go test -race ./... clean. tools/sr1-mutants.sh: 35 mutants, all caught.
- e2e (ops/sr1/sr1-10-e2e.sh, default N=10): steps 0 layout, cycles with key unload/load, D drift refusal, R
  rekey probe, K, T, P, X dead instance, L, S crypto-shred; predictions in its header.
- Decisions for the user: (1) crypto-shred completeness: a wrapped key survives in any snapshot or raw-send
  backup of the dataset holding the yard-ctl db (and the TPM root still opens it); keep that db's dataset out
  of snapshots/backups, or accept "shredded once backups age out"; (2) create the TPM wrap key 0x81010012
  (root); (3) `yard-svc down` leaves the lifecycle row as it was (an Active row of a removed session blocks its
  project's key unload): add a Removed transition to SR0; (4) a dead instance -> Failed; a restart policy for
  services is not designed; (5) n0-10-zfs.sh still creates zroot/yard/vm on a fresh install.

## Key service: yard-ctl spill keys + workspace keys (branch keysvc, from sr1-service-jails c25799b; 2026-10-07)
STATE (keep current; resume here):
- [x] worktree /work/platform/yard-keysvc, branch keysvc
- [x] read IDENTITY.md "Spill keys" + joint section, spec/keys, halo stream/spill-crypt yard_keys.cpp/serve.cpp
- [x] spec/keys (README "Key service (keysvc) changes"): halo's current rules (through + durable fence, slot
      deadline min(token exp, reg + TTL), round-4 revoke bounded by the token epoch), controller SuspendAbort,
      burnt epochs, OpVerifyRetry, explicit through; K6 checkpointKept; mutants revokeDefaultThrough,
      unboundedRevoke; K7 revokeBoundedByAuthority (coordinator/halo SE round 4: capped + scoped revoke,
      mutants revokeUncapped, revokeUnscoped); steps stepKeysvc (replay), stepCore/stepCoreFast (project
      mutants), stepRevoke (K6), stepRevokeLate (K7). revokeOnlyByMessage is obsolete as a break (finding 6).
      run.sh: final rerun in progress (results.txt).
- [x] internal/keysvc: Ctl (model mirror), Store (spill_* tables in the key DB /yard/data/keys/wskeys.db,
      KEK = wskey.KEK), HaloClient (admin Unix socket, peer uid checked; TCP only for the tailnet route),
      IssuerMinter (halo_spill JWTs), Service (Seal/Open/Discard/Remove/Poll/InFlight/Shredded), KV backend +
      Artifacts wrapper + LateEpochs (lifecycle wiring), fake halo (halo rules, faults), tests.
- [x] ITF replay 157 traces / 7647 steps (spec/keys/gen_traces.sh); 15 scenarios (lost/late/duplicate/stale,
      restarts, abort, delayed revoke, round-4 bound, delayed revoke after a newer seal); lifecycle Machine integration (kv); 8 planted mutants
      all caught (TestMutantsCaught); go test -race ./... clean.
- [x] docs: IDENTITY.md "Key service (built)" (research dir, not a git repo), spec/keys README.
- Open / decisions: SR0 should bump the epoch on an abort after a possible spill (else ErrEpochBurnt until
  the next commit); cmd/yard-svc wiring left for the merge (SR1 edits it); SR1's Removed -> Service.Remove
  hook; halo restart loses the cache entry (ErrEntryGone -> re-prefill, SR1 draft ResumePrefill); EntryMap
  (yard session -> halo entry) is SR5's; no real halo_serve run (spill needs the GPU).
- Merge note: SR1 (yard-sr1, uncommitted) ALSO edits spec/keys (fence/through/entry/prefill/socketOnly) and
  adds lifecycle Removed + -keys-db. Expect a conflict in spec/keys/keys.qnt; halo-rule parts are equivalent.

### Interrupted-session closeout (2026-10-08)
- Signed stable `halo_spill.op` now has service-level regression evidence: lost registration answer,
  controller restart preserving identity, cancelled/TTL-exhausted registration verified absent before
  renewal, new seal key/id and old-key shred. Issuer claim test checks the actual signed `op`.
- Restored the replay generator's current scripted run names and regenerated 174 ITF traces / 8,782 steps;
  `RenewOp` replayed 16 times. Full `go test -race ./...` passed; focused keysvc suite passed again after
  refusal-class and nonce tests. 10/10 controller mutants caught (including reuseOpID and noRenew).
- Full default-sample model rerun completed: `spec/keys/results.txt`, failures 0; 29 design scripts,
  14 mutant scripts, all witnesses reached across the design steps. These are bounded simulation results.
- GLM reviewed the interrupted delta; replay/tests/docs gaps closed. Conflicting identity is ErrOpConflict;
  history-full is ErrRetryLater, stops this drive and permits a later verify/retry within the attempt limit.
  Nonce widened to 63 random bits; restart test pins the persisted nonce used in signed identities.
- Model boundary documented: peer tombstone pruning/table saturation is not modeled. Unbounded historical
  Go rows and a stale-issuer revoke's liveness remain follow-ups; time-bound shredding remains the fallback.
- Actual cross-repository integration now passes under -race and the shared GPU lock: TestRealHaloPeer
  mints 2048-bit RS256 operation-id JWTs through the real issuer, sends them over the private admin socket,
  and completes two spill/restore cycles against SE's real-model C++ halo_serve. Restored epochs 2/3 observed;
  clean peer shutdown verified. Raw completion fixture explicitly uses fast cache mode to retain a state.
  Optional test gates HALO_KEYS_PEER_BINARY / HALO_KEYS_PEER_MODEL (no GPU execution in ordinary Go suites).
- Changes are included in the requested closeout commit. Existing integration/deployment items above remain:
  cmd/yard-svc wiring at integration, entry map/SR5 and user-run NUC root tests.
