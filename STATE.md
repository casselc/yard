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

## SR3 spike: bhyve snapshot/restore (branch sr3, 2026-10-07) -- bhyveload GATE PASS; UEFI restore hangs
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
