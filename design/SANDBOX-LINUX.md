# Sandboxes for wrapped harnesses: alternatives (2026-10-12)

> Context: yard's agent-platform design notes (REPORT, HARNESS, IDENTITY, CONTROL-PLANE, WARDEN) are private
> working documents and are not in this repository; this note names their decisions where it relies on them.
> The operation contract it refers to is cordis RFC 0007 and halo-flash docs/OPERATIONS.md.

## The question

Where and how should yard run Claude Code, Codex and opencode (Linux programs) as agent operations? An agent
operation is a Cordis effect such as a Claude review cell (see the agent-operations sketch).

HARNESS.md planned Firecracker on the Halo (SR2) and FreeBSD jails on the NUC for the native yard-agent. This note
lays out the alternatives, now that:
- the Halo's kernel supports Landlock and gVisor is installed;
- the NUC has Linux compatibility loaded.

## What the hosts have (checked 2026-10-12)

| | Halo (Ryzen AI MAX+ 395, 128 GB) | NUC (N150, 16 GB) |
|---|---|---|
| OS | Linux 7.0.0-34 (Ubuntu) | FreeBSD 15.1-STABLE |
| Sandboxing primitives | **Landlock ABI 8**, seccomp filters, unprivileged user namespaces (but `apparmor_restrict_unprivileged_userns=1`), cgroup v2 | VNET jails, rctl, pf anchors, Capsicum, securelevel |
| Installed tools | `bwrap` (works), `runsc` release-20260810.0 (**rootless `runsc do` fails**: "re-executing self: permission denied", most likely the AppArmor userns restriction), crun, podman, docker, systemd-run | `yard-spawn` + `yard-exec-shim` (J0 done), the broker |
| Virtualisation | `/dev/kvm`, user in `kvm`; **Firecracker v1.17 spike P0-2 done**: boot to init 126 ms with the i8042 flags, vsock RTT ~0.4-0.5 ms | bhyve (SR3 spikes) |
| Linux compatibility | native | **linux64 loaded on the host** (HARNESS.md decided "off, jailhost VM only"; the decision and the host disagree) |
| Workspaces | ZFS 2.4.1 on `rpool` (`/home`); `/data` is XFS (reflink copies) | ZFS (`zroot/yard`) |
| Shares the machine with | halo_serve: the GPU, ~70 GB of weights, the engine's CPU threads | the control plane (STS, yard-ctl, broker) |

The Halo is also the inference box. A sandbox there shares a kernel with the engine and its GPU devices
(`/dev/kfd`, `/dev/dri`) unless it sits under its own kernel.

## Requirements every design must meet

From the platform's decisions (REPORT, IDENTITY, HARNESS) and RFC 0007:
1. **Credentials never enter the sandbox.** Model and cloud calls go through the broker, which injects keys and
   meters usage, so cost is measured outside the agent.
2. **Egress is denied by default.** The only route out is the broker, reached as a Unix socket or vsock, not a
   general network.
3. **The workspace is a version, not the live tree.**
   - A read-only task mounts a snapshot.
   - A write task gets a branch (a ZFS clone) and returns a new version.
   - Applying the change is a separate, approved operation.
4. **The enforcement is the sandbox's, not the harness's.** Claude Code's own sandbox (bwrap on Linux) and Codex's
   (Landlock + seccomp) are inner layers and conveniences.
5. **Kill the tree on cancel or timeout**, and report what was metered.
6. **No GPU devices, and bounded CPU and memory**, so a sandbox cannot slow halo_serve.
7. **Startup well under the task's own latency.** A review is seconds to minutes, so 0.1-1 s of setup is fine.

## The alternatives

### A. Namespaces + Landlock + seccomp + cgroup (bwrap-based), on the Halo

`yard-run-linux` (Go, privileged only through the setuid-free bwrap) assembles, per task:
- **Namespaces:** bwrap with every namespace unshared; a new mount namespace that holds only a read-only base
  rootfs (a squashfs or a directory with node, the harness and ripgrep), `/workspace` (bind of a ZFS snapshot,
  read-only, or of a clone, read-write) and a tmpfs home.
- **Network:** none. The broker is reachable as a bind-mounted Unix socket, with a tiny in-sandbox HTTP-to-UDS
  shim, or `HTTPS_PROXY` pointing at it through socat on loopback inside the net namespace.
- **Landlock** as a second, independent filesystem fence: read under the base and `/workspace`, write only to
  the clone and tmp. On ABI 4 and later it also limits TCP connect to the shim's port.
- **seccomp:** a deny list (`ptrace`, `bpf`, `perf_event_open`, `kexec*`, `mount*`, `keyctl`, `userfaultfd`,
  `io_uring_*` (libuv falls back) and so on).
- **cgroup v2:** a transient `systemd-run --user --scope` per task with CPU, memory and pids limits, inside a
  `yard.slice` capped below what halo_serve needs.
- **No GPU:** `/dev/kfd` and `/dev/dri` are not in the mount namespace.

| | |
|---|---|
| Boundary | The shared Linux kernel, the host's own. A kernel bug is a host compromise, on the inference box. |
| Startup | ~10-30 ms |
| Overhead | none at run time |
| Workspace | native: ZFS snapshot and clone binds (delegated with `zfs allow` to a yard uid) |
| Suspend and resume | none (CRIU is possible but fragile with node) |
| Effort | small: days. bwrap, Landlock (go-landlock), seccomp (libseccomp-golang) and systemd-run are all present |
| Fit | read-only and low-risk tasks (reviews, analysis) with only brokered network |

### B. gVisor (runsc), on the Halo

Each task is an OCI bundle run by `runsc`. Its user-space kernel (the Sentry) handles syscalls, so the host
kernel sees a small, filtered surface.
- **Platform:** `systrap` (the default) or **`kvm`** (`/dev/kvm` is available). KVM is faster for syscall-heavy
  workloads, and node and ripgrep are syscall-heavy.
- **Filesystem:** a gofer, or `--directfs`, which is faster. `/workspace` binds a ZFS snapshot or clone as in A.
  The overlay rootfs is in memory.
- **Network:** `--network=none`, with the broker as a host Unix socket (`--host-uds=open`) or a netstack-only
  loopback to a forwarder.
- **To make it run:**
  - either give `runsc` an AppArmor profile that allows unprivileged user namespaces, as bwrap has;
  - or run it rootful, under a dedicated yard uid, from a root-owned systemd unit; podman can do this with
    `--runtime=runsc`.
- **Checkpoint and restore** (`runsc checkpoint/restore`) fit the SR suspend and resume milestones.

| | |
|---|---|
| Boundary | the Sentry plus a seccomp-limited host interface. Stronger than A; weaker than a VM. |
| Startup | ~150-400 ms |
| Overhead | syscall- and filesystem-heavy work is slower (expect 1.2-2x on `npm`/`rg`-style loads; measure) |
| Workspace | bind mounts work (gofer or directfs) |
| Suspend and resume | yes |
| Effort | moderate: about a week, including the AppArmor/rootful decision and an image pipeline (OCI from the same base) |
| Fit | reviews and tasks that run code (tests), where a VM's weight is not wanted |

### C. Firecracker microVMs, on the Halo (SR2; P0-2 spike done)

One VM per sandbox session: a guest kernel (6.1 from the Firecracker CI), a read-only rootfs image with the
harnesses, and `fcinit`. The vsock carries the protocol and the broker.
- **Workspace:** Firecracker has no virtiofs, so the workspace is a block device. A **ZFS zvol clone** of a
  workspace version's snapshot, attached as virtio-blk, is instant.
  - Read-only for a review.
  - Read-write for a task; after it, `zfs diff` or a mount on the host gives the new version.
- **Jailer:** uid 64000, a chroot, a cgroup v2 `yard.slice`, and a network namespace per VM (the P0-2 setup notes).
- **Snapshots:** full or diff snapshots map to SR2's suspend and resume.

| | |
|---|---|
| Boundary | a VM: the guest kernel plus KVM and Firecracker's minimal device model. The strongest here. |
| Startup | ~130 ms boot (measured), plus the harness's own start |
| Overhead | 256 MiB-2 GiB of RAM per VM (fine beside 70 GB of weights for a few); a vsock hop per broker call (~0.5 ms, irrelevant next to model latency) |
| Workspace | zvol clones (instant), but no shared filesystem: tools see a block device's ext4/xfs |
| Suspend and resume | yes (SR2) |
| Effort | the largest: a guest agent (vsock protocol, exec, the broker forward), an image pipeline, and the jailer setup. About 2-3 weeks on top of P0-2 |
| Fit | everything, including untrusted code and long sessions; the target for write and exec tasks |

### D. Cloud Hypervisor or Kata, with virtiofs, on the Halo

Like C, but virtiofs shares the ZFS snapshot or clone as a directory: no block device, and a natural `zfs diff`.
- **Cost:** a heavier VMM and virtiofsd per VM. Kata adds an OCI shim (podman `--runtime=kata`).
- **Fit:** worth it only if C's block-device workspaces prove awkward (many small writes, host-side diffs while it
  runs).
- **Effort:** like C, plus packaging; Kata is not installed.

### E. FreeBSD jails with Linux compatibility, on the NUC

Reuse yard-spawn and yard-exec-shim as they are: a jail with `linux=new`, a `linux_base-rl9` (or Ubuntu
debootstrap) root under the template, nullfs for `/workspace` from `zroot/yard` snapshots or clones, a pf
anchor to the broker only, rctl limits and securelevel 3.
- **What runs:**
  - Codex ships static (musl) binaries, likely fine.
  - Claude Code (node) and ripgrep are likely fine; node runs under the Linuxulator.
  - opencode (Bun) is the riskiest.
  - io_uring is absent, so libuv falls back; inotify is partial.
- **The model is reached through the broker:** Halo's API over the tailnet or LAN, or brokered Anthropic and
  OpenAI.

| | |
|---|---|
| Boundary | a FreeBSD jail plus the Linuxulator: another kernel, and **another machine from the GPU box**. A sandbox escape lands on the NUC, not beside halo_serve. |
| Startup | 2-10 ms per call (measured for J0); a session jail ~tens of ms |
| Overhead | the Linuxulator's translation (small); the N150's 4 cores and 16 GB bound concurrency (harnesses are mostly waiting on the model) |
| Workspace | native ZFS, the J0 design |
| Suspend and resume | jails: no (SR3 is bhyve) |
| Effort | small to moderate: build the Linux base, then a compatibility spike per harness (S-L below). yard-spawn needs only a `linux` jail parameter |
| Risk | Linuxulator gaps per harness version, the advisories (SA-26:47 class), and the open decision that linux64 belongs in the jailhost VM, not the host |
| Fit | reviews and agent tasks whose code runs elsewhere; keeps agent load off the inference box |

### F. Harness-provided sandboxes only (Claude Code's bwrap sandbox, Codex's Landlock+seccomp)

These are configured by the harness, and the harness is what we are containing: requirement 4 rules them out as
the boundary. Keep them on as inner layers inside A-E; they cost nothing and add depth.

## Side by side

| | Boundary | Off the GPU box | Startup | Exec of untrusted code | Suspend | Effort |
|---|---|---|---|---|---|---|
| A bwrap+Landlock+seccomp | shared host kernel | no | ~20 ms | no | no | days |
| B gVisor | Sentry | no | ~0.3 s | acceptable | yes | ~1 week |
| C Firecracker | VM | no (own kernel) | ~0.13 s | yes | yes | 2-3 weeks (spike done) |
| D CH/Kata + virtiofs | VM | no (own kernel) | ~0.3-0.5 s | yes | yes | 2-3+ weeks |
| E NUC jail + Linuxulator | jail, other kernel, other machine | **yes** | ~ms | acceptable | no | ~1 week incl. spikes |

## Decision (user, 2026-10-12)

- **No bwrap or Landlock stopgap (A is out).**
- **Firecracker (C) is the first and default backend** for agent tasks.
- **NUC jails (E) stay on the roadmap** as a later backend.
- Agent operations are in `design/AGENT-OPERATIONS.md`.

## Recommendation (revised 2026-10-12, after the user's question)

The first version preferred the NUC for read-only tasks and the Halo for code-running tasks. That was backwards on
risk. It came from where each mechanism already exists, and the mistake underneath was taking "read-only" to mean
lower kernel exposure. It does not:
- Any of these harnesses with a shell tool runs arbitrary code inside its sandbox, and it may be steered by
  injected content in what it reads.
- "Read-only" decides only whether it can change the workspace.

So:
1. **One boundary for every agent task, and never the shared host kernel:** a VM or a jail on another machine.
   - The **default is C (Firecracker on the Halo)**. An escape needs a KVM or Firecracker bug, not just a reachable
     kernel bug. The Halo has the capacity for builds and tests, and P0-2 is done.
   - **E (NUC jails)** is extra capacity, and the placement for anything that should be physically off the GPU box.
   - **B (gVisor, KVM platform)** is the lighter-weight alternative to C if its image and guest-agent work is the
     bottleneck.
   - **A (bwrap + Landlock)** is a stopgap only, accepted explicitly and time-boxed. Its boundary is the inference
     box's own kernel.
2. **Placement is a capacity and blast-radius choice, not a task-class one.** The Halo has the cores and memory;
   the NUC keeps an escape away from halo_serve and the weights.
3. **Read-only vs read-write decides the workspace, not the sandbox.** A read-only task gets a snapshot mount; a
   read-write one gets a clone and returns a new version. Applying that version is a separate operation, approved
   by policy.
4. **Always:**
   - the broker is the only egress, and the meter;
   - workspaces are ZFS versions;
   - the harness's own sandbox stays on inside;
   - anything on the Halo runs in a `yard.slice` cgroup capped below halo_serve.

The executor interface hides the backend: `Run{task, workspace_version, mode ro|rw, broker_scope, limits}` →
`Done{result, usage (metered), snap_after, diff}`. A backend is chosen by placement, so C, E (and B or A) are
swappable.

## Spikes (predictions written before each run, as usual)

- **S-L (NUC, E):** `claude -p` (against Halo's `/v1/messages` through the broker), `codex exec` and `opencode run`
  in a `linux=new` jail with a read-only nullfs workspace and only the broker reachable. Record per harness:
  - does it start, and does a review task complete;
  - wall time vs the same on the Halo natively;
  - which syscalls fail (ktrace).
- **S-A (Halo, A):** the same three harnesses under bwrap + Landlock + seccomp + a cgroup scope, with only the
  broker socket. Record start overhead and any Landlock or seccomp denials (audit).
- **S-G (Halo, B):** `runsc` with an AppArmor profile vs rootful under a yard uid; systrap vs KVM. Measure
  `rg` over the repo and `npm test` on a fixture against native, and the startup.
- **S-C (Halo, C):** the P0-2 image with node and the harnesses, a zvol-clone workspace, and the vsock broker
  forward. Run the review end to end and measure it.

## Open decisions for the user

1. linux64: keep it on the NUC host (E runs on the host's jails), or move it into the jailhost VM, as decided
   (E then runs in jails inside it, adding a bhyve layer)?
2. gVisor: allow an AppArmor exception for `runsc` (rootless), or run it rootful under a yard uid?
3. Is A acceptable as a time-boxed stopgap before C is ready? Its boundary is the inference box's own kernel.
