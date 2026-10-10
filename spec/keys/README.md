# The yard-ctl key service: a Quint model (spec/keys)

This is a model of one key service in yard-ctl with two consumers:

- **ZFS project workspace keys.** Each project has one key, for the encryption root
  `ws/<project>` (`keyformat=raw`, `keylocation=prompt`). yard-ctl loads the key only while a
  session of the project is active or resuming, and unmounts and unloads it otherwise.
- **halo_serve per-checkpoint spill keys.** These follow IDENTITY.md "Spill keys" (SE stream,
  2026-10-07).

The model was written for SR1 (branch `sr1-service-jails`). The spill-key controller is now built
as `internal/keysvc` (branch `keysvc`), which an ITF replay checks against the model (section
"Key service (keysvc)" below); the workspace-key side is `internal/wskey` + `internal/service` +
`internal/lifecycle` (replayed against spec/sr0).

The modelling rules are those of casselc/observability `otel-chdb/model/TEMPLATE.md` and
`research/agent-platform/ref-observability/AMBIGUITY.md`:
- every cross-process call is a request, an effect and an answer, with a lost request, a late
  effect, a lost answer and a duplicate (retry, network duplicate, replay);
- each caller rule is a field of `RULES`, and each unsafe choice is a named mutant;
- settle bounds are time where time matters: a registration token's `exp`, and halo's key TTL.

Only `quint run` and `quint test` are used (quint 0.32), never `quint verify`.

**Results in one line.**
- The design keeps K1–K10 over 1,200 random traces under the full step, 1,500
  under the focused spill step, 1,200 under the key-service step and 1,000 under
  each revoke step (80 steps, seed `0x5eed`); every witness is reached across the runs.
- The active mutants break their named property. Obsolete mutants explicitly
  listed as holding below remain negative controls; all 14 scripted mutant
  counterexamples and 29 scripted design tests pass.
- `run.sh` reports `failures: 0`; the full output is in `results.txt`.
- The model found three gaps in the design text. They are listed under "Findings".

## Key service (keysvc) changes, 2026-10-07

What changed in the model on branch `keysvc`, and why:

1. **halo's current rules** (halo-flash `stream/spill-crypt` round 3 + round 4, `yard_keys.cpp`):
   - the revoke carries `through` (the op's `ver`; 0 none) and the token epoch (`tep`); halo keeps a
     durable fence (`revoked_through`): no seal at a file epoch at or below it, no open of one; a revoke
     zeroes the keys and erases the files at or below it and leaves later ones;
   - **round 4** (crypto review, 2026-10-07; halo SE): every revoke effect is bounded by the token
     epoch T. `revokeCapped`: R = the explicit through (refused if > T), else min(last spill, T), none
     if nothing was spilled. `revokeScoped`: with R only keys at file epochs <= the fence go; without
     R only keys registered at epochs <= T. A revoke below halo's highest epoch is applied (never
     stale), bounded by T, and raises the highest epoch to T;
   - a slot's deadline is min(token exp, first registration + TTL); a repeat keeps the first
     registration time (the cap).
2. **the controller as built:**
   - `SuspendAbort` (SR0 aborts a suspend: Active at the same epoch, the key's shred begins);
   - `burnt` / `burntEpoch`: a spill of key k may have landed. No new seal at a burnt epoch (halo
     would refuse it as used), and a revoke only for a burnt key (a revoke through an epoch whose spill
     never happened fences the next checkpoint at that epoch; an unspilled key is shredded by the time
     bound alone);
   - `OpVerifyRetry`: an unanswered registration is verified with `GET /admin/keys` at once; seen, it is
     done; not seen, the same registration is resent (IDENTITY.md's "verify, then idempotent retry").
     A miss never makes it not done;
   - revokes always carry an explicit `through` = the checkpoint's epoch (`explicitThrough`);
   - `Kill` is also allowed in `PRestore` once the restore is known not done (settled).
3. **K7 `revokeBoundedByAuthority`** (ghost `revokeOverreach`): a revoke at token epoch T never
   zeroes a key, erases a file or raises the fence for a file epoch above T. Mutants
   `revokeUncapped` (fence = last spill, with yard relying on the default) and `revokeUnscoped`
   (every key of the session, as this model did before round 4) break it under `stepRevokeLate`
   (a revoke delayed past a newer seal/spill: its copies land only once halo holds something of the
   session above T, and time stops while it is in flight); scripted `revokeUncappedBreaksTest` /
   `revokeUnscopedBreaksTest` (`delayedRevokeAfterSeal`: the revoke at T = 2 lands after the seal at
   3). `revokeDefaultThrough` keeps K7 (the bounded default stays within the token's authority) but
   breaks K6.
4. **K6 `checkpointKept`**: a suspended session's checkpoint file is still at halo and not fenced.
   Mutants `revokeDefaultThrough` (yard relies on halo's default, even the bounded one: a delayed revoke
   lands after the newer spill at its own token epoch) and `unboundedRevoke` (halo round 3 + the
   default: erases a checkpoint spilled at T+1).
5. `stepKeysvc` (the replay traces' step: every keysvc action, both sessions, every fault, no project
   actions), `stepCore` / `stepCoreFast` (the project-key mutants' rows: the new actions and the slot
   deadline diluted their counterexamples), `stepRevoke` / `stepRevokeLate` (K6 / K7), and
   `gen_traces.sh` (replay traces from stepKeysvc, stepRevoke and stepRevokeLate).

**Model gap (round 4).** The model as it stood before this branch would not have caught the
unbounded-revoke defect (confirmed by halo SE, round 4): its revoke dropped every slot of the
session regardless of epoch (no fence, no file erasure, no `through <= T` cap, no server default),
and no invariant said a revoke at T cannot change state after T. K7 (with the capped/scoped rules
and their mutants) and K6 close it.

### Operation identity and retention (halo rounds 5–6; closeout 2026-10-08)

Seal/open JWTs carry a signed `halo_spill.op` of the form `y<database nonce>.<oid>`.
The durable operation row owns `oid`; retry and controller restart keep it, while
renewal creates a new id. A cancelled or TTL-exhausted seal is verified absent
before renewal replaces its key and begins shredding the old one. Open renewal
keeps the checkpoint's key. Conflicting operation identities fail loudly.

The Go scenarios exercise lost answers, restart, cancellation and TTL expiry
through the real issuer and Unix client; both new controller mutants are caught
(10/10 total). Regenerated ITF replay has 174 traces, including `RenewOp`.
`gen_traces.sh` includes the current operation-identity scripted runs.

Model boundary: halo's bounded tombstone retention and 1024-record backpressure
are not modeled; the model retains records within its finite run bounds. Go
classifies backpressure as `ErrRetryLater`, stops the current drive, and verifies
before a later retry (still subject to the per-operation attempt limit).
Permanent id uniqueness and arbitrary database rollback are outside this model.

`TestRealHaloPeer` also passes with the real-model C++ spill-crypt server: two
signed operation-id seal/open cycles over its private Unix admin socket, with
restored epochs checked and a clean shutdown. It is opt-in via
`HALO_KEYS_PEER_BINARY` and `HALO_KEYS_PEER_MODEL` and must run under the shared
GPU lock; ordinary Go suites skip it. This checks Go/C++ protocol compatibility,
not NUC workspace/jail deployment.

## Files

| File | What |
|---|---|
| `keys.qnt` | `keysTypes` (`Rules`, `DESIGN`) and `keys` (state, effects, the controller, invariants, witnesses, `step`, and the focused `stepSpill`) |
| `keysTest.qnt` | instances: `design`, one module per mutant, and `runs*` (the scripted runs on each) |
| `keysRuns.qnt` | scripted runs: the happy path, and a `*BreaksTest` / `*DesignTest` pair per mutant |
| `run.sh`, `results.txt` | the check table; `OUT=results.txt ./run.sh` |
| `gen_traces.sh` | the ITF traces of `internal/keysvc`'s replay test |

## Shared state, not Choreo

The model uses shared state, with SR0's op-row and copy pattern (`spec/sr0/lifecycle.qnt`):
- **One controller drives everything.** The protocol is yard-ctl's durable op rows
  (`load-key`, `unmount`, `unload-key`, `destroy`, `change-key`, register, spill, restore). The
  two consumers are single processes that apply a request and answer it; they run no protocol
  of their own toward each other.
- **Copies already give the network faults.** Lost, late, duplicated and replayed delivery
  come from copies in flight (`copies`) and from every token sent (`wire`), as in SR0.
  Choreo's per-recipient message sets would add handlers but no new interleavings.
- **The Go code can follow it the same way.** The Go side (`internal/lifecycle` ops
  `OLoadKey`/`OUnmount`/`OUnloadKey`) is a replay of the same op-row machine, so a shared-state
  model maps onto it action for action, as SR0's replay test does.

Warden is Choreo because it has five parties with their own handlers. Here there is one.

## Scope and assumptions

- **Two sessions, `s1` and `s2`, of one project `p`.** At the start both are active, the key
  (id 1) is loaded, and both session clones are mounted. A session's life is abstracted to the
  steps that touch keys:
  - suspend: seal registration at epoch E (`PSeal`), then halo spill (`PSpill`), then commit
    (the epoch becomes E+1 and the instance is gone);
  - resume: open registration at E+1 (`POpen`), then `zfs load-key` and mount (`PLoad`), then
    halo restore and the jail (`PRestore`), then complete (K is deleted);
  - expiry; and a kill, from any state up to `PLoad`, with the op abandoned.

  SR0 (`spec/sr0`) models the rest of the lifecycle.
- **KEK.** It is derived at yard-ctl start from a deterministic RSASSA-PKCS1v1.5 signature by a
  dedicated, non-rotating TPM key (handle `0x81010012`), through HKDF. This is a local
  computation that fails closed, not a call with an ambiguous outcome. Creating a key, wrapping
  it and INSERTing it is one SQLite transaction. Shred begins by deleting the wrapped key
  (`wrapped = false`, `secure_delete`). The shred is *claimed* (`shredded`) only at its settle
  bound.
- **ZFS (the kernel).**
  - `load-key` succeeds only with the user key that wraps the master key now; the kernel checks
    this.
  - `unload-key` needs nothing mounted.
  - `unmount` is modelled as applying even under a running jail. This is the conservative
    reading: the design does not count on EBUSY from the jail's nullfs mount.
  - `change-key` needs the key loaded.
  - `destroy -r` removes the master key with the dataset.
  - A host **reboot** unloads every key, kills jails and zfs processes, and crashes yard-ctl
    (same host).
- **halo_serve.**
  - It accepts a registration if the token is unexpired and its jti is unseen, and, with
    `staleCheck`:
    - the epoch is at least the highest it has seen;
    - an open is exactly last seal + 1;
    - with `usedCheck`, the epoch's seal or open key was not already used.
  - Spill and restore use the matching key once and forget it.
  - An unused key is forgotten after `HALO_TTL`.
  - A **halo restart** forgets keys and jtis. The per-session epochs survive only with
    `haloDurable`.
  - Revoke drops the session's keys and raises its highest epoch.
- **Time.**
  - `TOKEN_TTL = 2`, `HALO_TTL = 5`, which keeps the 300 s / 600 s ratio.
  - `OP_TIMEOUT = 2`; bounds: 30 ticks, 24 ops, 7 keys, epoch ≤ 4, 2 attempts, 3 faults.

## Register of calls

| Call (op) | Done / not done / unknown | Settle bound | Observation that resolves it | Caller rule |
|---|---|---|---|---|
| `zfs load-key` (stdin) + `zfs mount` clone (`OLoadKey`) | exit 0 / error with keystatus unavailable / no answer, timeout, restart | the zfs process exited (flock inherited) | `keystatus=available` and the clone is `mounted` | idempotent retry ("already loaded" counts as done by observation). **fence:** sent only when no unmount/unload of the project can still land (`keyFence`). **verify:** always sent at resume, never skipped on belief (`reloadAlways`) |
| `zfs unmount` of every session clone (`OUnmount`) | as above | process exited | no clone mounted | sent only when no session of the project is active or in flight and no load-key can still land (`keyGuard`); retry while current |
| `zfs unload-key` (`OUnloadKey`) | as above | process exited | `keystatus=unavailable` | after `OUnmount` done; retry while current |
| `zfs change-key` (`OChangeKey`) | as above | process exited | `zfs load-key -n` with the new key succeeds | the new key is created and wrapped first; the old one is deleted only once this is done (`rekeyKeepOld`) |
| `zfs destroy -r` (`ODestroy`) | as above | process exited | the dataset is gone | the project shred is claimed only on done, with no zfs copy left (`shredSettle`) |
| halo register seal/open (`POST /admin/keys`, `OReg`) | 200 / 401, 409 / no answer | **every token of the op expired** (`exp = iat + 300 s`) | `GET /admin/keys` shows the slot (session, epoch, key name) | verify, then idempotent retry with a fresh token, same use, epoch and key (`idempotentReg`; never a fresh K) |
| halo revoke (`OReg` use revoke) | as above | as above | `GET /admin/keys` shows no slot at or below the revoked epoch | sent once every token of K expired; counts toward the shred only when observed done (`shredVerify`) |
| halo spill / restore (`OSpill`, `ORestore`) | 200 / 409 no key / no answer | the request's process | the spill file exists / the jail exists | refused means not done: register again (verify first) |
| spill-key shred (yard-ctl, local) | — | `lastIat(K) + TOKEN_TTL` (no token can install K), then `+ HALO_TTL`, or a verified revoke | — | `shredSettle` + `shredVerify` |

## Invariants

| # | Name | Property |
|---|---|---|
| K1 | `noStaleEpoch` | No consumer installs a registration for an epoch older than the session's current one, and no restore lands under a stale epoch. A ghost flag is set at install time. |
| K2 | `noDecryptAfterShred` | For every key claimed shredded: no consumer holds it (no live halo slot; for a project key, no master key loaded), and no token carrying it can still be accepted (`clock > lastIat + TOKEN_TTL`). |
| K3 | `keyUnderRunning` | A running instance's project key is loaded and its clone mounted: never unloaded or unmounted under an active session. |
| K4 | `keysAccounted` | Every wrapped spill key belongs to a suspend record (no orphan that is never shredded), and a suspended session's key is still wrapped. |
| K5 | `projectKeyAvailable` | The user key that wraps the project's master key is in the store, until the project shred. |
| K7 | `revokeBoundedByAuthority` | A revoke at token epoch T never zeroes a key, erases a file or raises the fence for a file epoch above T. |
| K6 | `checkpointKept` | A suspended session's checkpoint file is still at halo (sealed at the epoch before the current one, under its key) and not fenced: no revoke for an older checkpoint, however late, erases it. |
| K8 | `noCancelledInstall` | A cancelled operation cannot be installed again by a delayed token. |
| K9 | `slotWithinCap` | Re-registration cannot extend the first registration's TTL cap. |
| K10 | `opIdOneOperation` | One operation id cannot name two distinct key/epoch operations. |

## Mutants (`run.sh`, seed `0x5eed`)

| Mutant | Rule off | Breaks | How |
|---|---|---|---|
| `shredBeforeLoadSettles` | `shredSettle` | K2 | K is claimed shredded at ResumeComplete while its open token is still valid; a duplicate or replay can install it again. On the ZFS side: claimed before `destroy` is done. |
| `revokeOnlyByMessage` | `shredVerify` | (K2 holds) | Obsolete as a break: halo now zeroes a key at its token's exp, so once every token of K expired no slot holds it (finding 6). Kept as a row that must hold. |
| `staleEpochAccepted` | `staleCheck` | K1 | A seal token for epoch E is replayed after the commit; halo installs it. |
| `haloForgetsEpochs` | `haloDurable` | K1 | A halo restart forgets the highest, last-seal and used epochs; a replayed old seal token is accepted. |
| `identityAsWritten` | `usedCheck` | K1 | IDENTITY.md as written: the seal at E is used by the spill, halo restarts (jti memory gone), and a replay of the seal token, still unexpired, is accepted, because E is not below the highest epoch. |
| `unloadUnderActive` | `keyGuard` | K3 | Unmount lands under both active sessions. |
| `loadDuringUnload` | `keyFence` | K3 | A resume's load-key is sent while the unmount is in flight; the unmount lands after the load; the restore runs on an unmounted path. |
| `trustConsumerAfterRestart` | `reloadAlways` | K3 | After a reboot yard-ctl still believes the key loaded, skips load-key, and the jail starts on the empty mountpoint. |
| `blindRegisterRetry` | `idempotentReg` | K4 | An unanswered seal is replaced by a fresh K; the first K is never shredded. |
| `rekeyDropsOld` | `rekeyKeepOld` | K5 | The old project key is deleted when change-key is sent; if change-key never lands, nothing in the store opens the project. |
| `revokeDefaultThrough` | `explicitThrough` | K6 | K1's revoke (token epoch 2) is delayed; K2 seals and spills at 2; the revoke lands with halo's (bounded) default through = min(2, 2): K2's file is erased. |
| `revokeUncapped` | `explicitThrough`, `revokeCapped` | K7 | The delayed revoke (T = 2, default through) lands after the spill at 3: fence = last spill = 3 > T. |
| `revokeUnscoped` | `revokeScoped` | K7 | The delayed revoke (T = 2, explicit through 1) lands after the seal at 3 and zeroes it. |
| `unboundedRevoke` | `explicitThrough`, `revokeCapped`, `revokeScoped` | K6 | halo round 3: the same delayed revoke lands one cycle later and fences the checkpoint spilled at 3 = T+1. |
| `cancelWeakens` | cancellation retention | K8 | A fresh token reinstalls a cancelled operation. |
| `capResets` | first-registration cap | K9 | A retry resets the original TTL. |
| `opIdReused` | unique operation identity and peer identity check | K10 | A later checkpoint reuses an earlier operation id. |

The spill-side mutants need a whole suspend cycle within one token lifetime, followed by a
duplicate or a replay. Plain random runs under `step` rarely reach that. The focused step
`stepSpill` is a restriction of `step` (session `s1`'s spill-key life with duplicated, lost
and replayed registrations and halo restarts). It reaches them within the mutant sample count,
and the design holds under it. The scripted runs (`keysRuns.qnt`) replay one counterexample per
mutant and show the design refusing the fatal step.

## Findings (for the SE stream and the key-service design)

1. **Shred is not instant on the halo side.** Deleting K at yard stops new registrations, but:
   - a token already minted carries K in its body (halo has no TLS) and can be delivered again
     until it expires;
   - halo may keep an unused key for its TTL.

   So the shred is complete only at `lastIat + 300 s + 600 s`, or at `lastIat + 300 s` plus a
   revoke sent after that and *observed* done by `GET /admin/keys`. IDENTITY.md says "shred does
   not depend on [revoke] (K is gone)". That holds for yard's copy of K, not for halo's. The
   model carries this as `shredSettle` + `shredVerify`.
2. **The used-epoch check, and making halo's per-session epochs durable.**
   - **Replay after a restart.** The rules as written (stale = below highest, replay = a seen
     jti, open only after a seal) do not stop a seal or open token from being delivered again
     after a halo restart (jtis are memory) for an epoch whose key halo already used
     (`identityAsWritten`).
   - **The fix.** halo keeps, per session and *durably*, the highest epoch, the last seal, the
     last spilled and the last restored epoch. It refuses a seal at or below the last spill,
     and an open at or below the last restore.
   - **If those epochs are memory only** (`haloForgetsEpochs`), stale registrations are
     accepted after any restart. The open-after-seal rule would also refuse every open after a
     restart: a spill could not be restored until it is re-prefilled.
3. **Revoke is per session, not per key.** It also drops a re-suspended session's new seal key.
   That is safe (the spill is refused, and yard re-registers after verifying), but it costs a
   round trip. **Proposal:** revoke by `key_id`.
4. **ZFS: a rekey is not a shred** (`zfs-change-key(8)`).
   - `change-key` rewraps the same master key and leaves the old wrapped master key on disk.
     Every past user-key version therefore stays as sensitive as the current one until
     `zfs destroy`, and only destroy (plus TRIM) shreds a project.
   - In the model, a rekey *retires* the old key (deleted from the store); it does not claim a
     shred.
   - **Consequence for per-session keys via `change-key` on a clone (not modelled here):** the
     clone keeps the project's master key. The project key plus the clone's on-disk wrapped
     blob open the session, so destroying a per-session user key does not crypto-shred that
     session.
5. **Unload must wait for killed resumes' load-keys.** A load-key left in flight by a killed
   resume can land after the unload. It is safe for K3, but the project key would stay loaded
   with no session. The design guard (`keyGuard`) therefore also waits for every load-key to be
   resolved (`loadsResolved`).

6. **K2 no longer depends on the verified revoke.** halo zeroes a key at min(token exp,
   registration + TTL), so once every token of K expired (the shred's first condition) no slot can
   hold K: `revokeOnlyByMessage` cannot break K2 any more. The revoke still erases the file and
   fences its epoch; the design keeps it (and the TTL alternative) as belt and braces, also for a
   lease (`in_use`) the model does not represent.
7. **An abort after the spill burns the epoch.** SR0's SuspendAbort keeps the credential epoch. If the
   spill may have landed, halo holds that epoch as used: no seal at it ever again, so the session
   cannot suspend until its epoch moves. keysvc refuses such a seal up front (`ErrEpochBurnt`, no
   request sent). **SR0 must bump the epoch on an abort after a checkpoint whose spill may have
   landed** (a decision for the user: it also invalidates the live instance's credentials).
8. **Revoke bound (halo round 4).** See "Key service (keysvc) changes": yard always sends an explicit
   `through`; with the server default even the bounded rule erases a newer checkpoint spilled at the
   token's own epoch (`revokeDefaultThrough`).

## Mapping to the Go names (parent stream)

| Model | Go |
|---|---|
| `newKey` (create + wrap + INSERT) | `wskey.Service.Create(project)`; KEK from `wskey.KEK` (TPM signer, or a 32-byte file for tests and the e2e) |
| `ResumeLoad` / `OLoadKey` | lifecycle op `OLoadKey` → `wskey.Service.Load(project)` (unwrap, `zfs load-key` from stdin, mount the session clone) |
| `UnloadBegin` / `OUnmount`, `UnmountDone` / `OUnloadKey` | lifecycle ops `OUnmount`, `OUnloadKey` → `wskey.Service.Unload(project)` steps |
| `ShredBegin` / `ODestroy` / `ShredDone` | `wskey.Service.Shred(project)`: unload observed done, load copies settled, delete the wrapped keys, `zfs destroy -r` |
| `RekeyBegin` / `OChangeKey` / `RekeyDone` | `wskey.Service.Rekey(project)` (optional) |
| `proj.believed` | the projects row's `loaded` belief (durable) |
| spill keys, every spill-side action | `internal/keysvc.Ctl` (same names; `Service` runs it: `Seal` = SuspendBegin..spill, `Open` = commit (lazy, from the epoch source) + ResumeBegin..ResumeComplete, `Discard` = SuspendAbort / Expire / Kill / ResumeComplete, `Remove` = Kill, `Poll` = SendRevoke, OpVerifyRetry, ShredSpill) |
| `OpLand` answers, `OpResolve` observations | `Service.send` (one copy, its answer), `Service.observe` (`GET /admin/keys`, `GET /admin/sessions`), `Service.settled` |
