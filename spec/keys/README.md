# The yard-ctl key service: a Quint model (spec/keys)

This is a model of one key service in yard-ctl with two consumers:

- **ZFS project workspace keys.** Each project has one key, for the encryption root
  `ws/<project>` (`keyformat=raw`, `keylocation=prompt`). yard-ctl loads the key only while a
  session of the project is active or resuming, and unmounts and unloads it otherwise.
- **halo_serve per-checkpoint spill keys.** These follow IDENTITY.md "Spill keys" (SE stream,
  2026-10-07), as revised in SE's fix round the same night (see "Revision: SE's fix round" below).

The model was written for SR1 (branch `sr1-service-jails`). It is design-level: yard has no
key-service code yet. The Go names it maps to are listed below.

The modelling rules are those of casselc/observability `otel-chdb/model/TEMPLATE.md` and
`research/agent-platform/ref-observability/AMBIGUITY.md`:
- every cross-process call is a request, an effect and an answer, with a lost request, a late
  effect, a lost answer and a duplicate (retry, network duplicate, replay);
- each caller rule is a field of `RULES`, and each unsafe choice is a named mutant;
- settle bounds are time where time matters: a registration token's `exp`, and halo's key TTL.

Only `quint run` and `quint test` are used (quint 0.32), never `quint verify`.

**Results in one line.**
- The design keeps all five properties over 1,200 random traces under the full step, 1,500 under
  the focused spill step and 1,000 under the replay step (80 steps, seed `0x5eed`), over the Unix
  socket and in TCP mode (`designTcp`), and every witness is reached.
- Each of the 10 mutants breaks the property it is named for, both in simulation and in a
  scripted counterexample (the halo-side ones in TCP mode, `revokeOnlyByMessage` with halo as
  before SE's fix round); their four twins under the revised protocol hold (re-check after SE's
  fix round, below).
- `run.sh` reports `failures: 0`; the full output is in `results.txt`.
- The model found three gaps in the design text. They are listed under "Findings".

## Files

| File | What |
|---|---|
| `keys.qnt` | `keysTypes` (`Rules`, `DESIGN`) and `keys` (state, effects, the controller, invariants, witnesses, `step`, and the focused `stepSpill`) |
| `keysTest.qnt` | instances: `design`, one module per mutant, and `runs*` (the scripted runs on each) |
| `keysRuns.qnt` | scripted runs: the happy path, and a `*BreaksTest` / `*DesignTest` pair per mutant |
| `run.sh`, `results.txt` | the check table; `OUT=results.txt ./run.sh` |

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
  - Revoke carries `through` (the epoch of the checkpoint yard wants gone, never stale): the
    durable fence rises to it, keys and files at file epochs at or below it are erased, and no
    seal or open at or below it is accepted again. A later checkpoint is not touched.
  - A key is zeroed at `min(token exp, registration + HALO_TTL)`.
  - The cache entry records the checkpoint (file) it holds; a halo restart loses that index, so a
    spill is never restored after one: the session is re-prefilled (`ResumePrefill`).
  - Transport: the key route is served only on halo's admin Unix socket (peer uid checked), so
    no third party can deliver a token again (`socketOnly`, the design). TCP mode over the
    tailnet (`DESIGN_TCP`) allows replay of a captured, unexpired token.
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

## Mutants (`run.sh`, seed `0x5eed`)

| Mutant | Rule off | Breaks | How |
|---|---|---|---|
| `shredBeforeLoadSettles` | `shredSettle` | K2 | K is claimed shredded at ResumeComplete while its open token is still valid; a duplicate or replay can install it again. On the ZFS side: claimed before `destroy` is done. |
| `revokeOnlyByMessage` | `shredVerify` (with halo as before the fix: `haloExpZero` off) | K2 | Kill during `POpen` leaves the open key in halo; a revoke is sent and lost; the shred is claimed while halo still holds K. With halo zeroing keys at token exp it holds (`revokeOnlyByMessageExpZero`). |
| `staleEpochAccepted` | `staleCheck` (TCP mode) | K1 | A seal token for epoch E is replayed after the commit; halo installs it. Over the socket: holds (`*Socket`). |
| `haloForgetsEpochs` | `haloDurable` (TCP mode) | K1 | A halo restart forgets the highest, last-seal and used epochs; a replayed old seal token is accepted. |
| `identityAsWritten` | `usedCheck` (TCP mode) | K1 | IDENTITY.md as written: the seal at E is used by the spill, halo restarts (jti memory gone), and a replay of the seal token, still unexpired, is accepted, because E is not below the highest epoch. |
| `unloadUnderActive` | `keyGuard` | K3 | Unmount lands under both active sessions. |
| `loadDuringUnload` | `keyFence` | K3 | A resume's load-key is sent while the unmount is in flight; the unmount lands after the load; the restore runs on an unmounted path. |
| `trustConsumerAfterRestart` | `reloadAlways` | K3 | After a reboot yard-ctl still believes the key loaded, skips load-key, and the jail starts on the empty mountpoint. |
| `blindRegisterRetry` | `idempotentReg` | K4 | An unanswered seal is replaced by a fresh K; the first K is never shredded. |
| `rekeyDropsOld` | `rekeyKeepOld` | K5 | The old project key is deleted when change-key is sent; if change-key never lands, nothing in the store opens the project. |

The spill-side mutants need a whole suspend cycle within one token lifetime, followed by a
duplicate or a replay. Plain random runs under `step` rarely reach that. The focused step
`stepSpill` is a restriction of `step` (session `s1`'s spill-key life with duplicated, lost
and replayed registrations and halo restarts). It reaches them within the mutant sample count,
and the design holds under it. The scripted runs (`keysRuns.qnt`) replay one counterexample per
mutant and show the design refusing the fatal step.

## Revision: SE's fix round (2026-10-07, re-checked by SR1)

SE changed the spill protocol after its review rounds 2-3. What the model now does:

| SE change | Model |
|---|---|
| halo persists the highest, revoke-fence, last seal, last spilled and last restored epochs (fsync'd before it answers) | `haloDurable` keeps all five (`fence` added); the design's rule is now what halo does. `haloForgetsEpochs` stays as the mutant |
| seal refused at or below the last spill, open at or below the last restore | `usedCheck` (already the design); `identityAsWritten` stays as the mutant (the text before the fix) |
| revoke `through`, a durable fence, erasure of keys and files at or below it | `haloReg` revoke; yard sends `through` = the checkpoint's epoch (finding 3 resolved) |
| keys zeroed at `min(token exp, registration + TTL)` | `Slot.exp`, `liveSlot` |
| entry identity: the seal token names the cache entry; a checkpoint id per file; an older authentic file is refused | `Halo.entry` (the key of the file the entry holds); a restore needs it. One entry per session in the model, so a seal for another session's entry does not arise |
| spills are not restored after a halo restart (the cache index is memory) | `entry` is cleared by `HaloRestart`; `ResumeReopen` only while the entry still holds the file, else `ResumePrefill` (the session starts without its spill, K shredded) |
| key route only on the admin Unix socket (`SO_PEERCRED`), TCP only over the tailnet | `RULES.socketOnly` (design true: `Replay` disabled). Late copies and yard's own duplicate deliveries stay. The halo-side mutants (`staleEpochAccepted`, `haloForgetsEpochs`, `identityAsWritten`) are run in TCP mode, where they break; their `*Socket` twins hold over the socket: those rules are defence in depth there |

Yard-side changes of the same round reflected here:
- **SR0 Removed** (`yard-svc down`): a removed session is `Gone` here, like an expired, failed or
  killed one; it no longer blocks the project's unload, and its spill key's shred begins.
- **The key database on its own dataset** (`zroot/yard/data/keys`, no snapshots, no backups): the
  model's shred begins by deleting the wrapped key; that is now the only copy on the NUC, so the
  yard-side shred is immediate there. A copy backed up elsewhere stays openable (by the TPM root)
  until it ages out; that is outside the model.

Further consequences found while re-checking:
- **halo's zeroing at token exp makes the verified revoke redundant for halo's copy.** yard's
  shred rule (tokens expired, then `+ HALO_TTL` or a verified revoke) is still safe, but with
  `haloExpZero` the spill key is gone from halo at `lastIat + TOKEN_TTL`. `revokeOnlyByMessage`
  therefore runs with halo as it was before the fix (`haloExpZero` off), where it breaks K2; its
  twin `revokeOnlyByMessageExpZero` holds. The revoke stays useful for erasing *files*
  (`through`), not for the key.
- **The halo-side mutants need a valid token delivered again,** which only TCP mode allows. They
  run on `stepReplay` (no clock, so tokens stay valid; a restriction of `step`) and break there;
  their socket twins hold. Over the Unix socket those halo rules are defence in depth.
- New witnesses: `wPrefilled` (a resume after a halo restart starts without its spill) and
  `wRevokeFenced` (a registration refused under a raised fence or as stale, with a fence set).
  New scripted runs: `revokeThroughTest`, `prefillAfterHaloRestartTest`, `prefillAfterHaloRestart2Test`,
  `socketReplayImpossibleTest` (on the socket design).

Results after the revision: `run.sh` (`results.txt`), failures 0.

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
3. **Revoke was per session, not per key** (resolved by SE: revoke `through` an epoch). It used to
   drop a re-suspended session's new seal key as well; `revokeThroughTest` shows the second seal
   surviving a revoke of the first checkpoint.
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

## Mapping to the Go names (parent stream)

| Model | Go |
|---|---|
| `newKey` (create + wrap + INSERT) | `wskey.Service.Create(project)`; KEK from `wskey.KEK` (TPM signer, or a 32-byte file for tests and the e2e) |
| `ResumeLoad` / `OLoadKey` | lifecycle op `OLoadKey` → `wskey.Service.Load(project)` (unwrap, `zfs load-key` from stdin, mount the session clone) |
| `UnloadBegin` / `OUnmount`, `UnmountDone` / `OUnloadKey` | lifecycle ops `OUnmount`, `OUnloadKey` → `wskey.Service.Unload(project)` steps |
| `ShredBegin` / `ODestroy` / `ShredDone` | `wskey.Service.Shred(project)`: unload observed done, load copies settled, delete the wrapped keys, `zfs destroy -r` |
| `RekeyBegin` / `OChangeKey` / `RekeyDone` | `wskey.Service.Rekey(project)` (optional) |
| `proj.believed` | the projects row's `loaded` belief (durable) |
| spill keys, `OReg`, `SendRevoke`, `ShredSpill` | yard-ctl side of IDENTITY.md "Spill keys" (later stream) |
