# Guest resume duties: a Quint model

The design behind `internal/guestagent`: what a restored guest's agent must do (clock, entropy,
key-holding services, a record for the host) before it accepts privileged work again, given two
lossy signals (the VM-generation notify, the host's resume epoch) and snapshot rewinds. Prose,
results table, findings and the Quint-to-Go mapping: `docs/guest-resume.md`.

| File | What it is |
|---|---|
| `guestresume.qnt` | The model (consts = the design's rules), properties, witnesses, scripted runs. |
| `guestresumeTest.qnt` | `design` and one instance per mutant (15). |
| `run.sh` | Every check; prints the table, exits non-zero if a row is not as expected. |
| `results.txt` | The last run (quint 0.32.0, seed 0x5eed, 20000 x 200). |

```sh
quint typecheck spec/guestresume/guestresumeTest.qnt
OUT=results.txt spec/guestresume/run.sh          # SAMPLES=20000 MSAMPLES=20000 STEPS=200 SEED=0x5eed
quint run spec/guestresume/guestresumeTest.qnt --main staleReply --invariant noStaleWork --max-samples 20000 --max-steps 200 --seed 0x5eed
quint test spec/guestresume/guestresumeTest.qnt --main staleReply --match '^staleReplyBreaksTest$' --max-samples 1
```

`quint run` and `quint test` only (no `quint verify`).
