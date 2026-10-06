# verify/ — the verifier, published

`verify_pins.py` is the program that reads this repository's pins and answers in one of three words: **VERIFIED**, **BROKEN** (with the row), or **COULD NOT LOOK** (with the reason). It is one file. It imports nothing of ours. It needs Python 3.11+ and the `opentimestamps` package (`pip install opentimestamps`) to parse the `.ots` proofs; nothing else.

## Its fingerprint

```
sha256 (LF line endings)  6cb08f67190a0ec0e697d16108a01146833293ad63eb441b52c655f24a74405a   published 2026-10-06
```

Every report prints the hash of the file that produced it on its first line. From 2026-10-06 on, each pin statement (v3) also carries `verifier_sha256`: the hash of the verifier that was current when the pin was made, so the chain attests the tool that checks it. If the hash in your report differs from the one in a statement, the report prints `VERIFIER MISMATCH` and keeps going; the verdict does not change, but you should know which verifier you ran. Earlier hashes are listed at the bottom of this file as the verifier changes.

## How to run it

You need three inputs, two from this repository and one from anywhere you trust:

1. **The chain file** we are attesting. It is not in this repository; the pins commit to it. Ask for it, or verify the pins alone (the OTS proofs stand on their own; see "Without the chain").
2. **The pins**: this repository's `tips/<chain>/` folders. Clone the repo.
3. **Bitcoin block headers** for the heights the proofs name, as a JSON file `{"<height>": {"merkle_root": "<hex>", "time": <unix>, "hash": "<hex>"}}`. Fetch them from any explorer or your own node. The verifier never touches the network; the headers file is how you decide whose Bitcoin to believe.

```
python verify_pins.py --chain <chain file> --pins tips --btc-headers headers.json
```

Exit code 0 is VERIFIED, 1 is BROKEN, 2 is COULD NOT LOOK. `--json` gives the same report as data. `--now <ISO>` fixes the clock for the cadence check; without it the report says it used system time.

## What a verdict means

- **VERIFIED**: the chain file you supplied reproduces every pinned tip, each pin's statement hashes to the digest inside its OTS proof, each proof's Merkle path lands on the root of the block header you supplied, and each pin chains to the previous one. Rows after the newest verified pin are listed as unpinned; they are not attested yet.
- **BROKEN**: one of those checks failed. The report names the pin and the step.
- **COULD NOT LOOK**: the verifier was missing something (a header, a proof not yet in a block, a file it could not read) and says what. It never says VERIFIED early: a proof that only has calendar attestations is `pending`, not verified.

What it does **not** prove: that the chain's contents are true, that nothing happened before the first attested pin (the report prints that boundary), or that the operator is honest about anything outside the bytes. It proves that a record existed by a block's time and has not changed since.

## Without the chain

Each `tips/<chain>/<stamp>/statement.json.ots` is a standard OpenTimestamps proof over `statement.json`. `ots verify statement.json.ots` with the reference client checks that statement's existence against Bitcoin using nothing we wrote. That half needs nothing from us.

## Cadence

v3 statements carry `cadence_seconds` (21600: four pins a day). If the newest statement is more than two cadences old by your clock, the report prints `OVERDUE` and how many cadences late. That line is a warning, not a verdict; a stopped pinner is a fact about the operator, not about the chain.

## Hash history

| published | sha256 (LF) | note |
|---|---|---|
| 2026-10-06 | 6cb08f67190a0ec0e697d16108a01146833293ad63eb441b52c655f24a74405a | first public copy; v3 statements; standalone |
