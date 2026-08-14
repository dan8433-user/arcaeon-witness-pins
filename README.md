# arcaeon-witness-pins

The **public pin store** for the Arcaeon hosted witness
(API: the `arcaeon-witness` service).

Each pin is a commit under `pins/<namespace>/`. **The commit history IS the
tamper-evidence**: commits are timestamped by GitHub (a third party), publicly
readable, and any rewrite of history is visible to anyone who has cloned or
watched this repo.

Pins contain ONLY fingerprints — `{namespace, rows, chain, pinned_at, seq}` —
never log content. If this store were breached there is nothing sensitive here:
just hashes, useless without the original log ("password nowhere").

- `pins/<namespace>/<seq>.json` — one pin per commit, append-only.
- `pins/<namespace>/latest.json` — the current head pin for that namespace.

To verify a log against a pin: check that the log's chain value at row `rows`
equals `chain`. Fewer rows than a pin = truncation; a different chain at the
pinned row = rewrite. You do not need to trust the witness API to run this
check — this repo and its history are the whole evidence.

## Anchoring (OpenTimestamps counter-anchor)

GitHub's clock is the first witness; Bitcoin's is the second. Once a day an
automated job records this repo's HEAD commit hash to
`anchors/<date>-head.txt` (`<sha> <iso-timestamp>`) and stamps that file with
[OpenTimestamps](https://opentimestamps.org), committing the resulting `.ots`
proof alongside it. Because each anchor lands in the repo itself, the witness
is self-escrowing: force-rewriting this repo's history would also have to
erase or fake proofs whose hashes are already anchored in the Bitcoin
blockchain.

Verify an anchor yourself — no trust in this repo's owner required:

```
pip install opentimestamps-client
ots verify anchors/<date>-head.txt.ots
# then confirm the sha inside the .txt is a real commit in this repo:
git log --format=%H | grep <sha-from-the-txt>
```

A fresh proof reads "Pending confirmation in Bitcoin blockchain" — that is
normal: `ots stamp` collects calendar-server attestations immediately, and the
Bitcoin attestation follows once the calendar's merkle root is committed to a
block (the job upgrades the previous day's proof automatically). After the
upgrade, `ots verify` reports the block height and time.

Honest scope: an anchor proves this repo's HEAD — and therefore every pin
beneath it — **existed by time T**. It does NOT prove any pin's contents are
true, complete, or honestly produced; only that they were not fabricated after
the fact. Each day's anchor covers all history through the previous day's
anchor commits, forming a chain.
