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
