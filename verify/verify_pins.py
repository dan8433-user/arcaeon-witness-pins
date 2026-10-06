"""verify_pins -- the no-network verifier for outside pins of a hash chain (W13).

Spec: memory/WITNESS_DESIGN_2026-10-03.md section 3.5. Stdlib and the
`opentimestamps` library (imported only when a .ots proof is parsed) only.
It is ONE FILE: it imports none of our modules (the RFC 6962 inclusion check
is inlined from bridge/arcaeon/rekor_merkle.py), so a stranger can copy this
file alone and run it. NO NETWORK: nothing
here opens a socket, ever. What it cannot fetch, it says it could not look at.
"Offline" means it fetches nothing, NOT that it needs nothing: see WHAT IT
NEEDS below.

    py -m bridge.witness.verify_pins --chain <chain file> --pins <folder>
        [--rekor-key <TUF trusted_root.json>] [--btc-headers <headers.json>]
        [--chain-id <id>] [--public-listing <listing.json>] [--now <ISO>] [--json]

THREE WORDS, three exit codes: VERIFIED (0), BROKEN (1), COULD NOT LOOK (2).
Every BROKEN names a row or a proof file; every COULD NOT LOOK names what it
could not read.

WHAT IT NEEDS (it opens no socket, so everything is handed to it):
  - the chain file (--chain) and the pins folder (--pins);
  - block headers for the Bitcoin attestation (--btc-headers: the merkle
    root, and the time, of each attested height, fetched by you from any node
    or explorer). Without them the outside time is COULD NOT LOOK;
  - a Sigstore TUF trusted root (--rekor-key) to check a stored Rekor
    checkpoint's signature; without it Rekor is COULD NOT LOOK (unkeyed);
  - optionally, a public listing of the published tips/ folder
    (--public-listing) to catch a replayed or erased series.
Size guard: a chain line over 1 MiB or a chain file over 512 MiB is COULD
NOT LOOK (line/file too large), never read into a crash.

WHAT VERIFIED MEANS: every check below passed for the newest pin that could be
checked end to end, and the chain file's rows 1..N are exactly the rows that
pin saw, and sha256 of that pin's statement sits under a Bitcoin block whose
merkle root you supplied (and, if a Rekor entry is stored, in a Rekor tree
whose signed checkpoint you supplied the key for).

WHAT VERIFIED DOES NOT MEAN:
  - NOT TRUTH. It dates the record, not the truth. A false row written
    honestly into the chain is pinned and timestamped exactly like a true one.
  - NOT THE 6-HOUR WINDOW. An edit made and reverted between two canon seals
    (the sampler runs every 6 hours) never enters the chain, so no pin can see
    it. The tamper bound is that 6-hour sampling window, not this verifier.
  - NOT WITNESSED REKOR. A Rekor checkpoint is the log operator's own signed
    word. No independent cosigner has checked it; every Rekor result prints
    `witnessed: false`. OTS (Bitcoin) is the primary clock; Rekor is secondary.
  - NOT "NO LATER PINS". Offline, this sees only the folder it was handed. An
    older genuine pin set replayed as current verifies; the newest pin's age is
    printed every time so you can confirm it against the public copy. Pass
    --public-listing (a stored list of the public tips/ folder names and
    statement digests) and pins published but missing here are COULD NOT
    LOOK: replay, never a pass; a digest that differs under one name is BROKEN.
    Published pins OLDER than the earliest pin here (and not held here under
    any name) are COULD NOT LOOK too: a series that starts later than the
    public record may be an erase-and-restart. --public-listing may also be a
    FOLDER (a clone of tips/; the listing is built from it) or a saved
    Software Heritage directory listing (names only; see load_public_listing).
  - NOT THE ROWS AFTER THE NEWEST PIN. Those are reported as unpinned_rows.
    A bad row there (garbage, or a chain value that does not recompute) is
    no rewrite of pinned history: it is an "unpinned tail" COULD NOT LOOK
    line, and the pinned part's own verdict is printed beside it (BROKEN in
    the pinned rows still wins).
  - `stated_at` is OUR clock and is never reported as the proof time.
  - NOT THE CHAIN'S AGE. Nothing before the FIRST Bitcoin-attested pin is
    attested. Every report prints that pin, its stated_at and the rows it
    covers ("nothing before <T> is attested"), and for every attested pin the
    gap from stated_at to the block time; a gap above 48 h is a WARN line (an
    erase-and-restart re-stamps old-looking statements late; honest upgrades
    land within about 34 h).
  - NOT A PARTIAL SERIES. If the earliest pin here names a previous pin that
    is not in the folder (a partial clone, a pruned copy), the verdict is
    COULD NOT LOOK naming that missing digest, never BROKEN: two pins in hand
    that disagree are BROKEN; a pin we do not hold is unchecked.
  - NOT A REKOR CLOCK. T_rekor is the integrated_time AS CLAIMED BY THE
    STORED ENTRY; this verifier does not check the log's signed entry
    timestamp (SET), so the number is printed as claimed, unverified.
  - NOT A VERIFIED VERIFIER. Every report prints sha256 of this file. Compare
    it against the value published with the public copy BEFORE trusting the
    output, and run it from a fresh clone, never from the audited machine.
    The printed sha256 is of this file's LF-CANONICAL bytes (every CRLF ->
    LF, the W18 rule), so a Windows (CRLF) checkout and an LF clone print the
    same value. A v3 pin states `verifier_sha256` (that digest at pin time)
    and `verifier_sha256_of: "lf"`. When
    it differs from the running file the report prints "VERIFIER MISMATCH:
    statement attests <x>, this file is <y>" in the header and on that pin's
    line. It is NOT a verdict change: a stranger may run a newer verifier.
  - NOT ON TIME. A v3 pin states `cadence_seconds` (how often a pin is due).
    If the newest pin (VERIFIED or still pending) is more than 2 cadences
    older than the clock (system time, or --now ISO; the report says which),
    the report prints "OVERDUE: latest pin <stated_at>, cadence <n>s, <k>
    cadences late". A warning line, never a verdict change. v2 pins state
    no cadence and are not checked for it.
  - CRLF in chain_values.txt and in the chain file's pinned prefix is
    accepted (a Windows checkout); it changes no parsed row. A pin stating
    file_sha256_of "lf" (W18 on) committed to the LF-canonical bytes (every
    CRLF -> LF): the prefix is normalized and compared strictly, so any line
    ending layout matches and any other byte change is BROKEN. A LEGACY pin
    (no file_sha256_of) committed to the raw bytes of the checkout that
    pinned it: raw is tried, then LF-normalized. If neither matches and the
    prefix here has MIXED endings (both CRLF and bare LF), this is the
    original checkout (a normalizing clone never yields mixed endings) and
    the verdict is BROKEN re-serialized. If neither matches, the prefix is
    uniform and every chain value matches, that pin's byte check is COULD NOT
    LOOK (the mixed endings of the original cannot be rebuilt here).
  - The bytes of rows 1..rows_i are checked against EVERY pin's file_sha256,
    not only the newest's: a re-serialized row followed by a fresh honest pin
    is BROKEN naming the older pin that committed to the original bytes.

PIN FOLDERS (section 3.4): <pins>/<chain>/<YYYY-MM-DD>T<HHMM>Z/ holding
statement.json (canonical bytes, exactly as hashed), statement.json.ots
(the proof as first stamped, usually calendar-pending), an optional
statement.json.ots.bitcoin (the Bitcoin-upgraded proof, published later under
its own create-only name; PREFERRED when present), chain_values.txt (one row chain value per line, LF, trailing LF), and an
optional rekor_entry.json. --pins may be the <chain> folder or its parent (with
several chains under the parent, pass --chain-id).

--btc-headers FILE (offline block data you fetched yourself from any node or
explorer): JSON keyed by block height. A .ots proof commits a digest to a
block's MERKLE ROOT, so the file holds merkle roots, not block hashes:
    {"962469": "<merkle root hex>"}
    {"962469": {"merkle_root": "<hex>", "time": 1755182000}}
    {"962469": {"header": "<80-byte raw header hex>"}}   (root + time read from it)
Merkle roots are accepted in display order (what bitcoind's getblockheader
and explorers print) or internal byte order. `time` (unix seconds or ISO) is
the only source of T_outside; without it the height is reported and the time
is said to be unknown. Without the file at all the result for the time is
COULD NOT LOOK: block header unconfirmed, and the structural checks still print.
A header given for the attested height whose root differs from the proof's is
BROKEN (block header root mismatch); no header for that height is COULD NOT
LOOK (no block header supplied for height H); an entry for that height that
does not parse (no root, bad hex, a header that is not 80 bytes), or a file
that is not a JSON object, is COULD NOT LOOK naming the parse problem.

--rekor-key FILE: a Sigstore TUF trusted_root.json (or the cache wrapper
bridge/state/arcaeon/tuf_trusted_root.json). Every tlog key in it is tried
against the checkpoint's signature lines (ECDSA P-256 and Ed25519, verified in
pure Python here).

THE CHAIN RULE (bridge/immune/canon_hash_chain.py `_chain`): row i's chain
value = sha256(chain[i-1] + json.dumps(row_i without "chain", sort_keys=True,
ensure_ascii=False))[:32] hex, chain[0] = the literal "genesis". Blank lines
are not rows.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

VERIFIED = "VERIFIED"
BROKEN = "BROKEN"
COULD_NOT_LOOK = "COULD NOT LOOK"
EXIT_CODES = {VERIFIED: 0, BROKEN: 1, COULD_NOT_LOOK: 2}
_SEVERITY = {VERIFIED: 0, COULD_NOT_LOOK: 1, BROKEN: 2}

STATEMENT = "statement.json"
OTS = "statement.json.ots"
OTS_BITCOIN = "statement.json.ots.bitcoin"
REKOR = "rekor_entry.json"
VALUES = "chain_values.txt"

PIN_FIELDS = ("chain", "chain_values_sha256", "file_sha256", "file_sha256_of",
              "prev_pin_sha256", "rows", "stated_at", "tip", "v")
# a pre-W18 (legacy) pin: no file_sha256_of; its file_sha256 is of the raw bytes
LEGACY_PIN_FIELDS = tuple(f for f in PIN_FIELDS if f != "file_sha256_of")
# a v3 pin (forum readers 2026-10-05): v2 plus cadence_seconds and
# verifier_sha256 (+ verifier_sha256_of "lf"), `v: 3`, file_sha256_of
# required. A v2 pin stays readable.
PIN_V3_FIELDS = tuple(sorted(PIN_FIELDS + ("cadence_seconds", "verifier_sha256",
                                           "verifier_sha256_of")))
VERIFIER_SHA256_OF = "lf"
OVERDUE_CADENCES = 2
FILE_SHA256_OF = "lf"
_HEX = re.compile(r"^[0-9a-f]{32,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{4}Z$")
GAP_WARN_HOURS = 48
# Size guard (outside red team R2, DeepSeek): bigger than this is COULD NOT
# LOOK, never a MemoryError with no verdict.
MAX_CHAIN_LINE_BYTES = 1 << 20          # 1 MiB per chain line
MAX_CHAIN_FILE_BYTES = 512 << 20        # 512 MiB per chain file


def verifier_digest(file_bytes: bytes) -> str:
    """sha256 of the LF-canonical bytes (every b"\r\n" -> b"\n"). The same
    rule as seal_chain.lf_canonical (W18), reimplemented here on purpose (this
    file imports none of our modules); a test pins the two together. Without
    it a CRLF checkout (git autocrlf on Windows) and an LF clone of the same
    commit would print different digests."""
    return hashlib.sha256(bytes(file_bytes).replace(b"\r\n", b"\n")).hexdigest()


def verifier_sha256() -> str:
    """sha256 of this file's LF-canonical bytes, printed on every report
    (F16) and stated in v3 pins: compare it against the published value
    before trusting the output."""
    try:
        return verifier_digest(Path(__file__).read_bytes())
    except OSError:
        return "unreadable"


# ---------------------------------------------------------------------------
# small pure helpers (reimplemented, not imported: a stranger's verifier
# depends on the rules, not on our modules; the tests pin them to seal_chain
# and canon_hash_chain so they cannot drift)
# ---------------------------------------------------------------------------

def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def chain_step(prev: str, row: dict) -> str:
    body = json.dumps(row, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()[:32]


def values_text(values) -> str:
    return "".join(v + "\n" for v in values)


def values_sha256(values) -> str:
    return hashlib.sha256(values_text(values).encode("utf-8")).hexdigest()


def _iso(ts) -> str | None:
    if ts is None:
        return None
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        return datetime.fromtimestamp(int(ts), timezone.utc).isoformat()
    return str(ts)


def _parse_dt(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _age(delta_s: float) -> str:
    s = int(abs(delta_s))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    txt = (f"{d}d {h}h" if d else f"{h}h {m}m")
    return txt if delta_s >= 0 else f"{txt} in the FUTURE"


# ---------------------------------------------------------------------------
# RFC 6962 Merkle inclusion: inlined from bridge/arcaeon/rekor_merkle.py; the
# module stays canonical. Copied (not imported) so this file runs alone; a
# test checks these against the module on fixed vectors so they cannot drift.
# ---------------------------------------------------------------------------

def merkle_leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_check_hashes(hashes) -> bool:
    return all(isinstance(h, (bytes, bytearray)) and len(h) == 32 for h in hashes)


def merkle_verify_inclusion(leaf: bytes, index: int, tree_size: int, audit_path,
                            root: bytes) -> tuple[bool, str]:
    """RFC 6962 section 2.1.1 as an iterative fold (the RFC 9162 form).
    `leaf` is the already-hashed leaf. Never raises on a bad proof."""
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return False, "index and tree_size must be integers"
    if tree_size <= 0 or index < 0 or index >= tree_size:
        return False, "index outside tree"
    if not _merkle_check_hashes([leaf, root]) or not _merkle_check_hashes(audit_path):
        return False, "hashes must be 32-byte digests"
    fn, sn = index, tree_size - 1
    r = bytes(leaf)
    for p in audit_path:
        if sn == 0:
            return False, "audit path longer than the tree needs"
        if fn & 1 or fn == sn:
            r = merkle_node_hash(bytes(p), r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = merkle_node_hash(r, bytes(p))
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return False, "audit path shorter than the tree needs"
    return (r == bytes(root)), ("ok" if r == bytes(root) else "root mismatch")


# ---------------------------------------------------------------------------
# ECDSA P-256 and Ed25519 signature checks, pure Python. Slow and fine: a
# handful of verifications per run. Verify-only; nothing here signs.
# ---------------------------------------------------------------------------

_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = _P - 3
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + _A) * pow(2 * p1[1], -1, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, _P) % _P
    x = (lam * lam - p1[0] - p2[0]) % _P
    return x, (lam * (p1[0] - x) - p1[1]) % _P


def _ec_mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = _ec_add(out, pt)
        pt = _ec_add(pt, pt)
        k >>= 1
    return out


def _der_tlv(buf: bytes, i: int):
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(buf[i:i + nb], "big")
        i += nb
    return tag, buf[i:i + ln], i + ln


def _der_children(buf: bytes):
    out, i = [], 0
    while i < len(buf):
        tag, val, i = _der_tlv(buf, i)
        out.append((tag, val))
    return out


_OID_EC = bytes.fromhex("2a8648ce3d0201")
_OID_P256 = bytes.fromhex("2a8648ce3d030107")
_OID_ED25519 = bytes.fromhex("2b6570")


def parse_spki(der: bytes):
    """-> ("p256", (x, y)) | ("ed25519", raw32) | (None, reason)."""
    try:
        tag, seq, _ = _der_tlv(der, 0)
        (t_alg, alg), (t_bits, bits) = _der_children(seq)[:2]
        oids = [v for t, v in _der_children(alg) if t == 0x06]
        key = bits[1:]  # drop the unused-bits byte
    except Exception as e:  # noqa: BLE001
        return None, f"unparseable SubjectPublicKeyInfo ({type(e).__name__})"
    if oids[:1] == [_OID_EC] and _OID_P256 in oids:
        if len(key) != 65 or key[0] != 4:
            return None, "P-256 key is not an uncompressed point"
        x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
        if (y * y - (x * x * x + _A * x + _B)) % _P:
            return None, "P-256 point is not on the curve"
        return "p256", (x, y)
    if oids[:1] == [_OID_ED25519]:
        return ("ed25519", key) if len(key) == 32 else (None, "Ed25519 key is not 32 bytes")
    return None, "key type is neither ECDSA P-256 nor Ed25519"


def p256_verify(point, der_sig: bytes, msg: bytes) -> bool:
    try:
        tag, seq, _ = _der_tlv(der_sig, 0)
        (t1, rb), (t2, sb) = _der_children(seq)
        r, s = int.from_bytes(rb, "big"), int.from_bytes(sb, "big")
    except Exception:  # noqa: BLE001
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    pt = _ec_add(_ec_mul(e * w % _N, _G), _ec_mul(r * w % _N, point))
    return pt is not None and pt[0] % _N == r


_EP = 2 ** 255 - 19
_EL = 2 ** 252 + 27742317777372353535851937790883648493
_ED = -121665 * pow(121666, -1, _EP) % _EP
_SQRT_M1 = pow(2, (_EP - 1) // 4, _EP)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _EP
    b = (p[1] + p[0]) * (q[1] + q[0]) % _EP
    c = 2 * p[3] * q[3] * _ED % _EP
    d = 2 * p[2] * q[2] % _EP
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _EP, g * h % _EP, f * g % _EP, e * h % _EP


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _EP == 0 and (p[1] * q[2] - q[1] * p[2]) % _EP == 0


def _ed_x(y, sign):
    if y >= _EP:
        return None
    x2 = (y * y - 1) * pow(_ED * y * y + 1, -1, _EP) % _EP
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_EP + 3) // 8, _EP)
    if (x * x - x2) % _EP:
        x = x * _SQRT_M1 % _EP
    if (x * x - x2) % _EP:
        return None
    if (x & 1) != sign:
        x = _EP - x
    return x


def _ed_point(raw: bytes):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _EP)


_EG_Y = 4 * pow(5, -1, _EP) % _EP
_EG = (_ed_x(_EG_Y, 0), _EG_Y, 1, _ed_x(_EG_Y, 0) * _EG_Y % _EP)


def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(sig) != 64:
        return False
    a = _ed_point(pub)
    r = _ed_point(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _EL:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _EL
    return _ed_eq(_ed_mul(s, _EG), _ed_add(r, _ed_mul(h, a)))


# ---------------------------------------------------------------------------
# inputs: trusted root keys, btc headers
# ---------------------------------------------------------------------------

def load_rekor_keys(source) -> tuple[list[dict], str | None]:
    """[{der, kind, key, label}] from a trusted_root.json (raw or the TUF cache
    wrapper) or an already-parsed dict. -> (keys, problem)."""
    try:
        doc = source if isinstance(source, dict) else json.loads(
            Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [], f"--rekor-key {source} unreadable ({type(e).__name__}: {e})"
    if isinstance(doc, dict) and isinstance(doc.get("trusted_root"), dict):
        doc = doc["trusted_root"]
    keys = []
    for tlog in (doc.get("tlogs") or []) if isinstance(doc, dict) else []:
        raw = ((tlog or {}).get("publicKey") or {}).get("rawBytes")
        try:
            der = base64.b64decode(raw, validate=True)
        except Exception:  # noqa: BLE001
            continue
        kind, key = parse_spki(der)
        if kind:
            keys.append({"der": der, "kind": kind, "key": key,
                         "label": tlog.get("baseUrl") or "tlog"})
    if not keys:
        return [], f"--rekor-key {source} holds no usable tlog public key"
    return keys, None


def _header_root(value, what: str) -> bytes:
    """32 bytes from a merkle-root hex string, or ValueError naming why."""
    if not isinstance(value, str):
        raise ValueError(f"{what} is a {type(value).__name__}, not a hex string")
    try:
        b = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{what} is not hex") from None
    if len(b) != 32:
        raise ValueError(f"{what} is {len(b)} bytes, not 32")
    return b


def load_btc_headers(source) -> tuple[dict, str | None]:
    """{height: {"roots": {internal-order bytes}, "time": iso|None,
    "problem": str|None}}. An entry present for a height but unparseable
    keeps its height with `problem` set (W17, GPT R2): "this height's entry
    does not parse" is never confused with "no entry for this height"."""
    try:
        doc = source if isinstance(source, dict) else json.loads(
            Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {}, f"--btc-headers {source} unreadable ({type(e).__name__}: {e})"
    if not isinstance(doc, dict):
        return {}, (f"--btc-headers {source} is not a JSON object keyed by block height "
                    f"(it is a JSON {type(doc).__name__})")
    out = {}
    for k, v in doc.items():
        try:
            h = int(k)
        except ValueError:
            continue        # not a height key; nothing here claims to be a header
        roots, t, problem = set(), None, None
        try:
            if isinstance(v, str):
                b = _header_root(v, "merkle root")
                roots |= {b, b[::-1]}
            elif isinstance(v, dict):
                if v.get("merkle_root") is None and v.get("header") is None:
                    raise ValueError("the entry has neither merkle_root nor header")
                if v.get("merkle_root") is not None:
                    b = _header_root(v["merkle_root"], "merkle_root")
                    roots |= {b, b[::-1]}
                if v.get("header") is not None:
                    if not isinstance(v["header"], str):
                        raise ValueError("header is not a hex string")
                    try:
                        hdr = bytes.fromhex(v["header"])
                    except ValueError:
                        raise ValueError("header is not hex") from None
                    if len(hdr) != 80:
                        raise ValueError(f"header is {len(hdr)} bytes, not 80")
                    roots.add(hdr[36:68])
                    t = int.from_bytes(hdr[68:72], "little")
                if v.get("time") is not None:
                    t = v["time"]
            else:
                raise ValueError(f"the entry is a JSON {type(v).__name__}, neither a merkle "
                                 f"root string nor an object")
        except ValueError as e:
            roots, t, problem = set(), None, str(e)
        out[h] = {"roots": roots, "time": _iso(t), "problem": problem}
    return out, None


# ---------------------------------------------------------------------------
# proofs
# ---------------------------------------------------------------------------

def read_ots(raw: bytes) -> dict:
    """Parse a detached .ots proof. Pure parse: the library applies every op
    from the file digest up to each attestation, so `msg` at a Bitcoin
    attestation IS the merkle root the proof claims for that block."""
    try:
        from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                                PendingAttestation)
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except ImportError as e:
        return {"error": f"the opentimestamps library is not installed ({e})"}
    try:
        dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(raw)))
    except Exception as e:  # noqa: BLE001
        return {"error": f"not a parseable .ots proof ({type(e).__name__}: {e})"}
    btc, pending, other = [], [], []
    for msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            btc.append({"height": att.height, "root": bytes(msg),
                        "merkle_root": bytes(msg)[::-1].hex()})
        elif isinstance(att, PendingAttestation):
            pending.append(att.uri)
        else:
            other.append(type(att).__name__)
    btc.sort(key=lambda a: a["height"])
    return {
        "hash_op": "sha256" if isinstance(dtf.file_hash_op, OpSHA256) else str(dtf.file_hash_op),
        "file_digest": bytes(dtf.file_digest).hex(),
        "bitcoin": btc, "pending": pending, "other": other,
    }


def _first(d: dict, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return None


def read_rekor_entry(doc) -> dict:
    """Normalize either the section 3.4 shape ({body, inclusion_proof,
    checkpoint, log_index, uuid, ...}) or the raw API shape
    ({uuid: {body, logIndex, verification: {inclusionProof: {...}}}})."""
    if not isinstance(doc, dict):
        return {"error": "rekor_entry.json is not a JSON object"}
    uuid = None
    if "body" not in doc and len(doc) == 1:
        (uuid, inner), = doc.items()
        doc = inner if isinstance(inner, dict) else {}
    proof = _first(doc, "inclusion_proof", "inclusionProof") or \
        _first(doc.get("verification") or {}, "inclusionProof", "inclusion_proof") or {}
    checkpoint = _first(doc, "checkpoint") or _first(proof, "checkpoint")
    out = {
        "uuid": _first(doc, "uuid") or uuid,
        "body": _first(doc, "body"),
        "log_index": _first(doc, "log_index", "logIndex"),
        "integrated_time": _first(doc, "integrated_time", "integratedTime"),
        "leaf_index": _first(proof, "log_index", "logIndex"),
        "tree_size": _first(proof, "tree_size", "treeSize"),
        "root_hash": _first(proof, "root_hash", "rootHash"),
        "hashes": _first(proof, "hashes") or [],
        "checkpoint": checkpoint,
    }
    if out["leaf_index"] is None:
        out["leaf_index"] = out["log_index"]
    missing = [k for k in ("body", "leaf_index", "tree_size", "root_hash", "checkpoint")
               if out[k] is None]
    if missing:
        out["error"] = f"rekor_entry.json lacks {', '.join(missing)}"
    return out


def parse_note(note: str):
    """C2SP signed note -> (origin, size, root bytes, signed text, sig lines)."""
    if not isinstance(note, str) or "\n\n" not in note:
        return None
    idx = note.index("\n\n")
    signed = note[:idx + 1]
    head = signed.split("\n")
    try:
        origin, size, root = head[0], int(head[1]), base64.b64decode(head[2], validate=True)
    except (IndexError, ValueError):
        return None
    sigs = [ln for ln in note[idx + 2:].split("\n") if ln.strip()]
    return origin, size, root, signed, sigs


def check_note_signature(note_parts, keys: list[dict]) -> tuple[str, str]:
    """-> (VERIFIED|BROKEN|COULD NOT LOOK, why). BROKEN only when a signature
    line's key hint names one of the given keys and does not verify."""
    _origin, _size, _root, signed, sigs = note_parts
    msg = signed.encode("utf-8")
    hinted = False
    for line in sigs:
        parts = line.split(" ")
        if len(parts) < 3:
            continue
        try:
            raw = base64.b64decode(parts[-1])
        except Exception:  # noqa: BLE001
            continue
        if len(raw) <= 4:
            continue
        hint, sig = raw[:4], raw[4:]
        name = parts[-2]
        for k in keys:
            hints = {hashlib.sha256(k["der"]).digest()[:4]}
            if k["kind"] == "ed25519":
                hints.add(hashlib.sha256(name.encode() + b"\n\x01" + k["key"]).digest()[:4])
            ok = (p256_verify(k["key"], sig, msg) if k["kind"] == "p256"
                  else ed25519_verify(k["key"], sig, msg))
            if ok:
                return VERIFIED, f"checkpoint signed by the {k['label']} key"
            hinted = hinted or hint in hints
    if hinted:
        return BROKEN, "a signature line names a supplied key but does not verify against it"
    return COULD_NOT_LOOK, "no supplied key matches any signature line on the checkpoint"


# ---------------------------------------------------------------------------
# pin folders
# ---------------------------------------------------------------------------

def find_pin_folders(pins_dir, chain_id=None) -> tuple[list[Path], str | None]:
    root = Path(pins_dir)
    if not root.is_dir():
        return [], f"pins folder {root} is missing or not a folder"

    def pins_in(d: Path) -> list[Path]:
        return sorted((c for c in d.iterdir() if c.is_dir() and (c / STATEMENT).exists()),
                      key=lambda p: p.name)

    direct = pins_in(root)
    if direct:
        return direct, None
    chains = [c for c in sorted(root.iterdir()) if c.is_dir() and pins_in(c)]
    if chain_id is not None:
        chains = [c for c in chains if c.name == chain_id]
    if len(chains) > 1:
        return [], (f"pins folder {root} holds several chains "
                    f"({', '.join(c.name for c in chains)}); pass --chain-id")
    return (pins_in(chains[0]) if chains else []), None


def _read_values(path: Path):
    """-> (values, problem). CRLF is normalized to LF (a Windows checkout of
    the public copy turns LF into CRLF; the values are hex, so no CR is ever
    content)."""
    try:
        text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    except (OSError, UnicodeDecodeError) as e:
        return None, f"{path} unreadable ({type(e).__name__})"
    if text and not text.endswith("\n"):
        text += "\n"  # tolerate a lost final LF; the sha check still decides
    return [v for v in text.split("\n") if v], None


# ---------------------------------------------------------------------------
# the chain file
# ---------------------------------------------------------------------------

def walk_chain(raw: bytes) -> dict:
    """Recompute the chain. -> {values, ends, first_break_row, unparseable_row,
    too_large_row, too_large_bytes}. `ends[k]` is the byte offset just past
    row k+1's line (its LF included). A line over MAX_CHAIN_LINE_BYTES stops
    the walk there (too_large_row), unparsed."""
    values, ends = [], []
    first_break = unparseable = too_large = None
    too_large_bytes = None
    prev = "genesis"
    pos = 0
    for line in raw.splitlines(keepends=True):
        pos += len(line)
        s = line.strip()
        if not s:
            continue
        row_no = len(values) + 1
        if len(line) > MAX_CHAIN_LINE_BYTES:
            too_large, too_large_bytes = row_no, len(line)
            break
        try:
            obj = json.loads(s.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("row is not an object")
        except (ValueError, UnicodeDecodeError):
            unparseable = unparseable or row_no
            values.append(None)
            ends.append(pos)
            continue
        claimed = obj.pop("chain", None)
        if not isinstance(claimed, str) or chain_step(prev, obj) != claimed:
            first_break = first_break or row_no
        values.append(claimed if isinstance(claimed, str) else None)
        ends.append(pos)
        prev = claimed if isinstance(claimed, str) else prev
    return {"values": values, "ends": ends, "first_break_row": first_break,
            "unparseable_row": unparseable, "too_large_row": too_large,
            "too_large_bytes": too_large_bytes}


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def _listing_from_folder(root: Path, chain_id=None) -> tuple[list[dict], str | None]:
    """A clone of the public tips/ folder (or its <chain>/ folder) read into
    listing rows: one {name, statement_sha256} per pin folder, the digest
    being sha256 of the statement.json bytes exactly as published."""
    folders, problem = find_pin_folders(root, chain_id)
    if problem:
        return [], f"--public-listing {problem}"
    if not folders:
        return [], (f"--public-listing {root} holds no pin folder with a {STATEMENT} "
                    f"(expected tips/<chain>/<stamp>/{STATEMENT})")
    out = []
    for f in folders:
        try:
            raw = (f / STATEMENT).read_bytes()
        except OSError as e:
            return [], f"--public-listing {f / STATEMENT} unreadable ({type(e).__name__})"
        out.append({"name": f.name, "statement_sha256": hashlib.sha256(raw).hexdigest()})
    return out, None


def _is_swh_directory(doc) -> bool:
    return (isinstance(doc, list) and bool(doc) and all(
        isinstance(i, dict) and "type" in i and "target" in i and "name" in i for i in doc))


def load_public_listing(source, chain_id=None) -> tuple[list[dict], str | None]:
    """What the public `tips/<chain>/` folder shows, in one of three forms
    (a path or an already-parsed list/dict). -> (rows, problem).

    1. A JSON list of {"name": "<YYYY-MM-DD>T<HHMM>Z", "statement_sha256":
       "<64 hex>"} (or {"pins": [...]}).
    2. A FOLDER: a clone of the public tips/ (or tips/<chain>/); the rows are
       built here, name + sha256 of each pin's statement.json.
    3. A saved Software Heritage directory listing of tips/<chain>/, read as a
       NAME-ONLY listing (statement_sha256 null: names are checked, digests
       are not). This verifier never fetches it. The calls, made by you on
       another machine:
         GET https://archive.softwareheritage.org/api/1/origin/<repo url>/visit/latest/
             -> "snapshot"
         GET https://archive.softwareheritage.org/api/1/snapshot/<snapshot>/
             -> branches["refs/heads/main"].target (a revision)
         GET https://archive.softwareheritage.org/api/1/revision/<revision>/
             -> "directory" (the root tree)
         GET https://archive.softwareheritage.org/api/1/directory/<root>/tips/<chain>/
             -> a JSON list of {name, type, target, ...}: save THAT list and pass it.
       For digests too: GET .../api/1/directory/<root>/tips/<chain>/<stamp>/statement.json/
       returns the file entry whose checksums.sha256 is the statement_sha256
       of form 1; write form 1 from those."""
    if not isinstance(source, (list, dict)):
        p = Path(source)
        if p.is_dir():
            return _listing_from_folder(p, chain_id)
    try:
        doc = source if isinstance(source, (list, dict)) else json.loads(
            Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [], f"--public-listing {source} unreadable ({type(e).__name__}: {e})"
    if isinstance(doc, dict):
        doc = doc.get("pins")
    if _is_swh_directory(doc):
        doc = [{"name": i["name"], "statement_sha256": None} for i in doc
               if i.get("type") == "dir" and isinstance(i.get("name"), str)
               and _STAMP.match(i["name"])]
        if not doc:
            return [], (f"--public-listing {source} is a Software Heritage directory listing "
                        f"with no pin folders in it")
    if not isinstance(doc, list):
        return [], f"--public-listing {source} is not a list of pins"
    out = []
    for item in doc:
        name = item.get("name") if isinstance(item, dict) else None
        dig = item.get("statement_sha256") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name or (dig is not None and not (
                isinstance(dig, str) and _HEX64.match(dig))):
            return [], f"--public-listing {source} holds an entry that is not {{name, statement_sha256}}: {item!r}"
        out.append({"name": name, "statement_sha256": dig})
    return out, None


def _check_public_listing(listing, pins, add):
    """Replay check (design 3.7). Pins named in the public listing and absent
    here are COULD NOT LOOK (this verifier cannot check what it does not hold,
    and a stale local copy and a deliberate deletion look the same from
    here); a local pin whose statement digest differs from the listing's for
    the same folder name is BROKEN (two statements under one stamp).

    W16: a listed pin OLDER than the earliest pin here (by folder-name
    stamp) whose statement digest is not held here under any name is the
    erase-and-restart shape: a series that starts later than the public
    record. COULD NOT LOOK naming those pins, reported first."""
    local = {p["name"]: p for p in pins}
    local_digests = {p["digest"] for p in pins if p["digest"]}
    newest_local = max(local) if local else None
    oldest_local = min(local) if local else None
    missing_older, missing_newer, missing_gap = [], [], []
    for item in sorted(listing, key=lambda x: x["name"]):
        p = local.get(item["name"])
        if p is None:
            if oldest_local is not None and item["name"] < oldest_local:
                if item["statement_sha256"] in local_digests:
                    continue        # the same statement is held here under another name
                missing_older.append(item["name"])
            else:
                (missing_newer if newest_local is None or item["name"] > newest_local
                 else missing_gap).append(item["name"])
        elif item["statement_sha256"] and p["digest"] and item["statement_sha256"] != p["digest"]:
            add(2, BROKEN, f"BROKEN: parallel series: pin {item['name']} here hashes to "
                f"{p['digest']}, the public listing names {item['statement_sha256']} for the "
                f"same folder", pin=item["name"], proof_file=Path(p["folder"]) / STATEMENT)
    if missing_older:
        add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: older pins exist in the public listing that "
            f"are missing locally: {', '.join(missing_older)}; a series that starts later than "
            f"the public record may be an erase-and-restart")
    if missing_newer:
        add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: replay: {len(missing_newer)} newer pins in the "
            f"public listing are missing locally: {', '.join(missing_newer)} (the newest local "
            f"pin, {newest_local}, is not the newest published pin)")
    if missing_gap:
        add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: {len(missing_gap)} pins in the public listing "
            f"are missing locally between local pins: {', '.join(missing_gap)}")
    return missing_older + missing_gap + missing_newer


def verify(chain_path, pins_dir, rekor_key=None, btc_headers=None, now=None,
           chain_id=None, public_listing=None) -> dict:
    """Run section 3.5 end to end. Returns a dict with at least: verdict,
    reason, row, proof_file, pins_checked, newest_verified, first_broken,
    unpinned_rows, exit_code, witnessed (always False), findings, pins,
    newest_pin_age, lines (the text report), missing_published_pins (None
    when no public_listing was given)."""
    if now is not None:
        now_dt = _parse_dt(now)
        if now_dt is None:
            raise ValueError(f"--now {now!r} is not an ISO date-time")
        clock_line = f"clock: {now_dt.isoformat()} (given with --now)"
    else:
        now_dt = datetime.now(timezone.utc)
        clock_line = f"clock: {now_dt.isoformat(timespec='seconds')} (system time)"
    findings: list[dict] = []

    def add(step, verdict, reason, pin=None, row=None, proof_file=None, tail=False):
        findings.append({"step": step, "verdict": verdict, "reason": reason,
                         "pin": pin, "row": row,
                         "proof_file": str(proof_file) if proof_file else None,
                         "tail": tail})

    keys, key_problem = (load_rekor_keys(rekor_key) if rekor_key is not None else ([], None))
    headers, hdr_problem = (load_btc_headers(btc_headers) if btc_headers is not None else ({}, None))
    if key_problem:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {key_problem}")
    if hdr_problem:
        add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: {hdr_problem}")

    folders, folder_problem = find_pin_folders(pins_dir, chain_id)
    if folder_problem:
        add(1, COULD_NOT_LOOK, f"COULD NOT LOOK: {folder_problem}")

    pins: list[dict] = []
    # ---- step 1: statements and the digests the proofs name -------------
    for folder in folders:
        pin = {"folder": str(folder), "name": folder.name, "statement": None,
               "digest": None, "ots": None, "rekor": None, "values": None,
               "height": None, "t_outside": None, "rekor_index": None,
               "t_rekor": None, "witnessed": False}
        pins.append(pin)
        sp = folder / STATEMENT
        try:
            raw = sp.read_bytes()
        except OSError as e:
            add(1, COULD_NOT_LOOK, f"COULD NOT LOOK: {sp} unreadable ({type(e).__name__})",
                pin=folder.name, proof_file=sp)
            continue
        digest = hashlib.sha256(raw).hexdigest()
        pin["digest"] = digest
        try:
            st = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            add(1, BROKEN, f"BROKEN: proof swap: {sp} is not a JSON statement; the proofs "
                f"name sha256 of a canonical statement", pin=folder.name, proof_file=sp)
            continue
        shape_problem = _statement_problem(st)
        if shape_problem:
            add(1, BROKEN, f"BROKEN: {sp} is not a v2/v3 pin statement ({shape_problem})",
                pin=folder.name, proof_file=sp)
            continue
        pin["statement"] = st
        pin["canonical_digest"] = hashlib.sha256(canonical_bytes(st)).hexdigest()
        if canonical_bytes(st) != raw:
            add(1, BROKEN, f"BROKEN: proof swap: {sp} is not in canonical form (sorted keys, "
                f"no whitespace); the proofs name sha256 of the canonical bytes, and these "
                f"bytes hash to {digest}", pin=folder.name, proof_file=sp)

        # OTS: subject digest (step 1) and attestation (step 3). The
        # Bitcoin-upgraded copy (statement.json.ots.bitcoin) is preferred when
        # it parses and carries a Bitcoin attestation; otherwise the .ots.
        op = folder / OTS
        bp = folder / OTS_BITCOIN
        chosen, ots = None, None
        if bp.exists():
            try:
                b_ots = read_ots(bp.read_bytes())
            except OSError:
                b_ots = {"error": "unreadable"}
            if "error" not in b_ots and b_ots["hash_op"] == "sha256" and                     b_ots["file_digest"] != digest:
                add(1, BROKEN, f"BROKEN: proof swap: {bp} commits to sha256 "
                    f"{b_ots['file_digest']}, but {STATEMENT} hashes to {digest}",
                    pin=folder.name, proof_file=bp)
            elif "error" not in b_ots and b_ots["hash_op"] == "sha256" and b_ots["bitcoin"]:
                chosen, ots = bp, b_ots
        if chosen is None:
            try:
                ots_raw = op.read_bytes()
            except OSError:
                add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: no OTS proof at {op}",
                    pin=folder.name, proof_file=op)
                ots_raw = None
            if ots_raw is not None:
                chosen, ots = op, read_ots(ots_raw)
        if ots is not None:
            pin["ots_file"] = chosen.name
            pin["ots"] = {k: v for k, v in ots.items() if k != "bitcoin"}
            if "error" in ots:
                add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: {chosen}: {ots['error']}",
                    pin=folder.name, proof_file=chosen)
            elif ots["hash_op"] != "sha256":
                add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: {chosen} hashes the file with "
                    f"{ots['hash_op']}; this verifier reads sha256 proofs only",
                    pin=folder.name, proof_file=chosen)
            elif ots["file_digest"] != digest:
                add(1, BROKEN, f"BROKEN: proof swap: {chosen} commits to sha256 "
                    f"{ots['file_digest']}, but {STATEMENT} hashes to {digest}",
                    pin=folder.name, proof_file=chosen)
            elif not ots["bitcoin"]:
                cals = ", ".join(ots["pending"]) or "none"
                add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: pending: {chosen} carries only calendar "
                    f"attestations ({cals}); no Bitcoin block yet", pin=folder.name,
                    proof_file=chosen)
            else:
                pin["ots"]["bitcoin"] = [{"height": a["height"], "merkle_root": a["merkle_root"]}
                                         for a in ots["bitcoin"]]
                _check_btc(pin, ots["bitcoin"], btc_headers is not None and not hdr_problem,
                           headers, chosen, add)

        # Rekor (optional): subject digest (step 1), inclusion + key (step 4)
        rp = folder / REKOR
        if rp.exists():
            _check_rekor(pin, rp, digest, keys, rekor_key is not None and not key_problem, add)

    # ---- step 2a: the series against the public listing (replay, W16
    # erase-and-restart). Run before the series walk so that, when both fire,
    # what the public record shows leads over "partial series" ----------
    missing_published = None
    if public_listing is not None:
        listing, lproblem = load_public_listing(public_listing, chain_id)
        if lproblem:
            add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: {lproblem}")
        else:
            missing_published = _check_public_listing(listing, pins, add)

    # ---- step 2: the statement series ------------------------------------
    good =[p for p in pins if p["statement"] is not None]
    prev = None
    seen_genesis = False
    missing_prev = None
    for p in good:
        st, name = p["statement"], p["name"]
        vp = Path(p["folder"]) / VALUES
        vals, vproblem = _read_values(vp)
        if vproblem:
            add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: {vproblem}", pin=name, proof_file=vp)
        elif values_sha256(vals) != st["chain_values_sha256"]:
            add(2, BROKEN, f"BROKEN: parallel series: {vp} hashes to {values_sha256(vals)}, "
                f"the statement names chain_values_sha256 {st['chain_values_sha256']}",
                pin=name, proof_file=vp)
        elif len(vals) != st["rows"] or vals[-1] != st["tip"]:
            add(2, BROKEN, f"BROKEN: parallel series: {vp} has {len(vals)} rows ending in "
                f"{vals[-1] if vals else None}; the statement says {st['rows']} rows, tip "
                f"{st['tip']}", pin=name, proof_file=vp)
        else:
            p["values"] = vals
        link = st["prev_pin_sha256"]
        if link is None:
            if seen_genesis or prev is not None:
                add(2, BROKEN, f"BROKEN: parallel series: pin {name} claims genesis "
                    f"(prev_pin_sha256 null) after the series already started",
                    pin=name, proof_file=Path(p["folder"]) / STATEMENT)
            seen_genesis = True
        elif prev is None:
            # The earliest pin in hand is not a genesis. A partial clone, a
            # pruned folder and a hidden history look the same from here: this
            # is "I could not check", never "I checked and it is wrong". The
            # series check anchors to this pin; BROKEN stays for two pins in
            # hand that disagree.
            add(2, COULD_NOT_LOOK, f"COULD NOT LOOK: partial series: the earliest pin here, "
                f"{name}, names a previous pin {link} that is not in this folder; the series "
                f"before it was not checked (fetch the full public copy to check it)",
                proof_file=Path(p["folder"]) / STATEMENT)
            missing_prev = link
        elif link != prev["canonical_digest"]:
            add(2, BROKEN, f"BROKEN: parallel series: pin {name} names previous pin {link}, "
                f"but the pin before it ({prev['name']}) hashes to {prev['canonical_digest']}",
                pin=name, proof_file=Path(p["folder"]) / STATEMENT)
        if prev is not None:
            pst = prev["statement"]
            if st["chain"] != pst["chain"]:
                add(2, BROKEN, f"BROKEN: parallel series: pin {name} is for chain "
                    f"{st['chain']!r}, the pin before it for {pst['chain']!r}",
                    pin=name, proof_file=Path(p["folder"]) / STATEMENT)
            if st["rows"] < pst["rows"]:
                add(2, BROKEN, f"BROKEN: parallel series: rows fell from {pst['rows']} "
                    f"({prev['name']}) to {st['rows']} ({name})",
                    pin=name, proof_file=Path(p["folder"]) / STATEMENT)
            elif p["values"] is not None:
                k = pst["rows"]
                if values_sha256(p["values"][:k]) != pst["chain_values_sha256"] or \
                        p["values"][k - 1] != pst["tip"]:
                    row = None
                    if prev["values"] is not None:
                        row = next((i + 1 for i in range(k) if prev["values"][i] != p["values"][i]), k)
                    add(2, BROKEN, f"BROKEN: parallel series: pin {name}'s chain values do not "
                        f"reproduce pin {prev['name']} on the shared rows 1..{k}"
                        + (f" (first difference at row {row})" if row else ""),
                        pin=name, row=row, proof_file=vp)
        prev = p

    # ---- step 5: the chain file ------------------------------------------
    chain_rows = None
    unpinned = None
    cp = Path(chain_path)
    walk = None
    craw = None
    try:
        csize = cp.stat().st_size
        if csize > MAX_CHAIN_FILE_BYTES:
            add(5, COULD_NOT_LOOK, f"COULD NOT LOOK: chain file {cp}: file too large ({csize} "
                f"bytes; the limit is {MAX_CHAIN_FILE_BYTES} bytes); not read", proof_file=cp)
        else:
            craw = cp.read_bytes()
    except OSError as e:
        add(5, COULD_NOT_LOOK, f"COULD NOT LOOK: chain file {cp} unreadable "
            f"({type(e).__name__})", proof_file=cp)
        craw = None
    newest = good[-1] if good else None
    if craw is not None:
        walk = _check_chain_file(craw, cp, newest, good, add)
        chain_rows = len(walk["values"])

    # ---- verdict ---------------------------------------------------------
    def pin_verdict(p):
        worst = VERIFIED
        for f in findings:
            if f["pin"] == p["name"] and _SEVERITY[f["verdict"]] > _SEVERITY[worst]:
                worst = f["verdict"]
        if p["statement"] is None or p["height"] is None:
            worst = worst if worst != VERIFIED else COULD_NOT_LOOK
        return worst

    for p in pins:
        p["verdict"] = pin_verdict(p)
    newest_ok = next((p for p in reversed(good) if p["verdict"] == VERIFIED), None)
    newest_verified = None
    if newest_ok is not None:
        newest_verified = {k: newest_ok[k] for k in ("name", "folder", "height", "t_outside",
                                                     "rekor_index", "t_rekor", "witnessed")}
        newest_verified.update(rows=newest_ok["statement"]["rows"],
                               tip=newest_ok["statement"]["tip"],
                               chain=newest_ok["statement"]["chain"])
        if chain_rows is not None:
            unpinned = max(0, chain_rows - newest_ok["statement"]["rows"])

    order = sorted(range(len(findings)),
                   key=lambda i: (findings[i]["step"], i))
    broken = [findings[i] for i in order if findings[i]["verdict"] == BROKEN]
    cnl_all = [findings[i] for i in order if findings[i]["verdict"] == COULD_NOT_LOOK]
    # the unpinned tail (W17) is judged apart from the pinned part: the
    # pinned verdict is computed without it, then the tail can only lower a
    # VERIFIED to COULD NOT LOOK (never raise anything, never mask a BROKEN)
    tail = [f for f in cnl_all if f["tail"]]
    cnl = [f for f in cnl_all if not f["tail"]]
    first_broken = broken[0] if broken else None

    if broken:
        verdict, lead = BROKEN, broken[0]
        reason = lead["reason"]
    elif not folders:
        verdict, lead = COULD_NOT_LOOK, None
        reason = (f"COULD NOT LOOK: no pin ({folder_problem or f'no pin folder with a {STATEMENT} under {pins_dir}'})")
    elif newest_ok is None or any(f["pin"] is None for f in cnl):
        verdict = COULD_NOT_LOOK
        newest_name = newest["name"] if newest else None
        global_cnl = [f for f in cnl if f["pin"] is None]
        lead = (global_cnl or [f for f in cnl if f["pin"] == newest_name] or cnl or [None])[0]
        reason = lead["reason"] if lead else "COULD NOT LOOK: no pin could be checked end to end"
    else:
        verdict, lead = VERIFIED, None
        nv = newest_verified
        when = (f"{nv['t_outside']}" if nv["t_outside"]
                else f"Bitcoin block {nv['height']} (block time not supplied)")
        rk = (f"Rekor index {nv['rekor_index']}, unwitnessed" if nv["rekor_index"] is not None
              else "no Rekor entry")
        reason = (f"VERIFIED: chain {nv['chain']} rows 1..{nv['rows']} unchanged since {when} "
                  f"(OTS height {nv['height']}; {rk}); {unpinned or 0} rows after the newest "
                  f"pin are unpinned")
    pinned_verdict, pinned_reason = verdict, reason
    if tail and verdict == VERIFIED:
        verdict, lead = COULD_NOT_LOOK, tail[0]
        reason = lead["reason"]

    age_txt = None
    if newest is not None:
        sdt = _parse_dt(newest["statement"].get("stated_at"))
        age_txt = (f"{_age((now_dt - sdt).total_seconds())} old by our clock (stated_at)"
                   if sdt and now_dt else "age unknown (stated_at unreadable)")

    # ---- F6: the erase-and-restart tell-tales ----------------------------
    first_attested = None
    fa = next((p for p in good if p["height"] is not None), None)
    if fa is not None:
        first_attested = {"name": fa["name"], "stated_at": fa["statement"].get("stated_at"),
                          "rows": fa["statement"]["rows"], "height": fa["height"],
                          "t_outside": fa["t_outside"]}
    gap_warnings = []
    for p in good:
        p["gap_hours"] = None
        sdt = _parse_dt(p["statement"].get("stated_at"))
        tdt = _parse_dt(p["t_outside"]) if p["t_outside"] else None
        if sdt is not None and tdt is not None:
            p["gap_hours"] = round((tdt - sdt).total_seconds() / 3600.0, 1)
            if p["gap_hours"] > GAP_WARN_HOURS:
                gap_warnings.append(
                    f"WARN: pin {p['name']}: the Bitcoin block time {p['t_outside']} is "
                    f"{_age((tdt - sdt).total_seconds())} after its stated_at "
                    f"{p['statement'].get('stated_at')} (> {GAP_WARN_HOURS} h; honest upgrades land "
                    f"within about 34 h). A statement dated long before any outside clock held it "
                    f"is the erase-and-restart tell-tale: compare against the public copy and the "
                    f"witness /history")

    vsha = verifier_sha256()
    # v3: the verifier the chain attests (a mismatch is printed, never judged)
    mismatch_by_pin, verifier_mismatches = {}, []
    for p in good:
        att = p["statement"].get("verifier_sha256")
        if att is not None and att != vsha:
            mismatch_by_pin[p["name"]] = f"VERIFIER MISMATCH: statement attests {att}, this file is {vsha}"
            verifier_mismatches.append({"pin": p["name"], "attested": att, "this_file": vsha})
    # v3: the cadence the chain states, against the clock (a warning, never judged)
    overdue = None
    cadence_line = None
    latest = next((p for p in reversed(good) if p["verdict"] != BROKEN), None)
    if latest is not None and latest["statement"].get("cadence_seconds") is not None:
        cad = latest["statement"]["cadence_seconds"]
        lraw = latest["statement"].get("stated_at")
        ldt = _parse_dt(lraw)
        if ldt is None:
            cadence_line = (f"cadence: latest pin {latest['name']} stated_at {lraw!r} unreadable; "
                            f"overdue not checked")
        else:
            elapsed = (now_dt - ldt).total_seconds()
            if elapsed > OVERDUE_CADENCES * cad:
                late = (elapsed - cad) / cad
                cadence_line = (f"OVERDUE: latest pin {lraw}, cadence {cad}s, {late:.1f} cadences "
                                f"late ({_age(elapsed)} since that stated_at by the clock above; "
                                f"pin {latest['name']}; a warning, not a verdict)")
                overdue = {"pin": latest["name"], "stated_at": lraw, "cadence_seconds": cad,
                           "elapsed_seconds": int(elapsed), "cadences_late": round(late, 1)}
            else:
                cadence_line = (f"cadence: latest pin {lraw} ({latest['name']}), cadence {cad}s, "
                                f"{_age(elapsed)} ago by the clock above; not overdue")
    elif latest is not None:
        cadence_line = (f"cadence: latest pin {latest['name']} is a v2 statement (no "
                        f"cadence_seconds); overdue not checked")
    lines = [f"verifier: verify_pins.py sha256 {vsha}; compare it against the value published "
             f"with the public copy before trusting this report"]
    seen_att = set()
    for m in reversed(verifier_mismatches):          # newest first, one line per attested digest
        if m["attested"] not in seen_att:
            seen_att.add(m["attested"])
            lines.append(mismatch_by_pin[m["pin"]] + f" (newest such pin {m['pin']}; not a verdict "
                         f"change: a newer verifier may legitimately differ)")
    lines.append(clock_line)
    for p in pins:
        st = p["statement"] or {}
        ots_txt = (f"OTS height {p['height']}" + (f" at {p['t_outside']}" if p["t_outside"] else "")
                   if p["height"] is not None else "OTS not attested in Bitcoin")
        if p.get("gap_hours") is not None:
            ots_txt += f" (block time minus stated_at: {p['gap_hours']:+.1f} h)"
        if p.get("ots_file") == OTS_BITCOIN:
            ots_txt += f" [from {OTS_BITCOIN}]"
        rk_txt = (f"Rekor index {p['rekor_index']}"
                  + (f" T_rekor {p['t_rekor']} (integrated_time as claimed by the stored entry, "
                     f"unverified)" if p["t_rekor"] else "")
                  + ", witnessed: false") if p["rekor"] is not None else "no Rekor entry"
        lines.append(f"pin {p['name']}: {p['verdict']}; rows {st.get('rows')}, tip {st.get('tip')}; "
                     f"{ots_txt}; {rk_txt}"
                     + (f"; {mismatch_by_pin[p['name']]}" if p["name"] in mismatch_by_pin else ""))
        if p["ots"] and p["ots"].get("bitcoin"):
            for a in p["ots"]["bitcoin"]:
                lines.append(f"    Bitcoin attestation: height {a['height']}, computed merkle root "
                             f"{a['merkle_root']}")
    for f in findings:
        if f["verdict"] != VERIFIED:
            lines.append(f"  step {f['step']}: {f['reason']}")
    if chain_rows is not None:
        lines.append(f"chain file {cp}: {chain_rows} rows"
                     + (f"; {unpinned} unpinned_rows after the newest verified pin"
                        if unpinned else ""))
    if first_attested is not None:
        fwhen = first_attested["t_outside"] or f"Bitcoin block {first_attested['height']} (block time not supplied)"
        first_attested_line = (f"first attested pin {first_attested['name']} (stated_at "
                               f"{first_attested['stated_at']}) covers rows "
                               f"1..{first_attested['rows']}; nothing before {fwhen} is attested")
    else:
        first_attested_line = ("first attested pin: none; no row of this chain is attested by "
                               "Bitcoin here, so a rewrite of ANY row before the first Bitcoin "
                               "attestation lands is undetectable from this report alone")
    lines.append(first_attested_line)
    lines.extend(gap_warnings)
    if missing_prev is not None:
        lines.append(f"partial series: missing previous pin {missing_prev}")
    if newest is not None:
        lines.append(f"newest pin {newest['name']} {age_txt}; confirm against the public copy")
    else:
        lines.append("newest pin: none; confirm against the public copy")
    if cadence_line is not None:
        lines.append(cadence_line)
    if tail and newest is not None:
        lines.append(f"pinned part (rows 1..{newest['statement']['rows']}): {pinned_reason}")
    lines.append(reason)

    return {
        "verdict": verdict,
        "exit_code": EXIT_CODES[verdict],
        "reason": reason,
        "pinned_verdict": pinned_verdict,     # rows 1..newest pin, without the unpinned tail
        "unpinned_tail_rows": [f["row"] for f in tail],
        "row": lead["row"] if lead else None,
        "proof_file": lead["proof_file"] if lead else None,
        "pins_checked": len(pins),
        "newest_verified": newest_verified,
        "first_broken": first_broken,
        "unpinned_rows": unpinned,
        "chain_rows": chain_rows,
        "newest_pin": newest["name"] if newest else None,
        "newest_pin_age": age_txt,
        "missing_published_pins": missing_published,
        "missing_previous_pin": missing_prev,
        "first_attested": first_attested,
        "first_attested_line": first_attested_line,   # T0 for tools reading --json
        "gap_warnings": gap_warnings,
        "verifier_sha256": vsha,
        "verifier_mismatches": verifier_mismatches,   # v3 pins only; never a verdict change
        "overdue": overdue,                           # v3 cadence check; never a verdict change
        "clock": clock_line,
        "witnessed": False,
        "findings": findings,
        "pins": [{k: v for k, v in p.items() if k not in ("values",)} for p in pins],
        "lines": lines,
    }


def _statement_problem(st) -> str | None:
    if not isinstance(st, dict):
        return f"a JSON {type(st).__name__}, not an object"
    if st.get("v") == 3:
        if set(st) != set(PIN_V3_FIELDS):
            return f"v=3, fields {sorted(st)}"
        c = st["cadence_seconds"]
        if not isinstance(c, int) or isinstance(c, bool) or c <= 0:
            return f"cadence_seconds={c!r} is not a positive integer"
        if not isinstance(st["verifier_sha256"], str) or not _HEX64.match(st["verifier_sha256"]):
            return "verifier_sha256 is not 64 hex"
        if st["verifier_sha256_of"] != VERIFIER_SHA256_OF:
            return (f"verifier_sha256_of={st['verifier_sha256_of']!r} (only "
                    f"{VERIFIER_SHA256_OF!r} is defined)")
    elif st.get("v") != 2 or set(st) not in (set(PIN_FIELDS), set(LEGACY_PIN_FIELDS)):
        return f"v={st.get('v')!r}, fields {sorted(st)}"
    if "file_sha256_of" in st and st["file_sha256_of"] != FILE_SHA256_OF:
        return f"file_sha256_of={st['file_sha256_of']!r} (only {FILE_SHA256_OF!r} is defined)"
    if not isinstance(st["chain"], str) or not st["chain"]:
        return "chain id is not a string"
    if not isinstance(st["rows"], int) or isinstance(st["rows"], bool) or st["rows"] < 1:
        return f"rows={st['rows']!r} is not a positive integer"
    if not isinstance(st["tip"], str) or not _HEX.match(st["tip"]):
        return "tip is not hex"
    for k in ("chain_values_sha256", "file_sha256"):
        if not isinstance(st[k], str) or not _HEX64.match(st[k]):
            return f"{k} is not 64 hex"
    p = st["prev_pin_sha256"]
    if p is not None and (not isinstance(p, str) or not _HEX64.match(p)):
        return "prev_pin_sha256 is neither null nor 64 hex"
    return None


def _check_btc(pin, attestations, have_headers, headers, op, add):
    name = pin["name"]
    first = attestations[0]
    pin["height"] = first["height"]
    if not have_headers:
        add(3, COULD_NOT_LOOK, f"COULD NOT LOOK: block header unconfirmed (height "
            f"{first['height']}, merkle root {first['merkle_root']}): no --btc-headers file "
            f"to compare against", pin=name, proof_file=op)
        return
    confirmed, unparsed, missing = [], [], []
    for a in attestations:
        h = headers.get(a["height"])
        if h is None:
            missing.append(a["height"])
            continue
        if h.get("problem"):
            unparsed.append((a["height"], h["problem"]))
            continue
        if a["root"] in h["roots"]:
            confirmed.append((a, h))
        else:
            add(3, BROKEN, f"BROKEN: block header root mismatch: {op} claims Bitcoin block "
                f"{a['height']} has merkle root {a['merkle_root']}; the headers file gives a "
                f"different root for that height", pin=name, proof_file=op)
            return
    if not confirmed:
        head = (f"COULD NOT LOOK: block header unconfirmed (height {first['height']}, merkle "
                f"root {first['merkle_root']}): ")
        if unparsed:
            # a header supplied for the height that does not parse is "could not
            # read it", never "there is none" and never a pass
            why = "; ".join(f"block header for height {hh} does not parse: {pr}"
                            for hh, pr in unparsed)
        else:
            why = (f"no block header supplied for height{'s' if len(missing) > 1 else ''} "
                   f"{', '.join(str(x) for x in missing)}")
        add(3, COULD_NOT_LOOK, head + why, pin=name, proof_file=op)
        return
    a, h = confirmed[0]
    pin["height"] = a["height"]
    pin["t_outside"] = h["time"]


def _check_rekor(pin, rp, digest, keys, keyed, add):
    name = pin["name"]
    try:
        entry = read_rekor_entry(json.loads(rp.read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {rp} unreadable ({type(e).__name__})",
            pin=name, proof_file=rp)
        return
    if "error" in entry:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {rp}: {entry['error']}", pin=name, proof_file=rp)
        return
    pin["rekor"] = {"log_index": entry["log_index"], "uuid": entry["uuid"], "witnessed": False}
    pin["rekor_index"] = entry["log_index"]
    pin["t_rekor"] = _iso(entry["integrated_time"])
    try:
        body = base64.b64decode(entry["body"], validate=True)
        spec = json.loads(body.decode("utf-8")).get("spec") or {}
        h = (spec.get("data") or {}).get("hash") or {}
        subject = h.get("value") if h.get("algorithm", "sha256") == "sha256" else None
    except Exception as e:  # noqa: BLE001
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {rp}: body is not a base64 JSON Rekor entry "
            f"({type(e).__name__})", pin=name, proof_file=rp)
        return
    if not subject:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {rp}: body carries no sha256 subject digest "
            f"(spec.data.hash)", pin=name, proof_file=rp)
        return
    if subject != digest:
        add(1, BROKEN, f"BROKEN: proof swap: {rp} logs digest {subject}, but {STATEMENT} "
            f"hashes to {digest}", pin=name, proof_file=rp)
        return
    leaf = merkle_leaf_hash(body)
    uuid = entry["uuid"]
    if isinstance(uuid, str) and len(uuid) >= 64 and uuid[-64:].lower() != leaf.hex():
        add(4, BROKEN, f"BROKEN: {rp}: uuid {uuid} does not end in the body's leaf hash "
            f"{leaf.hex()}", pin=name, proof_file=rp)
        return
    note = parse_note(entry["checkpoint"])
    if note is None:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: {rp}: checkpoint is not a signed note",
            pin=name, proof_file=rp)
        return
    _origin, size, root, _signed, _sigs = note
    try:
        proof_root = bytes.fromhex(entry["root_hash"])
        path = [bytes.fromhex(x) for x in entry["hashes"]]
    except (TypeError, ValueError):
        add(4, BROKEN, f"BROKEN: {rp}: inclusion proof hashes are not hex", pin=name,
            proof_file=rp)
        return
    if size != entry["tree_size"] or root != proof_root:
        add(4, BROKEN, f"BROKEN: {rp}: the checkpoint (size {size}, root {root.hex()}) is not "
            f"the tree the inclusion proof names (size {entry['tree_size']}, root "
            f"{proof_root.hex()})", pin=name, proof_file=rp)
        return
    ok, why = merkle_verify_inclusion(leaf, entry["leaf_index"], size, path, root)
    if not ok:
        add(4, BROKEN, f"BROKEN: {rp}: inclusion proof does not verify ({why})", pin=name,
            proof_file=rp)
        return
    if not keyed:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: unkeyed: the checkpoint signature in {rp} was "
            f"not checked (no usable --rekor-key); inclusion verified against an unsigned "
            f"root", pin=name, proof_file=rp)
        return
    v, why = check_note_signature(note, keys)
    if v == BROKEN:
        add(4, BROKEN, f"BROKEN: {rp}: checkpoint signature: {why}", pin=name, proof_file=rp)
    elif v == COULD_NOT_LOOK:
        add(4, COULD_NOT_LOOK, f"COULD NOT LOOK: unkeyed: {rp}: {why}", pin=name, proof_file=rp)


def _check_chain_file(craw, cp, newest, good, add):
    walk = walk_chain(craw)
    vals = walk["values"]
    if walk["too_large_row"]:
        k = walk["too_large_row"]
        add(5, COULD_NOT_LOOK, f"COULD NOT LOOK: chain file {cp} row {k}: line too large "
            f"({walk['too_large_bytes']} bytes; the limit is {MAX_CHAIN_LINE_BYTES} bytes); "
            f"not parsed, and the rows from it on were not checked", row=k, proof_file=cp)
        return walk
    # W17 (outside red team R2, Gemini): a bad row AFTER the newest pin is no
    # rewrite of pinned history. Rows 1..n are judged as before; a bad row in
    # the unpinned tail is its own COULD NOT LOOK line ("tail": the verdict
    # step lets the pinned part's verdict stand and prints it beside).
    n_pinned = newest["statement"]["rows"] if newest is not None else None
    for key, what in (("unparseable_row", "it does not parse as a JSON row"),
                      ("first_break_row", "the stored chain value is not "
                                          "sha256(previous + row)[:32]")):
        k = walk[key]
        if not k:
            continue
        if n_pinned is not None and k > n_pinned:
            add(5, COULD_NOT_LOOK, f"COULD NOT LOOK: unpinned tail: row {k} fails its own "
                f"recompute (not covered by any pin): {what}", row=k, proof_file=cp, tail=True)
        elif key == "unparseable_row":
            add(5, BROKEN, f"BROKEN: chain file {cp} row {k} does not parse as a JSON row",
                row=k, proof_file=cp)
        else:
            add(5, BROKEN, f"BROKEN: chain file {cp} fails its own recompute walk at row {k} "
                f"(the stored chain value is not sha256(previous + row)[:32])",
                row=k, proof_file=cp)
    if newest is None:
        return walk
    st = newest["statement"]
    n = st["rows"]
    if len(vals) < n:
        k = len(vals) + 1
        add(5, BROKEN, f"BROKEN: TRUNCATED, rows {k}..{n} missing (pin {newest['name']} saw "
            f"{n} rows; the file {cp} has {len(vals)})", row=k, proof_file=cp)
        return walk
    pinned = newest["values"]
    mismatch = None
    if pinned is not None:
        mismatch = next((i + 1 for i in range(n) if vals[i] != pinned[i]), None)
        if mismatch:
            seen, now_has = pinned[mismatch - 1], vals[mismatch - 1]
    elif vals[n - 1] != st["tip"]:
        mismatch, seen, now_has = n, st["tip"], vals[n - 1]
    if mismatch:
        cover = next((p for p in good if p["statement"]["rows"] >= mismatch
                      and p["height"] is not None), None) or newest
        when = cover["t_outside"] or ("block time not supplied" if cover["height"] is not None
                                      else "no Bitcoin attestation")
        rk = cover["rekor_index"] if cover["rekor_index"] is not None else "none"
        add(5, BROKEN, f"BROKEN: REWRITTEN at row {mismatch}; the row the pin saw had chain "
            f"{seen}, the file now has {now_has}; pinned by OTS at {when} (height "
            f"{cover['height']}) and Rekor index {rk} (pin {cover['name']})",
            row=mismatch, proof_file=cp)
        return walk
    def values_match(p, rows_i: int) -> bool:
        pv = p["values"]
        if pv is not None:
            return len(pv) >= rows_i and vals[:rows_i] == pv[:rows_i]
        return vals[rows_i - 1] == p["statement"]["tip"]

    def prefix_sha(p, rows_i: int, want_i: str) -> tuple[str, str]:
        """(got, status): status "ok", "mismatch" (BROKEN, re-serialized) or
        "legacy" (COULD NOT LOOK: a legacy pin's raw bytes are not
        reproducible here, but every chain value matches)."""
        prefix = craw[:walk["ends"][rows_i - 1]]
        lf_got = hashlib.sha256(prefix.replace(b"\r\n", b"\n")).hexdigest()
        if p["statement"].get("file_sha256_of") == FILE_SHA256_OF:
            # W18: committed to the LF-canonical bytes. Strict: any line-ending
            # layout normalizes to the same bytes; anything else is a change.
            return lf_got, ("ok" if lf_got == want_i else "mismatch")
        # legacy (pre-W18): committed to the RAW bytes of the checkout that pinned it
        raw_got = hashlib.sha256(prefix).hexdigest()
        if raw_got == want_i:
            return raw_got, "ok"
        if lf_got == want_i:
            return lf_got, "ok"     # a CRLF checkout of an LF-pinned file
        # W18 narrowing: a normalizing clone never yields MIXED endings, so a
        # prefix holding both CRLF and bare LF is the original checkout and its
        # bytes really changed: BROKEN, never the legacy COULD NOT LOOK.
        n_crlf = prefix.count(b"\r\n")
        if n_crlf and prefix.count(b"\n") > n_crlf:
            return raw_got, "mismatch"
        return raw_got, ("legacy" if values_match(p, rows_i) else "mismatch")

    def legacy_cnl(p):
        add(5, COULD_NOT_LOOK, f"COULD NOT LOOK: legacy pin {p['name']} committed to the raw "
            f"bytes of one checkout (mixed line endings); the row contents match but the bytes "
            f"cannot be reproduced here; re-pin with file_sha256_of=lf to make this checkable",
            pin=p["name"], proof_file=cp)

    # W17 (outside red team R2, Gemini): EVERY pin's file_sha256 is checked
    # against the file's prefix at that pin's row count, not only the newest's.
    # Otherwise: re-serialize a pinned row (same parse, same chain values),
    # build a NEW honest pin over the altered bytes, and only the newest pin,
    # which agrees with the tamper, was ever compared. The earliest pin whose
    # bytes no longer match leads (it names the narrowest range).
    checked = []
    for p in good:
        rows_i = p["statement"]["rows"]
        if rows_i > len(vals):
            continue        # cannot happen past the TRUNCATED gate above; never index past the walk
        want_i = p["statement"]["file_sha256"]
        checked.append((p, rows_i, want_i, *prefix_sha(p, rows_i, want_i)))
    for idx, (p, rows_i, want_i, got_i, status) in enumerate(checked):
        if p is newest or status == "ok":
            continue
        if status == "legacy":
            legacy_cnl(p)
            continue
        later = next((q for q, _r, _w, _g, s in checked[idx + 1:] if s == "ok"), None)
        tail_txt = (f"; a later pin {later['name']} committed to the altered bytes"
                    if later is not None else "")
        add(5, BROKEN, f"BROKEN: chain file {cp} rows 1..{rows_i} were re-serialized after pin "
            f"{p['name']} committed to them{tail_txt} (pin {p['name']} names file_sha256 "
            f"{want_i}; rows 1..{rows_i} now hash to {got_i}, although every chain value "
            f"matches)", row=1, proof_file=cp)
        break
    want = st["file_sha256"]
    got, status = prefix_sha(newest, n, want)
    if status == "legacy":
        legacy_cnl(newest)
    elif status == "mismatch":
        # The pinned PREFIX is what the pin's file_sha256 commits to, however many
        # rows have been appended since (the chain keeps growing between pins, so
        # a longer file is the NORMAL state). Gating this on len(vals) == n let an
        # attacker re-serialize a pinned row (a duplicate JSON key, whitespace, a
        # different key order) and hide it by appending one honest row; found by
        # an outside reader on 2026-10-04 (WITNESS_OUTSIDE_REDTEAM, Gemini R1).
        add(5, BROKEN, f"BROKEN: chain file {cp} rows 1..{n} hash to {got}, the pin "
            f"{newest['name']} names file_sha256 {want}, although every chain value matches "
            f"(the bytes of rows 1..{n} were re-serialized; {len(vals) - n} row(s) follow the pin)",
            row=1, proof_file=cp)
    return walk


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    doc = __doc__ or ""
    start = doc.index("THREE WORDS")
    ap = argparse.ArgumentParser(
        prog="py -m bridge.witness.verify_pins",
        description="No-network verifier for outside pins (OTS + Rekor) of a hash chain. It "
                    "fetches nothing, so it needs what it checks handed to it: the chain file, "
                    "the pins folder, block headers (--btc-headers) for the Bitcoin "
                    "attestation, a TUF trusted root (--rekor-key) for Rekor, and optionally "
                    "a public listing (--public-listing).",
        epilog=doc[start:],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--chain", required=True, help="the chain file (JSONL)")
    ap.add_argument("--pins", required=True,
                    help="pin folder: <chain>/ holding <stamp>/ folders, or its parent")
    ap.add_argument("--rekor-key", help="Sigstore TUF trusted_root.json (optional)")
    ap.add_argument("--btc-headers", help="JSON of block height -> merkle root [+ time] (optional)")
    ap.add_argument("--chain-id", help="which chain folder, when --pins holds several")
    ap.add_argument("--public-listing",
                    help="the public tips/ record (optional): a JSON list of {name, "
                         "statement_sha256}, a clone of the tips/ folder itself, or a saved "
                         "Software Heritage directory listing; published pins missing here "
                         "(newer: replay; older: erase-and-restart) are COULD NOT LOOK")
    ap.add_argument("--now", metavar="ISO",
                    help="the clock for pin age and the v3 OVERDUE check (default: system "
                         "time; the report says which was used)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    return ap


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    args = _parser().parse_args(argv)
    try:
        res = verify(args.chain, args.pins, rekor_key=args.rekor_key,
                     btc_headers=args.btc_headers, chain_id=args.chain_id,
                     public_listing=args.public_listing, now=args.now)
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, indent=1, default=str))
    else:
        print("\n".join(res["lines"]))
    return res["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
