# Witness log checkpoint keys

Ed25519 verifier keys for the checkpoints in this directory, in the format
`<name>+<8 hex key hash>+<base64(0x01 || public key)>`. Each checkpoint's
signature line names the key that made it.

This file is only ever appended to. A rotated key stays listed with its last-use
date, because the checkpoints it signed stay verifiable by it.

## Keys

- `arcaeon.io/witness-log/2026-09-22+09765dec+AdKhx0P0WL2jig0oBbA5OC4I/Yu7dyiA54ju7lcMgQ07`  first used 2026-09-23

Check a checkpoint with `node tools/follow.js --key "<key>"` from
https://github.com/dan8433-user/arcaeon-witness. The same key is printed in that
repository's README. A key proves the operator signed a checkpoint; it does not
prove the operator signed only one checkpoint for a size, and it does not prove
anything recorded is true.
