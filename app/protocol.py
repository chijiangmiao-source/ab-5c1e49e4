"""Binary checkpoint message that every Ed25519 signature covers.

The signed payload is *not* the JSON request body.  It is a fixed,
unambiguous big-endian byte string:

    MAGIC (25 bytes, NUL-free ASCII, newline terminated)
    log_id length        uint8
    log_id               raw ASCII bytes
    tree_size            uint64 big-endian
    timestamp_ms         uint64 big-endian
    root_hash            32 bytes
    public_key           32 bytes (Ed25519, the signing key itself)

Embedding the log id and public key in the signed bytes makes a
signature un-replayable across logs or keys; fixed-width fields with an
explicit length prefix leave no canonicalisation ambiguity.
"""

import re

MAGIC = b"SEABED-LOG-CHECKPOINT-V1\n"
U64_MAX = (1 << 64) - 1
ROOT_SIZE = 32
KEY_SIZE = 32
MAX_LOG_ID_LEN = 128
LOG_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ProtocolError(ValueError):
    """A request field is malformed."""


def validate_log_id(log_id):
    if not isinstance(log_id, str) or not LOG_ID_RE.match(log_id):
        raise ProtocolError(
            "log_id must be 1-128 ASCII chars from [A-Za-z0-9_.-], starting alphanumeric"
        )
    raw = log_id.encode("ascii")
    if len(raw) > MAX_LOG_ID_LEN:
        raise ProtocolError("log_id too long")
    return raw


def encode_message(log_id, tree_size, timestamp_ms, root_hash, public_key):
    """Return the exact raw bytes an Ed25519 signature must be over."""
    log_raw = validate_log_id(log_id)
    if not isinstance(tree_size, int) or not (0 <= tree_size <= U64_MAX):
        raise ProtocolError("tree_size must be a uint64 integer")
    if not isinstance(timestamp_ms, int) or not (0 <= timestamp_ms <= U64_MAX):
        raise ProtocolError("timestamp_ms must be a uint64 integer")
    if not isinstance(root_hash, (bytes, bytearray)) or len(root_hash) != ROOT_SIZE:
        raise ProtocolError("root_hash must be exactly 32 bytes")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != KEY_SIZE:
        raise ProtocolError("public_key must be exactly 32 bytes")
    return b"".join(
        (
            MAGIC,
            bytes((len(log_raw),)),
            log_raw,
            tree_size.to_bytes(8, "big"),
            timestamp_ms.to_bytes(8, "big"),
            bytes(root_hash),
            bytes(public_key),
        )
    )
