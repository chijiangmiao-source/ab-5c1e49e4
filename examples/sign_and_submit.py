#!/usr/bin/env python3
"""Caller reference: build, sign and submit seabed checkpoints.

The checkpoint signer is the observation log operator: it holds the full
ordered list of leaf hashes, can therefore compute Merkle roots and RFC
9162 consistency proofs itself, and signs the *canonical binary message*
(app/protocol.py) - never the JSON body.

Stdlib-only apart from the shipped app package (Ed25519 + Merkle).

Examples
--------
    python examples/sign_and_submit.py keygen station.key
    python examples/sign_and_submit.py genesis http://localhost:8080 \
        station-7 station.key 3
    python examples/sign_and_submit.py extend http://localhost:8080 \
        station-7 station.key 7
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ed25519 import PrivateKey  # noqa: E402
from app.merkle import MerkleTree, leaf_hash  # noqa: E402
from app.protocol import encode_message  # noqa: E402

LEAF_STORE = os.environ.get("LEAF_STORE", os.path.join(os.getcwd(), "leaves"))


def b64(raw):
    return base64.b64encode(raw).decode()


def load_key(path):
    with open(path, "rb") as f:
        return PrivateKey(f.read())


def save_key(path, key):
    with open(path, "wb") as f:
        f.write(key.raw)
    os.chmod(path, 0o600)


def leaves_path(log_id):
    return os.path.join(LEAF_STORE, log_id + ".leaves")


def materialize_leaves(log_id, size):
    """Deterministic demo leaves; a real station stores real entries."""
    path = leaves_path(log_id)
    leaves = []
    if os.path.exists(path):
        with open(path, "rb") as f:
            blob = f.read()
        leaves = [blob[i:i + 32] for i in range(0, len(blob), 32)]
    while len(leaves) < size:
        leaves.append(leaf_hash(("%s|leaf|%d" % (log_id, len(leaves))).encode()))
    os.makedirs(LEAF_STORE, exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"".join(leaves[:size]))
    return leaves[:size]


def post(base, log_id, key, size, timestamp_ms, leaves, old_size):
    tree = MerkleTree(leaves)
    root = tree.root()
    proof = tree.consistency_proof(old_size) if 0 < old_size < size else []
    message = encode_message(log_id, size, timestamp_ms, root, key.public.raw)
    body = {
        "tree_size": size,
        "timestamp_ms": timestamp_ms,
        "root_hash": b64(root),
        "public_key": b64(key.public.raw),
        "signature": b64(key.sign(message)),  # over raw binary, not JSON
        "consistency_proof": [b64(p) for p in proof],
    }
    req = urllib.request.Request(
        "%s/logs/%s/checkpoints" % (base, log_id),
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(resp.status, resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(exc.code, exc.read().decode())
        sys.exit(1)


def main(argv):
    cmd = argv[1]
    if cmd == "keygen":
        key = PrivateKey.generate()
        save_key(argv[2], key)
        print("wrote %s" % argv[2])
        print("public key (base64): %s" % b64(key.public.raw))
        return
    base, log_id, key_path = argv[2], argv[3], argv[4]
    size = int(argv[5])
    key = load_key(key_path)
    leaves = materialize_leaves(log_id, size)
    import time

    ts = int(time.time() * 1000)
    if cmd == "genesis":
        post(base, log_id, key, size, ts, leaves, 0)
    elif cmd == "extend":
        old_size = int(argv[6])
        post(base, log_id, key, size, ts, leaves, old_size)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
