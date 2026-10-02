#!/usr/bin/env python3
"""Acceptance suite for the seabed checkpoint transparency log.

Runs inside the ``verify`` Compose service against a live API and exits
non-zero on the first failed acceptance criterion.  Observations are
interleaved on purpose:

  * HTTP smoke: first checkpoint, legal extension, forged extension,
    same-size fork, idempotent concurrent retransmissions;
  * proof-algorithm tests: RFC 8032 Ed25519 vectors, OpenSSL-equivalent
    round trips, exhaustive RFC 9162 consistency/inclusion checks;
  * image-build checks: build manifest baked into the image, byte-code
    compilation of every shipped module;
  * persistence: a second, freshly started API process serving the same
    data directory must show the trusted checkpoint and sealed fork.
"""

import base64
import concurrent.futures
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from app.ed25519 import PrivateKey, PublicKey, BadSignatureError  # noqa: E402
from app.merkle import (  # noqa: E402
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
    InvalidProof,
    EMPTY_TREE_HASH,
    _split,
)
from app.protocol import MAGIC, encode_message, validate_log_id  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://api:8080").rstrip("/")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
BUILD_INFO = os.environ.get(
    "BUILD_INFO", "/build-info.json" if os.path.exists("/build-info.json")
    else os.path.join(APP_ROOT, "build-info.json")
)
APP_PKG = os.environ.get(
    "APP_PKG",
    "/app/app" if os.path.isdir("/app/app") else os.path.join(APP_ROOT, "app"),
)
SHIPPED_ROOT = os.environ.get(
    "SHIPPED_ROOT",
    "/app" if os.path.isdir("/app/app") else APP_ROOT,
)
FAILURES = []
PASS_COUNT = 0


def check(name, cond, detail=""):
    if cond:
        global PASS_COUNT
        PASS_COUNT += 1
        print("  PASS  %s" % name)
    else:
        FAILURES.append((name, detail))
        print("  FAIL  %s  %s" % (name, detail))


def section(title):
    print("\n=== %s ===" % title)


def request(method, path, body=None, timeout=15):
    url = BASE_URL + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def b64(raw):
    return base64.b64encode(raw).decode()


def wait_healthy(url, attempts=50):
    for _ in range(attempts):
        try:
            status, body = _raw_get(url + "/healthz")
            if status == 200 and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def _raw_get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


# ---------------------------------------------------------------- fixtures

def make_leaves(n, tag):
    return [leaf_hash(("leaf-%s-%d" % (tag, i)).encode()) for i in range(n)]


def signed_checkpoint(sk, log_id, size, ts, root, proof):
    msg = encode_message(log_id, size, ts, root, sk.public.raw)
    return {
        "tree_size": size,
        "timestamp_ms": ts,
        "root_hash": b64(root),
        "public_key": b64(sk.public.raw),
        "signature": b64(sk.sign(msg)),
        "consistency_proof": [b64(p) for p in proof],
    }


# ------------------------------------------------------------- proof tests

def test_ed25519_vectors():
    section("proof algorithms (1/2): RFC 8032 Ed25519 vectors")
    vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]
    for seed, expected_pk, msg_hex, expected_sig in vectors:
        sk = PrivateKey(bytes.fromhex(seed))
        check(
            "public key derivation %s" % seed[:8],
            sk.public.raw.hex() == expected_pk,
        )
        msg = bytes.fromhex(msg_hex)
        sig = sk.sign(msg)
        check("signature matches RFC vector %s" % seed[:8], sig.hex() == expected_sig)
        PublicKey(bytes.fromhex(expected_pk)).verify(msg, bytes.fromhex(expected_sig))
        check("verification of RFC vector %s" % seed[:8], True)

    sk = PrivateKey.generate()
    msg = MAGIC + b"observatory-7"
    sig = sk.sign(msg)
    check("fresh keypair sign/verify", True if sk.public.verify(msg, sig) else False)
    tampered = bytearray(sig)
    tampered[7] ^= 0xFF
    try:
        sk.public.verify(msg, bytes(tampered))
        check("tampered signature rejected", False)
    except BadSignatureError:
        check("tampered signature rejected", True)
    try:
        sk.public.verify(msg + b"x", sig)
        check("modified message rejected", False)
    except BadSignatureError:
        check("modified message rejected", True)
    try:
        PublicKey(b"\xff" * 32)
        check("out-of-range public key rejected", False)
    except BadSignatureError:
        check("out-of-range public key rejected", True)


def independent_mth(leaves):
    if not leaves:
        return EMPTY_TREE_HASH
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(independent_mth(leaves[:k]), independent_mth(leaves[k:]))


def test_merkle_exhaustive():
    section("proof algorithms (2/2): RFC 9162 Merkle proofs, sizes 1..70")
    import os
    import random

    random.seed(20261002)
    ok = True
    for n in range(1, 71):
        leaves = [leaf_hash(os.urandom(5)) for _ in range(n)]
        tree = MerkleTree(leaves)
        if tree.root() != independent_mth(leaves):
            ok = False
            break
        for i in range(n):
            verify_inclusion(i, n, leaves[i], tree.root(), tree.inclusion_proof(i))
        for m in range(1, n):
            old_root = MerkleTree(leaves[:m]).root()
            proof = tree.consistency_proof(m)
            verify_consistency(m, n, old_root, tree.root(), proof)
            bad = [bytes(x) for x in proof]
            b0 = bytearray(bad[0])
            b0[0] ^= 1
            bad[0] = bytes(b0)
            try:
                verify_consistency(m, n, old_root, tree.root(), bad)
                ok = False
            except InvalidProof:
                pass
            try:
                verify_consistency(m, n, old_root, tree.root(), proof[:-1])
                ok = False
            except InvalidProof:
                pass
    check("valid proofs verify for every size 1..70", ok)

    # RFC 9162 section 2.1.5 worked example identities.
    leaves = [leaf_hash(bytes([i])) for i in range(7)]
    a, b, c, d, e, f, d6 = leaves
    g = node_hash(a, b)
    h = node_hash(c, d)
    ii = node_hash(e, f)
    k = node_hash(g, h)
    l = node_hash(ii, d6)
    root = node_hash(k, l)
    tree = MerkleTree(leaves)
    check("PROOF(3, D7) == [c, d, g, l]", tree.consistency_proof(3) == [c, d, g, l])
    check("PROOF(4, D7) == [l]", tree.consistency_proof(4) == [l])
    check("PROOF(6, D7) == [i, j, k]", tree.consistency_proof(6) == [ii, d6, k])
    verify_consistency(3, 7, MerkleTree(leaves[:3]).root(), root, [c, d, g, l])
    check("worked-example consistency verifies", True)

    # A rewritten prefix cannot be smuggled with a proof generated for the
    # honest history.
    leaves = [leaf_hash(b"obs-%d" % i) for i in range(13)]
    tree = MerkleTree(leaves)
    m = 5
    evil_old = list(leaves[:m])
    bx = bytearray(evil_old[2])
    bx[0] ^= 1
    evil_old[2] = bytes(bx)
    try:
        verify_consistency(
            m, 13, MerkleTree(evil_old).root(), tree.root(), tree.consistency_proof(m)
        )
        check("rewritten (non-prefix) history rejected", False)
    except InvalidProof:
        check("rewritten (non-prefix) history rejected", True)


# --------------------------------------------------------------- http smoke

def http_smoke_genesis():
    section("HTTP smoke (1/4): health, unknown log, first checkpoint")
    check("API is healthy", wait_healthy(BASE_URL))
    status, body = request("GET", "/logs/no-such-log-xyz")
    check("unknown log -> 404 with locatable reason",
          status == 404 and body.get("error") == "unknown_log", body)

    log_id = "station-%d" % int(time.time() * 1000)
    sk = PrivateKey.generate()
    leaves3 = make_leaves(3, log_id)
    root3 = MerkleTree(leaves3).root()
    ts1 = 1_780_000_000_000
    cp = signed_checkpoint(sk, log_id, 3, ts1, root3, [])

    status, body = request("POST", "/logs/%s/checkpoints" % log_id, cp)
    check("genesis accepted -> 201 genesis",
          status == 201 and body.get("verdict") == "genesis", body)
    check("genesis echoes trusted size/root/key",
          body["tree_size"] == 3 and body["root_hash"] == root3.hex()
          and body["frozen_public_key"] == sk.public.raw.hex(), body)

    status, body = request("GET", "/logs/%s" % log_id)
    check("GET exposes trusted head while status=active",
          status == 200 and body["tree_size"] == 3
          and body["root_hash"] == root3.hex() and body["status"] == "active", body)

    # identical retransmission -> same adjudication, idempotent
    status, body = request("POST", "/logs/%s/checkpoints" % log_id, cp)
    check("identical retransmission -> 200 duplicate, same record",
          status == 200 and body.get("verdict") == "duplicate"
          and body["root_hash"] == root3.hex(), body)

    # malformed submissions leave no half-finished state
    bad = dict(cp)
    bad["signature"] = b64(b"\x00" * 64)
    status, body = request("POST", "/logs/%s/checkpoints" % log_id, bad)
    check("forged signature -> 422 invalid_signature",
          status == 422 and body.get("error") == "invalid_signature", body)
    bad = dict(cp)
    bad["tree_size"] = 2
    stale_msg = encode_message(
        log_id, 2, ts1, MerkleTree(leaves3[:2]).root(), sk.public.raw
    )
    bad["signature"] = b64(
        sk.sign(stale_msg)
    )
    bad["root_hash"] = b64(MerkleTree(leaves3[:2]).root())
    status, body = request("POST", "/logs/%s/checkpoints" % log_id, bad)
    check("stale size -> 422 stale_tree_size",
          status == 422 and body.get("error") == "stale_tree_size", body)
    bad = dict(cp)
    del bad["root_hash"]
    status, body = request("POST", "/logs/%s/checkpoints" % log_id, bad)
    check("missing field -> 400 bad_field",
          status == 400 and body.get("error") == "bad_field", body)
    status, hist = request("GET", "/logs/%s/history" % log_id)
    check("failed submissions leave no history artefact",
          status == 200 and len(hist["history"]) == 1
          and hist["history"][0]["event"] == "genesis", hist)
    return log_id, sk, leaves3, root3, ts1


def http_smoke_extension(log_id, sk, leaves3, root3, ts1):
    section("HTTP smoke (2/4): legal extension + concurrent identical retries")
    leaves7 = leaves3 + make_leaves(4, log_id + "-ext")
    root7 = MerkleTree(leaves7).root()
    proof37 = MerkleTree(leaves7).consistency_proof(3)
    ts2 = ts1 + 60_000
    ext = signed_checkpoint(sk, log_id, 7, ts2, root7, proof37)

    status, body = request("POST", "/logs/%s/checkpoints" % log_id, ext)
    check("consistent extension -> 201 advanced",
          status == 201 and body.get("verdict") == "advanced"
          and body["tree_size"] == 7, body)
    status, body = request("GET", "/logs/%s" % log_id)
    check("trusted head atomically advanced to size 7",
          body["tree_size"] == 7 and body["root_hash"] == root7.hex()
          and body["timestamp_ms"] == ts2, body)

    # Concurrent identical retries of one extension: exactly one winner,
    # every observer sees the same verdict basis.
    ext_again = signed_checkpoint(sk, log_id, 7, ts2, root7, proof37)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [
            pool.submit(request, "POST", "/logs/%s/checkpoints" % log_id, ext_again)
            for _ in range(8)
        ]
        results = [f.result() for f in futs]
    statuses = sorted(s for s, _ in results)
    heads = {(b["tree_size"], b["root_hash"]) for _, b in results}
    check("8 concurrent retransmits: all 200 duplicate",
          statuses == [200] * 8, statuses)
    check("every concurrent answer shows the same trusted head",
          heads == {(7, root7.hex())}, heads)

    # And a genuinely new concurrent extension race on a second log: the
    # identical transition submitted in parallel is accepted exactly once.
    log2 = "race-%d" % int(time.time() * 1000)
    sk2 = PrivateKey.generate()
    l2a = make_leaves(2, log2)
    root2 = MerkleTree(l2a).root()
    gen2 = signed_checkpoint(sk2, log2, 2, ts1, root2, [])
    s, _ = request("POST", "/logs/%s/checkpoints" % log2, gen2)
    check("race log genesis 201", s == 201)
    l2b = l2a + make_leaves(6, log2 + "-x")
    root8 = MerkleTree(l2b).root()
    ext2 = signed_checkpoint(sk2, log2, 8, ts2, root8,
                             MerkleTree(l2b).consistency_proof(2))
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futs = [
            pool.submit(request, "POST", "/logs/%s/checkpoints" % log2, ext2)
            for _ in range(10)
        ]
        rs = [f.result() for f in futs]
    codes = sorted(s for s, _ in rs)
    check("10 identical parallel extensions: exactly one 201, nine 200",
          codes == [200] * 9 + [201], codes)
    return leaves7, root7, ts2, proof37


def http_smoke_forgery(log_id, sk, leaves7, root7, ts2):
    section("HTTP smoke (3/4): forged / truncated / stale submissions")
    # 1. truncated proof
    leaves9 = leaves7 + make_leaves(2, log_id + "-more")
    root9 = MerkleTree(leaves9).root()
    full = MerkleTree(leaves9).consistency_proof(7)
    truncated = signed_checkpoint(sk, log_id, 9, ts2 + 1000, root9, full[:-1])
    s, body = request("POST", "/logs/%s/checkpoints" % log_id, truncated)
    check("truncated proof -> 422 invalid_consistency_proof",
          s == 422 and body.get("error") == "invalid_consistency_proof", body)

    # 2. proof from a different history (correct length, wrong nodes)
    foreign = make_leaves(9, "foreign-tree")
    fproof = MerkleTree(foreign).consistency_proof(7)
    forged = signed_checkpoint(sk, log_id, 9, ts2 + 1000, root9, fproof)
    s, body = request("POST", "/logs/%s/checkpoints" % log_id, forged)
    check("proof of a different history -> 422",
          s == 422 and body.get("error") == "invalid_consistency_proof", body)

    # 3. wrong root hash (sign a root that the proof cannot recompute)
    bad_root = bytearray(root9)
    bad_root[0] ^= 1
    wrong = signed_checkpoint(sk, log_id, 9, ts2 + 1000, bytes(bad_root), full)
    s, body = request("POST", "/logs/%s/checkpoints" % log_id, wrong)
    check("wrong root hash with valid signature -> 422",
          s == 422 and body.get("error") == "invalid_consistency_proof", body)

    # 4. extension signed by a different, self-consistent key
    other = PrivateKey.generate()
    wrong_key = signed_checkpoint(other, log_id, 9, ts2 + 1000, root9, full)
    s, body = request("POST", "/logs/%s/checkpoints" % log_id, wrong_key)
    check("foreign-key extension -> 422 public_key_mismatch",
          s == 422 and body.get("error") == "public_key_mismatch", body)

    # 5. JSON-transcoded signature must not validate (sign bytes that are
    # not the canonical binary message): flip one byte inside the message.
    msg = encode_message(log_id, 9, ts2 + 1000, root9, sk.public.raw)
    evil_msg = bytearray(msg)
    evil_msg[-1] ^= 1  # flip inside public key tail of the signed message
    body_evil = {
        "tree_size": 9,
        "timestamp_ms": ts2 + 1000,
        "root_hash": b64(root9),
        "public_key": b64(sk.public.raw),
        "signature": b64(sk.sign(bytes(evil_msg))),
        "consistency_proof": [b64(p) for p in full],
    }
    s, body = request("POST", "/logs/%s/checkpoints" % log_id, body_evil)
    check("signature over non-canonical bytes -> 422 invalid_signature",
          s == 422 and body.get("error") == "invalid_signature", body)

    s, body = request("GET", "/logs/%s" % log_id)
    check("trusted head untouched after every forgery attempt",
          s == 200 and body["tree_size"] == 7 and body["root_hash"] == root7.hex()
          and body["status"] == "active", body)
    s, hist = request("GET", "/logs/%s/history" % log_id)
    check("no half-finished history rows (still genesis+advanced)",
          [e["event"] for e in hist["history"]] == ["genesis", "advanced"], hist)


def http_smoke_fork(log_id, sk, root7, ts2):
    section("HTTP smoke (4/4): same-size signed fork is sealed, never rewritten")
    # Same size 7, independently built root, validly signed by a second
    # observer key - the signed binary still parses and verifies.
    other = PrivateKey.generate()
    alt_leaves = make_leaves(7, log_id + "-alt")
    alt_root = MerkleTree(alt_leaves).root()
    fork_cp = signed_checkpoint(other, log_id, 7, ts2 + 5000, alt_root, [])

    s, body = request("POST", "/logs/%s/checkpoints" % log_id, fork_cp)
    check("same-size divergent signed head -> 409 fork_detected",
          s == 409 and body.get("verdict") == "fork_detected"
          and "fork" in body and body["fork"]["fork_id"], body)
    fork_id = body["fork"]["fork_id"]
    check("fork record preserves both checkpoints and flags the trusted one",
          body["fork"]["first_checkpoint"]["sealed_as_trusted"] is True
          and body["fork"]["conflicting_checkpoint"]["sealed_as_trusted"] is False
          and body["fork"]["conflicting_checkpoint"]["root_hash"] == alt_root.hex(),
          body)

    # repeat the exact same conflicting submission: one fork record only
    s, body2 = request("POST", "/logs/%s/checkpoints" % log_id, fork_cp)
    check("repeated fork submission -> 409 and the same fork id",
          s == 409 and body2["fork"]["fork_id"] == fork_id, body2)

    # a second, different same-size divergence is also evidence; sealed too
    alt2 = make_leaves(7, log_id + "-alt2")
    alt2_root = MerkleTree(alt2).root()
    fork2 = signed_checkpoint(sk, log_id, 7, ts2 + 9000, alt2_root, [])
    s, body3 = request("POST", "/logs/%s/checkpoints" % log_id, fork2)
    check("second divergence -> 409 with a distinct fork id",
          s == 409 and body3["fork"]["fork_id"] != fork_id, body3)

    s, body = request("GET", "/logs/%s" % log_id)
    check("original trusted record is not rewritten; status forked; count 2",
          body["tree_size"] == 7 and body["root_hash"] != alt_root.hex()
          and body["root_hash"] != alt2_root.hex()
          and body["status"] == "forked" and body["fork_count"] == 2, body)

    s, listing = request("GET", "/logs/%s/forks" % log_id)
    check("forks are listable", s == 200 and len(listing["forks"]) == 2, listing)
    s, one = request("GET", "/logs/%s/forks/%s" % (log_id, fork_id))
    check("individual fork record is retrievable",
          s == 200 and one["fork_id"] == fork_id, one)
    s, bad = request("GET", "/logs/%s/forks/..%%2fetc" % log_id)
    check("malformed fork id -> 400", s in (400, 404), bad)

    # Extra edge cases on a fresh log:
    edge = "edge-%d" % int(time.time() * 1000)
    edge_sk = PrivateKey.generate()
    edge_root = MerkleTree(make_leaves(3, edge)).root()
    s, _ = request("POST", "/logs/%s/checkpoints" % edge,
                   signed_checkpoint(edge_sk, edge, 3, 1000, edge_root, []))
    check("edge log genesis 201", s == 201)

    # same size and root, but a *different valid key*: still a fork
    other_sk = PrivateKey.generate()
    s, body = request(
        "POST", "/logs/%s/checkpoints" % edge,
        signed_checkpoint(other_sk, edge, 3, 1000, edge_root, []))
    check("same-size same-root different-key head -> 409 fork",
          s == 409 and body.get("verdict") == "fork_detected"
          and body["fork"]["first_checkpoint"]["sealed_as_trusted"] is True, body)
    fork_ref = body["fork"]["fork_id"]
    s2, body2 = request(
        "POST", "/logs/%s/checkpoints" % edge,
        signed_checkpoint(other_sk, edge, 3, 1000, edge_root, []))
    check("that conflict resubmitted converges to the same fork id",
          s2 == 409 and body2["fork"]["fork_id"] == fork_ref, body2)

    # signature created for a different log id cannot be replayed
    foreign_msg = encode_message("not-the-same-log", 3, 1000, edge_root, edge_sk.public.raw)
    replay = signed_checkpoint(edge_sk, edge, 3, 1000, edge_root, [])
    replay["signature"] = b64(edge_sk.sign(foreign_msg))
    s, body = request("POST", "/logs/%s/checkpoints" % edge, replay)
    check("cross-log signature replay -> 422",
          s == 422 and body.get("error") == "invalid_signature", body)

    # genesis checkpoint must not carry a proof
    edge2 = "edge2-%d" % int(time.time() * 1000)
    with_proof = signed_checkpoint(edge_sk, edge2, 3, 1000, edge_root, [b"\x00" * 32])
    s, body = request("POST", "/logs/%s/checkpoints" % edge2, with_proof)
    check("genesis with non-empty proof -> 422",
          s == 422 and body.get("error") == "invalid_consistency_proof", body)
    return fork_id


# ----------------------------------------------------------- build checks

def image_build_checks():
    section("image build check: build manifest and shipped modules")
    check("build manifest exists (%s)" % BUILD_INFO, os.path.exists(BUILD_INFO))
    if os.path.exists(BUILD_INFO):
        manifest = json.loads(open(BUILD_INFO).read())
        check("manifest records image, python and digest",
              manifest.get("image") == "seabed-checkpoint"
              and manifest.get("python_version", "").startswith("3.")
              and len(manifest.get("source_sha256", "")) == 64, manifest)
        # recompute digest over the exact shipped file tree in the image
        h = hashlib.sha256()
        counted = 0
        for dirpath, dirs, files in os.walk(SHIPPED_ROOT):
            dirs[:] = sorted(d for d in dirs if d not in ("__pycache__", ".git"))
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo")) or name == "build-info.json":
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, SHIPPED_ROOT)
                h.update(rel.encode())
                h.update(b"\0")
                with open(full, "rb") as f:
                    h.update(f.read())
                h.update(b"\0")
                counted += 1
        check("source digest matches the image manifest",
              h.hexdigest() == manifest["source_sha256"]
              and counted == manifest["file_count"],
              "%s vs %s" % (h.hexdigest(), manifest.get("source_sha256")))

    import compileall
    ok = compileall.compile_dir(APP_PKG, quiet=1, force=True)
    check("all application modules byte-compile cleanly", bool(ok))


# ------------------------------------------------------------- restart

def crash_recovery(log_id, root7):
    section("crash recovery: journal/state divergence and torn history line")
    # Scenario A: crash between journal append and state rename leaves
    # history ahead of state; the next read must rebuild state.
    rec_log = "recover-a-%d" % int(time.time() * 1000)
    skr = PrivateKey.generate()
    l = make_leaves(2, rec_log)
    root2 = MerkleTree(l).root()
    s, _ = request("POST", "/logs/%s/checkpoints" % rec_log,
                   signed_checkpoint(skr, rec_log, 2, 1000, root2, []))
    check("recover-A genesis 201", s == 201)
    with open(os.path.join(DATA_DIR, rec_log, "history.jsonl"), "rb") as f:
        gen_event = json.loads(f.read().decode().strip())
    gen_event.update({
        "event": "advanced",
        "recorded_at_ms": 2000,
        "tree_size": 6,
        "timestamp_ms": 2000,
        "root_hash": hashlib.sha256(b"post-crash-head").hexdigest(),
        "previous_tree_size": 2,
    })
    with open(os.path.join(DATA_DIR, rec_log, "history.jsonl"), "ab") as f:
        f.write((json.dumps(gen_event, sort_keys=True) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    s, body = request("GET", "/logs/%s" % rec_log)
    check("state rebuilt from journal after crash window",
          s == 200 and body["tree_size"] == 6
          and body["root_hash"] == gen_event["root_hash"], body)

    # Scenario B: a torn trailing history line (partial write at crash)
    # must never poison reads; it is tolerated and truncated on repair.
    rec_b = "recover-b-%d" % int(time.time() * 1000)
    s, _ = request("POST", "/logs/%s/checkpoints" % rec_b,
                   signed_checkpoint(skr, rec_b, 1, 1000,
                                     leaf_hash(b"x"), []))
    check("recover-B genesis 201", s == 201)
    hpath = os.path.join(DATA_DIR, rec_b, "history.jsonl")
    with open(hpath, "ab") as f:
        f.write(b'{"event":"advanced","tree_size":9')  # no close quote/newline
        f.flush()
        os.fsync(f.fileno())
    s, body = request("GET", "/logs/%s" % rec_b)
    check("log still readable with torn history tail",
          s == 200 and body["tree_size"] == 1, body)
    with open(hpath, "rb") as f:
        tail = f.read()
    check("torn bytes were truncated on repair",
          b'"event":"advanced"' not in tail and tail.count(b"\n") == 1, tail[-60:])
    s, hist = request("GET", "/logs/%s/history" % rec_b)
    check("history shows exactly the one durable event",
          len(hist["history"]) == 1
          and hist["history"][0]["event"] == "genesis", hist)


def restart_persistence(log_id, root7, fork_id_expected):
    section("restart persistence: fresh process serving the same data dir")
    port = os.environ.get("RESTART_PORT", "8091")
    env = dict(os.environ)
    env.update({"PORT": port, "HOST": "127.0.0.1", "DATA_DIR": DATA_DIR})
    proc = subprocess.Popen(
        [sys.executable, "-m", "app"],
        cwd=os.path.dirname(APP_PKG), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        url = "http://127.0.0.1:%s" % port
        healthy = False
        for _ in range(50):
            try:
                with urllib.request.urlopen(url + "/healthz", timeout=2) as r:
                    if r.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(0.2)
        check("second API process started from durable state", healthy)
        if healthy:
            with urllib.request.urlopen("%s/logs/%s" % (url, log_id), timeout=5) as r:
                head = json.loads(r.read().decode())
            check("trusted checkpoint survives restart",
                  head["tree_size"] == 7 and head["status"] == "forked"
                  and head["fork_count"] == 2, head)
            with urllib.request.urlopen(
                "%s/logs/%s/forks/%s" % (url, log_id, fork_id_expected), timeout=5
            ) as r:
                fork = json.loads(r.read().decode())
            check("sealed fork evidence survives restart",
                  fork["fork_id"] == fork_id_expected
                  and fork["first_checkpoint"]["sealed_as_trusted"] is True, fork)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    print("Seabed checkpoint log acceptance suite")
    print("target API: %s   data dir: %s" % (BASE_URL, DATA_DIR))

    log_id, sk, leaves3, root3, ts1 = http_smoke_genesis()
    test_ed25519_vectors()
    leaves7, root7, ts2, _ = http_smoke_extension(log_id, sk, leaves3, root3, ts1)
    test_merkle_exhaustive()
    http_smoke_forgery(log_id, sk, leaves7, root7, ts2)
    fork_id = http_smoke_fork(log_id, sk, root7, ts2)
    crash_recovery(log_id, root7)
    image_build_checks()
    restart_persistence(log_id, root7, fork_id)

    print("\n=== summary ===")
    print("passed: %d" % PASS_COUNT)
    if FAILURES:
        print("failed: %d" % len(FAILURES))
        for name, detail in FAILURES:
            print("  - %s  %s" % (name, detail))
        return 1
    print("ACCEPTANCE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
