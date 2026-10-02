"""Durable per-log log-state store.

All mutations happen while holding both an in-process lock and an
``flock`` on ``<logdir>/lock`` (so concurrent writers converge even
across worker processes).  Every state change is made durable by

  1. write-new-temp-file + fsync,
  2. os.replace (atomic rename),
  3. fsync of the directory,

before the lock is released, hence a crash can never leave a half
written checkpoint or a fork record without the state it refers to.

Accepted heads are additionally mirrored to an append-only
``history.jsonl``; that file is never rewritten, so the sequence of
published trusted heads remains auditable after restart.
"""

import contextlib
import fcntl
import hashlib
import json
import os
import threading
import time

from .merkle import InvalidProof, verify_consistency
from .protocol import encode_message
from .ed25519 import BadSignatureError

# Verdicts
GENESIS = "genesis"
ADVANCED = "advanced"
DUPLICATE = "duplicate"
FORK = "fork_detected"


class Rejected(Exception):
    """A submitted checkpoint that parsed but is semantically invalid."""

    def __init__(self, code, message, http_status=422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data: bytes):
    d = os.path.dirname(path)
    tmp = os.path.join(d, ".%s.tmp-%d" % (os.path.basename(path), os.getpid()))
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(d)


class LogStore:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._locks = {}
        self._locks_guard = threading.Lock()

    # -- paths / locking ---------------------------------------------------

    def _log_dir(self, log_id):
        return os.path.join(self.data_dir, log_id)

    def _state_path(self, log_id):
        return os.path.join(self._log_dir(log_id), "state.json")

    def _history_path(self, log_id):
        return os.path.join(self._log_dir(log_id), "history.jsonl")

    def _fork_dir(self, log_id):
        return os.path.join(self._log_dir(log_id), "forks")

    def _fork_path(self, log_id, fork_id):
        return os.path.join(self._fork_dir(log_id), fork_id + ".json")

    def _lock_for(self, log_id):
        with self._locks_guard:
            lock = self._locks.get(log_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[log_id] = lock
            return lock

    @contextlib.contextmanager
    def _locked(self, log_id, create=False):
        d = self._log_dir(log_id)
        if create:
            os.makedirs(self._fork_dir(d), exist_ok=True)
        elif not os.path.isdir(d):
            raise Rejected("unknown_log", "no trusted checkpoint for log %r" % log_id, 404)
        lock = self._lock_for(log_id)
        lock.acquire()
        lockfile = open(os.path.join(d, "lock"), "a+b")
        try:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_UN)
            lockfile.close()
            lock.release()

    # -- (de)serialisation -------------------------------------------------

    @staticmethod
    def _submission_record(sub):
        return {
            "tree_size": sub.tree_size,
            "timestamp_ms": sub.timestamp_ms,
            "root_hash": sub.root_hash_hex,
            "public_key": sub.public_key_hex,
            "signature": sub.signature_hex,
            "consistency_proof": sub.proof_hex,
        }

    def _load_state(self, log_id):
        return self._reconcile(log_id)

    def _read_events(self, log_id, repair=False):
        """Parse history.jsonl, tolerating one torn trailing line."""
        path = self._history_path(log_id)
        if not os.path.exists(path):
            return []
        with open(path, "rb") as f:
            raw = f.read()
        lines = raw.split(b"\n")
        events = []
        valid_end = 0
        for i, line in enumerate(lines):
            if not line:
                if i == len(lines) - 1:
                    valid_end += 1  # trailing newline
                continue
            try:
                events.append(json.loads(line.decode("utf-8")))
                valid_end = i + 1
            except (ValueError, UnicodeDecodeError):
                # Torn write from a crash mid-line: stop and (optionally)
                # truncate the garbage so it can never be mistaken for data.
                break
        if repair and valid_end < len(lines):
            keep = sum(len(lines[j]) + 1 for j in range(valid_end))
            with open(path, "r+b") as f:
                f.truncate(keep)
                f.flush()
                os.fsync(f.fileno())
        return events

    def _reconcile(self, log_id):
        """Crash recovery: rebuild state from the append-only history.

        The commit order is (1) durable history append, (2) atomic state
        rename.  A crash between the two would otherwise leave state one
        step behind; replaying the history closes that window.  A state
        newer than the history is left untouched.
        """
        with open(self._state_path(log_id), "rb") as f:
            state = json.loads(f.read().decode("utf-8"))
        hist_path = self._history_path(log_id)
        if not os.path.exists(hist_path):
            return state
        events = self._read_events(log_id, repair=True)
        rebuilt = None
        for ev in events:
            if ev["event"] not in (GENESIS, ADVANCED):
                continue
            rebuilt = {
                "log_id": log_id,
                "frozen_public_key": ev["public_key"],
                "tree_size": ev["tree_size"],
                "timestamp_ms": ev["timestamp_ms"],
                "root_hash": ev["root_hash"],
                "signature": ev["signature"],
                "consistency_proof": ev["consistency_proof"],
                "updated_at_ms": ev["recorded_at_ms"],
            }
        if rebuilt is not None and rebuilt["tree_size"] > state["tree_size"]:
            atomic_write(
                self._state_path(log_id),
                (json.dumps(rebuilt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
            return rebuilt
        return state

    def _save_state(self, log_id, state):
        atomic_write(
            self._state_path(log_id),
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def _commit(self, log_id, state, event):
        # Journal first, atomically replace state second (see _reconcile).
        self._append_history(log_id, event)
        self._save_state(log_id, state)

    def _append_history(self, log_id, record):
        path = self._history_path(log_id)
        line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        with open(path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self._log_dir(log_id))

    # -- read API ----------------------------------------------------------

    def get_log(self, log_id):
        with self._locked(log_id):
            state = self._load_state(log_id)
            forks = sorted(
                n[:-5]
                for n in os.listdir(self._fork_dir(log_id))
                if n.endswith(".json")
            )
        return {
            "log_id": state["log_id"],
            "status": "forked" if forks else "active",
            "frozen_public_key": state["frozen_public_key"],
            "tree_size": state["tree_size"],
            "timestamp_ms": state["timestamp_ms"],
            "root_hash": state["root_hash"],
            "updated_at_ms": state["updated_at_ms"],
            "fork_count": len(forks),
        }

    def exists(self, log_id):
        return os.path.exists(self._state_path(log_id))

    def list_forks(self, log_id):
        with self._locked(log_id):
            names = sorted(
                n for n in os.listdir(self._fork_dir(log_id)) if n.endswith(".json")
            )
            return [self._read_fork_file(log_id, n) for n in names]

    def _read_fork_file(self, log_id, name):
        with open(os.path.join(self._fork_dir(log_id), name), "rb") as f:
            return json.loads(f.read().decode("utf-8"))

    def get_fork(self, log_id, fork_id):
        if not fork_id.replace("-", "").isalnum() or len(fork_id) > 80:
            raise Rejected("bad_fork_id", "malformed fork id", 400)
        with self._locked(log_id):
            path = self._fork_path(log_id, fork_id)
            if not os.path.exists(path):
                raise Rejected("fork_not_found", "fork %r not found" % fork_id, 404)
            return self._read_fork_file(log_id, fork_id + ".json")

    def history(self, log_id):
        with self._locked(log_id):
            return self._read_events(log_id, repair=False)

    # -- write API ---------------------------------------------------------

    def submit(self, sub):
        """Process one validated :class:`Submission`; returns (verdict, body)."""
        # Signature is verified against the exact binary message, rebuilt
        # from the canonical fields -- never against the JSON request.
        message = encode_message(
            sub.log_id, sub.tree_size, sub.timestamp_ms, sub.root_hash, sub.public_key
        )
        try:
            sub.public_key_obj.verify(message, sub.signature)
        except BadSignatureError as exc:
            raise Rejected("invalid_signature", "Ed25519 verification failed: %s" % exc)

        with self._locked(sub.log_id, create=True):
            state = None
            if os.path.exists(self._state_path(sub.log_id)):
                state = self._load_state(sub.log_id)

            if state is None:
                return self._accept_genesis(sub)

            if sub.tree_size < state["tree_size"]:
                raise Rejected(
                    "stale_tree_size",
                    "trusted tree_size is %d; submission of size %d moves backwards"
                    % (state["tree_size"], sub.tree_size),
                )

            if sub.tree_size == state["tree_size"]:
                # A same-size, validly signed submission that differs in
                # root, time, key or signature is evidence of a fork -
                # including one signed by a different key.  It is sealed,
                # never used to rewrite the trusted record.
                return self._handle_same_size(sub, state)

            # Only the genesis-frozen key may advance the trusted tree.
            if sub.public_key_hex != state["frozen_public_key"]:
                raise Rejected(
                    "public_key_mismatch",
                    "the verification key for this log was frozen at genesis "
                    "and cannot sign tree extensions",
                )

            return self._advance(sub, state)

    def _same_as_trusted(self, sub, state):
        # Duplicate means the same signed tuple; the proof is not signed,
        # so a resend carrying an equivalent proof is still the same head.
        return (
            sub.root_hash_hex == state["root_hash"]
            and sub.timestamp_ms == state["timestamp_ms"]
            and sub.signature_hex == state["signature"]
            and sub.public_key_hex == state["frozen_public_key"]
        )

    def _handle_same_size(self, sub, state):
        if self._same_as_trusted(sub, state):
            # Idempotent retransmission: converge on the same verdict.
            return DUPLICATE, self._trusted_view(state, replayed=True)

        # Valid signature, same size, but root/time/key/signature differs:
        # seal one fork record per conflicting head; the trusted head never
        # changes.  The id binds the conflict itself (trusted + contender),
        # so resends converge while distinct divergences get distinct ids.
        digest = hashlib.sha256(
            b"\x1f".join(
                (
                    str(state["tree_size"]).encode(),
                    state["root_hash"].encode(),
                    state["signature"].encode(),
                    sub.root_hash_hex.encode(),
                    sub.signature_hex.encode(),
                    sub.public_key_hex.encode(),
                )
            )
        ).hexdigest()[:16]
        fork_id = "fork-%d-%s" % (state["tree_size"], digest)
        path = self._fork_path(sub.log_id, fork_id)
        if os.path.exists(path):
            with open(path, "rb") as f:
                record = json.loads(f.read().decode("utf-8"))
        else:
            record = {
                "fork_id": fork_id,
                "log_id": sub.log_id,
                "sealed_at_ms": int(time.time() * 1000),
                "tree_size": state["tree_size"],
                "reason": (
                    "two independently signed checkpoints share tree_size "
                    "but differ in root hash, timestamp, key or signature"
                ),
                "first_checkpoint": {
                    **{
                        k: state[k]
                        for k in (
                            "tree_size",
                            "timestamp_ms",
                            "root_hash",
                            "frozen_public_key",
                            "signature",
                            "consistency_proof",
                        )
                    },
                    "sealed_as_trusted": True,
                },
                "conflicting_checkpoint": {
                    **self._submission_record(sub),
                    "sealed_as_trusted": False,
                },
            }
            atomic_write(path, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        body = self._trusted_view(self._load_state(sub.log_id))
        body["fork"] = record
        return FORK, body

    def _accept_genesis(self, sub):
        if sub.tree_size < 1:
            raise Rejected("invalid_tree_size", "the first checkpoint needs tree_size >= 1")
        if sub.proof:
            raise Rejected(
                "invalid_consistency_proof",
                "the genesis checkpoint has no previous head: proof must be empty",
            )
        now = int(time.time() * 1000)
        state = {
            "log_id": sub.log_id,
            "frozen_public_key": sub.public_key_hex,
            "tree_size": sub.tree_size,
            "timestamp_ms": sub.timestamp_ms,
            "root_hash": sub.root_hash_hex,
            "signature": sub.signature_hex,
            "consistency_proof": sub.proof_hex,
            "updated_at_ms": now,
        }
        self._commit(
            sub.log_id,
            state,
            {"event": GENESIS, "recorded_at_ms": now, **self._submission_record(sub)},
        )
        return GENESIS, self._trusted_view(state)

    def _advance(self, sub, state):
        if not sub.proof:
            raise Rejected(
                "invalid_consistency_proof",
                "a larger tree requires a non-empty RFC 6962/9162 consistency proof",
            )
        try:
            verify_consistency(
                state["tree_size"],
                sub.tree_size,
                bytes.fromhex(state["root_hash"]),
                sub.root_hash,
                sub.proof,
            )
        except InvalidProof as exc:
            raise Rejected(
                "invalid_consistency_proof",
                "old tree is not a verified prefix of the new tree: %s" % exc,
            )

        now = int(time.time() * 1000)
        new_state = {
            "log_id": sub.log_id,
            "frozen_public_key": state["frozen_public_key"],
            "tree_size": sub.tree_size,
            "timestamp_ms": sub.timestamp_ms,
            "root_hash": sub.root_hash_hex,
            "signature": sub.signature_hex,
            "consistency_proof": sub.proof_hex,
            "updated_at_ms": now,
        }
        # State file replacement and the history append are serialised by
        # the exclusive lock and the journal-first commit order.
        self._commit(
            sub.log_id,
            new_state,
            {
                "event": ADVANCED,
                "recorded_at_ms": now,
                "previous_tree_size": state["tree_size"],
                **self._submission_record(sub),
            },
        )
        return ADVANCED, self._trusted_view(new_state)

    @staticmethod
    def _trusted_view(state, replayed=False):
        return {
            "log_id": state["log_id"],
            "frozen_public_key": state["frozen_public_key"],
            "tree_size": state["tree_size"],
            "timestamp_ms": state["timestamp_ms"],
            "root_hash": state["root_hash"],
            "updated_at_ms": state["updated_at_ms"],
            "replayed": replayed,
        }
