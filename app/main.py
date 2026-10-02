"""Seabed observatory checkpoint transparency log - HTTP service.

Stdlib-only HTTP front end for :mod:`app.storage`.

Endpoints
---------
GET  /healthz                              liveness probe
POST /logs/{log_id}/checkpoints            submit a signed checkpoint
GET  /logs/{log_id}                        trusted tree head + status
GET  /logs/{log_id}/forks                  sealed fork evidence list
GET  /logs/{log_id}/forks/{fork_id}        one fork record
GET  /logs/{log_id}/history                append-only head publication log

Binary fields in JSON are standard Base64 (RFC 4648, padding optional;
URL-safe alphabet also accepted).  The Ed25519 signature is always
verified over the canonical binary message built in app.protocol, never
over the JSON body.
"""

import base64
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .ed25519 import BadSignatureError
from .merkle import InvalidProof
from .protocol import KEY_SIZE, ROOT_SIZE, U64_MAX, validate_log_id
from .storage import ADVANCED, DUPLICATE, FORK, GENESIS, LogStore, Rejected

MAX_BODY = 1 << 20  # 1 MiB is far beyond any checkpoint request
SIGNATURE_SIZE = 64


class Submission:
    """Parsed and shape-validated checkpoint submission."""

    __slots__ = (
        "log_id",
        "tree_size",
        "timestamp_ms",
        "root_hash",
        "public_key",
        "signature",
        "proof",
        "root_hash_hex",
        "public_key_hex",
        "signature_hex",
        "proof_hex",
        "public_key_obj",
    )

    def __init__(self, log_id, obj):
        self.log_id = log_id
        if not isinstance(obj, dict):
            raise Rejected("bad_request", "request body must be a JSON object", 400)

        self.tree_size = _u64(obj.get("tree_size"), "tree_size")
        self.timestamp_ms = _u64(obj.get("timestamp_ms"), "timestamp_ms")
        self.public_key = _b64_field(obj, "public_key", KEY_SIZE)
        self.root_hash = _b64_field(obj, "root_hash", ROOT_SIZE)
        self.signature = _b64_field(obj, "signature", SIGNATURE_SIZE)
        self.proof = _proof_field(obj.get("consistency_proof"))

        self.root_hash_hex = self.root_hash.hex()
        self.public_key_hex = self.public_key.hex()
        self.signature_hex = self.signature.hex()
        self.proof_hex = [p.hex() for p in self.proof]
        try:
            from .ed25519 import PublicKey

            self.public_key_obj = PublicKey(self.public_key)
        except BadSignatureError as exc:
            raise Rejected("invalid_public_key", str(exc), 400)


def _u64(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= U64_MAX):
        raise Rejected("bad_field", "%s must be a uint64 non-negative integer" % name, 400)
    return value


def _b64decode(value, name):
    if not isinstance(value, str):
        raise Rejected("bad_field", "%s must be a base64 string" % name, 400)
    text = value.strip().replace("-", "+").replace("_", "/")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text + padding, validate=True)
    except Exception as exc:
        raise Rejected("bad_field", "%s is not valid base64: %s" % (name, exc), 400)


def _b64_field(obj, name, length):
    raw = _b64decode(obj.get(name), name)
    if len(raw) != length:
        raise Rejected(
            "bad_field",
            "%s must decode to exactly %d bytes, got %d" % (name, length, len(raw)),
            400,
        )
    return raw


def _proof_field(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise Rejected(
            "bad_field",
            "consistency_proof must be an array of at most 64 base64 32-byte hashes",
            400,
        )
    out = []
    for i, node in enumerate(value):
        raw = _b64decode(node, "consistency_proof[%d]" % i)
        if len(raw) != ROOT_SIZE:
            raise Rejected(
                "bad_field",
                "consistency_proof[%d] must be exactly 32 bytes" % i,
                400,
            )
        out.append(raw)
    return out


_PATH_CHECKPOINT = re.compile(r"^/logs/([^/]+)/checkpoints/?$")
_PATH_LOG = re.compile(r"^/logs/([^/]+)/?$")
_PATH_FORKS = re.compile(r"^/logs/([^/]+)/forks/?$")
_PATH_FORK = re.compile(r"^/logs/([^/]+)/forks/([^/]+)/?$")
_PATH_HISTORY = re.compile(r"^/logs/([^/]+)/history/?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "SeabedCheckpoint/1.0"

    # Injected by make_server:
    store = None

    def log_message(self, fmt, *args):  # quiet, structured stderr one-liner
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, status, payload):
        body = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, message, **extra):
        payload = {"error": code, "message": message}
        payload.update(extra)
        self._send_json(status, payload)

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path in ("/healthz", "/health"):
                self._send_json(200, {"status": "ok"})
                return
            m = _PATH_FORK.match(path)
            if m:
                record = self.store.get_fork(m.group(1), m.group(2))
                self._send_json(200, record)
                return
            m = _PATH_FORKS.match(path)
            if m:
                self._send_json(200, {"forks": self.store.list_forks(m.group(1))})
                return
            m = _PATH_HISTORY.match(path)
            if m:
                self._send_json(200, {"history": self.store.history(m.group(1))})
                return
            m = _PATH_LOG.match(path)
            if m:
                self._send_json(200, self.store.get_log(m.group(1)))
                return
            self._error(404, "not_found", "unknown endpoint %r" % path)
        except Rejected as exc:
            self._error(exc.http_status, exc.code, exc.message)

    def do_POST(self):
        path = urlsplit(self.path).path
        m = _PATH_CHECKPOINT.match(path)
        if not m:
            self._error(404, "not_found", "unknown endpoint %r" % path)
            return
        log_id = m.group(1)
        try:
            validate_log_id(log_id)
        except Exception as exc:
            self._error(400, "bad_log_id", str(exc))
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._error(400, "bad_request", "empty request body")
            return
        if length > MAX_BODY:
            self._error(413, "body_too_large", "request body exceeds 1 MiB")
            return
        raw = self.rfile.read(length)

        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._error(400, "bad_json", "request body is not valid JSON: %s" % exc)
            return

        try:
            sub = Submission(log_id, obj)
            if sub.tree_size < 1:
                raise Rejected(
                    "invalid_tree_size", "tree_size must be at least 1", 422
                )
            verdict, body = self.store.submit(sub)
        except Rejected as exc:
            self._error(exc.http_status, exc.code, exc.message)
            return
        except (InvalidProof, BadSignatureError) as exc:
            self._error(422, "invalid_checkpoint", str(exc))
            return

        if verdict == FORK:
            body["verdict"] = verdict
            self._send_json(409, body)
        elif verdict == DUPLICATE:
            body["verdict"] = verdict
            self._send_json(200, body)
        else:
            body["verdict"] = verdict
            self._send_json(201, body)


def make_server(host, port, data_dir):
    store = LogStore(data_dir)

    class _Server(ThreadingHTTPServer):
        request_queue_size = 256  # burst of concurrent submissions
        daemon_threads = True
        allow_reuse_address = True

    handler = Handler
    handler.store = store
    return _Server((host, port), handler)


def main(argv=None):
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    data_dir = os.environ.get("DATA_DIR", "/data")
    httpd = make_server(host, port, data_dir)
    sys.stderr.write(
        "seabed checkpoint log listening on http://%s:%d (data=%s)\n"
        % (host, port, data_dir)
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
