"""Pure-Python (stdlib only) Ed25519 signing and verification.

Reference: RFC 8032 ("Edwards-Curve Digital Signature Algorithm (EdDSA)").

Point arithmetic uses extended twisted-Edwards coordinates (X, Y, Z, T)
so that scalar multiplication needs no modular inversion per ladder
step; only one inversion is taken when a point is compressed.  The code
is short enough to audit and is exercised against the RFC 8032 test
vectors (see verify/acceptance.py).
"""

import hashlib
import secrets

__all__ = ["PublicKey", "PrivateKey", "BadSignatureError", "KEY_SIZE", "SIGNATURE_SIZE"]

KEY_SIZE = 32
SIGNATURE_SIZE = 64

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
d2 = (2 * d) % p
I = pow(2, (p - 1) // 4, p)


def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


_by = 4 * pow(5, p - 2, p)
_bx = _xrecover(_by)
IDENTITY = (0, 1, 1, 0)
B = (_bx % p, _by % p, 1, (_bx * _by) % p)


def _xadd(P, Q):
    """Unified addition on the -x^2+y^2=1+d x^2y^2 twisted Edwards curve."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % p
    B = ((y1 + x1) * (y2 + x2)) % p
    C = (d2 * t1 * t2) % p
    D = (2 * z1 * z2) % p
    E = (B - A) % p
    F = (D - C) % p
    G = (D + C) % p
    H = (B + A) % p
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _xdouble(P):
    x1, y1, z1, _ = P
    A = x1 * x1 % p
    B = y1 * y1 % p
    C = 2 * z1 * z1 % p
    H = (A + B) % p
    E = (H - (x1 + y1) * (x1 + y1)) % p
    G = (A - B) % p
    F = (C + G) % p
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _xscalar(P, e):
    Q = IDENTITY
    while e:
        if e & 1:
            Q = _xadd(Q, P)
        P = _xdouble(P)
        e >>= 1
    return Q


def _compress(P):
    x, y, z, _ = P
    zi = pow(z, p - 2, p)
    x = x * zi % p
    y = y * zi % p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _decompress(s):
    if len(s) != 32:
        raise BadSignatureError("point encoding must be 32 bytes")
    bits = int.from_bytes(s, "little")
    x_sign = bits >> 255
    y = bits & ((1 << 255) - 1)
    if y >= p:
        raise BadSignatureError("point coordinate out of range")
    x = _xrecover(y)
    if (x & 1) != x_sign:
        x = p - x
    if (-x * x + y * y - 1 - d * x * x * y * y) % p != 0:
        raise BadSignatureError("point not on curve")
    return (x, y, 1, x * y % p)


class BadSignatureError(ValueError):
    """Raised when an Ed25519 signature fails verification."""


class PublicKey:
    __slots__ = ("raw", "A")

    def __init__(self, raw):
        if isinstance(raw, str):
            raw = bytes.fromhex(raw)
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != KEY_SIZE:
            raise BadSignatureError("Ed25519 public key must be exactly 32 bytes")
        self.raw = bytes(raw)
        self.A = _decompress(self.raw)

    def verify(self, message, signature):
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_SIZE:
            raise BadSignatureError("signature must be exactly 64 bytes")
        R = _decompress(bytes(signature[:32]))
        S = int.from_bytes(signature[32:], "little")
        if S >= L:
            raise BadSignatureError("signature scalar S out of range")
        k = _hint(bytes(signature[:32]) + self.raw + message) % L
        if _compress(_xscalar(B, S)) != _compress(_xadd(R, _xscalar(self.A, k))):
            raise BadSignatureError("signature verification failed")
        return True

    def __bytes__(self):
        return self.raw

    def __eq__(self, other):
        return isinstance(other, PublicKey) and self.raw == other.raw

    def __hash__(self):
        return hash(self.raw)


class PrivateKey:
    __slots__ = ("raw", "a", "public")

    def __init__(self, seed):
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        self.raw = bytes(seed)
        h = hashlib.sha512(self.raw).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        self.a = a
        self.public = PublicKey(_compress(_xscalar(B, a)))

    @classmethod
    def generate(cls):
        return cls(secrets.token_bytes(32))

    def sign(self, message):
        h = hashlib.sha512(self.raw).digest()
        r = _hint(h[32:] + message) % L
        Rb = _compress(_xscalar(B, r))
        k = _hint(Rb + self.public.raw + message) % L
        S = (r + k * self.a) % L
        return Rb + S.to_bytes(32, "little")
