"""RFC 9162 (formerly RFC 6962) Merkle tree hashing and proofs.

Leaf data is hashed with the 0x00 domain separator, interior nodes with
0x01.  Only consistency proofs are required by the checkpoint protocol
but inclusion proofs are implemented too, because the acceptance suite
exercises both algorithms exhaustively.
"""

import hashlib

__all__ = [
    "leaf_hash",
    "node_hash",
    "tree_head",
    "MerkleTree",
    "verify_consistency",
    "verify_inclusion",
    "InvalidProof",
    "EMPTY_TREE_HASH",
]

EMPTY_TREE_HASH = hashlib.sha256(b"").digest()


class InvalidProof(ValueError):
    """Raised when a Merkle proof fails verification."""


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n):
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1 << (n.bit_length() - 1)
    return k >> 1 if k == n else k


def tree_head(leaves):
    """MTH(D) computed with the RFC 9162 section 2.1.1 stack algorithm."""
    stack = []  # (node hash, subtree height)
    for lh in leaves:
        node, height = lh, 0
        while stack and stack[-1][1] == height:
            left, _ = stack.pop()
            node = node_hash(left, node)
            height += 1
        stack.append((node, height))
    if not stack:
        return EMPTY_TREE_HASH
    root = stack.pop()[0]
    while stack:
        left, _ = stack.pop()
        root = node_hash(left, root)
    return root


class MerkleTree:
    """A leaf-hash indexed Merkle tree that can generate proofs."""

    def __init__(self, leaf_hashes):
        self.h = list(leaf_hashes)
        self._memo = {}

    @property
    def size(self):
        return len(self.h)

    def root(self):
        return self._mth(0, len(self.h))

    def _mth(self, start, n):
        if n == 0:
            return EMPTY_TREE_HASH
        if n == 1:
            return self.h[start]
        key = (start, n)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        k = _split(n)
        value = node_hash(self._mth(start, k), self._mth(start + k, n - k))
        self._memo[key] = value
        return value

    def consistency_proof(self, m):
        """PROOF(m, D_n) for 0 < m < n (RFC 9162 section 2.1.4.1)."""
        n = len(self.h)
        if not (0 < m < n):
            raise ValueError("consistency proof requires 0 < m < n")
        out = []

        def sub(m_, n_, start, complete):
            if m_ == n_:
                if not complete:
                    out.append(self._mth(start, m_))
                return
            k = _split(n_)
            if m_ <= k:
                sub(m_, k, start, complete)
                out.append(self._mth(start + k, n_ - k))
            else:
                sub(m_ - k, n_ - k, start + k, False)
                out.append(self._mth(start, k))

        sub(m, n, 0, True)
        return out

    def inclusion_proof(self, index):
        """Merkle audit path for leaf ``index`` (RFC 9162 section 2.1.2)."""
        n = len(self.h)
        if not (0 <= index < n):
            raise ValueError("leaf index out of range")
        out = []

        def path(start, count, idx):
            if count == 1:
                return
            k = _split(count)
            if idx < k:
                path(start, k, idx)
                out.append(self._mth(start + k, count - k))
            else:
                path(start + k, count - k, idx - k)
                out.append(self._mth(start, k))

        path(0, n, index)
        return out


def _is_power_of_two(x):
    return x > 0 and (x & (x - 1)) == 0


def verify_consistency(first, second, first_hash, second_hash, proof):
    """Verify a consistency proof per RFC 9162 section 2.1.4.2.

    Raises :class:`InvalidProof` if anything is wrong; returns True on
    success.  The edge case ``first == 0`` is trivially consistent (an
    empty log is a prefix of every tree) and requires an empty proof.
    """
    if first < 0 or second < 0 or first > second:
        raise InvalidProof("inconsistent tree sizes")
    if first == second:
        if proof:
            raise InvalidProof("proof must be empty for equal sizes")
        if first != 0 and first_hash != second_hash:
            raise InvalidProof("equal-size heads must share a root")
        return True
    if first == 0:
        if proof:
            raise InvalidProof("proof must be empty when the old tree is empty")
        return True
    if not proof:
        raise InvalidProof("empty consistency path")
    if any(not isinstance(h, (bytes, bytearray)) or len(h) != 32 for h in proof):
        raise InvalidProof("every proof node must be exactly 32 bytes")

    path = [bytes(h) for h in proof]
    if _is_power_of_two(first):
        # RFC 9162 2.1.4.2 step 2: unconditionally prepend the old head.
        # The generator (section 2.1.4.1) omits it; the final fr check
        # below is what binds the proof to the supplied old head.
        path.insert(0, first_hash)

    fn, sn = first - 1, second - 1
    while fn & 1:  # step 4: shift until LSB(fn) is clear
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:  # step 6a
            raise InvalidProof("proof longer than tree structure allows")
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not (fn & 1):  # step 6.b.iii
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    if fr != first_hash:
        raise InvalidProof("proof does not recompute the old tree head")
    if sr != second_hash:
        raise InvalidProof("proof does not recompute the new tree head")
    if sn != 0:
        raise InvalidProof("proof is truncated")
    return True


def verify_inclusion(index, size, leaf, root, proof):
    """Verify a Merkle inclusion proof per RFC 9162 section 2.1.3.2."""
    if not (0 <= index < size) or size == 0:
        raise InvalidProof("leaf index out of range")
    if any(not isinstance(h, (bytes, bytearray)) or len(h) != 32 for h in proof):
        raise InvalidProof("every proof node must be exactly 32 bytes")

    fn, sn = index, size - 1
    r = leaf
    for c in (bytes(h) for h in proof):
        if sn == 0:
            raise InvalidProof("proof longer than tree structure allows")
        if (fn & 1) or (fn == sn):
            r = node_hash(c, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, c)
        fn >>= 1
        sn >>= 1
    if r != root:
        raise InvalidProof("proof does not recompute the tree root")
    if sn != 0:
        raise InvalidProof("proof is truncated")
    return True
