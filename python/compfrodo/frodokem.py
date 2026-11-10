"""FrodoKEM, standard (salted) variant, as specified in draft-longa-cfrg-frodokem-03.

Only the parameter sets the composite drafts use are defined: FrodoKEM-976 and
FrodoKEM-1344, each with the AES128 and the SHAKE128 generator for the matrix A.
The code follows the section structure of the specification; section numbers in
the comments refer to draft-longa-cfrg-frodokem-03.

This is an interoperability-testing implementation. It is not constant time and
makes no attempt to resist side channels.
"""

import hashlib
import hmac
import os
import struct
from itertools import repeat
from operator import add, mul

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class FrodoParams(object):
    """One FrodoKEM parameter set (Section 9.1, Tables 1, 2 and 5)."""

    def __init__(self, name, n, B, len_sec_bits, t_chi, prg):
        self.name = name
        self.n = n
        self.nbar = 8                       # nHat
        self.D = 16                         # q = 2^D; D = 16 for both 976 and 1344
        self.q = 1 << self.D
        self.B = B
        self.len_A = 16                     # lenA = 128 bits
        self.len_sec = len_sec_bits // 8    # lensec
        self.len_SE = 2 * self.len_sec      # lenSE, standard variant (Table 2)
        self.len_salt = 2 * self.len_sec    # lensalt, standard variant (Table 2)
        self.t_chi = tuple(t_chi)           # T_X(0) .. T_X(d)
        self.d = len(t_chi) - 1
        self.prg = prg                      # "AES" or "SHAKE": the generator for A (Section 6.7)
        # Table 1: SHAKE256 for hashing at the 976 and 1344 levels
        self._shake = hashlib.shake_256

        nbar = self.nbar
        self.pk_len = self.len_A + self.D * n * nbar // 8
        self.sk_len = self.len_sec + self.pk_len + 2 * n * nbar + self.len_sec
        self.c1_len = self.D * nbar * n // 8
        self.c2_len = self.D * nbar * nbar // 8
        self.ct_len = self.c1_len + self.c2_len + self.len_salt
        self.ss_len = self.len_sec

    def shake(self, data, out_len):
        return self._shake(data).digest(out_len)

    def __repr__(self):
        return self.name


_T_CHI_976 = (5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767)
_T_CHI_1344 = (9142, 23462, 30338, 32361, 32725, 32765, 32767)

FRODOKEM_976_AES = FrodoParams("FrodoKEM-976-AES", 976, 3, 192, _T_CHI_976, "AES")
FRODOKEM_976_SHAKE = FrodoParams("FrodoKEM-976-SHAKE", 976, 3, 192, _T_CHI_976, "SHAKE")
FRODOKEM_1344_AES = FrodoParams("FrodoKEM-1344-AES", 1344, 4, 256, _T_CHI_1344, "AES")
FRODOKEM_1344_SHAKE = FrodoParams("FrodoKEM-1344-SHAKE", 1344, 4, 256, _T_CHI_1344, "SHAKE")

PARAMETER_SETS = (FRODOKEM_976_AES, FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE)


# ---------------------------------------------------------------------------
# Supporting functions (Section 6)
# ---------------------------------------------------------------------------

def _u16_le(data, count):
    """Parse count 16-bit little-endian unsigned integers (Section 6.1)."""
    return list(struct.unpack("<%dH" % count, data))


def encode(p, bits):
    """Encode(b), Section 6.3: a lensec-bit string to an nbar x nbar matrix mod q.

    Bits are taken LSB-first from the byte string (Section 6.1); each B-bit chunk
    val becomes the entry val * q / 2^B, filling the matrix row by row."""
    v = int.from_bytes(bits, "little")
    mask = (1 << p.B) - 1
    shift = p.D - p.B
    flat = [((v >> (idx * p.B)) & mask) << shift for idx in range(p.nbar * p.nbar)]
    return [flat[i * p.nbar:(i + 1) * p.nbar] for i in range(p.nbar)]


def decode(p, m):
    """Decode(C), Section 6.3: dc(c) = round(c * 2^B / q) mod 2^B, packed LSB-first."""
    mask = (1 << p.B) - 1
    shift = p.D - p.B
    half = 1 << (shift - 1)
    v = 0
    idx = 0
    for row in m:
        for c in row:
            v |= (((c + half) >> shift) & mask) << (idx * p.B)
            idx += 1
    return v.to_bytes(p.nbar * p.nbar * p.B // 8, "little")


def pack(p, m):
    """Pack(C, n1, n2), Section 6.4. With D = 16 every coefficient is written as a
    16-bit big-endian value (bits taken MSB-first, Section 6.2), row by row."""
    flat = [x & (p.q - 1) for row in m for x in row]
    return struct.pack(">%dH" % len(flat), *flat)


def unpack(p, data, n1, n2):
    """Unpack(o, n1, n2), Section 6.4 (D = 16)."""
    if len(data) != 2 * n1 * n2:
        raise ValueError("unpack: wrong input length")
    flat = struct.unpack(">%dH" % (n1 * n2), data)
    return [list(flat[i * n2:(i + 1) * n2]) for i in range(n1)]


def sample(p, r):
    """Sample(r), Section 6.5: inversion sampling from T_X; T_X(d) is never used."""
    t = r >> 1
    e = 0
    for i in range(p.d):
        if t > p.t_chi[i]:
            e += 1
    return -e if (r & 1) else e


def sample_matrix(p, rs, n1, n2):
    """SampleMatrix(r, n1, n2), Section 6.6: row by row from E[0,0]."""
    if len(rs) != n1 * n2:
        raise ValueError("sample_matrix: wrong number of samples")
    flat = [sample(p, r) for r in rs]
    return [flat[i * n2:(i + 1) * n2] for i in range(n1)]


def gen_rows(p, seed_a):
    """Gen(seedA), Section 6.7: yields the rows A[i, 0..n-1] for i = 0 .. n-1."""
    n = p.n
    if p.prg == "AES":
        # Section 6.7.1: block i || j || 0 ... 0, each element 2 bytes little-endian
        enc = Cipher(algorithms.AES(seed_a), modes.ECB()).encryptor()
        for i in range(n):
            blocks = b"".join(struct.pack("<HH12x", i, j) for j in range(0, n, 8))
            # q = 2^16, so "mod q" leaves each 16-bit value unchanged
            yield _u16_le(enc.update(blocks), n)
    elif p.prg == "SHAKE":
        # Section 6.7.2: SHAKE128(i || seedA, 16 * n) per row, i as 2 bytes little-endian
        for i in range(n):
            yield _u16_le(hashlib.shake_128(struct.pack("<H", i) + seed_a).digest(2 * n), n)
    else:
        raise ValueError("unknown PRG " + repr(p.prg))


def _dot(x, y):
    return sum(map(mul, x, y))


# ---------------------------------------------------------------------------
# FrodoKEM (Section 7)
# ---------------------------------------------------------------------------

def keygen_internal(p, s, seed_se, z):
    """KeyGenInternal(s, seedSE, z), Section 7.1.1. Returns (pk, sk)."""
    if len(s) != p.len_sec or len(seed_se) != p.len_SE or len(z) != p.len_A:
        raise ValueError("keygen_internal: wrong seed length")
    n, nbar, q = p.n, p.nbar, p.q
    seed_a = p.shake(z, p.len_A)
    r = _u16_le(p.shake(b"\x5f" + seed_se, 4 * n * nbar), 2 * n * nbar)
    st = sample_matrix(p, r[:n * nbar], nbar, n)          # S^T, nbar x n
    e = sample_matrix(p, r[n * nbar:], n, nbar)           # E, n x nbar
    # B = A * S + E, computed one row of A at a time: B[i, j] = A[i, .] . S^T[j, .] + E[i, j]
    bmat = []
    for i, a_row in enumerate(gen_rows(p, seed_a)):
        bmat.append([(_dot(a_row, st[j]) + e[i][j]) % q for j in range(nbar)])
    b = pack(p, bmat)
    pkh = p.shake(seed_a + b, p.len_sec)
    pk = seed_a + b
    # S^T as signed 16-bit little-endian values, row by row (end of Section 7.1.1)
    st_bytes = struct.pack("<%dh" % (n * nbar), *[x for row in st for x in row])
    sk = s + pk + st_bytes + pkh
    return pk, sk


def keygen(p, randombytes=os.urandom):
    """KeyGen(), Section 7.1. s, seedSE and z are drawn in that order in one call, the
    order the FrodoKEM KAT files use."""
    seeds = randombytes(p.len_sec + p.len_SE + p.len_A)
    s = seeds[:p.len_sec]
    seed_se = seeds[p.len_sec:p.len_sec + p.len_SE]
    z = seeds[p.len_sec + p.len_SE:]
    return keygen_internal(p, s, seed_se, z)


def _encrypt(p, pk, u, salt, pkh):
    """The common part of Encaps (Section 7.2) and Decaps (Section 7.3): returns
    (c1, c2, k) for the message u."""
    n, nbar, q = p.n, p.nbar, p.q
    seed_a = pk[:p.len_A]
    b = pk[p.len_A:]
    se_k = p.shake(pkh + u + salt, p.len_SE + p.len_sec)
    seed_se, k = se_k[:p.len_SE], se_k[p.len_SE:]
    r = _u16_le(p.shake(b"\x96" + seed_se, 2 * (2 * n * nbar + nbar * nbar)), 2 * n * nbar + nbar * nbar)
    sp = sample_matrix(p, r[:n * nbar], nbar, n)                      # S', nbar x n
    ep = sample_matrix(p, r[n * nbar:2 * n * nbar], nbar, n)          # E', nbar x n
    epp = sample_matrix(p, r[2 * n * nbar:], nbar, nbar)              # E'', nbar x nbar
    # B' = S' * A + E': accumulate S'[i, k] * A[k, .] one row of A at a time
    acc = [list(row) for row in ep]
    for kk, a_row in enumerate(gen_rows(p, seed_a)):
        for i in range(nbar):
            s_ik = sp[i][kk]
            if s_ik:
                acc[i] = list(map(add, acc[i], map(mul, a_row, repeat(s_ik))))
    bp = [[x % q for x in row] for row in acc]
    c1 = pack(p, bp)
    # V = S' * B + E''; C = V + Encode(u)
    bmat = unpack(p, b, n, nbar)
    bt = [list(col) for col in zip(*bmat)]                            # B^T, nbar x n
    mu = encode(p, u)
    cmat = [[(_dot(sp[i], bt[j]) + epp[i][j] + mu[i][j]) % q for j in range(nbar)] for i in range(nbar)]
    c2 = pack(p, cmat)
    return c1, c2, k


def encaps(p, pk, randombytes=os.urandom):
    """Encaps(pk), Section 7.2. Returns (ct, ss). u and salt are drawn in that order
    in one call, the order the FrodoKEM KAT files use."""
    if len(pk) != p.pk_len:
        raise ValueError("encaps: public key must be %d bytes" % p.pk_len)
    rnd = randombytes(p.len_sec + p.len_salt)
    u, salt = rnd[:p.len_sec], rnd[p.len_sec:]
    pkh = p.shake(pk, p.len_sec)
    c1, c2, k = _encrypt(p, pk, u, salt, pkh)
    ss = p.shake(c1 + c2 + salt + k, p.len_sec)
    return c1 + c2 + salt, ss


def decaps(p, sk, ct):
    """Decaps(sk, ct), Section 7.3. Returns ss. Inputs of the wrong length are
    rejected with ValueError."""
    if len(sk) != p.sk_len:
        raise ValueError("decaps: private key must be %d bytes" % p.sk_len)
    if len(ct) != p.ct_len:
        raise ValueError("decaps: ciphertext must be %d bytes" % p.ct_len)
    n, nbar, q = p.n, p.nbar, p.q
    s = sk[:p.len_sec]
    pk = sk[p.len_sec:p.len_sec + p.pk_len]
    off = p.len_sec + p.pk_len
    st_flat = struct.unpack("<%dh" % (n * nbar), sk[off:off + 2 * n * nbar])
    st = [list(st_flat[j * n:(j + 1) * n]) for j in range(nbar)]     # S^T, nbar x n
    pkh = sk[off + 2 * n * nbar:]

    c1 = ct[:p.c1_len]
    c2 = ct[p.c1_len:p.c1_len + p.c2_len]
    salt = ct[p.c1_len + p.c2_len:]
    bp = unpack(p, c1, nbar, n)
    cmat = unpack(p, c2, nbar, nbar)
    # M = C - B' * S, where (B' * S)[i, j] = B'[i, .] . S^T[j, .]
    m = [[(cmat[i][j] - _dot(bp[i], st[j])) % q for j in range(nbar)] for i in range(nbar)]
    u_prime = decode(p, m)
    c1_prime, c2_prime, k_prime = _encrypt(p, pk, u_prime, salt, pkh)
    # B' == B'' and C == C', compared through their packed encodings
    ok = hmac.compare_digest(c1 + c2, c1_prime + c2_prime)
    k_hat = k_prime if ok else s
    return p.shake(c1 + c2 + salt + k_hat, p.len_sec)


def public_key_from_private(p, sk):
    """The public key is embedded in the expanded private key s || pk || S^T || pkh."""
    if len(sk) != p.sk_len:
        raise ValueError("private key must be %d bytes" % p.sk_len)
    return sk[p.len_sec:p.len_sec + p.pk_len]
