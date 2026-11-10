"""The AES-256 CTR_DRBG (no derivation function, no prediction resistance) that the
NIST PQC KAT generators use as randombytes(), seeded from a 48-byte value.

randombytes_init(entropy, None, 256) and randombytes(n) as in the NIST rng.c, so a
.rsp record's seed reproduces the randomness its keygen and encaps calls consumed."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class NistDrbg(object):

    def __init__(self, seed):
        if len(seed) != 48:
            raise ValueError("seed must be 48 bytes")
        self._key = bytes(32)
        self._v = bytes(16)
        self._update(seed)

    def _block(self):
        v = (int.from_bytes(self._v, "big") + 1) % (1 << 128)
        self._v = v.to_bytes(16, "big")
        enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        return enc.update(self._v) + enc.finalize()

    def _update(self, provided):
        temp = b"".join(self._block() for _ in range(3))
        if provided is not None:
            temp = bytes(a ^ b for a, b in zip(temp, provided))
        self._key, self._v = temp[:32], temp[32:]

    def randombytes(self, n):
        out = b""
        while len(out) < n:
            out += self._block()
        self._update(None)
        return out[:n]
