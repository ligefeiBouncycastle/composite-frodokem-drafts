"""FrodoKEM against the FrodoKEM team's known-answer tests, plus length and rejection checks."""

import unittest

import util  # noqa: F401  (sets sys.path)
from nist_drbg import NistDrbg

from compfrodo import frodokem as fk

KATS = {
    "PQCkemKAT_31296-count0.rsp": fk.FRODOKEM_976_AES,
    "PQCkemKAT_31296_shake-count0.rsp": fk.FRODOKEM_976_SHAKE,
    "PQCkemKAT_43088-count0.rsp": fk.FRODOKEM_1344_AES,
    "PQCkemKAT_43088_shake-count0.rsp": fk.FRODOKEM_1344_SHAKE,
}


class FrodoKEMKatTest(unittest.TestCase):

    def test_sizes(self):
        # draft-longa-cfrg-frodokem-03 Table 6, and Table 1 of the X.509 draft
        for p, sizes in ((fk.FRODOKEM_976_AES, (15632, 31296, 15792, 24)),
                         (fk.FRODOKEM_976_SHAKE, (15632, 31296, 15792, 24)),
                         (fk.FRODOKEM_1344_AES, (21520, 43088, 21696, 32)),
                         (fk.FRODOKEM_1344_SHAKE, (21520, 43088, 21696, 32))):
            self.assertEqual((p.pk_len, p.sk_len, p.ct_len, p.ss_len), sizes, p.name)

    def test_kat_count0(self):
        for filename, p in sorted(KATS.items()):
            with self.subTest(p.name):
                name, rec = util.load_kat(filename)
                self.assertEqual(name, p.name)
                drbg = NistDrbg(bytes.fromhex(rec["seed"]))
                pk, sk = fk.keygen(p, drbg.randombytes)
                self.assertEqual(pk.hex().upper(), rec["pk"])
                self.assertEqual(sk.hex().upper(), rec["sk"])
                ct, ss = fk.encaps(p, pk, drbg.randombytes)
                self.assertEqual(ct.hex().upper(), rec["ct"])
                self.assertEqual(ss.hex().upper(), rec["ss"])
                self.assertEqual(fk.decaps(p, sk, ct).hex().upper(), rec["ss"])

    def test_wrong_lengths_rejected(self):
        p = fk.FRODOKEM_976_SHAKE
        name, rec = util.load_kat("PQCkemKAT_31296_shake-count0.rsp")
        pk, sk, ct = bytes.fromhex(rec["pk"]), bytes.fromhex(rec["sk"]), bytes.fromhex(rec["ct"])
        for bad_ct in (ct[:-1], ct + b"\x00"):
            self.assertRaises(ValueError, fk.decaps, p, sk, bad_ct)
        for bad_sk in (sk[:-1], sk + b"\x00"):
            self.assertRaises(ValueError, fk.decaps, p, bad_sk, ct)
        for bad_pk in (pk[:-1], pk + b"\x00"):
            self.assertRaises(ValueError, fk.encaps, p, bad_pk)

    def test_implicit_rejection(self):
        # A modified ciphertext decapsulates to SHAKE(c1 || c2 || salt || s) (Section 7.3)
        for filename, p in sorted(KATS.items()):
            with self.subTest(p.name):
                name, rec = util.load_kat(filename)
                sk, ct = bytes.fromhex(rec["sk"]), bytearray.fromhex(rec["ct"])
                ct[5] ^= 0x01
                ct = bytes(ct)
                expected = p.shake(ct + sk[:p.len_sec], p.len_sec)
                self.assertEqual(fk.decaps(p, sk, ct), expected)


if __name__ == "__main__":
    unittest.main()
