"""KeyGen, encodings, Encaps and Decaps round trips for all eight algorithms."""

import unittest

import util  # noqa: F401  (sets sys.path)

from compfrodo import composite, pkix
from compfrodo.composite import CompositeError

KEYS = {}


def keypair(alg):
    if alg.oid_name not in KEYS:
        KEYS[alg.oid_name] = composite.keygen(alg)
    return KEYS[alg.oid_name]


class RoundTripTest(unittest.TestCase):

    def test_roundtrip(self):
        for alg in composite.ALGORITHMS:
            with self.subTest(alg.oid_name):
                ek, dk = keypair(alg)
                self.assertEqual(composite.public_key_from_private(alg, dk), ek)
                # SubjectPublicKeyInfo and OneAsymmetricKey (both versions) round trips
                self.assertEqual(pkix.decode_spki(pkix.encode_spki(alg, ek)), (alg, ek))
                self.assertEqual(pkix.decode_private_key(pkix.encode_private_key(alg, dk)), (alg, dk, None))
                self.assertEqual(pkix.decode_private_key(pkix.encode_private_key(alg, dk, True)), (alg, dk, ek))

                r = composite.encaps_detailed(alg, ek)
                self.assertEqual(len(r["ct"]), alg.ct_len)
                self.assertEqual(len(r["ss"]), 32)
                d = composite.decaps_detailed(alg, dk, r["ct"])
                for field in ("ss", "frodo_ss", "trad_ss", "trad_ct", "trad_pk", "label"):
                    self.assertEqual(d[field], r[field], field)
                self.assertEqual(r["ss"], composite.combiner(alg, r["frodo_ss"], r["trad_ss"], r["trad_ct"], r["trad_pk"]))

                # two encapsulations differ
                self.assertNotEqual(composite.encaps(alg, ek)[1], r["ss"])

    def test_tampered_ciphertext(self):
        for alg in composite.ALGORITHMS:
            with self.subTest(alg.oid_name):
                ek, dk = keypair(alg)
                ct, ss = composite.encaps(alg, ek)
                # FrodoKEM part: implicit rejection gives a different secret
                bad = bytearray(ct)
                bad[100] ^= 0x01
                self.assertNotEqual(composite.decaps(alg, dk, bytes(bad)), ss)
                # traditional part: RSA-OAEP decryption fails; X25519 / X448 give another secret
                bad = bytearray(ct)
                bad[alg.frodo.ct_len + 1] ^= 0x01
                if alg.trad == "RSA":
                    self.assertRaises(CompositeError, composite.decaps, alg, dk, bytes(bad))
                else:
                    self.assertNotEqual(composite.decaps(alg, dk, bytes(bad)), ss)

    def test_label_binds_algorithm(self):
        labels = [a.label for a in composite.ALGORITHMS]
        self.assertEqual(len(set(labels)), 8)
        self.assertEqual(composite.algorithm("id-FrodoKEM976-RSA3072-SHA3-256").label, b"FrodoKEM976-RSA3072")
        self.assertEqual(composite.algorithm("id-FrodoKEM1344-X448-SHA3-256").label, b"FrodoKEM1344-X448")
        self.assertEqual(composite.algorithm("id-FrodoKEM1344-AES-RSA4096-SHA3-256").label, b"FrodoKEM1344-AES-RSA4096")

    def test_spki_parameters_must_be_absent(self):
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type import univ
        from pyasn1_alt_modules import rfc5280
        alg = composite.algorithm("id-FrodoKEM976-X25519-SHA3-256")
        ek, _ = keypair(alg)
        spki, _ = decoder.decode(pkix.encode_spki(alg, ek), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        spki["algorithm"]["parameters"] = encoder.encode(univ.Null(""))
        self.assertRaises(CompositeError, pkix.decode_spki, encoder.encode(spki))


if __name__ == "__main__":
    unittest.main()
