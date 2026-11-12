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

    def test_keygen_draws_from_randombytes(self):
        # the FrodoKEM seeds and an X25519 / X448 private key, in that order
        for name in ("id-FrodoKEM976-AES-X25519-SHA3-256", "id-FrodoKEM1344-SHAKE-X448-SHA3-256"):
            with self.subTest(name):
                alg = composite.algorithm(name)
                calls = []

                def rnd(n):
                    calls.append(n)
                    return bytes((len(calls) + i) % 256 for i in range(n))
                ek, dk = composite.keygen(alg, rnd)
                p = alg.frodo
                self.assertEqual(calls, [p.len_sec + p.len_SE + p.len_A, alg.trad_ct_len])
                # trad_sk is the bytes of the second call, raw
                self.assertEqual(dk[p.sk_len:], bytes((2 + i) % 256 for i in range(alg.trad_ct_len)))
                self.assertEqual(composite.public_key_from_private(alg, dk), ek)

    def test_names_labels_and_oids(self):
        # draft-song-lamps-pq-composite-frodokem-02 section 5.1, TBD1 to TBD8 in order
        table = (("id-FrodoKEM976-SHAKE-RSA3072-SHA3-256", b"FrodoKEM976-SHAKE-RSA3072", "FrodoKEM-976-SHAKE", "RSA"),
                 ("id-FrodoKEM976-SHAKE-X25519-SHA3-256", b"FrodoKEM976-SHAKE-X25519", "FrodoKEM-976-SHAKE", "X25519"),
                 ("id-FrodoKEM1344-SHAKE-RSA4096-SHA3-256", b"FrodoKEM1344-SHAKE-RSA4096", "FrodoKEM-1344-SHAKE", "RSA"),
                 ("id-FrodoKEM1344-SHAKE-X448-SHA3-256", b"FrodoKEM1344-SHAKE-X448", "FrodoKEM-1344-SHAKE", "X448"),
                 ("id-FrodoKEM976-AES-RSA3072-SHA3-256", b"FrodoKEM976-AES-RSA3072", "FrodoKEM-976-AES", "RSA"),
                 ("id-FrodoKEM976-AES-X25519-SHA3-256", b"FrodoKEM976-AES-X25519", "FrodoKEM-976-AES", "X25519"),
                 ("id-FrodoKEM1344-AES-RSA4096-SHA3-256", b"FrodoKEM1344-AES-RSA4096", "FrodoKEM-1344-AES", "RSA"),
                 ("id-FrodoKEM1344-AES-X448-SHA3-256", b"FrodoKEM1344-AES-X448", "FrodoKEM-1344-AES", "X448"))
        got = [(a.oid_name, a.label, a.frodo.name, a.trad) for a in composite.ALGORITHMS]
        self.assertEqual(got, list(table))
        self.assertEqual([a.oid for a in composite.ALGORITHMS],
                         ["1.3.6.1.4.1.22554.5.12.%d" % i for i in range(1, 9)])
        self.assertEqual(len(set(a.label for a in composite.ALGORITHMS)), 8)

    def test_spki_parameters_must_be_absent(self):
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type import univ
        from pyasn1_alt_modules import rfc5280
        alg = composite.algorithm("id-FrodoKEM976-SHAKE-X25519-SHA3-256")
        ek, _ = keypair(alg)
        spki, _ = decoder.decode(pkix.encode_spki(alg, ek), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        spki["algorithm"]["parameters"] = encoder.encode(univ.Null(""))
        self.assertRaises(CompositeError, pkix.decode_spki, encoder.encode(spki))


if __name__ == "__main__":
    unittest.main()
