"""Every test case in ../vectors/testvectors.json and combiner-intermediates.txt, byte for byte."""

import unittest

from pyasn1.codec.der import encoder as der_encoder

import util

from compfrodo import composite, pkix
from compfrodo.composite import CompositeError

VECTORS = util.load_testvectors()
INTERMEDIATES = util.load_intermediates()
CA = pkix.Certificate(util.b64(VECTORS["cacert"]))


class TestVectors(unittest.TestCase):

    def test_all_eight_present(self):
        self.assertEqual(sorted(t["tcId"] for t in VECTORS["tests"]), sorted(a.oid_name for a in composite.ALGORITHMS))
        self.assertEqual(sorted(INTERMEDIATES), sorted(a.oid_name for a in composite.ALGORITHMS))

    def test_decaps_reproduces_k_and_intermediates(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                alg = composite.algorithm(t["tcId"])
                ek, dk, c, k = util.b64(t["ek"]), util.b64(t["dk"]), util.b64(t["c"]), util.b64(t["k"])
                d = composite.decaps_detailed(alg, dk, c)
                self.assertEqual(d["ss"], k)
                want = INTERMEDIATES[t["tcId"]]
                for field in ("label", "frodo_ss", "trad_ss", "trad_ct", "trad_pk", "ss"):
                    self.assertEqual(d[field], want[field], field)
                self.assertEqual(len(d["frodo_ss"] + d["trad_ss"] + d["trad_ct"] + d["trad_pk"] + d["label"]),
                                 want["input_length"])
                # the same with ek supplied as the source of trad_pk
                self.assertEqual(composite.decaps(alg, dk, c, ek), k)

    def test_public_key_from_private_key(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                alg = composite.algorithm(t["tcId"])
                self.assertEqual(composite.public_key_from_private(alg, util.b64(t["dk"])), util.b64(t["ek"]))

    def test_key_and_ciphertext_lengths(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                alg = composite.algorithm(t["tcId"])
                ek, dk, c = util.b64(t["ek"]), util.b64(t["dk"]), util.b64(t["c"])
                self.assertEqual(len(c), alg.ct_len)
                frodo_pk, trad_pk = composite.split_public_key(alg, ek)
                self.assertEqual(len(frodo_pk), alg.frodo.pk_len)
                if alg.trad != "RSA":
                    self.assertEqual(len(trad_pk), alg.trad_ct_len)
                frodo_sk, trad_sk = composite.split_private_key(alg, dk)
                self.assertEqual(len(frodo_sk), alg.frodo.sk_len)

    def test_private_key_info(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                alg, dk, ek = pkix.decode_private_key(util.b64(t["dk_pkcs8"]))
                self.assertIs(alg, composite.algorithm(t["tcId"]))
                self.assertEqual(dk, util.b64(t["dk"]))
                self.assertIsNone(ek)
                # re-encoding gives the same bytes
                self.assertEqual(pkix.encode_private_key(alg, dk), util.b64(t["dk_pkcs8"]))
                # and the version 2 form with publicKey round-trips
                alg2, dk2, ek2 = pkix.decode_private_key(pkix.encode_private_key(alg, dk, include_public_key=True))
                self.assertEqual((alg2, dk2, ek2), (alg, dk, util.b64(t["ek"])))

    def test_certificates(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                cert = pkix.Certificate(util.b64(t["x5c"]))
                alg, ek = cert.composite_public_key()
                self.assertIs(alg, composite.algorithm(t["tcId"]))
                self.assertEqual(ek, util.b64(t["ek"]))
                self.assertEqual(cert.key_usage(), set(["keyEncipherment"]))
                self.assertEqual(cert.issuer_der, CA.subject_der)
                self.assertEqual(pkix.encode_spki(alg, ek), der_encoder.encode(cert.spki))

    def test_certificate_signatures(self):
        verified = [pkix.Certificate(util.b64(t["x5c"])).verify_signature(CA) for t in VECTORS["tests"]]
        if not any(verified):
            self.skipTest("the installed cryptography package cannot verify ML-DSA-65")
        self.assertTrue(all(verified))
        self.assertTrue(CA.verify_signature(CA))
        # negative control: the last byte of a certificate is part of its signature
        der = bytearray(util.b64(VECTORS["tests"][0]["x5c"]))
        der[-1] ^= 0x01
        with self.assertRaises(Exception):
            pkix.Certificate(bytes(der)).verify_signature(CA)

    def test_ciphertext_length_enforced(self):
        for t in VECTORS["tests"]:
            with self.subTest(t["tcId"]):
                alg = composite.algorithm(t["tcId"])
                dk, c = util.b64(t["dk"]), util.b64(t["c"])
                for bad in (c[:-1], c + b"\x00", c[:alg.frodo.ct_len]):
                    with self.assertRaises(CompositeError) as cm:
                        composite.decaps(alg, dk, bad)
                    self.assertIn("ciphertext must be %d bytes" % alg.ct_len, str(cm.exception))

    def test_rsa_modulus_size_enforced(self):
        by_id = dict((t["tcId"], t) for t in VECTORS["tests"])
        # put each RSA private key behind the other RSA size's FrodoKEM private key
        for target, donor in (("id-FrodoKEM976-RSA3072-SHA3-256", "id-FrodoKEM1344-RSA4096-SHA3-256"),
                              ("id-FrodoKEM1344-RSA4096-SHA3-256", "id-FrodoKEM976-RSA3072-SHA3-256")):
            with self.subTest(target):
                alg = composite.algorithm(target)
                donor_alg = composite.algorithm(donor)
                frodo_sk, _ = composite.split_private_key(alg, util.b64(by_id[target]["dk"]))
                _, other_rsa = composite.split_private_key(donor_alg, util.b64(by_id[donor]["dk"]))
                dk = frodo_sk + other_rsa
                c = util.b64(by_id[target]["c"])
                with self.assertRaises(CompositeError) as cm:
                    composite.decaps(alg, dk, c)
                self.assertIn("RSA modulus", str(cm.exception))
                frodo_pk, _ = composite.split_public_key(alg, util.b64(by_id[target]["ek"]))
                _, other_pk = composite.split_public_key(donor_alg, util.b64(by_id[donor]["ek"]))
                self.assertRaises(CompositeError, composite.encaps, alg, frodo_pk + other_pk)

    def test_mismatched_public_key_rejected(self):
        t = VECTORS["tests"][1]
        alg = composite.algorithm(t["tcId"])
        ek = bytearray(util.b64(t["ek"]))
        ek[-1] ^= 0x01
        self.assertRaises(CompositeError, composite.decaps, alg, util.b64(t["dk"]), util.b64(t["c"]), bytes(ek))

    def test_wrong_algorithm_rejected(self):
        # an X25519 key under the X448 OID, and the SHAKE key under the AES OID decapsulates
        # to a different secret (implicit rejection), never to k
        by_id = dict((t["tcId"], t) for t in VECTORS["tests"])
        t = by_id["id-FrodoKEM976-X25519-SHA3-256"]
        dk, c, k = util.b64(t["dk"]), util.b64(t["c"]), util.b64(t["k"])
        self.assertRaises(CompositeError, composite.decaps, composite.algorithm("id-FrodoKEM1344-X448-SHA3-256"), dk, c)
        self.assertNotEqual(composite.decaps(composite.algorithm("id-FrodoKEM976-AES-X25519-SHA3-256"), dk, c), k)


if __name__ == "__main__":
    unittest.main()
