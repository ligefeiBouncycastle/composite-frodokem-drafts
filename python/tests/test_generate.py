"""generate_vectors.py: it runs, it writes the files that ../vectors holds, and what it wrote reads
back."""

import base64
import json
import os
import re
import shutil
import tempfile
import unittest

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_alt_modules import rfc5280

import util

from compfrodo import cms, composite, pkix

import generate_vectors


def b64(s):
    return base64.b64decode(s)


def masked(text):
    """The example text with the body of each CERTIFICATE PEM block removed: the ML-DSA-65
    signatures in them are hedged and change from run to run."""
    return re.sub(r"(-----BEGIN CERTIFICATE-----\n).*?(\n-----END CERTIFICATE-----)", r"\1...\2", text, flags=re.S)


def certificates(text):
    return [b64(m) for m in re.findall(r"-----BEGIN CERTIFICATE-----\n(.*?)\n-----END CERTIFICATE-----", text, re.S)]


def tbs(der):
    cert, _ = der_decoder.decode(der, asn1Spec=rfc5280.Certificate())
    return der_encoder.encode(cert["tbsCertificate"])


@unittest.skipIf(generate_vectors.mldsa is None, "the cryptography package has no ML-DSA")
class GenerateVectorsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        generate_vectors.generate(cls.out, log=lambda *a: None)
        cls.vectors = util.load_testvectors(cls.out)
        with open(os.path.join(cls.out, "cms.json")) as fh:
            cls.messages = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out)

    def test_writes_the_files_of_the_repository(self):
        self.assertEqual(sorted(os.listdir(self.out)), sorted(f for f in os.listdir(util.VECTORS) if f != "README.md"))

    def test_layout_matches_the_repository_vectors(self):
        repo = util.load_testvectors()
        self.assertEqual(sorted(self.vectors), sorted(repo))
        self.assertEqual([t["tcId"] for t in self.vectors["tests"]], [t["tcId"] for t in repo["tests"]])
        for mine, theirs in zip(self.vectors["tests"], repo["tests"]):
            self.assertEqual(sorted(mine), sorted(theirs))
        self.assertEqual(sorted(util.load_intermediates(self.out)), sorted(util.load_intermediates()))

    def test_written_cases_read_back(self):
        ca = pkix.Certificate(b64(self.vectors["cacert"]))
        intermediates = util.load_intermediates(self.out)
        for t in self.vectors["tests"]:
            with self.subTest(t["tcId"]):
                alg = composite.algorithm(t["tcId"])
                cert = pkix.Certificate(b64(t["x5c"]))
                self.assertEqual(cert.composite_public_key(), (alg, b64(t["ek"])))
                self.assertTrue(cert.verify_signature(ca))
                self.assertEqual(pkix.decode_private_key(b64(t["dk_pkcs8"])), (alg, b64(t["dk"]), None))
                self.assertEqual(pkix.decode_private_key(b64(t["dk_pkcs8_v2"])), (alg, b64(t["dk"]), b64(t["ek"])))
                d = composite.decaps_detailed(alg, b64(t["dk"]), b64(t["c"]))
                self.assertEqual(d["ss"], b64(t["k"]))
                for field in ("label", "frodo_ss", "trad_ss", "trad_ct", "trad_pk", "ss"):
                    self.assertEqual(d[field], intermediates[t["tcId"]][field], field)

    def test_messages_read_back(self):
        by_id = dict((t["tcId"], t) for t in self.vectors["tests"])
        self.assertEqual(len(self.messages), 13)
        for m in self.messages:
            for r in m["recipients"]:
                t = by_id[r]
                content, _ = cms.open_envelope(b64(m["cms"]), pkix.Certificate(b64(t["x5c"])), b64(t["dk"]))
                self.assertEqual(content, b64(m["content"]))

    def test_pem_examples(self):
        by_id = dict((t["tcId"], t) for t in self.vectors["tests"])
        for name in generate_vectors.PEM_EXAMPLES:
            with self.subTest(name):
                base = os.path.join(self.out, "cms-" + name[len("id-"):])
                cert = pkix.Certificate(util.pem(base + "-recipient-cert.pem"))
                self.assertEqual(cert.der, b64(by_id[name]["x5c"]))
                alg, dk, _ = pkix.decode_private_key(util.pem(base + "-recipient-key.pem"))
                self.assertEqual(dk, b64(by_id[name]["dk"]))
                self.assertEqual(cms.open_envelope(util.pem(base + "-enveloped.pem"), cert, dk, alg)[0],
                                 generate_vectors.CONTENT)

    def test_cms_example_is_fixed(self):
        # Apart from the certificate signatures, a new run writes the example in the repository
        # byte for byte, and the certificates differ only in their signatures.
        with open(os.path.join(self.out, generate_vectors.EXAMPLE_FILE)) as fh:
            mine = fh.read()
        with open(os.path.join(util.VECTORS, generate_vectors.EXAMPLE_FILE)) as fh:
            theirs = fh.read()
        self.assertEqual(masked(mine), masked(theirs))
        self.assertEqual([tbs(c) for c in certificates(mine)], [tbs(c) for c in certificates(theirs)])


@unittest.skipIf(generate_vectors.mldsa is None, "the cryptography package has no ML-DSA")
class GenerateWithKeysTest(unittest.TestCase):
    """generate_vectors.py --keys: the key material of ../vectors carried over unchanged."""

    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        cls.keys = os.path.join(util.VECTORS, "testvectors.json")
        generate_vectors.generate(cls.out, log=lambda *a: None, keys_from=cls.keys)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out)

    def test_key_material_and_intermediates_unchanged(self):
        repo, mine = util.load_testvectors(), util.load_testvectors(self.out)
        for theirs, t in zip(repo["tests"], mine["tests"]):
            with self.subTest(t["tcId"]):
                for field in ("tcId", "ek", "dk", "c", "k"):
                    self.assertEqual(t[field], theirs[field], field)
                # the certificate is new, but carries the same key, under the new CA
                self.assertNotEqual(t["x5c"], theirs["x5c"])
                cert = pkix.Certificate(b64(t["x5c"]))
                self.assertEqual(cert.composite_public_key()[1], b64(t["ek"]))
                self.assertTrue(cert.verify_signature(pkix.Certificate(b64(mine["cacert"]))))
        self.assertEqual(util.load_intermediates(self.out), util.load_intermediates())

    def test_bad_key_material_refused(self):
        repo = util.load_testvectors()
        t = repo["tests"][0]
        k = bytearray(b64(t["k"]))
        k[0] ^= 1
        t["k"] = base64.b64encode(bytes(k)).decode("ascii")
        path = os.path.join(self.out, "bad.json")
        with open(path, "w") as fh:
            json.dump(repo, fh)
        with self.assertRaises(RuntimeError) as cm:
            generate_vectors.generate(os.path.join(self.out, "unused"), log=lambda *a: None, keys_from=path)
        self.assertIn("does not check out", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
