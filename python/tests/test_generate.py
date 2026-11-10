"""generate_vectors.py: it runs, its files have the documented layout, and what it wrote reads back."""

import base64
import json
import os
import shutil
import tempfile
import unittest

import util

from compfrodo import cms, composite, pkix

import generate_vectors


def b64(s):
    return base64.b64decode(s)


@unittest.skipIf(generate_vectors.mldsa is None, "the cryptography package has no ML-DSA")
class GenerateVectorsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        generate_vectors.generate(cls.out, log=lambda *a: None)
        with open(os.path.join(cls.out, "testvectors.json")) as fh:
            cls.vectors = json.load(fh)
        with open(os.path.join(cls.out, "cms.json")) as fh:
            cls.messages = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out)

    def test_layout_matches_the_repository_vectors(self):
        repo = util.load_testvectors()
        self.assertEqual(sorted(self.vectors), sorted(repo))
        self.assertEqual([t["tcId"] for t in self.vectors["tests"]], [t["tcId"] for t in repo["tests"]])
        for mine, theirs in zip(self.vectors["tests"], repo["tests"]):
            self.assertEqual(sorted(mine), sorted(list(theirs) + ["dk_pkcs8_v2"]))

    def test_written_cases_read_back(self):
        ca = pkix.Certificate(b64(self.vectors["cacert"]))
        for t in self.vectors["tests"]:
            alg = composite.algorithm(t["tcId"])
            cert = pkix.Certificate(b64(t["x5c"]))
            self.assertEqual(cert.composite_public_key(), (alg, b64(t["ek"])))
            self.assertTrue(cert.verify_signature(ca))
            self.assertEqual(pkix.decode_private_key(b64(t["dk_pkcs8"])), (alg, b64(t["dk"]), None))
            self.assertEqual(pkix.decode_private_key(b64(t["dk_pkcs8_v2"])), (alg, b64(t["dk"]), b64(t["ek"])))
            self.assertEqual(composite.decaps(alg, b64(t["dk"]), b64(t["c"])), b64(t["k"]))

    def test_messages_read_back(self):
        by_id = dict((t["tcId"], t) for t in self.vectors["tests"])
        self.assertEqual(len(self.messages), 13)
        for m in self.messages:
            for r in m["recipients"]:
                t = by_id[r]
                content, _ = cms.open_envelope(b64(m["cms"]), pkix.Certificate(b64(t["x5c"])), b64(t["dk"]))
                self.assertEqual(content, b64(m["content"]))


if __name__ == "__main__":
    unittest.main()
