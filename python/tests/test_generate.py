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
from pyasn1_alt_modules import rfc5083, rfc5280, rfc5652

import util

from compfrodo import cms, composite, oids, pkix

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


def message_parts(der):
    """(the fields of the EnvelopedData or AuthEnvelopedData other than recipientInfos,
    {kem OID: (the KEMRecipientInfo without its encryptedKey, the encryptedKey)})."""
    ci, _ = der_decoder.decode(der, asn1Spec=rfc5652.ContentInfo())
    auth = str(ci["contentType"]) == oids.ID_AUTH_ENVELOPED_DATA
    env, _ = der_decoder.decode(bytes(ci["content"]), asn1Spec=rfc5083.AuthEnvelopedData() if auth else rfc5652.EnvelopedData())
    fields = [(name, der_encoder.encode(env[name])) for name in env.keys()
              if name != "recipientInfos" and env[name].isValue]
    recipients = {}
    for ri in env["recipientInfos"]:
        kemri = cms.parse_kemri(ri)
        encrypted_key = bytes(kemri["encryptedKey"])
        kemri["encryptedKey"] = b""
        recipients[str(kemri["kem"]["algorithm"])] = (der_encoder.encode(kemri), encrypted_key)
    return (str(ci["contentType"]), fields), recipients


def read_all(directory):
    files = {}
    for f in sorted(os.listdir(directory)):
        if f != "README.md":
            with open(os.path.join(directory, f), "rb") as fh:
                files[f] = fh.read()
    return files


@unittest.skipIf(generate_vectors.mldsa is None, "the cryptography package has no ML-DSA")
class RelabelTest(unittest.TestCase):
    """generate_vectors.py --relabel: only the values that depend on a Label change."""

    PATCHED = ("id-FrodoKEM976-SHAKE-X25519-SHA3-256", "id-FrodoKEM1344-AES-RSA4096-SHA3-256")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_relabel_keeps_the_repository_vectors(self):
        # The repository vectors already have the current Labels, so nothing changes.
        out = os.path.join(self.tmp, "out")
        generate_vectors.relabel(util.VECTORS, out, log=lambda *a: None)
        self.assertEqual(read_all(out), read_all(util.VECTORS))

    def test_relabel_and_back(self):
        algs = [composite.algorithm(n) for n in self.PATCHED]
        labels = [a.label for a in algs]
        other = os.path.join(self.tmp, "other")
        back = os.path.join(self.tmp, "back")
        try:
            for a in algs:
                a.label = b"compfrodo test Label " + a.label
            generate_vectors.relabel(util.VECTORS, other, log=lambda *a: None)
        finally:
            for a, label in zip(algs, labels):
                a.label = label
        generate_vectors.relabel(other, back, log=lambda *a: None)
        self.assertEqual(read_all(back), read_all(util.VECTORS))

        # With the other Labels, k, the Label, combiner input length and ss intermediates and the
        # encryptedKey of the patched algorithms' KEMRecipientInfos change, and nothing else does.
        repo, mine = util.load_testvectors(), util.load_testvectors(other)
        self.assertEqual(mine["cacert"], repo["cacert"])
        for theirs, t in zip(repo["tests"], mine["tests"]):
            for field in theirs:
                with self.subTest(t["tcId"], field=field):
                    if field == "k" and t["tcId"] in self.PATCHED:
                        self.assertNotEqual(t[field], theirs[field])
                    else:
                        self.assertEqual(t[field], theirs[field])
        ri, mi = util.load_intermediates(), util.load_intermediates(other)
        for tc in ri:
            for field in ri[tc]:
                with self.subTest(tc, field=field):
                    if field in ("label", "input_length", "ss") and tc in self.PATCHED:
                        self.assertNotEqual(mi[tc][field], ri[tc][field])
                    else:
                        self.assertEqual(mi[tc][field], ri[tc][field])
        patched_oids = set(composite.algorithm(n).oid for n in self.PATCHED)
        with open(os.path.join(util.VECTORS, "cms.json")) as fh:
            repo_messages = json.load(fh)
        with open(os.path.join(other, "cms.json")) as fh:
            messages = json.load(fh)
        for theirs, m in zip(repo_messages, messages):
            with self.subTest(m["label"]):
                self.assertEqual((m["label"], m["recipients"], m["content"]),
                                 (theirs["label"], theirs["recipients"], theirs["content"]))
                (fields, recipients), (their_fields, their_recipients) = message_parts(b64(m["cms"])), message_parts(b64(theirs["cms"]))
                self.assertEqual(fields, their_fields)
                self.assertEqual(sorted(recipients), sorted(their_recipients))
                for oid in recipients:
                    self.assertEqual(recipients[oid][0], their_recipients[oid][0])
                    self.assertEqual(recipients[oid][1] != their_recipients[oid][1], oid in patched_oids)
        files = read_all(other)
        for name, data in read_all(util.VECTORS).items():
            if name not in ("testvectors.json", "combiner-intermediates.txt", "cms.json",
                            generate_vectors.EXAMPLE_FILE) and not name.startswith("cms-FrodoKEM976-SHAKE-X25519-"):
                self.assertEqual(files[name], data, name)
        # The example has the other Label, but keeps its certificates, signatures and all.
        example = files[generate_vectors.EXAMPLE_FILE].decode("ascii")
        theirs = read_all(util.VECTORS)[generate_vectors.EXAMPLE_FILE].decode("ascii")
        self.assertNotEqual(example, theirs)
        self.assertEqual(certificates(example), certificates(theirs))

    def test_wrong_earlier_label_refused(self):
        earlier = os.path.join(self.tmp, "earlier")
        shutil.copytree(util.VECTORS, earlier)
        path = os.path.join(earlier, "combiner-intermediates.txt")
        with open(path) as fh:
            text = fh.read()
        label = composite.ALGORITHMS[0].label
        self.assertIn(label.hex(), text)
        with open(path, "w") as fh:
            fh.write(text.replace(label.hex(), (label + b"!").hex(), 1))
        with self.assertRaises(RuntimeError) as cm:
            generate_vectors.relabel(earlier, os.path.join(self.tmp, "out"), log=lambda *a: None)
        self.assertIn("does not check out", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
