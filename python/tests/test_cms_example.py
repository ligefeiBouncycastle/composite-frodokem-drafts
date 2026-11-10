"""The AuthEnvelopedData example in ../vectors, checked from the values printed in it.

Each value is recomputed from the fixed inputs with the primitives directly (hashlib, hmac, the
cryptography package's X25519, AES key wrap and AES-GCM), not through compfrodo's composite and
CMS code. Only FrodoKEM itself comes from compfrodo.frodokem, which test_frodokem checks
against the FrodoKEM KATs.
"""

import base64
import hashlib
import hmac
import os
import re
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_alt_modules import rfc5083, rfc5084, rfc5652, rfc9629

import util

from compfrodo import cms, frodokem, pkix

PATH = os.path.join(util.VECTORS, "cms-example-authenveloped-frodokem976-shake-x25519.txt")
PREFIX = b"Composite FrodoKEM CMS example: "
P = frodokem.FRODOKEM_976_SHAKE

with open(PATH) as fh:
    TEXT = fh.read()


def parse(text):
    """[(section, caption, bytes)] for each block of caption lines, the last ending in ':',
    followed by indented hex lines and nothing else."""
    values = []
    section = None
    for block in text.split("\n\n"):
        lines = block.strip("\n").split("\n")
        if len(lines) == 1 and re.match(r"^(Fixed Inputs|B\.1\. |B\.2\. )", lines[0]):
            section = lines[0]
            continue
        is_hex = [bool(re.match(r"^  [0-9a-f]+$", l)) for l in lines]
        if True not in is_hex:
            continue
        first = is_hex.index(True)
        if first == 0 or False in is_hex[first:] or not lines[first - 1].endswith(":"):
            continue
        caption = " ".join(lines[:first])[:-1]
        values.append((section, caption, bytes.fromhex("".join(l.strip() for l in lines[first:]))))
    return values


VALUES = parse(TEXT)


def value(section, prefix):
    found = [v for s, c, v in VALUES if s.startswith(section) and c.startswith(prefix)]
    if len(found) != 1:
        raise KeyError("%d values for %r in %r" % (len(found), prefix, section))
    return found[0]


def pems():
    return [(label, base64.b64decode(body)) for label, body in
            re.findall(r"-----BEGIN ([A-Z ]+)-----\n(.*?)\n-----END \1-----", TEXT, re.S)]


def hkdf_sha256(salt, ikm, info, length):
    """RFC 5869."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t = b"", b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


class CMSExampleTest(unittest.TestCase):

    def test_line_length(self):
        self.assertEqual([l for l in TEXT.splitlines() if len(l) > 72], [])

    def test_fixed_inputs(self):
        names = {"s": 24, "seedSE": 48, "z": 16, "X25519 private key": 32, "u": 24, "salt": 48,
                 "X25519 ephemeral private key": 32, "CEK": 32, "GCM nonce": 12, "CA ML-DSA-65 seed": 32}
        for name, length in names.items():
            with self.subTest(name):
                self.assertEqual(value("Fixed Inputs", '"%s" (%d)' % (name, length)),
                                 hashlib.shake_256(PREFIX + name.encode("ascii")).digest(length))

    def test_originator(self):
        fi = lambda name: value("Fixed Inputs", '"%s"' % name)
        b1 = lambda prefix: value("B.1", prefix)
        # Bob's key pair: FrodoKEM KeyGen from (s, seedSE, z), and X25519
        frodo_pk, frodo_sk = frodokem.keygen_internal(P, fi("s"), fi("seedSE"), fi("z"))
        bob = x25519.X25519PrivateKey.from_private_bytes(fi("X25519 private key"))
        trad_pk = bob.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(b1("trad_pk"), trad_pk)
        # Encaps: FrodoKEM with (u, salt), X25519 with the ephemeral key
        frodo_ct, frodo_ss = frodokem.encaps(P, frodo_pk, lambda n: fi("u") + fi("salt"))
        self.assertEqual(b1("frodo_ss"), frodo_ss)
        eph = x25519.X25519PrivateKey.from_private_bytes(fi("X25519 ephemeral private key"))
        trad_ct = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(b1("trad_ct"), trad_ct)
        trad_ss = eph.exchange(bob.public_key())
        self.assertEqual(b1("trad_ss"), trad_ss)
        label = b"FrodoKEM976-SHAKE-X25519"
        self.assertEqual(b1("Label"), label)
        ss = hashlib.sha3_256(frodo_ss + trad_ss + trad_ct + trad_pk + label).digest()
        self.assertEqual(b1("The composite shared secret"), ss)
        self.assertEqual(b1("The composite ciphertext"), frodo_ct + trad_ct)
        # KDF, key wrap and AES-GCM
        info = bytes.fromhex("3010300b060960864801650304012d020120")
        self.assertEqual(b1("Alice encodes the CMSORIforKEMOtherInfo"), info)
        kek = hkdf_sha256(b"", ss, info, 32)
        self.assertEqual(b1("Alice derives the KEK"), kek)
        cek = fi("CEK")
        self.assertEqual(b1("Alice uses the fixed CEK"), cek)
        self.assertEqual(b1("Alice wraps the CEK"), aes_key_wrap(kek, cek))
        self.assertEqual(b1("content"), b"Hello, world!")
        self.assertEqual(b1("nonce"), fi("GCM nonce"))
        sealed = AESGCM(cek).encrypt(fi("GCM nonce"), b"Hello, world!", None)
        self.assertEqual(b1("encryptedContent") + b1("mac"), sealed)

        # The PEM objects: Bob's certificate and private key, and the message
        (l1, cert_der), (l2, key_der), (l3, message), (l4, ca_der) = pems()
        self.assertEqual((l1, l2, l3, l4), ("CERTIFICATE", "PRIVATE KEY", "CMS", "CERTIFICATE"))
        alg, ek = pkix.Certificate(cert_der).composite_public_key()
        self.assertEqual(ek, frodo_pk + trad_pk)
        self.assertEqual(alg.oid_name, "id-FrodoKEM976-SHAKE-X25519-SHA3-256")
        alg2, dk, ek2 = pkix.decode_private_key(key_der)
        self.assertEqual((alg2, dk, ek2), (alg, frodo_sk + fi("X25519 private key"), None))
        self.assertEqual(pkix.Certificate(cert_der).subject_key_identifier(), hashlib.sha1(ek).digest())

        ci, rest = der_decoder.decode(message, asn1Spec=rfc5652.ContentInfo())
        self.assertEqual((str(ci["contentType"]), rest), ("1.2.840.113549.1.9.16.1.23", b""))
        env, _ = der_decoder.decode(bytes(ci["content"]), asn1Spec=rfc5083.AuthEnvelopedData())
        self.assertEqual((int(env["version"]), len(env["recipientInfos"])), (0, 1))
        ri = env["recipientInfos"][0]
        self.assertEqual(str(ri["ori"]["oriType"]), "1.2.840.113549.1.9.16.13.3")
        kemri, _ = der_decoder.decode(bytes(ri["ori"]["oriValue"]), asn1Spec=rfc9629.KEMRecipientInfo())
        self.assertEqual(bytes(kemri["rid"]["subjectKeyIdentifier"]), hashlib.sha1(ek).digest())
        self.assertEqual(bytes(kemri["rid"]["subjectKeyIdentifier"]), value("B.2", "Bob finds"))
        self.assertEqual(str(kemri["kem"]["algorithm"]), alg.oid)
        self.assertEqual(bytes(kemri["kemct"]), frodo_ct + trad_ct)
        self.assertEqual(str(kemri["kdf"]["algorithm"]), "1.2.840.113549.1.9.16.3.28")
        self.assertEqual(int(kemri["kekLength"]), 32)
        self.assertFalse(kemri["ukm"].isValue)
        self.assertEqual(str(kemri["wrap"]["algorithm"]), "2.16.840.1.101.3.4.1.45")
        self.assertEqual(bytes(kemri["encryptedKey"]), aes_key_wrap(kek, cek))
        eci = env["authEncryptedContentInfo"]
        self.assertEqual(str(eci["contentType"]), "1.2.840.113549.1.7.1")
        self.assertEqual(str(eci["contentEncryptionAlgorithm"]["algorithm"]), "2.16.840.1.101.3.4.1.46")
        params, _ = der_decoder.decode(bytes(eci["contentEncryptionAlgorithm"]["parameters"]),
                                       asn1Spec=rfc5084.GCMParameters())
        self.assertEqual((bytes(params["aes-nonce"]), int(params["aes-ICVlen"])), (fi("GCM nonce"), 16))
        self.assertEqual(bytes(eci["encryptedContent"]) + bytes(env["mac"]), sealed)

    def test_recipient(self):
        b1 = lambda prefix: value("B.1", prefix)
        b2 = lambda prefix: value("B.2", prefix)
        (_, cert_der), (_, key_der), (_, message), _ = pems()
        alg, dk, _ = pkix.decode_private_key(key_der)
        frodo_sk, trad_sk = dk[:P.sk_len], dk[P.sk_len:]
        ct = b1("The composite ciphertext")
        self.assertEqual(frodokem.decaps(P, frodo_sk, ct[:P.ct_len]), b2("frodo_ss"))
        bob = x25519.X25519PrivateKey.from_private_bytes(trad_sk)
        self.assertEqual(bob.exchange(x25519.X25519PublicKey.from_public_bytes(ct[P.ct_len:])), b2("trad_ss"))
        for prefix in ("frodo_ss", "trad_ss"):
            self.assertEqual(b2(prefix), b1(prefix))
        self.assertEqual(b2("ss"), b1("The composite shared secret"))
        self.assertEqual(b2("Bob derives the KEK"), b1("Alice derives the KEK"))
        self.assertEqual(aes_key_unwrap(b2("Bob derives the KEK"), b1("Alice wraps the CEK")), b2("Bob unwraps"))
        self.assertEqual(b2("Bob unwraps"), b1("Alice uses the fixed CEK"))
        self.assertEqual(b2("Bob decrypts"), b"Hello, world!")
        # and compfrodo's own CMS code opens the message
        content, d = cms.open_envelope(message, pkix.Certificate(cert_der), dk, alg)
        self.assertEqual((content, d["ss"], d["kek"]), (b"Hello, world!", b2("ss"), b2("Bob derives the KEK")))

    def test_certificates(self):
        (_, cert_der), _, _, (_, ca_der) = pems()
        cert, ca = pkix.Certificate(cert_der), pkix.Certificate(ca_der)
        self.assertEqual(cert.issuer_der, ca.subject_der)
        self.assertEqual(cert.key_usage(), set(["keyEncipherment"]))
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
        except ImportError:
            self.skipTest("the cryptography package has no ML-DSA")
        self.assertTrue(cert.verify_signature(ca))
        self.assertTrue(ca.verify_signature(ca))
        seed = value("Fixed Inputs", '"CA ML-DSA-65 seed"')
        public = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key()
        self.assertEqual(der_encoder.encode(ca.spki), public.public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))


if __name__ == "__main__":
    unittest.main()
