"""KEMRecipientInfo (draft-song-lamps-cms-composite-frodokem-01): the two CMS examples in
../vectors, round trips for all eight algorithms, and the field checks."""

import os
import unittest

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc9629

import util

from compfrodo import cms, composite, oids, pkix
from compfrodo.cms import CMSError
from compfrodo.composite import CompositeError

VECTORS = util.load_testvectors()
CONTENT = b"Hello, world!"


def vector_recipient(tc_id):
    """(certificate, algorithm, dk) of a test case in testvectors.json."""
    t = [t for t in VECTORS["tests"] if t["tcId"] == tc_id][0]
    alg, dk, _ = pkix.decode_private_key(util.b64(t["dk_pkcs8"]))
    return pkix.Certificate(util.b64(t["x5c"])), alg, dk


def with_subject_key_identifier(cert, ski):
    """A copy of cert with a subjectKeyIdentifier extension added (the signature is left as it
    was, so it no longer verifies; only rid matching uses this)."""
    c, _ = der_decoder.decode(cert.der, asn1Spec=rfc5280.Certificate())
    ext = rfc5280.Extension()
    ext["extnID"] = rfc5280.id_ce_subjectKeyIdentifier
    ext["critical"] = False
    ext["extnValue"] = der_encoder.encode(rfc5280.SubjectKeyIdentifier(ski))
    c["tbsCertificate"]["extensions"].append(ext)
    return pkix.Certificate(der_encoder.encode(c))


def tamper_kemri(message, edit):
    """Decode message (an EnvelopedData from cms.envelope), apply edit to its first
    KEMRecipientInfo and re-encode."""
    ci, _ = der_decoder.decode(message, asn1Spec=rfc5652.ContentInfo())
    env, _ = der_decoder.decode(bytes(ci["content"]), asn1Spec=rfc5652.EnvelopedData())
    ri = env["recipientInfos"][0]
    kemri, _ = der_decoder.decode(bytes(ri["ori"]["oriValue"]), asn1Spec=rfc9629.KEMRecipientInfo())
    edit(kemri)
    ri["ori"]["oriValue"] = der_encoder.encode(kemri)
    ci["content"] = der_encoder.encode(env)
    return der_encoder.encode(ci)


class CMSVectorTest(unittest.TestCase):

    def test_vector_examples(self):
        for name, wrap, kek_length in (("FrodoKEM976-X25519-SHA3-256", oids.ID_AES192_WRAP, 24),
                                       ("FrodoKEM1344-X448-SHA3-256", oids.ID_AES256_WRAP, 32)):
            with self.subTest(name):
                base = os.path.join(util.VECTORS, "cms-" + name)
                cert = pkix.Certificate(util.pem(base + "-recipient-cert.pem"))
                alg, dk, ek = pkix.decode_private_key(util.pem(base + "-recipient-key.pem"))
                self.assertIs(alg, composite.algorithm("id-" + name))
                self.assertEqual(cert.composite_public_key(), (alg, composite.public_key_from_private(alg, dk)))
                content, d = cms.open_envelope(util.pem(base + "-enveloped.pem"), cert, dk, alg)
                self.assertEqual(content, CONTENT)
                self.assertEqual((d["wrap"], d["kekLength"], d["ukm"], d["version"], d["rid"]),
                                 (wrap, kek_length, None, 3, "issuerAndSerialNumber"))
                self.assertEqual(d["contentEncryptionAlgorithm"], oids.ID_AES256_CBC)

    def test_vector_example_with_another_key_fails(self):
        base = os.path.join(util.VECTORS, "cms-FrodoKEM976-X25519-SHA3-256")
        cert = pkix.Certificate(util.pem(base + "-recipient-cert.pem"))
        alg = composite.algorithm("id-FrodoKEM976-X25519-SHA3-256")
        _, other_dk = composite.keygen(alg)
        self.assertRaises(CMSError, cms.open_envelope, util.pem(base + "-enveloped.pem"), cert, other_dk, alg)


class CMSRoundTripTest(unittest.TestCase):

    def test_all_algorithms(self):
        for alg in composite.ALGORITHMS:
            with self.subTest(alg.oid_name):
                cert, dk_alg, dk = vector_recipient(alg.oid_name)
                message = cms.envelope(CONTENT, [cert])
                content, d = cms.open_envelope(message, cert, dk, dk_alg)
                self.assertEqual(content, CONTENT)
                self.assertEqual(d["wrap"], cms.DEFAULT_WRAP[alg.frodo.n])

    def test_auth_enveloped_data(self):
        for name in ("id-FrodoKEM976-RSA3072-SHA3-256", "id-FrodoKEM1344-AES-X448-SHA3-256"):
            with self.subTest(name):
                cert, dk_alg, dk = vector_recipient(name)
                message = cms.envelope(CONTENT, [cert], content_alg=oids.ID_AES256_GCM)
                content, d = cms.open_envelope(message, cert, dk, dk_alg)
                self.assertEqual(content, CONTENT)
                self.assertEqual(d["version"], 0)

    def test_two_recipients(self):
        c1, a1, k1 = vector_recipient("id-FrodoKEM976-X25519-SHA3-256")
        c2, a2, k2 = vector_recipient("id-FrodoKEM1344-RSA4096-SHA3-256")
        message = cms.envelope(CONTENT, [c1, c2])
        self.assertEqual(cms.open_envelope(message, c1, k1, a1)[0], CONTENT)
        self.assertEqual(cms.open_envelope(message, c2, k2, a2)[0], CONTENT)

    def test_aes256_wrap_with_frodokem976(self):
        cert, dk_alg, dk = vector_recipient("id-FrodoKEM976-AES-X25519-SHA3-256")
        message = cms.envelope(CONTENT, [cert], wrap_oid=oids.ID_AES256_WRAP)
        content, d = cms.open_envelope(message, cert, dk, dk_alg)
        self.assertEqual((content, d["wrap"], d["kekLength"]), (CONTENT, oids.ID_AES256_WRAP, 32))

    def test_disallowed_wrap_not_generated(self):
        for name, wrap in (("id-FrodoKEM976-X25519-SHA3-256", oids.ID_AES128_WRAP),
                           ("id-FrodoKEM1344-X448-SHA3-256", oids.ID_AES128_WRAP),
                           ("id-FrodoKEM1344-X448-SHA3-256", oids.ID_AES192_WRAP)):
            with self.subTest(name=name, wrap=wrap):
                cert, _, _ = vector_recipient(name)
                self.assertRaises(CMSError, cms.envelope, CONTENT, [cert], wrap_oid=wrap)

    def test_disallowed_wrap_not_accepted(self):
        # the recipient refuses a weaker wrap even when the KEK derivation is otherwise right
        cert, dk_alg, dk = vector_recipient("id-FrodoKEM1344-X448-SHA3-256")
        message = cms.envelope(CONTENT, [cert])

        def to_aes192(kemri):
            kemri["wrap"]["algorithm"] = univ.ObjectIdentifier(oids.ID_AES192_WRAP)
            kemri["kekLength"] = 24
        with self.assertRaises(CMSError) as cm:
            cms.open_envelope(tamper_kemri(message, to_aes192), cert, dk, dk_alg)
        self.assertIn("not allowed", str(cm.exception))

    def test_field_checks(self):
        cert, dk_alg, dk = vector_recipient("id-FrodoKEM976-X25519-SHA3-256")
        message = cms.envelope(CONTENT, [cert])

        def version1(kemri):
            kemri["version"] = 1

        def kek_length(kemri):
            kemri["kekLength"] = 32

        def kdf_parameters(kemri):
            kemri["kdf"]["parameters"] = der_encoder.encode(univ.Null(""))

        def kem_parameters(kemri):
            kemri["kem"]["parameters"] = der_encoder.encode(univ.Null(""))

        def other_kdf(kemri):
            kemri["kdf"]["algorithm"] = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3.29")

        def short_kemct(kemri):
            kemri["kemct"] = bytes(kemri["kemct"])[:-1]

        def ukm_added(kemri):
            kemri["ukm"] = b"not what the originator used"

        for edit in (version1, kek_length, kdf_parameters, kem_parameters, other_kdf, short_kemct, ukm_added):
            with self.subTest(edit.__name__):
                # CMSError, or CompositeError (its base class) from Decaps for the short kemct
                self.assertRaises(CompositeError, cms.open_envelope, tamper_kemri(message, edit), cert, dk, dk_alg)

    def test_ukm(self):
        cert, dk_alg, dk = vector_recipient("id-FrodoKEM976-X25519-SHA3-256")
        message = cms.envelope(CONTENT, [cert], ukm=b"user keying material")
        content, d = cms.open_envelope(message, cert, dk, dk_alg)
        self.assertEqual((content, d["ukm"]), (CONTENT, b"user keying material"))

    def test_subject_key_identifier_rid(self):
        cert, dk_alg, dk = vector_recipient("id-FrodoKEM976-RSA3072-SHA3-256")
        cert = with_subject_key_identifier(cert, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        message = cms.envelope(CONTENT, [cert], rid_type="subjectKeyIdentifier")
        content, d = cms.open_envelope(message, cert, dk, dk_alg)
        self.assertEqual((content, d["rid"]), (CONTENT, "subjectKeyIdentifier"))
        other = with_subject_key_identifier(vector_recipient("id-FrodoKEM976-RSA3072-SHA3-256")[0], b"\x09" * 8)
        self.assertRaises(CMSError, cms.open_envelope, message, other, dk, dk_alg)

    def test_private_key_for_another_algorithm(self):
        cert, _, _ = vector_recipient("id-FrodoKEM976-X25519-SHA3-256")
        _, other_alg, other_dk = vector_recipient("id-FrodoKEM976-AES-X25519-SHA3-256")
        message = cms.envelope(CONTENT, [cert])
        self.assertRaises(CMSError, cms.open_envelope, message, cert, other_dk, other_alg)

    def test_kdf_info_encoding(self):
        # RFC 9629 section 5: DER(CMSORIforKEMOtherInfo); with no ukm it is
        # SEQUENCE { SEQUENCE { OID id-aes192-wrap }, INTEGER 24 }
        wrap = rfc5280.AlgorithmIdentifier()
        wrap["algorithm"] = univ.ObjectIdentifier(oids.ID_AES192_WRAP)
        self.assertEqual(cms.kdf_info(wrap, 24).hex(), "3010300b0609608648016503040119020118")


if __name__ == "__main__":
    unittest.main()
