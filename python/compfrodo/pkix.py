"""SubjectPublicKeyInfo, OneAsymmetricKey and certificate handling for Composite FrodoKEM keys
(draft-song-lamps-pq-composite-frodokem-01 sections 4.1, 4.2 and 5.1)."""

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958

from . import composite
from .composite import CompositeError


def _decode(spec, data, what):
    try:
        obj, rest = der_decoder.decode(data, asn1Spec=spec)
    except Exception as e:
        raise CompositeError("malformed %s: %s" % (what, e))
    if rest:
        raise CompositeError("trailing data after %s" % what)
    return obj


def _algorithm_from_identifier(alg_id):
    """Section 5.1: a Composite FrodoKEM OID with the parameters field absent."""
    alg = composite.algorithm(str(alg_id["algorithm"]))
    if alg_id["parameters"].isValue:
        raise CompositeError("%s AlgorithmIdentifier parameters must be absent" % alg.oid_name)
    return alg


def algorithm_identifier(alg, spec=None):
    ai = spec if spec is not None else rfc5280.AlgorithmIdentifier()
    ai["algorithm"] = univ.ObjectIdentifier(alg.oid)
    return ai


def _bits(data):
    return univ.BitString.fromOctetString(data)


def _octets_of_bits(bits, what):
    if len(bits) % 8:
        raise CompositeError("%s BIT STRING has unused bits" % what)
    return bits.asOctets()


def encode_spki(alg, ek):
    """Section 4.1: the algorithm field is the composite OID and subjectPublicKey holds ek."""
    composite.split_public_key(alg, ek)
    spki = rfc5280.SubjectPublicKeyInfo()
    algorithm_identifier(alg, spki["algorithm"])
    spki["subjectPublicKey"] = _bits(ek)
    return der_encoder.encode(spki)


def decode_spki_object(spki):
    alg = _algorithm_from_identifier(spki["algorithm"])
    ek = _octets_of_bits(spki["subjectPublicKey"], "subjectPublicKey")
    composite.split_public_key(alg, ek)
    return alg, ek


def decode_spki(data):
    """Returns (algorithm, ek)."""
    return decode_spki_object(_decode(rfc5280.SubjectPublicKeyInfo(), data, "SubjectPublicKeyInfo"))


def encode_private_key(alg, dk, include_public_key=False):
    """Section 4.2: a OneAsymmetricKey whose privateKey holds dk.

    With include_public_key the publicKey field carries ek (rebuilt from dk), which makes it a
    version 2 OneAsymmetricKey; without it the result is version 1 (a PrivateKeyInfo)."""
    composite.split_private_key(alg, dk)
    oak = rfc5958.OneAsymmetricKey()
    oak["version"] = 1 if include_public_key else 0
    algorithm_identifier(alg, oak["privateKeyAlgorithm"])
    oak["privateKey"] = dk
    if include_public_key:
        oak["publicKey"] = oak["publicKey"].clone(_bits(composite.public_key_from_private(alg, dk)))
    return der_encoder.encode(oak)


def decode_private_key(data):
    """Returns (algorithm, dk, ek or None). When the publicKey field is present it must match
    the public key derived from dk (-23 section 10.4, option 3)."""
    oak = _decode(rfc5958.OneAsymmetricKey(), data, "OneAsymmetricKey")
    version = int(oak["version"])
    alg = _algorithm_from_identifier(oak["privateKeyAlgorithm"])
    dk = bytes(oak["privateKey"])
    composite.split_private_key(alg, dk)
    ek = None
    if oak["publicKey"].isValue:
        if version != 1:
            raise CompositeError("OneAsymmetricKey with publicKey must be version 2")
        ek = _octets_of_bits(oak["publicKey"], "publicKey")
        if ek != composite.public_key_from_private(alg, dk):
            raise CompositeError("OneAsymmetricKey publicKey does not match privateKey")
    elif version not in (0, 1):
        raise CompositeError("unknown OneAsymmetricKey version %d" % version)
    return alg, dk, ek


class Certificate(object):
    """The parts of an X.509 certificate the composite and CMS code needs."""

    def __init__(self, der):
        self.der = der
        self.cert = _decode(rfc5280.Certificate(), der, "Certificate")
        tbs = self.cert["tbsCertificate"]
        self.tbs_der = der_encoder.encode(tbs)
        self.issuer = tbs["issuer"]
        self.issuer_der = der_encoder.encode(tbs["issuer"])
        self.subject_der = der_encoder.encode(tbs["subject"])
        self.serial = int(tbs["serialNumber"])
        self.spki = tbs["subjectPublicKeyInfo"]
        self.signature_algorithm = str(self.cert["signatureAlgorithm"]["algorithm"])
        self.signature = _octets_of_bits(self.cert["signature"], "signature")
        self.extensions = {}
        if tbs["extensions"].isValue:
            for ext in tbs["extensions"]:
                self.extensions[str(ext["extnID"])] = (bool(ext["critical"]), bytes(ext["extnValue"]))

    def subject_key_identifier(self):
        ext = self.extensions.get(str(rfc5280.id_ce_subjectKeyIdentifier))
        if ext is None:
            return None
        return bytes(_decode(rfc5280.SubjectKeyIdentifier(), ext[1], "SubjectKeyIdentifier"))

    def key_usage(self):
        """The set of asserted KeyUsage bit names, or None if the extension is absent."""
        ext = self.extensions.get(str(rfc5280.id_ce_keyUsage))
        if ext is None:
            return None
        ku = _decode(rfc5280.KeyUsage(), ext[1], "KeyUsage")
        names = dict((v, k) for k, v in rfc5280.KeyUsage.namedValues.items())
        return set(names[i] for i, bit in enumerate(ku) if bit)

    def composite_public_key(self):
        """Returns (algorithm, ek). Section 4.1 and the draft's CERT-KEY-USAGE: a key usage
        extension, when present, must assert exactly keyEncipherment."""
        alg, ek = decode_spki_object(self.spki)
        usage = self.key_usage()
        if usage is not None and usage != set(["keyEncipherment"]):
            raise CompositeError("a Composite FrodoKEM certificate must assert only keyEncipherment, got %s" % sorted(usage))
        return alg, ek

    def verify_signature(self, issuer):
        """Verify this certificate's signature with issuer's public key, through the
        cryptography package. Returns False if that package cannot verify the algorithm
        (ML-DSA needs a recent version); raises on a bad signature."""
        try:
            from cryptography import x509
            from cryptography.exceptions import UnsupportedAlgorithm
        except ImportError:
            return False
        try:
            mine = x509.load_der_x509_certificate(self.der)
            theirs = x509.load_der_x509_certificate(issuer.der)
            key = theirs.public_key()
        except (UnsupportedAlgorithm, ValueError):
            return False
        try:
            key.verify(mine.signature, mine.tbs_certificate_bytes)
        except TypeError:
            return False
        return True
