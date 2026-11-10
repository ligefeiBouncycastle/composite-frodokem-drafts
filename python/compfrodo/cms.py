"""Composite FrodoKEM in CMS: draft-song-lamps-cms-composite-frodokem-02.

KEMRecipientInfo (RFC 9629) is the part the draft specifies. The EnvelopedData (RFC 5652) and
AuthEnvelopedData (RFC 5083) code around it is a minimal container for testing: one or more
KEMRecipientInfo recipients, AES-CBC or AES-GCM content encryption, no attributes, no
originatorInfo.
"""

import os

from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5083, rfc5084, rfc5652, rfc9629

from . import ber, composite, oids
from .composite import CompositeError
from .pkix import algorithm_identifier

# kekLength for each key-encryption algorithm (RFC 3394 / RFC 3565)
WRAP_KEK_LENGTH = {
    oids.ID_AES128_WRAP: 16,
    oids.ID_AES192_WRAP: 24,
    oids.ID_AES256_WRAP: 32,
}

# The key-encryption algorithms accepted for each FrodoKEM level.
#
# Section 2.1 (wrap): implementations MUST support AES-Wrap-256 "for all Composite FrodoKEM
# algorithms" and "MAY support other key-encryption algorithms as well".
# Section 2.2: when other components are used, the symmetric key-encryption strength is at least
# 256 bits for both FrodoKEM-976 and FrodoKEM-1344.
# So the only AES key wrap accepted is AES-Wrap-256, with either level; AES-Wrap-192 falls short
# of the 256-bit minimum for FrodoKEM-976 too.
ALLOWED_WRAP = {
    976: (oids.ID_AES256_WRAP,),
    1344: (oids.ID_AES256_WRAP,),
}

# The wrap algorithm used when the caller names none: the one section 2.1 makes mandatory.
DEFAULT_WRAP = {
    976: oids.ID_AES256_WRAP,
    1344: oids.ID_AES256_WRAP,
}

CONTENT_CBC = {oids.ID_AES128_CBC: 16, oids.ID_AES192_CBC: 24, oids.ID_AES256_CBC: 32}
CONTENT_GCM = {oids.ID_AES128_GCM: 16, oids.ID_AES192_GCM: 24, oids.ID_AES256_GCM: 32}


class CMSError(CompositeError):
    pass


def _absent_parameters(alg_id, what):
    if alg_id["parameters"].isValue:
        raise CMSError("%s AlgorithmIdentifier parameters must be absent" % what)


def _check_wrap(alg, wrap_oid, kek_length):
    allowed = ALLOWED_WRAP[alg.frodo.n]
    if wrap_oid not in allowed:
        raise CMSError("key-encryption algorithm %s is not allowed with %s" % (wrap_oid, alg.oid_name))
    # RFC 9629 section 3 and draft section 2.2.1: kekLength consistent with the wrap algorithm
    if kek_length != WRAP_KEK_LENGTH[wrap_oid]:
        raise CMSError("kekLength %d does not match %s" % (kek_length, wrap_oid))


def kdf_info(wrap_alg_id, kek_length, ukm=None):
    """DER(CMSORIforKEMOtherInfo), RFC 9629 section 5."""
    info = rfc9629.CMSORIforKEMOtherInfo()
    info["wrap"]["algorithm"] = wrap_alg_id["algorithm"]
    if wrap_alg_id["parameters"].isValue:
        info["wrap"]["parameters"] = wrap_alg_id["parameters"]
    info["kekLength"] = kek_length
    if ukm is not None:
        info["ukm"] = ukm
    return der_encoder.encode(info)


def derive_kek(ss, wrap_alg_id, kek_length, ukm=None):
    """HKDF-SHA256 (RFC 5869, RFC 8619) with an empty salt (draft section 2.2.1),
    IKM = ss, info = DER(CMSORIforKEMOtherInfo), L = kekLength."""
    return HKDF(algorithm=hashes.SHA256(), length=kek_length, salt=b"",
                info=kdf_info(wrap_alg_id, kek_length, ukm)).derive(ss)


# ---------------------------------------------------------------------------
# KEMRecipientInfo
# ---------------------------------------------------------------------------

def _rid_matches(rid, cert):
    name = rid.getName()
    if name == "issuerAndSerialNumber":
        ias = rid["issuerAndSerialNumber"]
        return der_encoder.encode(ias["issuer"]) == cert.issuer_der and int(ias["serialNumber"]) == cert.serial
    if name == "subjectKeyIdentifier":
        ski = cert.subject_key_identifier()
        return ski is not None and bytes(rid["subjectKeyIdentifier"]) == ski
    return False


def build_kemri(cert, cek, wrap_oid=None, ukm=None, rid_type="issuerAndSerialNumber", randombytes=os.urandom):
    """Originator processing (RFC 9629 section 2): encapsulate to the recipient certificate's
    public key and wrap cek. Returns a RecipientInfo (the ori alternative)."""
    alg, ek = cert.composite_public_key()
    if wrap_oid is None:
        wrap_oid = DEFAULT_WRAP[alg.frodo.n]
    kek_length = WRAP_KEK_LENGTH.get(wrap_oid)
    if kek_length is None:
        raise CMSError("unsupported key-encryption algorithm " + wrap_oid)
    _check_wrap(alg, wrap_oid, kek_length)

    ct, ss = composite.encaps(alg, ek, randombytes)

    kemri = rfc9629.KEMRecipientInfo()
    kemri["version"] = 0
    if rid_type == "issuerAndSerialNumber":
        ias = kemri["rid"]["issuerAndSerialNumber"]
        ias["issuer"] = cert.issuer
        ias["serialNumber"] = cert.serial
    elif rid_type == "subjectKeyIdentifier":
        ski = cert.subject_key_identifier()
        if ski is None:
            raise CMSError("the certificate has no subjectKeyIdentifier")
        kemri["rid"]["subjectKeyIdentifier"] = ski
    else:
        raise ValueError(rid_type)
    algorithm_identifier(alg, kemri["kem"])
    kemri["kemct"] = ct
    kemri["kdf"]["algorithm"] = univ.ObjectIdentifier(oids.ID_ALG_HKDF_WITH_SHA256)
    kemri["kekLength"] = kek_length
    if ukm is not None:
        kemri["ukm"] = ukm
    kemri["wrap"]["algorithm"] = univ.ObjectIdentifier(wrap_oid)
    kek = derive_kek(ss, kemri["wrap"], kek_length, ukm)
    kemri["encryptedKey"] = aes_key_wrap(kek, cek)

    ri = rfc5652.RecipientInfo()
    ri["ori"]["oriType"] = univ.ObjectIdentifier(oids.ID_ORI_KEM)
    ri["ori"]["oriValue"] = der_encoder.encode(kemri)
    return ri


def parse_kemri(ri):
    """Returns the KEMRecipientInfo inside a RecipientInfo, or None if it is not one."""
    if ri.getName() != "ori" or str(ri["ori"]["oriType"]) != oids.ID_ORI_KEM:
        return None
    value = bytes(ri["ori"]["oriValue"])
    kemri, rest = ber_decoder.decode(value, asn1Spec=rfc9629.KEMRecipientInfo())
    if rest:
        raise CMSError("trailing data after KEMRecipientInfo")
    return kemri


def open_kemri(kemri, dk, dk_alg=None, ek=None):
    """Recipient processing (RFC 9629 section 2 and draft section 2.1): returns
    (cek, details), where details holds the shared secret, the KEK and the field values."""
    if int(kemri["version"]) != 0:
        raise CMSError("KEMRecipientInfo version must be 0")
    alg = composite.algorithm(str(kemri["kem"]["algorithm"]))
    _absent_parameters(kemri["kem"], "kem")
    if dk_alg is not None and dk_alg is not alg:
        raise CMSError("kem is %s but the private key is %s" % (alg.oid_name, dk_alg.oid_name))
    # Section 2.1 (kdf): HKDF with SHA-256, parameters absent. Other KDFs are not implemented.
    if str(kemri["kdf"]["algorithm"]) != oids.ID_ALG_HKDF_WITH_SHA256:
        raise CMSError("unsupported KDF " + str(kemri["kdf"]["algorithm"]))
    _absent_parameters(kemri["kdf"], "kdf")
    wrap_oid = str(kemri["wrap"]["algorithm"])
    if wrap_oid not in WRAP_KEK_LENGTH:
        raise CMSError("unsupported key-encryption algorithm " + wrap_oid)
    _absent_parameters(kemri["wrap"], "wrap")       # RFC 3565 section 2.3.2
    kek_length = int(kemri["kekLength"])
    _check_wrap(alg, wrap_oid, kek_length)
    ukm = bytes(kemri["ukm"]) if kemri["ukm"].isValue else None

    ss = composite.decaps(alg, dk, bytes(kemri["kemct"]), ek)
    kek = derive_kek(ss, kemri["wrap"], kek_length, ukm)
    try:
        cek = aes_key_unwrap(kek, bytes(kemri["encryptedKey"]))
    except InvalidUnwrap:
        raise CMSError("key unwrap failed")
    return cek, {"algorithm": alg, "ss": ss, "kek": kek, "wrap": wrap_oid, "kekLength": kek_length, "ukm": ukm}


# ---------------------------------------------------------------------------
# EnvelopedData and AuthEnvelopedData containers
# ---------------------------------------------------------------------------

def _content_info(content_type, content):
    ci = rfc5652.ContentInfo()
    ci["contentType"] = univ.ObjectIdentifier(content_type)
    ci["content"] = der_encoder.encode(content)
    return der_encoder.encode(ci)


def envelope(content, certs, wrap_oid=None, ukm=None, rid_type="issuerAndSerialNumber",
             content_alg=oids.ID_AES256_CBC, randombytes=os.urandom):
    """Encrypt content to each recipient certificate. With an AES-CBC content_alg the result is
    an EnvelopedData; with AES-GCM it is an AuthEnvelopedData (RFC 5083, RFC 5084)."""
    if content_alg in CONTENT_CBC:
        auth = False
        cek = randombytes(CONTENT_CBC[content_alg])
    elif content_alg in CONTENT_GCM:
        auth = True
        cek = randombytes(CONTENT_GCM[content_alg])
    else:
        raise CMSError("unsupported content-encryption algorithm " + content_alg)

    if auth:
        env = rfc5083.AuthEnvelopedData()
        env["version"] = 0                          # RFC 5083 section 2.1
        eci = env["authEncryptedContentInfo"]
    else:
        env = rfc5652.EnvelopedData()
        env["version"] = 3                          # RFC 5652 section 6.1: ori present
        eci = env["encryptedContentInfo"]
    for i, cert in enumerate(certs):
        env["recipientInfos"][i] = build_kemri(cert, cek, wrap_oid, ukm, rid_type, randombytes)

    eci["contentType"] = univ.ObjectIdentifier(oids.ID_DATA)
    eci["contentEncryptionAlgorithm"]["algorithm"] = univ.ObjectIdentifier(content_alg)
    if auth:
        nonce = randombytes(12)
        params = rfc5084.GCMParameters()
        params["aes-nonce"] = nonce
        params["aes-ICVlen"] = 16                   # the DEFAULT is 12
        eci["contentEncryptionAlgorithm"]["parameters"] = der_encoder.encode(params)
        sealed = AESGCM(cek).encrypt(nonce, content, None)
        eci["encryptedContent"] = sealed[:-16]
        env["mac"] = sealed[-16:]
        return _content_info(oids.ID_AUTH_ENVELOPED_DATA, env)
    iv = randombytes(16)
    eci["contentEncryptionAlgorithm"]["parameters"] = der_encoder.encode(univ.OctetString(iv))
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(content) + padder.finalize()
    enc = Cipher(algorithms.AES(cek), modes.CBC(iv)).encryptor()
    eci["encryptedContent"] = enc.update(padded) + enc.finalize()
    return _content_info(oids.ID_ENVELOPED_DATA, env)


def open_envelope(data, cert, dk, dk_alg=None, ek=None):
    """Find the KEMRecipientInfo for cert, recover the CEK with dk and decrypt the content.
    Returns (content, details)."""
    try:
        data = ber.definite(data)
    except ber.BERError as e:
        raise CMSError("malformed CMS encoding: %s" % e)
    ci, rest = ber_decoder.decode(data, asn1Spec=rfc5652.ContentInfo())
    if rest:
        raise CMSError("trailing data after ContentInfo")
    ctype = str(ci["contentType"])
    if ctype == oids.ID_ENVELOPED_DATA:
        env, _ = ber_decoder.decode(bytes(ci["content"]), asn1Spec=rfc5652.EnvelopedData())
        eci = env["encryptedContentInfo"]
        auth = False
    elif ctype == oids.ID_AUTH_ENVELOPED_DATA:
        env, _ = ber_decoder.decode(bytes(ci["content"]), asn1Spec=rfc5083.AuthEnvelopedData())
        eci = env["authEncryptedContentInfo"]
        auth = True
        if env["authAttrs"].isValue:
            raise CMSError("authAttrs are not supported here")
    else:
        raise CMSError("unsupported content type " + ctype)

    found = None
    for ri in env["recipientInfos"]:
        kemri = parse_kemri(ri)
        if kemri is not None and _rid_matches(kemri["rid"], cert):
            found = kemri
            break
    if found is None:
        raise CMSError("no KEMRecipientInfo for this certificate")
    cek, details = open_kemri(found, dk, dk_alg, ek)
    details["version"] = int(env["version"])
    details["rid"] = found["rid"].getName()

    content_alg = str(eci["contentEncryptionAlgorithm"]["algorithm"])
    encrypted = bytes(eci["encryptedContent"])
    details["contentEncryptionAlgorithm"] = content_alg
    if auth:
        if content_alg not in CONTENT_GCM or len(cek) != CONTENT_GCM[content_alg]:
            raise CMSError("unsupported content-authenticated-encryption algorithm " + content_alg)
        params, _ = ber_decoder.decode(bytes(eci["contentEncryptionAlgorithm"]["parameters"]),
                                       asn1Spec=rfc5084.GCMParameters())
        if int(params["aes-ICVlen"]) != 16 or len(bytes(env["mac"])) != 16:
            raise CMSError("only 16-byte GCM tags are supported here")
        content = AESGCM(cek).decrypt(bytes(params["aes-nonce"]), encrypted + bytes(env["mac"]), None)
        return content, details
    if content_alg not in CONTENT_CBC or len(cek) != CONTENT_CBC[content_alg]:
        raise CMSError("unsupported content-encryption algorithm " + content_alg)
    iv, _ = ber_decoder.decode(bytes(eci["contentEncryptionAlgorithm"]["parameters"]), asn1Spec=univ.OctetString())
    dec = Cipher(algorithms.AES(cek), modes.CBC(bytes(iv))).decryptor()
    padded = dec.update(encrypted) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize(), details
