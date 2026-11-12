"""Composite FrodoKEM, draft-song-lamps-pq-composite-frodokem-02.

Section numbers in the comments are those of draft-song-lamps-pq-composite-frodokem-02 unless
another document is named. "-23" means draft-ietf-lamps-pq-composite-kem-23, whose RSA-OAEP and
DH-KEM building blocks (its sections 2.1, 2.2, 4 and 6.1) the drafts adopt.

KeyGen, Encaps and Decaps (sections 3.1 to 3.4) and the raw encodings (section 4) work on byte
strings. The SubjectPublicKeyInfo and OneAsymmetricKey wrappings are in compfrodo.pkix.
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x448, x25519
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc8017

from . import frodokem
from .oids import PROTOTYPE_OIDS


class CompositeError(ValueError):
    """An input the drafts do not allow, or a component operation that failed."""


class CompositeAlgorithm(object):
    """One entry of the section 5.1 list."""

    def __init__(self, name, label, frodo, trad, rsa_bits=None):
        self.name = name                    # e.g. "FrodoKEM976-SHAKE-X25519-SHA3-256"
        self.oid_name = "id-" + name
        self.oid = PROTOTYPE_OIDS[self.oid_name]
        self.label = label.encode("ascii")  # the KEM Combiner Label (sections 3.4 and 5.1)
        self.frodo = frodo
        self.trad = trad                    # "RSA", "X25519" or "X448"
        self.rsa_bits = rsa_bits
        if trad == "RSA":
            self.trad_ct_len = rsa_bits // 8
        elif trad == "X25519":
            self.trad_ct_len = 32
        elif trad == "X448":
            self.trad_ct_len = 56
        else:
            raise ValueError(trad)
        self.ct_len = frodo.ct_len + self.trad_ct_len

    def __repr__(self):
        return self.oid_name


# Section 5.1, in the order of TBD1 to TBD8, with the Label each entry gives. The Label of an RSA
# combination names RSA-OAEP ("RSAOAEP3072") where its OID name says "RSA3072".
ALGORITHMS = (
    CompositeAlgorithm("FrodoKEM976-SHAKE-RSA3072-SHA3-256", "FrodoKEM976-SHAKE-RSAOAEP3072",
                       frodokem.FRODOKEM_976_SHAKE, "RSA", 3072),
    CompositeAlgorithm("FrodoKEM976-SHAKE-X25519-SHA3-256", "FrodoKEM976-SHAKE-X25519",
                       frodokem.FRODOKEM_976_SHAKE, "X25519"),
    CompositeAlgorithm("FrodoKEM1344-SHAKE-RSA4096-SHA3-256", "FrodoKEM1344-SHAKE-RSAOAEP4096",
                       frodokem.FRODOKEM_1344_SHAKE, "RSA", 4096),
    CompositeAlgorithm("FrodoKEM1344-SHAKE-X448-SHA3-256", "FrodoKEM1344-SHAKE-X448",
                       frodokem.FRODOKEM_1344_SHAKE, "X448"),
    CompositeAlgorithm("FrodoKEM976-AES-RSA3072-SHA3-256", "FrodoKEM976-AES-RSAOAEP3072",
                       frodokem.FRODOKEM_976_AES, "RSA", 3072),
    CompositeAlgorithm("FrodoKEM976-AES-X25519-SHA3-256", "FrodoKEM976-AES-X25519",
                       frodokem.FRODOKEM_976_AES, "X25519"),
    CompositeAlgorithm("FrodoKEM1344-AES-RSA4096-SHA3-256", "FrodoKEM1344-AES-RSAOAEP4096",
                       frodokem.FRODOKEM_1344_AES, "RSA", 4096),
    CompositeAlgorithm("FrodoKEM1344-AES-X448-SHA3-256", "FrodoKEM1344-AES-X448",
                       frodokem.FRODOKEM_1344_AES, "X448"),
)

BY_NAME = dict((a.oid_name, a) for a in ALGORITHMS)
BY_OID = dict((a.oid, a) for a in ALGORITHMS)


def algorithm(name_or_oid):
    """Look an algorithm up by its OID name ("id-...") or its dotted OID."""
    a = BY_NAME.get(name_or_oid) or BY_OID.get(name_or_oid)
    if a is None:
        raise CompositeError("unknown Composite FrodoKEM algorithm " + repr(name_or_oid))
    return a


# ---------------------------------------------------------------------------
# Traditional components
# ---------------------------------------------------------------------------
#
# Section 4.1 says the RSA trad_pk is "encoded according to [RFC8017]", and the X25519 and X448
# trad_pk is "the raw 32-octet or 56-octet values". Section 4.2 says only that trad_sk is "in its
# native encoding". Following -23 section 4: RSAPublicKey and RSAPrivateKey (version 0, no
# otherPrimeInfos) in DER. For X25519 and X448 the private key is assumed to be the raw 32- or
# 56-byte RFC 7748 value, not an RFC 8410 CurvePrivateKey. The X25519 and X448 ciphertexts are
# raw RFC 7748 public keys (section 2.2 and -23 section 2.2).

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_RSA_SS_LEN = 32    # -23 section 6.1: ss_len = 256 bits


def _der_strict(spec, data, what):
    """Decode data as spec, requiring a single DER value with nothing after it."""
    try:
        obj, rest = der_decoder.decode(data, asn1Spec=spec)
    except Exception as e:
        raise CompositeError("malformed %s: %s" % (what, e))
    if rest:
        raise CompositeError("trailing data after %s" % what)
    if der_encoder.encode(obj) != data:
        raise CompositeError("%s is not DER" % what)
    return obj


def _rsa_public_from_der(alg, data):
    pub = _der_strict(rfc8017.RSAPublicKey(), data, "RSAPublicKey")
    n, e = int(pub["modulus"]), int(pub["publicExponent"])
    _check_rsa_modulus(alg, n)
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError as ex:
        raise CompositeError("invalid RSA public key: %s" % ex)


def _rsa_public_der(n, e):
    pub = rfc8017.RSAPublicKey()
    pub["modulus"] = n
    pub["publicExponent"] = e
    return der_encoder.encode(pub)


def _rsa_private_from_der(alg, data):
    priv = _der_strict(rfc8017.RSAPrivateKey(), data, "RSAPrivateKey")
    if int(priv["version"]) != 0:
        raise CompositeError("RSAPrivateKey version must be 0")
    if priv["otherPrimeInfos"].isValue:
        raise CompositeError("RSAPrivateKey must not carry otherPrimeInfos")
    n, e = int(priv["modulus"]), int(priv["publicExponent"])
    _check_rsa_modulus(alg, n)
    numbers = rsa.RSAPrivateNumbers(
        p=int(priv["prime1"]), q=int(priv["prime2"]), d=int(priv["privateExponent"]),
        dmp1=int(priv["exponent1"]), dmq1=int(priv["exponent2"]), iqmp=int(priv["coefficient"]),
        public_numbers=rsa.RSAPublicNumbers(e, n))
    try:
        key = numbers.private_key()
    except ValueError as ex:
        raise CompositeError("invalid RSA private key: %s" % ex)
    # -23 section 10.4.1: the RSAPublicKey is re-encoded from n and e in the RSAPrivateKey
    return key, _rsa_public_der(n, e)


def _check_rsa_modulus(alg, n):
    # Section 3.3 (and -23 sections 3.3 and 6.1): the modulus is exactly 3072 or 4096 bits
    if n.bit_length() != alg.rsa_bits:
        raise CompositeError("RSA modulus is %d bits, %s requires %d" % (n.bit_length(), alg.oid_name, alg.rsa_bits))


def _x_class(alg):
    return x25519.X25519PrivateKey if alg.trad == "X25519" else x448.X448PrivateKey


def _x_public_class(alg):
    return x25519.X25519PublicKey if alg.trad == "X25519" else x448.X448PublicKey


def _raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _trad_keygen(alg, randombytes):
    """Returns (trad_pk, trad_sk) in the encodings above. An X25519 or X448 private key is
    drawn from randombytes; an RSA key comes from the cryptography package's own generator."""
    if alg.trad == "RSA":
        key = rsa.generate_private_key(public_exponent=65537, key_size=alg.rsa_bits)
        sk = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption())
        nums = key.public_key().public_numbers()
        return _rsa_public_der(nums.n, nums.e), sk
    sk = randombytes(alg.trad_ct_len)
    return _raw(_x_class(alg).from_private_bytes(sk).public_key()), sk


def _trad_encaps(alg, trad_pk, randombytes):
    """TradKEM.Encap(trad_pk) -> (trad_ct, trad_ss): -23 sections 2.1 and 2.2."""
    if alg.trad == "RSA":
        pub = _rsa_public_from_der(alg, trad_pk)
        trad_ss = randombytes(_RSA_SS_LEN)
        return pub.encrypt(trad_ss, _OAEP), trad_ss
    if len(trad_pk) != alg.trad_ct_len:
        raise CompositeError("%s public key must be %d bytes" % (alg.trad, alg.trad_ct_len))
    peer = _x_public_class(alg).from_public_bytes(trad_pk)
    eph = _x_class(alg).from_private_bytes(randombytes(alg.trad_ct_len))
    try:
        # cryptography rejects an all-zero X25519 / X448 output (RFC 7748 section 6)
        trad_ss = eph.exchange(peer)
    except ValueError as e:
        raise CompositeError("%s key agreement failed: %s" % (alg.trad, e))
    return _raw(eph.public_key()), trad_ss


def _trad_private(alg, trad_sk):
    """Decode trad_sk and derive trad_pk from it. Returns (key object, trad_pk)."""
    if alg.trad == "RSA":
        return _rsa_private_from_der(alg, trad_sk)
    if len(trad_sk) != alg.trad_ct_len:
        raise CompositeError("%s private key must be %d bytes" % (alg.trad, alg.trad_ct_len))
    key = _x_class(alg).from_private_bytes(trad_sk)
    return key, _raw(key.public_key())


def _trad_decaps(alg, key, trad_ct):
    """TradKEM.Decap(trad_sk, trad_ct) -> trad_ss: -23 sections 2.1 and 2.2."""
    if alg.trad == "RSA":
        try:
            trad_ss = key.decrypt(trad_ct, _OAEP)
        except ValueError:
            # section 3.3: an explicit error from a component is forwarded to the caller
            raise CompositeError("RSA-OAEP decryption failed")
        # The combiner inputs are fixed length (-23 section 3.3); an OAEP plaintext that is not
        # a 32-byte ss_len value is treated as a decapsulation error.
        if len(trad_ss) != _RSA_SS_LEN:
            raise CompositeError("RSA-OAEP plaintext is %d bytes, expected %d" % (len(trad_ss), _RSA_SS_LEN))
        return trad_ss
    peer = _x_public_class(alg).from_public_bytes(trad_ct)
    try:
        return key.exchange(peer)
    except ValueError as e:
        raise CompositeError("%s key agreement failed: %s" % (alg.trad, e))


# ---------------------------------------------------------------------------
# Serialization (section 4)
# ---------------------------------------------------------------------------

def split_public_key(alg, ek):
    """ek = frodo_pk || trad_pk (sections 3.2 step 1 and 4.1)."""
    n = alg.frodo.pk_len
    if len(ek) <= n:
        raise CompositeError("composite public key too short")
    frodo_pk, trad_pk = ek[:n], ek[n:]
    if alg.trad == "RSA":
        _rsa_public_from_der(alg, trad_pk)
    elif len(trad_pk) != alg.trad_ct_len:
        raise CompositeError("%s public key must be %d bytes" % (alg.trad, alg.trad_ct_len))
    return frodo_pk, trad_pk


def split_private_key(alg, dk):
    """dk = frodo_sk || trad_sk (sections 3.3 step 1 and 4.2)."""
    n = alg.frodo.sk_len
    if len(dk) <= n:
        raise CompositeError("composite private key too short")
    return dk[:n], dk[n:]


def split_ciphertext(alg, ct):
    """ct = frodo_ct || trad_ct (section 3.3 step 2). As section 3.3 requires, the ciphertext
    must be exactly the length the algorithm fixes: the FrodoKEM ciphertext plus the RSA modulus
    size, or 32 / 56 bytes."""
    if len(ct) != alg.ct_len:
        raise CompositeError("%s ciphertext must be %d bytes, got %d" % (alg.oid_name, alg.ct_len, len(ct)))
    n = alg.frodo.ct_len
    return ct[:n], ct[n:]


def public_key_from_private(alg, dk):
    """Rebuild ek from dk: frodo_pk is embedded in the expanded FrodoKEM private key and trad_pk
    is derived from trad_sk (-23 section 10.4)."""
    frodo_sk, trad_sk = split_private_key(alg, dk)
    _, trad_pk = _trad_private(alg, trad_sk)
    return frodokem.public_key_from_private(alg.frodo, frodo_sk) + trad_pk


# ---------------------------------------------------------------------------
# KeyGen, Encaps, Decaps, combiner (sections 3.1 to 3.4)
# ---------------------------------------------------------------------------

def combiner(alg, frodo_ss, trad_ss, trad_ct, trad_pk):
    """Section 3.4: ss = SHA3-256(frodo_ss || trad_ss || trad_ct || trad_pk || Label)."""
    return hashlib.sha3_256(frodo_ss + trad_ss + trad_ct + trad_pk + alg.label).digest()


def keygen(alg, randombytes=os.urandom):
    """Section 3.1. Returns (ek, dk). The FrodoKEM seeds (s, seedSE, z) and then an X25519 or
    X448 private key are drawn from randombytes; an RSA key comes from the cryptography
    package's own generator."""
    frodo_pk, frodo_sk = frodokem.keygen(alg.frodo, randombytes)
    trad_pk, trad_sk = _trad_keygen(alg, randombytes)
    return frodo_pk + trad_pk, frodo_sk + trad_sk


def encaps_detailed(alg, ek, randombytes=os.urandom):
    """Section 3.2, returning the ciphertext, the shared secret and the combiner inputs."""
    frodo_pk, trad_pk = split_public_key(alg, ek)
    frodo_ct, frodo_ss = frodokem.encaps(alg.frodo, frodo_pk, randombytes)
    trad_ct, trad_ss = _trad_encaps(alg, trad_pk, randombytes)
    ss = combiner(alg, frodo_ss, trad_ss, trad_ct, trad_pk)
    return {"ct": frodo_ct + trad_ct, "ss": ss, "frodo_ss": frodo_ss, "trad_ss": trad_ss,
            "trad_ct": trad_ct, "trad_pk": trad_pk, "label": alg.label}


def encaps(alg, ek, randombytes=os.urandom):
    """Section 3.2. Returns (ct, ss)."""
    r = encaps_detailed(alg, ek, randombytes)
    return r["ct"], r["ss"]


def decaps_detailed(alg, dk, ct, ek=None):
    """Section 3.3, returning the shared secret and the combiner inputs.

    The combiner needs trad_pk, which dk does not carry. Section 3.3 allows three sources, those
    of -23 section 10.4. trad_pk is always derived from trad_sk: the RSAPublicKey is re-encoded
    from the RSAPrivateKey (-23 section 10.4.1), and the X25519 / X448 public key is the scalar
    multiple of the base point. If the caller also supplies ek (from a certificate, or from
    OneAsymmetricKey.publicKey), it must match the derived public key."""
    frodo_sk, trad_sk = split_private_key(alg, dk)
    frodo_ct, trad_ct = split_ciphertext(alg, ct)
    key, trad_pk = _trad_private(alg, trad_sk)
    if ek is not None:
        derived = frodokem.public_key_from_private(alg.frodo, frodo_sk) + trad_pk
        if ek != derived:
            raise CompositeError("the supplied public key does not match the private key")
    frodo_ss = frodokem.decaps(alg.frodo, frodo_sk, frodo_ct)
    trad_ss = _trad_decaps(alg, key, trad_ct)
    ss = combiner(alg, frodo_ss, trad_ss, trad_ct, trad_pk)
    return {"ss": ss, "frodo_ss": frodo_ss, "trad_ss": trad_ss, "trad_ct": trad_ct,
            "trad_pk": trad_pk, "label": alg.label}


def decaps(alg, dk, ct, ek=None):
    """Section 3.3. Returns ss."""
    return decaps_detailed(alg, dk, ct, ek)["ss"]
