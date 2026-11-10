# compfrodo: a Python implementation of Composite FrodoKEM

This is an implementation of draft-song-lamps-pq-composite-frodokem-01 (X.509) and
draft-song-lamps-cms-composite-frodokem-01 (CMS), written for interoperability testing. It is not
constant time and is not meant for production use.

| Module | Contents |
|--------|----------|
| `compfrodo/frodokem.py` | Standard (salted) FrodoKEM-976 and FrodoKEM-1344, AES and SHAKE, written from draft-longa-cfrg-frodokem-03 |
| `compfrodo/composite.py` | The eight algorithms: KeyGen, Encaps, Decaps, the combiner, and the key and ciphertext encodings |
| `compfrodo/pkix.py` | SubjectPublicKeyInfo, OneAsymmetricKey and certificate handling |
| `compfrodo/cms.py` | KEMRecipientInfo (RFC 9629), inside a minimal EnvelopedData / AuthEnvelopedData |
| `compfrodo/ber.py` | Rewrites indefinite BER lengths as definite ones before decoding |
| `compfrodo/oids.py` | OIDs, including the placeholder Composite FrodoKEM OIDs |

## Requirements

Tested with Python 3.11, with `cryptography` 44.0.0 and 50.0.2. It needs:

```
pip install -r requirements.txt
```

The ML-DSA-65 signatures on the test certificates are verified only when the installed
`cryptography` package supports ML-DSA. 50.0.2 with OpenSSL 4.0.3 does; older versions skip that
test, and `generate_vectors.py` needs ML-DSA too (see below).

## Running the tests

From this directory:

```
python3 -m unittest discover -s tests -v
```

The suite takes about a minute and a half, or about a minute when `cryptography` has no ML-DSA and
the tests that need it are skipped. It covers:

- `test_frodokem.py`: FrodoKEM against the first record of the FrodoKEM team's KAT files for all four
  parameter sets, using the NIST AES-256 CTR_DRBG. It also checks wrong lengths and implicit rejection.
- `test_vectors.py`: every case in `../vectors/testvectors.json`. Decaps must give `k`, and every
  combiner intermediate in `../vectors/combiner-intermediates.txt` must match byte for byte. It also
  covers the OneAsymmetricKey and SubjectPublicKeyInfo encodings, the certificates, and the
  ciphertext-length and RSA modulus checks.
- `test_roundtrip.py`: KeyGen, encodings, Encaps and Decaps for all eight algorithms, plus tampered
  ciphertexts.
- `test_cms.py`: the two CMS examples in `../vectors`, CMS round trips for all eight algorithms,
  and the KEMRecipientInfo field checks (version, kem, kdf, kekLength, wrap, ukm, rid).
- `test_generate.py`: runs `generate_vectors.py` and reads its output back. It is skipped when
  `cryptography` has no ML-DSA.

## Generating vectors for another implementation

`../vectors` was written by the Java prototype; `generate_vectors.py` writes the same kind of
vectors from this implementation, so another implementation can be checked against it:

```
python3 generate_vectors.py OUTPUT_DIR
```

It takes about 25 seconds and needs a `cryptography` package with ML-DSA (tested with 50.0.2),
because a fresh ML-DSA-65 CA issues the certificates. Every run makes new keys. Each value is
checked with this implementation before it is written. It writes two files:

- `testvectors.json`: one test case per algorithm, in the layout of `../vectors/testvectors.json`
  (see [../vectors/README.md](../vectors/README.md)), with one more field, `dk_pkcs8_v2`: the
  private key as a version 2 OneAsymmetricKey that also carries the public key.
- `cms.json`: a list of 13 CMS messages, each an object with `label`, `recipients` (the `tcId`s of
  the test cases whose keys can open it), `content` and `cms` (both base64; `cms` is a DER
  ContentInfo). The content is always `Hello, world!`. The messages are:
  - EnvelopedData with AES-256-CBC, the default wrap and an issuerAndSerialNumber rid, one for each
    algorithm.
  - EnvelopedData with a subjectKeyIdentifier rid, one with a ukm, and one with AES-Wrap-256 for a
    FrodoKEM-976 composite.
  - AuthEnvelopedData with AES-256-GCM.
  - EnvelopedData with two recipients.

Output from this script has been read back by the Java prototype. Every certificate verified, the
SubjectPublicKeyInfo and version 1 OneAsymmetricKey encodings re-encoded to the same bytes, the
version 2 encoding was accepted, every ciphertext decapsulated to `k`, and every message decrypted
to its content.

## Choices this implementation makes

- **trad_pk in Decaps.** It is derived from trad_sk, as in draft-ietf-lamps-pq-composite-kem-23
  sections 3.3 and 10.4. The RSAPublicKey is re-encoded from the RSAPrivateKey; the X25519 or X448
  public key is computed from the private key. A public key supplied with the private key, from a
  certificate or OneAsymmetricKey.publicKey, must match the derived one.
- **Traditional components.** RSA-OAEP uses SHA-256, MGF1-SHA-256, an empty label and a 32-byte
  secret, as in draft-ietf-lamps-pq-composite-kem-23 section 6.1. RSA keys are RSAPublicKey and
  RSAPrivateKey (version 0) in DER. X25519 and X448 keys and ciphertexts are raw RFC 7748 values.
- **Labels.** Each Label is the algorithm name without "id-" and "-SHA3-256", e.g.
  "FrodoKEM976-AES-X25519".
- **Decaps input checks.** The ciphertext must be exactly the algorithm's length: the FrodoKEM
  ciphertext plus 384 or 512 bytes for RSA, 32 for X25519, or 56 for X448. The RSA modulus must be
  exactly 3072 or 4096 bits.
- **CMS key wrap.** Accepted: AES-Wrap-192 or AES-Wrap-256 with FrodoKEM-976, and AES-Wrap-256 with
  FrodoKEM-1344. When the caller names none, AES-Wrap-192 or AES-Wrap-256 is used (draft section
  2.1). kekLength must match the wrap algorithm. The KDF is HKDF-SHA256 with an empty salt.
- **OneAsymmetricKey.** Written as version 1 with no publicKey by default, or as version 2 with
  the composite public key on request. Both versions are read.
