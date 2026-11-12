# compfrodo: a Python implementation of Composite FrodoKEM

This is an implementation of draft-song-lamps-pq-composite-frodokem-02 (X.509) and
draft-song-lamps-cms-composite-frodokem-02 (CMS), written for interoperability testing. It wrote the
vectors in `../vectors`. It is not constant time and is not meant for production use.

| Module | Contents |
|--------|----------|
| `compfrodo/frodokem.py` | Standard (salted) FrodoKEM-976 and FrodoKEM-1344, AES and SHAKE, written from draft-longa-cfrg-frodokem-03 |
| `compfrodo/composite.py` | The eight algorithms: KeyGen, Encaps, Decaps, the combiner, and the key and ciphertext encodings |
| `compfrodo/pkix.py` | SubjectPublicKeyInfo, OneAsymmetricKey and certificate handling |
| `compfrodo/cms.py` | KEMRecipientInfo (RFC 9629), inside a minimal EnvelopedData / AuthEnvelopedData |
| `compfrodo/ber.py` | Rewrites indefinite BER lengths as definite ones before decoding |
| `compfrodo/oids.py` | OIDs, including the prototype Composite FrodoKEM OIDs |

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

The suite takes about 100 seconds, or about 70 seconds when `cryptography` has no ML-DSA and the
tests that need it are skipped. It covers:

- `test_frodokem.py`: FrodoKEM against the first record of the FrodoKEM team's KAT files for all four
  parameter sets, using the NIST AES-256 CTR_DRBG. It also checks wrong lengths and implicit rejection.
- `test_vectors.py`: every case in `../vectors/testvectors.json`. Decaps must give `k`, and every
  combiner intermediate in `../vectors/combiner-intermediates.txt` must match byte for byte. It also
  covers the OneAsymmetricKey and SubjectPublicKeyInfo encodings, the certificates, and the
  ciphertext-length and RSA modulus checks.
- `test_roundtrip.py`: KeyGen, encodings, Encaps and Decaps for all eight algorithms, plus tampered
  ciphertexts.
- `test_cms.py`: the two EnvelopedData examples and the 13 messages in `../vectors/cms.json`, CMS
  round trips for all eight algorithms, and the KEMRecipientInfo field checks (version, kem, kdf,
  kekLength, wrap, ukm, rid).
- `test_cms_example.py`: the AuthEnvelopedData example in `../vectors`. Every value printed in it
  is recomputed from its fixed inputs with hashlib, hmac and the `cryptography` package's X25519,
  AES key wrap and AES-GCM, not through this implementation's composite and CMS code.
- `test_generate.py`: runs `generate_vectors.py`, reads its output back, and checks that the
  AuthEnvelopedData example comes out as in `../vectors` apart from the certificate signatures. It
  is skipped when `cryptography` has no ML-DSA.

## Generating the vectors

`../vectors` holds the output of one run of `generate_vectors.py`:

```
python3 generate_vectors.py OUTPUT_DIR
```

It takes about 25 seconds and needs a `cryptography` package with ML-DSA (tested with 50.0.2),
because ML-DSA-65 CAs issue the certificates. Each value is checked with this implementation before
it is written. The files are described in [../vectors/README.md](../vectors/README.md). Every run
makes new keys, ciphertexts and messages, except for the AuthEnvelopedData example: its random
inputs are fixed, so a new run writes it again unchanged, apart from the two certificate
signatures, which ML-DSA-65 hedges.

With `--keys`, the key pairs, ciphertexts and shared secrets are read from an earlier
`testvectors.json` instead of being generated, and checked before they are used. The CA, the
certificates, the OneAsymmetricKey encodings and the CMS messages are still made anew. This moves
the vectors to new OIDs without changing their key material:

```
python3 generate_vectors.py OUTPUT_DIR --keys OLD/testvectors.json
```

With `--relabel`, everything is read from an earlier output directory, and only the values that
depend on a KEM Combiner Label are computed again, with the Labels this implementation now uses:
`k`, the combiner `ss`, and the `encryptedKey` of each KEMRecipientInfo, which wraps the same CEK
under the KEK of the new shared secret. The earlier Labels are read from the earlier
`combiner-intermediates.txt`. Every other value is kept, and checked first: the certificates, the
key encodings, the ciphertexts, the CEKs, the IVs and nonces, and every value of an algorithm whose
Label is unchanged. This follows a change of Labels:

```
python3 generate_vectors.py OUTPUT_DIR --relabel OLD
```

`cms.json` lists 13 CMS messages, each an object with `label`, `recipients` (the `tcId`s of the
test cases whose keys can open it), `content` and `cms` (both base64; `cms` is a DER ContentInfo).
The content is always `Hello, world!`, and the key wrap is always AES-Wrap-256. The messages are:

- EnvelopedData with AES-256-CBC and an issuerAndSerialNumber rid, one for each algorithm.
- EnvelopedData with a subjectKeyIdentifier rid, and one with a ukm.
- AuthEnvelopedData with AES-256-GCM, for id-FrodoKEM976-SHAKE-X25519-SHA3-256 and for
  id-FrodoKEM1344-AES-RSA4096-SHA3-256.
- EnvelopedData with two recipients.

## Choices this implementation makes

- **trad_pk in Decaps.** Section 3.3 allows three sources. It is always derived from trad_sk: the
  RSAPublicKey is re-encoded from the RSAPrivateKey, and the X25519 or X448 public key is computed
  from the private key. A public key supplied with the private key, from a certificate or
  OneAsymmetricKey.publicKey, must match the derived one.
- **Traditional components.** RSA-OAEP uses SHA-256, MGF1-SHA-256, an empty label and a 32-byte
  secret (section 2.2). RSA keys are RSAPublicKey and RSAPrivateKey (version 0) in DER, as in
  draft-ietf-lamps-pq-composite-kem-23 section 4. X25519 and X448 public keys and ciphertexts are
  raw RFC 7748 values (section 4.1).
- **X25519 and X448 private keys.** Section 4.2 says only that trad_sk is "in its native
  encoding". This implementation assumes the raw 32- or 56-byte RFC 7748 private key, not an RFC
  8410 CurvePrivateKey, so dk ends with exactly 32 or 56 bytes after the FrodoKEM private key.
- **Labels.** As listed in section 5.1, e.g. "FrodoKEM976-SHAKE-X25519" and
  "FrodoKEM976-AES-X25519". The Label of an RSA combination names RSA-OAEP where the OID name says
  RSA: "FrodoKEM976-SHAKE-RSAOAEP3072" for id-FrodoKEM976-SHAKE-RSA3072-SHA3-256.
- **Decaps input checks.** The ciphertext must be exactly the algorithm's length: the FrodoKEM
  ciphertext plus 384 or 512 bytes for RSA, 32 for X25519, or 56 for X448. The RSA modulus must be
  exactly 3072 or 4096 bits.
- **CMS key wrap.** AES-Wrap-256, for all eight algorithms, is both the default and the only key
  wrap accepted. CMS draft section 2.1 makes it mandatory for all eight and allows others, but
  section 2.2 sets a 256-bit minimum for the key-encryption strength with FrodoKEM-976 as well, so
  AES-Wrap-192 is refused. kekLength must match the wrap algorithm. The KDF is HKDF-SHA256 with an
  empty salt (section 2.2.1).
- **OneAsymmetricKey.** Written as version 1 with no publicKey by default, or as version 2 with
  the composite public key on request. Both versions are read.
