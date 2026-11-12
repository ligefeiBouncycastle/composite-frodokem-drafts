# Test vectors

These vectors are for the -02 drafts. They were written by
[`../python/generate_vectors.py`](../python/generate_vectors.py), which checks every value with the
Python implementation before it writes it: each ciphertext decapsulates to its shared secret, and
each CMS message opens for each of its recipients.

## Files

| File | Contents |
|------|----------|
| `testvectors.json` | One test case per algorithm, in the JSON layout of Appendix G of draft-ietf-lamps-pq-composite-kem (see below) |
| `combiner-intermediates.txt` | For each test case, the combiner inputs `frodo_ss`, `trad_ss`, `trad_ct`, `trad_pk` and `Label`, and the output `ss` (hex), in the manner of Appendix F of draft-ietf-lamps-pq-composite-kem |
| `cacert.pem` | The ML-DSA-65 CA certificate that issued every `x5c` |
| `cms.json` | 13 CMS messages to the test case keys, with the `tcId`s of their recipients and their content (see [../python/README.md](../python/README.md)) |
| `cms-<alg>-enveloped.pem` | A CMS EnvelopedData (RFC 5652) with one KEMRecipientInfo (RFC 9629). Its content is `Hello, world!`, encrypted with AES-256-CBC |
| `cms-<alg>-recipient-cert.pem`, `cms-<alg>-recipient-key.pem` | The recipient's certificate and its OneAsymmetricKey (RFC 5958), those of the `<alg>` test case |
| `cms-<alg>-kemri.txt` | An ASN.1 dump of that KEMRecipientInfo, with `kemct` shown only by its length |
| `cms-example-authenveloped-frodokem976-shake-x25519.txt` | An AuthEnvelopedData (RFC 5083) example built from fixed inputs, with the originator's and the recipient's intermediate values, in the manner of Appendix B of draft-ietf-lamps-cms-composite-kem |

The EnvelopedData examples are for FrodoKEM976-SHAKE-X25519 and FrodoKEM1344-SHAKE-X448. Both use
HKDF-SHA256 and AES-Wrap-256, as every message here does.

The AuthEnvelopedData example is for FrodoKEM976-SHAKE-X25519, with HKDF-SHA256, AES-Wrap-256 and
AES-256-GCM. Each of its random inputs is derived from a fixed string with SHAKE256, as the file
explains, so a new run of the generator writes it again unchanged, except for the ML-DSA-65
signatures on its two certificates. Its lines are at most 72 characters long.

Everything else is new on each run of the generator, except the key pairs, ciphertexts and shared
secrets when it is run with `--keys` (see below).

### testvectors.json

`cacert` is the base64 DER CA certificate. `tests` holds one object per algorithm. Every value except
`tcId` is base64:

| Field | Contents |
|-------|----------|
| `tcId` | The algorithm name, e.g. `id-FrodoKEM976-SHAKE-X25519-SHA3-256` |
| `ek` | The composite public key, `frodo_pk \|\| trad_pk` (the subjectPublicKey BIT STRING contents) |
| `x5c` | The end-entity certificate carrying `ek` |
| `dk` | The composite private key, `frodo_sk \|\| trad_sk` |
| `dk_pkcs8` | `dk` inside a version 1 OneAsymmetricKey, without `publicKey` |
| `dk_pkcs8_v2` | `dk` inside a version 2 OneAsymmetricKey, with `publicKey` set to `ek` |
| `c` | A ciphertext, `frodo_ct \|\| trad_ct` |
| `k` | The 32-byte shared secret that `c` decapsulates to |

`dk_pkcs8_v2` is not in the Appendix G layout. The other fields are.

### Key encodings

`frodo_sk` is the expanded FrodoKEM private key, `s || seedA || b || S^T || pkh`. An RSA `trad_pk`
is an RSAPublicKey and an RSA `trad_sk` an RSAPrivateKey, both DER. An X25519 or X448 `trad_pk` is
the raw 32- or 56-byte public key.

The drafts do not say how an X25519 or X448 `trad_sk` is encoded. These vectors assume the raw 32-
or 56-byte RFC 7748 private key, not an RFC 8410 CurvePrivateKey.

## Prototype OIDs

The drafts leave the OIDs as TBD1 to TBD8 under id-alg (1.3.6.1.5.5.7.6). Until IANA assigns them,
these vectors use the prototype OIDs listed in the IETF Hackathon
[pqc-certificates OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)
(docs/oid_mapping.md). They will change when the final OIDs are assigned:

| Algorithm | Draft | Prototype OID |
|-----------|-------|---------------|
| id-FrodoKEM976-SHAKE-RSA3072-SHA3-256  | TBD1 | 1.3.6.1.4.1.22554.5.12.1 |
| id-FrodoKEM976-SHAKE-X25519-SHA3-256   | TBD2 | 1.3.6.1.4.1.22554.5.12.2 |
| id-FrodoKEM1344-SHAKE-RSA4096-SHA3-256 | TBD3 | 1.3.6.1.4.1.22554.5.12.3 |
| id-FrodoKEM1344-SHAKE-X448-SHA3-256    | TBD4 | 1.3.6.1.4.1.22554.5.12.4 |
| id-FrodoKEM976-AES-RSA3072-SHA3-256    | TBD5 | 1.3.6.1.4.1.22554.5.12.5 |
| id-FrodoKEM976-AES-X25519-SHA3-256     | TBD6 | 1.3.6.1.4.1.22554.5.12.6 |
| id-FrodoKEM1344-AES-RSA4096-SHA3-256   | TBD7 | 1.3.6.1.4.1.22554.5.12.7 |
| id-FrodoKEM1344-AES-X448-SHA3-256      | TBD8 | 1.3.6.1.4.1.22554.5.12.8 |

The OIDs appear only in the certificates, the OneAsymmetricKey encodings and the CMS messages. They
are not an input to the combiner: the Label is.

Earlier versions of these -02 vectors used other placeholder OIDs, and other Labels for the four
RSA combinations. When the OIDs changed, the vectors were written again with
`generate_vectors.py --keys`, which keeps the key pairs: `ek`, `dk`, `c`, `k` and every combiner
intermediate were unchanged, and only the CA, the certificates, the OneAsymmetricKey encodings and
the CMS messages were new. When the RSA Labels changed to their RSAOAEP form, the vectors were
written again with `generate_vectors.py --relabel`, which keeps everything that does not depend on
a Label. Only `k` of the four RSA test cases, their Label, combiner input length and `ss` in
`combiner-intermediates.txt`, and the `encryptedKey` of each KEMRecipientInfo for those four
algorithms changed.
