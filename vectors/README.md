# Test vectors

These vectors were generated with Gefei Li's Java prototype of the -01 drafts. Every value was
checked when it was written: each ciphertext decapsulates to its shared secret, and the shared secret
was recomputed from the component primitives.

## Files

| File | Contents |
|------|----------|
| `testvectors.json` | One test case per algorithm, in the JSON layout of Appendix G of draft-ietf-lamps-pq-composite-kem (see below) |
| `combiner-intermediates.txt` | For each test case, the combiner inputs `frodo_ss`, `trad_ss`, `trad_ct`, `trad_pk` and `Label`, and the output `ss` (hex), in the manner of Appendix F of draft-ietf-lamps-pq-composite-kem |
| `cacert.pem` | The ML-DSA-65 CA certificate that issued every `x5c` |
| `cms-<alg>-enveloped.pem` | A CMS EnvelopedData (RFC 5652) with one KEMRecipientInfo (RFC 9629). Its content is `Hello, world!`, encrypted with AES-256-CBC |
| `cms-<alg>-recipient-cert.pem`, `cms-<alg>-recipient-key.pem` | The recipient's certificate and its OneAsymmetricKey (RFC 5958) |
| `cms-<alg>-kemri.txt` | An ASN.1 dump of that KEMRecipientInfo, with `kemct` shown only by its length |

The CMS examples are for FrodoKEM976-X25519, with HKDF-SHA256 and AES-Wrap-192, and for
FrodoKEM1344-X448, with HKDF-SHA256 and AES-Wrap-256.

### testvectors.json

`cacert` is the base64 DER CA certificate. `tests` holds one object per algorithm. Every value except
`tcId` is base64:

| Field | Contents |
|-------|----------|
| `tcId` | The algorithm name, e.g. `id-FrodoKEM976-X25519-SHA3-256` |
| `ek` | The composite public key, `frodo_pk \|\| trad_pk` (the subjectPublicKey BIT STRING contents) |
| `x5c` | The end-entity certificate carrying `ek` |
| `dk` | The composite private key, `frodo_sk \|\| trad_sk` |
| `dk_pkcs8` | `dk` inside a OneAsymmetricKey |
| `c` | A ciphertext, `frodo_ct \|\| trad_ct` |
| `k` | The 32-byte shared secret that `c` decapsulates to |

## Placeholder OIDs

The drafts leave the OIDs as TBD1 to TBD8 under id-alg (1.3.6.1.5.5.7.6). Until IANA assigns them,
these vectors use the following **unregistered placeholders**, which will change:

| Algorithm | Draft | Placeholder OID |
|-----------|-------|-----------------|
| id-FrodoKEM976-RSA3072-SHA3-256      | TBD1 | 2.25.244012452097848048867364395212826631944.1 |
| id-FrodoKEM976-X25519-SHA3-256       | TBD2 | 2.25.244012452097848048867364395212826631944.2 |
| id-FrodoKEM1344-RSA4096-SHA3-256     | TBD3 | 2.25.244012452097848048867364395212826631944.3 |
| id-FrodoKEM1344-X448-SHA3-256        | TBD4 | 2.25.244012452097848048867364395212826631944.4 |
| id-FrodoKEM976-AES-RSA3072-SHA3-256  | TBD5 | 2.25.244012452097848048867364395212826631944.5 |
| id-FrodoKEM976-AES-X25519-SHA3-256   | TBD6 | 2.25.244012452097848048867364395212826631944.6 |
| id-FrodoKEM1344-AES-RSA4096-SHA3-256 | TBD7 | 2.25.244012452097848048867364395212826631944.7 |
| id-FrodoKEM1344-AES-X448-SHA3-256    | TBD8 | 2.25.244012452097848048867364395212826631944.8 |

The OIDs appear only in the certificates, the OneAsymmetricKey encodings and the CMS examples. They
are not an input to the combiner: the Label is.
