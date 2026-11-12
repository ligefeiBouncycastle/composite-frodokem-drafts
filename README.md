# Composite FrodoKEM

This repository is for two Internet-Drafts and an independent Python implementation of them:

- **draft-song-lamps-pq-composite-frodokem**: Composite FrodoKEM for use in X.509 Public Key
  Infrastructure.
- **draft-song-lamps-cms-composite-frodokem**: Composite FrodoKEM for use in Cryptographic
  Message Syntax (CMS).

The implementation and the test vectors track the -02 versions of both drafts, dated 10 November
2026. The draft sources will be added in the
[i-d-template](https://github.com/martinthomson/i-d-template) layout, with each draft as a
`draft-*.md` file at the top level.

## Scope

Composite FrodoKEM combines standard (salted) FrodoKEM, as specified in draft-longa-cfrg-frodokem
and ISO/IEC 18033-2:2006/Amd 2:2026, with RSA-OAEP, X25519 or X448. The two drafts define eight
algorithms:

| Algorithm                              | FrodoKEM            | Traditional | Label (Section 5.1)            |
|----------------------------------------|---------------------|-------------|--------------------------------|
| id-FrodoKEM976-SHAKE-RSA3072-SHA3-256  | FrodoKEM-976-SHAKE  | RSA-3072    | FrodoKEM976-SHAKE-RSAOAEP3072  |
| id-FrodoKEM976-SHAKE-X25519-SHA3-256   | FrodoKEM-976-SHAKE  | X25519      | FrodoKEM976-SHAKE-X25519       |
| id-FrodoKEM1344-SHAKE-RSA4096-SHA3-256 | FrodoKEM-1344-SHAKE | RSA-4096    | FrodoKEM1344-SHAKE-RSAOAEP4096 |
| id-FrodoKEM1344-SHAKE-X448-SHA3-256    | FrodoKEM-1344-SHAKE | X448        | FrodoKEM1344-SHAKE-X448        |
| id-FrodoKEM976-AES-RSA3072-SHA3-256    | FrodoKEM-976-AES    | RSA-3072    | FrodoKEM976-AES-RSAOAEP3072    |
| id-FrodoKEM976-AES-X25519-SHA3-256     | FrodoKEM-976-AES    | X25519      | FrodoKEM976-AES-X25519         |
| id-FrodoKEM1344-AES-RSA4096-SHA3-256   | FrodoKEM-1344-AES   | RSA-4096    | FrodoKEM1344-AES-RSAOAEP4096   |
| id-FrodoKEM1344-AES-X448-SHA3-256      | FrodoKEM-1344-AES   | X448        | FrodoKEM1344-AES-X448          |

The shared secret is `SHA3-256(frodo_ss || trad_ss || trad_ct || trad_pk || Label)`. This is the
combiner of Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), with the FrodoKEM shared secret in
place of the ML-KEM one. The Label is the one the table gives. For X25519 and X448 it is the
algorithm name without "id-" and "-SHA3-256"; for RSA it names RSA-OAEP, as in Composite ML-KEM, so
id-FrodoKEM976-SHAKE-RSA3072-SHA3-256 has the Label "FrodoKEM976-SHAKE-RSAOAEP3072". In CMS, the
key-encryption key always wraps with AES-Wrap-256.

The OIDs are still TBD1 to TBD8 in the drafts. Until IANA assigns them, the vectors and the code use
the prototype OIDs listed in the IETF Hackathon
[pqc-certificates OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md);
see [vectors/README.md](vectors/README.md).

## Layout

| Path       | Contents                                                                  |
|------------|---------------------------------------------------------------------------|
| `python/`  | The Python implementation and its tests                                   |
| `vectors/` | Test vectors: keys, certificates, ciphertexts, combiner intermediates and CMS messages |

## Python implementation

`python/` holds an implementation of the drafts for interoperability testing, and the script that
wrote the vectors. It was written from the draft text and the specifications the drafts reference.
FrodoKEM itself is implemented from draft-longa-cfrg-frodokem-03 and checked against the FrodoKEM
team's known-answer tests. See [python/README.md](python/README.md).

## Licence

See [LICENSE.md](LICENSE.md).
