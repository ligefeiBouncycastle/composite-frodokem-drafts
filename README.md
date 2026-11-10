# Composite FrodoKEM

This repository is for two Internet-Drafts and an independent Python implementation of them:

- **draft-song-lamps-pq-composite-frodokem**: Composite FrodoKEM for use in X.509 Public Key
  Infrastructure.
- **draft-song-lamps-cms-composite-frodokem**: Composite FrodoKEM for use in Cryptographic
  Message Syntax (CMS).

The implementation and the test vectors track the -01 versions of both drafts, dated 30 October 2026.
The draft sources will be added in the [i-d-template](https://github.com/martinthomson/i-d-template)
layout, with each draft as a `draft-*.md` file at the top level.

## Scope

Composite FrodoKEM combines standard (salted) FrodoKEM, as specified in draft-longa-cfrg-frodokem
and ISO/IEC 18033-2:2006/Amd 2:2026, with RSA-OAEP, X25519 or X448. The two drafts define eight
algorithms:

| Algorithm                            | FrodoKEM            | Traditional |
|--------------------------------------|---------------------|-------------|
| id-FrodoKEM976-RSA3072-SHA3-256      | FrodoKEM-976-SHAKE  | RSA-3072    |
| id-FrodoKEM976-X25519-SHA3-256       | FrodoKEM-976-SHAKE  | X25519      |
| id-FrodoKEM1344-RSA4096-SHA3-256     | FrodoKEM-1344-SHAKE | RSA-4096    |
| id-FrodoKEM1344-X448-SHA3-256        | FrodoKEM-1344-SHAKE | X448        |
| id-FrodoKEM976-AES-RSA3072-SHA3-256  | FrodoKEM-976-AES    | RSA-3072    |
| id-FrodoKEM976-AES-X25519-SHA3-256   | FrodoKEM-976-AES    | X25519      |
| id-FrodoKEM1344-AES-RSA4096-SHA3-256 | FrodoKEM-1344-AES   | RSA-4096    |
| id-FrodoKEM1344-AES-X448-SHA3-256    | FrodoKEM-1344-AES   | X448        |

The shared secret is `SHA3-256(frodo_ss || trad_ss || trad_ct || trad_pk || Label)`. This is the
combiner of Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), with the FrodoKEM shared secret in
place of the ML-KEM one.

The OIDs are still TBD1 to TBD8 in the drafts. Until IANA assigns them, the vectors and the code use
unregistered placeholder OIDs; see [vectors/README.md](vectors/README.md).

## Layout

| Path       | Contents                                                                  |
|------------|---------------------------------------------------------------------------|
| `python/`  | The Python implementation and its tests                                   |
| `vectors/` | Test vectors: keys, certificates, ciphertexts, combiner intermediates and CMS |

## Python implementation

`python/` holds a second implementation of the drafts, for interoperability testing. It was written
from the draft text and the specifications the drafts reference. FrodoKEM itself is implemented from
draft-longa-cfrg-frodokem-03 and checked against the FrodoKEM team's known-answer tests. See
[python/README.md](python/README.md).

## Licence

See [LICENSE.md](LICENSE.md).
