# FrodoKEM known-answer test excerpt

Each `*-count0.rsp` file is the header and the first record (`count = 0`) of the KAT file of the same
name, without `-count0`, in the FrodoKEM team's repository:

- https://github.com/microsoft/PQCrypto-LWEKE, directory `FrodoKEM/KAT/`, commit `e1edeb3af1`

| File | Parameter set |
|------|---------------|
| `PQCkemKAT_31296-count0.rsp` | FrodoKEM-976-AES |
| `PQCkemKAT_31296_shake-count0.rsp` | FrodoKEM-976-SHAKE |
| `PQCkemKAT_43088-count0.rsp` | FrodoKEM-1344-AES |
| `PQCkemKAT_43088_shake-count0.rsp` | FrodoKEM-1344-SHAKE |

Each record's `seed` initialises the NIST AES-256 CTR_DRBG (`../../nist_drbg.py`). KeyGen then draws
`s || seedSE || z` and Encaps draws `u || salt` from it, and the resulting `pk`, `sk`, `ct` and `ss` must
match the record.

These files are taken from that repository and remain under its MIT licence; see `LICENSE-MIT`.
