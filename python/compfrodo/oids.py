"""Object identifiers.

The drafts leave the Composite FrodoKEM OIDs as TBD1 to TBD8 under id-alg (1.3.6.1.5.5.7.6).
Until IANA assigns them, these prototype OIDs are used, the ones listed in the IETF Hackathon
pqc-certificates OID mapping (docs/oid_mapping.md). They match the vectors in ../vectors and will
change; this table is the only place to edit.
"""

_ARC = "1.3.6.1.4.1.22554.5.12"

PROTOTYPE_OIDS = {
    "id-FrodoKEM976-SHAKE-RSA3072-SHA3-256": _ARC + ".1",   # TBD1
    "id-FrodoKEM976-SHAKE-X25519-SHA3-256": _ARC + ".2",    # TBD2
    "id-FrodoKEM1344-SHAKE-RSA4096-SHA3-256": _ARC + ".3",  # TBD3
    "id-FrodoKEM1344-SHAKE-X448-SHA3-256": _ARC + ".4",     # TBD4
    "id-FrodoKEM976-AES-RSA3072-SHA3-256": _ARC + ".5",     # TBD5
    "id-FrodoKEM976-AES-X25519-SHA3-256": _ARC + ".6",      # TBD6
    "id-FrodoKEM1344-AES-RSA4096-SHA3-256": _ARC + ".7",    # TBD7
    "id-FrodoKEM1344-AES-X448-SHA3-256": _ARC + ".8",       # TBD8
}

# CMS (draft-song-lamps-cms-composite-frodokem-02 section 3, RFC 9629, RFC 8619, RFC 3565)
ID_ORI_KEM = "1.2.840.113549.1.9.16.13.3"
ID_ALG_HKDF_WITH_SHA256 = "1.2.840.113549.1.9.16.3.28"
ID_AES128_WRAP = "2.16.840.1.101.3.4.1.5"
ID_AES192_WRAP = "2.16.840.1.101.3.4.1.25"
ID_AES256_WRAP = "2.16.840.1.101.3.4.1.45"
ID_AES128_CBC = "2.16.840.1.101.3.4.1.2"
ID_AES192_CBC = "2.16.840.1.101.3.4.1.22"
ID_AES256_CBC = "2.16.840.1.101.3.4.1.42"
ID_AES128_GCM = "2.16.840.1.101.3.4.1.6"
ID_AES192_GCM = "2.16.840.1.101.3.4.1.26"
ID_AES256_GCM = "2.16.840.1.101.3.4.1.46"
ID_DATA = "1.2.840.113549.1.7.1"
ID_ENVELOPED_DATA = "1.2.840.113549.1.7.3"
ID_AUTH_ENVELOPED_DATA = "1.2.840.113549.1.9.16.1.23"
