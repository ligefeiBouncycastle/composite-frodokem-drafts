"""Rewrite a BER encoding with every indefinite length replaced by a definite one.

CMS messages are often BER with indefinite lengths (RFC 5652 allows it), and pyasn1 cannot
decode an indefinite-length value inside an ANY. Tags and primitive contents are copied
unchanged; only the length octets of constructed values change.
"""


class BERError(ValueError):
    pass


def _length_octets(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _read_tag(data, pos):
    start = pos
    if pos >= len(data):
        raise BERError("truncated tag")
    first = data[pos]
    pos += 1
    if first & 0x1F == 0x1F:
        while True:
            if pos >= len(data):
                raise BERError("truncated tag")
            b = data[pos]
            pos += 1
            if not b & 0x80:
                break
    return data[start:pos], bool(first & 0x20), pos


def _read_length(data, pos):
    if pos >= len(data):
        raise BERError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        return None, pos
    count = first & 0x7F
    if count > 8 or pos + count > len(data):
        raise BERError("bad length")
    return int.from_bytes(data[pos:pos + count], "big"), pos + count


def _element(data, pos, depth):
    if depth > 64:
        raise BERError("nesting too deep")
    tag, constructed, pos = _read_tag(data, pos)
    length, pos = _read_length(data, pos)
    if length is None:
        if not constructed:
            raise BERError("indefinite length on a primitive value")
        parts = []
        while True:
            if data[pos:pos + 2] == b"\x00\x00":
                pos += 2
                break
            part, pos = _element(data, pos, depth + 1)
            parts.append(part)
        body = b"".join(parts)
    else:
        end = pos + length
        if end > len(data):
            raise BERError("value runs past the end of the data")
        if constructed:
            parts = []
            p = pos
            while p < end:
                part, p = _element(data, p, depth + 1)
                parts.append(part)
            if p != end:
                raise BERError("constructed value overruns its length")
            body = b"".join(parts)
        else:
            body = data[pos:end]
        pos = end
    return tag + _length_octets(len(body)) + body, pos


def definite(data):
    """Returns data with all lengths definite. Rejects trailing bytes."""
    out, pos = _element(bytes(data), 0, 0)
    if pos != len(data):
        raise BERError("trailing data")
    return out
