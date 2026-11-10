"""Shared helpers for the tests."""

import base64
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.dirname(HERE)
VECTORS = os.path.join(os.path.dirname(PYTHON_DIR), "vectors")
KAT_DIR = os.path.join(HERE, "data", "frodokem-kat")

if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)


def b64(s):
    return base64.b64decode(s)


def pem(path):
    with open(path) as fh:
        lines = fh.read().strip().splitlines()
    return base64.b64decode("".join(l for l in lines if not l.startswith("-----")))


def load_testvectors(directory=VECTORS):
    with open(os.path.join(directory, "testvectors.json")) as fh:
        return json.load(fh)


def load_intermediates(directory=VECTORS):
    """Parse combiner-intermediates.txt into {tcId: {field: bytes, "input_length": int}}."""
    with open(os.path.join(directory, "combiner-intermediates.txt")) as fh:
        text = fh.read()
    result = {}
    for block in re.split(r"\n(?=# id-)", text):
        m = re.match(r"# (id-\S+)", block)
        if not m:
            continue
        fields = {}
        for name, hexval in re.findall(r"^(Label|frodo_ss|trad_ss|trad_ct|trad_pk|ss = SHA3-256\(\.\.\.\))[^\n]*\n  ([0-9a-f]+)$",
                                       block, re.M):
            fields["label" if name == "Label" else ("ss" if name.startswith("ss") else name)] = bytes.fromhex(hexval)
        fields["input_length"] = int(re.search(r"combiner input length: (\d+) bytes", block).group(1))
        result[m.group(1)] = fields
    return result


def load_kat(filename):
    """Read the first record of a NIST KAT .rsp file."""
    rec = {}
    with open(os.path.join(KAT_DIR, filename)) as fh:
        name = fh.readline().lstrip("#").strip()
        for line in fh:
            if " = " in line:
                k, v = line.strip().split(" = ", 1)
                if k == "count" and rec:
                    break
                rec[k] = v
    return name, rec
