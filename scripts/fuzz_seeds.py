#!/usr/bin/env python3
"""The seed corpus of the fuzz targets of spec 016-fuzz-harness (R8), from `specs/vectors/`.

A mutated valid input reaches every step of a parser; a random one stops at the first length
check. So each target starts from every vector that carries its fields, positive and negative
alike, in the input layout of its entry in `fuzz_entry.rs`. Standard library only. The corpus
under `crates/core/fuzz/corpus/` is not committed; the nightly workflow runs this first. The
seeds are written beside whatever the fuzzer already added, which is never deleted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "specs" / "vectors"
CORPUS = ROOT / "crates" / "core" / "fuzz" / "corpus"
PAD_BLOCK = 1_024  # spec 013 R10
POLICY_BYTE = {"ignore": b"\x00", "reject": b"\x01"}  # spec 016 R3


def load(spec: str) -> list[dict]:
    return json.loads((VECTORS / f"{spec}.json").read_text(encoding="utf-8"))["vectors"]


def field(vector: dict, name: str) -> bytes | None:
    """A hexadecimal field of the vector's inputs, or else of its expected values."""
    value = vector["inputs"].get(name, vector["expected"].get(name))
    return None if value is None else bytes.fromhex(value)


def unpad(padded: bytes) -> bytes | None:
    """The record before the 0x80 marker of `sodium_pad`, or `None` for broken padding: as
    libsodium's `sodium_unpad`, the marker must sit in the last block."""
    marked = padded.rstrip(b"\x00")
    in_last_block = len(padded) >= PAD_BLOCK and len(padded) - len(marked) < PAD_BLOCK
    return marked[:-1] if marked.endswith(b"\x80") and in_last_block else None


def payload_record(v: dict) -> bytes | None:
    """The payload record of a 013 vector: the one it declares, or its padded one unpadded."""
    padded = field(v, "padded")
    return field(v, "payload") if padded is None else unpad(padded)


def padded_payload(v: dict) -> bytes:
    """The padded plaintext of a positive 013 vector."""
    padded = field(v, "padded")
    if padded is not None:
        return padded
    marked = field(v, "payload") + b"\x80"
    return marked + bytes(-len(marked) % PAD_BLOCK)


def times(v: dict) -> bytes:
    return field(v, "received_at") + field(v, "now")


# R8, one row per target: the vector file, which of its vectors carry the row's fields, and
# the seed of such a vector in the layout of the target's entry (R3–R5).
Seed = Callable[[dict], bytes]
TARGETS: dict[str, tuple[str, Callable[[dict], bool], Seed]] = {
    "record_decode": ("017", lambda v: True,
                      lambda v: POLICY_BYTE[v["inputs"]["policy"]] + field(v, "record")),
    "config_parse": ("011", lambda v: "record" in v["inputs"], lambda v: field(v, "record")),
    "config_parse_qr": ("011", lambda v: "qr" in v["inputs"], lambda v: field(v, "qr")),
    "payload_decode": ("013", lambda v: payload_record(v) is not None, payload_record),
    "receive": ("013", lambda v: True, lambda v: times(v) + field(v, "blob")),
    "receive_signed": ("013", lambda v: v["kind"] == "positive",
                       lambda v: field(v, "counter") + field(v, "nonce") + times(v)
                       + padded_payload(v)),
    "verify_qr_parse": ("014", lambda v: field(v, "qr") is not None, lambda v: field(v, "qr")),
}


def read_back(target: str, seed: bytes) -> dict[str, bytes]:
    """The fields a seed holds, cut by the layout of R3–R5 as `fuzz_entry.rs` reads it."""
    if target == "record_decode":
        return {"policy": seed[:1], "record": seed[1:]}
    if target == "receive":
        return {"received_at": seed[:8], "now": seed[8:16], "blob": seed[16:]}
    if target == "receive_signed":
        return {"counter": seed[:8], "nonce": seed[8:32], "received_at": seed[32:40],
                "now": seed[40:48], "padded": seed[48:]}
    return {"whole": seed}


def vector_fields(target: str, v: dict) -> dict[str, bytes | None]:
    """The fields of a vector that its seed must hold, by the names of `read_back`."""
    if target == "record_decode":
        return {"policy": POLICY_BYTE[v["inputs"]["policy"]], "record": field(v, "record")}
    if target == "receive":
        return {"received_at": field(v, "received_at"), "now": field(v, "now"),
                "blob": field(v, "blob")}
    if target == "receive_signed":
        return {"counter": field(v, "counter"), "nonce": field(v, "nonce"),
                "received_at": field(v, "received_at"), "now": field(v, "now"),
                "padded": field(v, "padded")}
    whole = {"config_parse": "record", "config_parse_qr": "qr", "payload_decode": "payload",
             "verify_qr_parse": "qr"}[target]
    return {"whole": field(v, whole)}


# How many vectors seed each target, counted once by hand from the frozen files: the filters of
# `TARGETS` are checked against it, so that a narrowed filter that drops seeds fails here.
SEED_COUNTS = {"record_decode": 23, "config_parse": 27, "config_parse_qr": 32,
               "payload_decode": 17, "receive": 30, "receive_signed": 18, "verify_qr_parse": 6}


def check_s016_t08_r08_corpus_is_seeded() -> None:
    """Each target's directory holds one file per vector that carries its row's fields, and
    each file, cut by its layout, gives the vector's own fields back."""
    for target, (spec, carries, _) in TARGETS.items():
        vectors = [v for v in load(spec) if carries(v)]
        if len(vectors) != SEED_COUNTS.get(target):
            raise SystemExit(f"fuzz_seeds.py: {target}: {len(vectors)} seeds, not "
                             f"{SEED_COUNTS.get(target)}")
        for v in vectors:
            fields = read_back(target, (CORPUS / target / v["name"]).read_bytes())
            expected = vector_fields(target, v)
            for name, value in expected.items():
                if value is None:
                    continue  # derived from another field: the padded or unpadded form
                if fields[name] != value:
                    raise SystemExit(f"fuzz_seeds.py: {target}/{v['name']}: {name} differs")
            if target == "payload_decode" and field(v, "payload") is None:
                if unpad(field(v, "padded")) != fields["whole"]:
                    raise SystemExit(f"fuzz_seeds.py: {target}/{v['name']}: not the record")
            if target == "receive_signed" and (len(fields["padded"]) % PAD_BLOCK or (
                    field(v, "padded") is None
                    and unpad(fields["padded"]) != field(v, "payload"))):
                raise SystemExit(f"fuzz_seeds.py: {target}/{v['name']}: not its padded payload")


def main() -> int:
    counts = []
    for target, (spec, carries, seed) in TARGETS.items():
        directory = CORPUS / target
        directory.mkdir(parents=True, exist_ok=True)
        vectors = [v for v in load(spec) if carries(v)]
        for v in vectors:
            (directory / v["name"]).write_bytes(seed(v))
        counts.append(f"{target} {len(vectors)}")
    check_s016_t08_r08_corpus_is_seeded()
    print(f"fuzz_seeds.py: ok, {', '.join(counts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
