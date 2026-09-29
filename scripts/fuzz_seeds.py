#!/usr/bin/env python3
"""The seed corpus of the fuzz targets of spec 016-fuzz-harness (R8), from `specs/vectors/`.

A mutated valid input reaches every step of a parser; a random one stops at the first length
check. So each target starts from every vector that carries its fields, positive and negative
alike, in the input layout of its entry in `fuzz_entry.rs`. Standard library only; the corpus
under `crates/core/fuzz/corpus/` is not committed, and the nightly workflow runs this first.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "specs" / "vectors"
CORPUS = ROOT / "crates" / "core" / "fuzz" / "corpus"
PAD_BLOCK = 1_024  # spec 013 R10
POLICY_BYTE = {"ignore": b"\x00", "reject": b"\x01"}  # spec 016 R3


def load(spec: str) -> list[dict]:
    return json.loads((VECTORS / f"{spec}.json").read_text(encoding="utf-8"))["vectors"]


def field(vector: dict, name: str) -> str | None:
    """A field of the vector's inputs, or else of its expected values."""
    return vector["inputs"].get(name, vector["expected"].get(name))


def u64(hex_value: str) -> bytes:
    data = bytes.fromhex(hex_value)
    if len(data) != 8:
        raise SystemExit(f"fuzz_seeds.py: a u64 of {len(data)} bytes")
    return data


def sodium_pad(data: bytes) -> bytes:
    marked = data + b"\x80"
    return marked + bytes(-len(marked) % PAD_BLOCK)


def unpad(padded: bytes) -> bytes | None:
    """The record before the 0x80 marker, or `None` when the padding is broken."""
    marked = padded.rstrip(b"\x00")
    return marked[:-1] if marked.endswith(b"\x80") else None


def record_decode() -> dict[str, bytes]:
    return {v["name"]: POLICY_BYTE[v["inputs"]["policy"]] + bytes.fromhex(v["inputs"]["record"])
            for v in load("017")}


def config_parse() -> dict[str, bytes]:
    return {v["name"]: bytes.fromhex(v["inputs"]["record"]) for v in load("011")
            if "record" in v["inputs"]}


def config_parse_qr() -> dict[str, bytes]:
    return {v["name"]: bytes.fromhex(v["inputs"]["qr"]) for v in load("011") if "qr" in v["inputs"]}


def payload_decode() -> dict[str, bytes]:
    seeds = {}
    for v in load("013"):
        if "payload" in v["expected"]:
            seeds[v["name"]] = bytes.fromhex(v["expected"]["payload"])
        elif "padded" in v["inputs"] and unpad(bytes.fromhex(v["inputs"]["padded"])) is not None:
            seeds[v["name"]] = unpad(bytes.fromhex(v["inputs"]["padded"]))
    return seeds


def receive() -> dict[str, bytes]:
    return {v["name"]: u64(v["inputs"]["received_at"]) + u64(v["inputs"]["now"])
            + bytes.fromhex(field(v, "blob")) for v in load("013")}


def receive_signed() -> dict[str, bytes]:
    seeds = {}
    for v in load("013"):
        if v["kind"] != "positive":
            continue
        inputs = v["inputs"]
        padded = (bytes.fromhex(inputs["padded"]) if "padded" in inputs
                  else sodium_pad(bytes.fromhex(v["expected"]["payload"])))
        seeds[v["name"]] = (u64(inputs["counter"]) + bytes.fromhex(inputs["nonce"])
                            + u64(inputs["received_at"]) + u64(inputs["now"]) + padded)
    return seeds


def verify_qr_parse() -> dict[str, bytes]:
    return {v["name"]: bytes.fromhex(field(v, "qr")) for v in load("014") if field(v, "qr")}


# R8, one row per target: the seeds, and the vectors of the file that carry the row's fields.
TARGETS = {
    "record_decode": (record_decode, "017", lambda v: True),
    "config_parse": (config_parse, "011", lambda v: "record" in v["inputs"]),
    "config_parse_qr": (config_parse_qr, "011", lambda v: "qr" in v["inputs"]),
    "payload_decode": (payload_decode, "013", lambda v: "payload" in v["expected"] or (
        "padded" in v["inputs"] and unpad(bytes.fromhex(v["inputs"]["padded"])) is not None)),
    "receive": (receive, "013", lambda v: True),
    "receive_signed": (receive_signed, "013", lambda v: v["kind"] == "positive"),
    "verify_qr_parse": (verify_qr_parse, "014", lambda v: field(v, "qr") is not None),
}


def check_s016_t08_r08_corpus_is_seeded() -> None:
    """Each target's directory holds one file per vector that carries its row's fields."""
    for target, (_, spec, carries) in TARGETS.items():
        expected = sorted(v["name"] for v in load(spec) if carries(v))
        written = sorted(path.name for path in (CORPUS / target).iterdir())
        if not expected or written != expected:
            raise SystemExit(f"fuzz_seeds.py: {target}: {written} for {expected}")


def main() -> int:
    for target, (seeds, _, _) in TARGETS.items():
        directory = CORPUS / target
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for name, data in seeds().items():
            (directory / name).write_bytes(data)
    check_s016_t08_r08_corpus_is_seeded()
    counts = ", ".join(f"{target} {len(list((CORPUS / target).iterdir()))}" for target in TARGETS)
    print(f"fuzz_seeds.py: ok, {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
