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


def load(specs: str) -> list[dict]:
    """The vectors of the files named, separated by spaces."""
    return [vector for spec in specs.split()
            for vector in json.loads((VECTORS / f"{spec}.json").read_text(encoding="utf-8"))["vectors"]]


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
    "record_decode": ("017 020", lambda v: v["inputs"].get("schema") in ("test", "types"),
                      lambda v: POLICY_BYTE[v["inputs"]["policy"]] + field(v, "record")),
    "config_parse": ("011", lambda v: "record" in v["inputs"], lambda v: field(v, "record")),
    "config_parse_qr": ("011", lambda v: "qr" in v["inputs"], lambda v: field(v, "qr")),
    "payload_decode": ("013", lambda v: payload_record(v) is not None, payload_record),
    "receive": ("013", lambda v: True, lambda v: times(v) + field(v, "blob")),
    "receive_signed": ("013", lambda v: v["kind"] == "positive",
                       lambda v: field(v, "counter") + field(v, "nonce") + times(v)
                       + padded_payload(v)),
    "verify_qr_parse": ("014", lambda v: field(v, "qr") is not None, lambda v: field(v, "qr")),
    "state_decode": ("020", lambda v: v["inputs"]["schema"] == "state", lambda v: field(v, "record")),
    "log_record_decode": ("020", lambda v: v["inputs"]["schema"] == "log",
                          lambda v: field(v, "record")),
    "settings_decode": ("020", lambda v: v["inputs"]["schema"] == "settings",
                        lambda v: field(v, "record")),
    "channel_decrypt": ("013", lambda v: True,
                        lambda v: times(v) + CHANNEL_SERVER_ID + field(v, "blob")),
    "frame_decode": ("028", lambda v: True, lambda v: field(v, "frame")),
    "session_on_frame": ("028 013", lambda v: True, lambda v: framed(session_frame(v))),
}


def framed(frame: bytes) -> bytes:
    """One frame in the layout of `session_on_frame`: `BE16(len) ‖ frame` (spec 028 R3)."""
    return len(frame).to_bytes(2, "big") + frame


# The key of `channel_id` by frame `type` (spec 028, table "Frames").
CHANNEL_KEY = {2: 1, 3: 1, 5: 1, 6: 3}
PUSH_TYPE = 5


def record_fields(record: bytes) -> list[tuple[int, bytes]] | None:
    """The `key ‖ BE32(len) ‖ value` fields of a record of spec 017, or `None` for broken framing."""
    fields, at = [], 0
    while at < len(record):
        if at + 5 > len(record):
            return None
        key, size = record[at], int.from_bytes(record[at + 1:at + 5], "big")
        if at + 5 + size > len(record):
            return None
        fields.append((key, record[at + 5:at + 5 + size]))
        at += 5 + size
    return fields


def record(fields: list[tuple[int, bytes]]) -> bytes:
    return b"".join(bytes([key]) + len(value).to_bytes(4, "big") + value for key, value in fields)


def text_k1_channel() -> bytes:
    return next(field(v, "channel_id") for v in load("013") if v["name"] == "text_k1")


def session_frame(v: dict) -> bytes:
    """The frame of a `session_on_frame` seed (spec 028 R3): a 028 frame with its `channel_id`
    set to the channel the target subscribes, so that it passes R9's routing; or a 013 blob as a
    `push` to that channel at its `received_at`, so that the seeds reach `decrypt`."""
    channel = text_k1_channel()
    if "frame" not in v["inputs"]:
        return record([(0, bytes([PUSH_TYPE])), (1, channel), (2, CHANNEL_SERVER_ID),
                       (3, field(v, "received_at")), (4, field(v, "blob"))])
    frame = field(v, "frame")
    fields = record_fields(frame)
    if not fields or fields[0][0] != 0 or len(fields[0][1]) != 1:
        return frame
    key = CHANNEL_KEY.get(fields[0][1][0])
    return record([(k, channel if k == key and len(value) == 16 else value) for k, value in fields])


# The `server_id` of every `channel_decrypt` seed (spec 021-channel-session R29).
CHANNEL_SERVER_ID = bytes(16)


def read_back(target: str, seed: bytes) -> dict[str, bytes]:
    """The fields a seed holds, cut by the layout of R3–R5 as `fuzz_entry.rs` reads it."""
    if target == "record_decode":
        return {"policy": seed[:1], "record": seed[1:]}
    if target == "receive":
        return {"received_at": seed[:8], "now": seed[8:16], "blob": seed[16:]}
    if target == "channel_decrypt":
        return {"received_at": seed[:8], "now": seed[8:16], "server_id": seed[16:32],
                "blob": seed[32:]}
    if target == "session_on_frame":
        return {"len": seed[:2], "frame": seed[2:]}
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
    if target == "channel_decrypt":
        return {"received_at": field(v, "received_at"), "now": field(v, "now"),
                "server_id": CHANNEL_SERVER_ID, "blob": field(v, "blob")}
    if target == "session_on_frame":
        frame = session_frame(v)
        return {"len": len(frame).to_bytes(2, "big"), "frame": frame}
    if target == "receive_signed":
        return {"counter": field(v, "counter"), "nonce": field(v, "nonce"),
                "received_at": field(v, "received_at"), "now": field(v, "now"),
                "padded": field(v, "padded")}
    whole = {"config_parse": "record", "config_parse_qr": "qr", "payload_decode": "payload",
             "verify_qr_parse": "qr", "state_decode": "record", "log_record_decode": "record",
             "settings_decode": "record", "frame_decode": "frame"}[target]
    return {"whole": field(v, whole)}


# How many vectors seed each target, counted once by hand from the frozen files: the filters of
# `TARGETS` are checked against it, so that a narrowed filter that drops seeds fails here.
SEED_COUNTS = {"record_decode": 31, "config_parse": 27, "config_parse_qr": 32,
               "payload_decode": 17, "receive": 30, "receive_signed": 18, "verify_qr_parse": 6,
               "state_decode": 2, "log_record_decode": 4, "settings_decode": 2,
               "channel_decrypt": 30, "frame_decode": 14, "session_on_frame": 44}


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


# What each row must seed from, written apart from `TARGETS` so that an edit of the table is
# checked against something: the targets of R2 and, for the decoders, the vector schemas.
R2_TARGETS = ROOT / "scripts" / "check_fuzz_targets.py"
FUZZ_ENTRY = ROOT / "crates" / "core" / "src" / "fuzz_entry.rs"
SCHEMAS = {"record_decode": ("017 020", {"test", "types"}), "state_decode": ("020", {"state"}),
           "log_record_decode": ("020", {"log"}), "settings_decode": ("020", {"settings"})}


def check_s016_t08_r08_rows_match_r2() -> None:
    """The rows are exactly the targets of R2, as the reach check lists them; each decoder row
    seeds every vector of its schemas and no other; the policy byte of an `ignore` seed is the
    one `fuzz_entry.rs` reads as `Ignore`."""
    listed = R2_TARGETS.read_text(encoding="utf-8").split("TARGETS = (", 1)[1].split(")", 1)[0]
    r2 = [name.strip().strip('"') for name in listed.replace("\n", " ").split(",") if name.strip()]
    if list(TARGETS) != r2:
        raise SystemExit(f"fuzz_seeds.py: the rows {list(TARGETS)} are not the targets of R2 {r2}")
    for target, (files, schemas) in SCHEMAS.items():
        spec, carries, _ = TARGETS[target]
        every = [v for v in load(files) if v["inputs"].get("schema") in schemas]
        seeded = [v for v in load(spec) if carries(v)]
        if spec != files or not every or seeded != every:
            raise SystemExit(f"fuzz_seeds.py: {target}: not every vector of {sorted(schemas)}")
    if POLICY_BYTE["ignore"] != b"\x00" or "if *policy == 0" not in FUZZ_ENTRY.read_text(encoding="utf-8"):
        raise SystemExit("fuzz_seeds.py: the ignore byte is not the one fuzz_entry.rs reads")


def main() -> int:
    check_s016_t08_r08_rows_match_r2()
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
