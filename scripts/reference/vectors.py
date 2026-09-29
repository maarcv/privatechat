#!/usr/bin/env python3
"""Reference producer of the test vectors (spec 015-test-vectors).

Writes every `specs/vectors/NNN.json` of the format specs from fixed inputs
written below, one section per spec; the Rust tests, and later Kotlin and
Swift, must reproduce every value. It shares no code with the core: the
primitives are transcribed from their RFCs with the standard library only, so
a wrong tag, byte order or composition in the core makes the two disagree.

The primitives here are slow and unhardened. They exist only to produce test
values offline, and nothing imports this file. Argon2id and XSalsa20 are
deliberately absent: spec 010-primitives-wrapper checks them against
published vectors (R5).

Before writing anything the script passes its self-checks, named after the
requirement they cover (`check_s015_tTT_rRR_*`) so that
`scripts/check_requirements.sh` finds them. It computes every file before it
writes the first, so a failure writes nothing. Exit code 0 on success.
"""

from __future__ import annotations

import ast
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent.parent
VECTORS_DIR = ROOT / "specs" / "vectors"
# The repository files the script reads, as data (R4): its own source for the import check,
# the published vectors of spec 010 for its self-tests and the word list of spec 014.
VECTORS_010 = VECTORS_DIR / "010.json"
WORD_LIST = ROOT / "crates" / "core" / "src" / "proto" / "bip39_english.txt"
WORD_LIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"  # 011 R17

PROTO_VERSION = 1
FORMAT_SPECS = ("011", "012", "013", "014", "017")
KINDS = ("positive", "negative")
SOURCES = ("published", "derived", "pinned")
# The fields whose strings are text; every other string is hexadecimal (R1).
TEXT_FIELDS = (
    "spec", "name", "kind", "source", "origin", "error", "content", "event", "policy", "schema",
    "words",
)
# The modules this file imports, all of the standard library (R4).
STANDARD_LIBRARY = ("__future__", "ast", "hashlib", "json", "struct", "sys", "pathlib", "typing")


class U64(int):
    """A 64-bit integer, written as its big-endian 8 bytes in hexadecimal (R1)."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"vectors.py: {message}")


# --- Hashes and the KDF (hashlib) -------------------------------------------------


def blake2b_256(data: bytes, key: bytes = b"") -> bytes:
    """The unkeyed and keyed hashes of `docs/spec.md` §4."""
    return hashlib.blake2b(data, digest_size=32, key=key).digest()


def kdf_derive(key: bytes, context: bytes) -> bytes:
    """`crypto_kdf_derive_from_key` with `subkey_id` = 0, the only id of §4, as libsodium's
    `crypto_kdf_blake2b_derive_from_key`: the salt is the id's 8 little-endian bytes followed by
    8 zero bytes, all zero here, and the 32-byte subkey is BLAKE2b of the empty message."""
    person = context + bytes(8)
    return hashlib.blake2b(b"", digest_size=32, key=key, salt=bytes(16), person=person).digest()


# --- ChaCha20, HChaCha20 and Poly1305 (RFC 8439 §2.3–2.8, draft-irtf-cfrg-xchacha) ---

MASK32 = 0xFFFFFFFF
SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = _rotl(s[b] ^ s[c], 7)


def _rounds(state: list[int]) -> list[int]:
    s = list(state)
    for _ in range(10):
        _quarter_round(s, 0, 4, 8, 12)
        _quarter_round(s, 1, 5, 9, 13)
        _quarter_round(s, 2, 6, 10, 14)
        _quarter_round(s, 3, 7, 11, 15)
        _quarter_round(s, 0, 5, 10, 15)
        _quarter_round(s, 1, 6, 11, 12)
        _quarter_round(s, 2, 7, 8, 13)
        _quarter_round(s, 3, 4, 9, 14)
    return s


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [*SIGMA, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]
    mixed = _rounds(state)
    return struct.pack("<16I", *((x + y) & MASK32 for x, y in zip(mixed, state)))


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[offset : offset + 64], block))
    return bytes(out)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    state = [*SIGMA, *struct.unpack("<8I", key), *struct.unpack("<4I", nonce)]
    mixed = _rounds(state)
    return struct.pack("<8I", *mixed[0:4], *mixed[12:16])


def _xchacha20_subkey(key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """The subkey and the 12-byte ChaCha20 nonce of a 24-byte XChaCha20 nonce."""
    return hchacha20(key, nonce[:16]), bytes(4) + nonce[16:24]


def xchacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """`crypto_stream_xchacha20_xor`: the keystream from block 0."""
    subkey, chacha_nonce = _xchacha20_subkey(key, nonce)
    return chacha20_xor(subkey, chacha_nonce, 0, data)


def poly1305(key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16] + b"\x01"
        accumulator = (accumulator + int.from_bytes(chunk, "little")) * r % p
    return ((accumulator + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return bytes(-len(data) % 16)


def xchacha20poly1305_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """`crypto_aead_xchacha20poly1305_ietf_encrypt`: ciphertext followed by the tag."""
    subkey, chacha_nonce = _xchacha20_subkey(key, nonce)
    one_time_key = chacha20_block(subkey, 0, chacha_nonce)[:32]
    ciphertext = chacha20_xor(subkey, chacha_nonce, 1, plaintext)
    lengths = struct.pack("<QQ", len(aad), len(ciphertext))
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext) + lengths
    return ciphertext + poly1305(one_time_key, mac_data)


# --- Ed25519 (RFC 8032 §6) --------------------------------------------------------

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
Point = tuple[int, int, int, int]


def _point_add(a: Point, b: Point) -> Point:
    e1, f1 = (a[1] - a[0]) * (b[1] - b[0]) % P, (a[1] + a[0]) * (b[1] + b[0]) % P
    c, d = 2 * a[3] * b[3] * D % P, 2 * a[2] * b[2] % P
    e, f, g, h = f1 - e1, d - c, d + c, f1 + e1
    return (e * f, g * h, f * g, e * h)


def _point_mul(scalar: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    return P - x if (x & 1) != sign else x


_G_Y = 4 * pow(5, P - 2, P) % P
_G_X = _recover_x(_G_Y, 0)
G: Point = (_G_X, _G_Y, 1, _G_X * _G_Y % P)


def _compress(point: Point) -> bytes:
    z_inverse = pow(point[2], P - 2, P)
    x, y = point[0] * z_inverse % P, point[1] * z_inverse % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def _sha512_mod_q(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % Q


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = _expand(seed)
    return _compress(_point_mul(scalar, G))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand(seed)
    public_key = _compress(_point_mul(scalar, G))
    r = _sha512_mod_q(prefix + message)
    r_bytes = _compress(_point_mul(r, G))
    h = _sha512_mod_q(r_bytes + public_key + message)
    return r_bytes + ((r + h * scalar) % Q).to_bytes(32, "little")


# --- The files ----------------------------------------------------------------


def vector(name: str, kind: str, source: str, origin: str, inputs: dict, expected: dict) -> dict:
    """One vector, its values encoded as R1 fixes: bytes as lowercase hexadecimal, `U64` as
    8 big-endian bytes, `int` as a JSON number of at most 32 bits, text only in text fields."""
    require(kind in KINDS, f"{name}: kind {kind}")
    require(source in SOURCES, f"{name}: source {source}")
    require(bool(origin.strip()), f"{name}: empty origin")
    return {
        "name": name, "kind": kind, "source": source, "origin": origin,
        "inputs": {key: _encode(key, inputs[key]) for key in sorted(inputs)},
        "expected": {key: _encode(key, expected[key]) for key in sorted(expected)},
    }


def _encode(key: str, value: object) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, U64):
        return value.to_bytes(8, "big").hex()
    if isinstance(value, int):
        require(0 <= value <= MASK32, f"{key}: {value} is not a 32-bit number")
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, str):
        require(key in TEXT_FIELDS, f"{key}: text outside the text fields")
        return value
    if isinstance(value, list):
        return [_encode(key, item) for item in value]
    raise SystemExit(f"vectors.py: {key}: {type(value).__name__} has no encoding under R1")


def render(spec: str, vectors: list[dict]) -> str:
    names = [item["name"] for item in vectors]
    require(bool(names), f"{spec}: a file holds at least one vector")
    require(len(set(names)) == len(names), f"{spec}: duplicate vector names")
    document = {"spec": spec, "proto_version": PROTO_VERSION, "vectors": vectors}
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    require("\\" not in text, f"{spec}: an escape the loader does not read")
    return text


# One entry per format spec, added with its section in that spec's pull request (R5): the spec
# number and the function that returns the spec's vectors, each a dict of the six arguments of
# `vector` with raw values, so that every value goes through its encoding. A section never
# builds a list by iterating a set: set order changes between processes, which the in-process
# check below cannot see.
SECTIONS: dict[str, Callable[[], list[dict]]] = {}


# --- Spec 017: record encoding ------------------------------------------------------

# The test schema of spec 017, in key order: field → (key, type). Key 0 is mandatory.
TEST_SCHEMA = {
    "small": (0, "u8"), "medium": (1, "u32"), "large": (2, "u64"),
    "bytes": (3, "bytes"), "bytes32": (4, "bytes32"), "text": (5, "text"),
}
TEST_MAX_RECORD = 512
TEST_MAX_VALUE = 64  # of `bytes` and of `text`
INTEGER_WIDTHS = {"u8": 1, "u32": 4, "u64": 8}
FIELD_HEADER_LEN = 5  # key and length (017 R1)


def record_field(key: int, value: bytes) -> bytes:
    """`key` ‖ `len` (4 bytes, big-endian) ‖ `value` (017 R1)."""
    return bytes([key]) + struct.pack(">I", len(value)) + value


def schema_value(kind: str, value: object) -> bytes:
    """The bytes of one value (R3, R4): an integer at its exact width, big-endian, text as UTF-8."""
    if kind in INTEGER_WIDTHS:
        return value.to_bytes(INTEGER_WIDTHS[kind], "big")
    data = value.encode("utf-8") if kind == "text" else value
    require(len(data) == 32 if kind == "bytes32" else len(data) <= TEST_MAX_VALUE, kind)
    return data


def encode_test_record(values: dict) -> bytes:
    """The canonical encoding (R10): keys in increasing order, no field for an absent key."""
    record = b"".join(record_field(key, schema_value(kind, values[name]))
                      for name, (key, kind) in TEST_SCHEMA.items() if name in values)
    require(len(record) <= TEST_MAX_RECORD, "a test record above its maximum")
    return record


def check_s017_t13_r13_section_produces_017_json() -> list[dict]:
    """The vectors of spec 017: each positive encoded from its values, the extra fields of
    `unknown_key_ignored` and `record_at_limit` appended by hand, each negative built by hand
    from the rule it breaks, all on the six bytes of `u8_field`."""
    small = {"small": 0x2a}
    head = record_field(0, b"\x2a")

    def expected(values: dict) -> dict:
        """The decoded fields; `text` is hex like every field outside TEXT_FIELDS (015 R1)."""
        return {name: value.encode("utf-8") if name == "text" else value
                for name, value in values.items()}

    def raw(name: str, kind: str, origin: str, policy: str, record: bytes, result: dict) -> dict:
        inputs = {"schema": "test", "policy": policy, "record": record}
        return {"name": name, "kind": kind, "source": "derived",
                "origin": f"spec 017 test schema: {origin}", "inputs": inputs, "expected": result}

    everything = {**small, "medium": 0x01020304, "large": U64(0x0102030405060708),
                  "bytes": bytes(range(TEST_MAX_VALUE)), "bytes32": bytes(range(32)),
                  "text": "é" * (TEST_MAX_VALUE // 2)}
    positives = [
        ("u8_field", "key 0 alone", small),
        ("u32_field", "key 0 and a key 1 at the u32 maximum", {**small, "medium": MASK32}),
        ("u64_field", "key 0 and a key 2 at the u64 maximum", {**small, "large": U64(2**64 - 1)}),
        ("bytes_field", "key 0 and a key 3 of 5 bytes", {**small, "bytes": bytes(range(5))}),
        ("bytes32_field", "key 0 and a key 4 of 32 bytes", {**small, "bytes32": bytes(range(32))}),
        ("text_field", "key 0 and a key 5 with a two-byte character", {**small, "text": "héllo"}),
        ("all_fields", "every key, integers whose bytes all differ, bytes and text at 64 bytes",
         everything),
    ]
    require(encode_test_record(small) == head, "u8_field is the head of every hand-built vector")
    vectors = [raw(name, "positive", origin, "reject", encode_test_record(values), expected(values))
               for name, origin, values in positives]
    unknown = record_field(9, b"x")
    filler = TEST_MAX_RECORD - len(head) - FIELD_HEADER_LEN
    vectors += [
        raw("unknown_key_ignored", "positive", "key 0 and an extra key 9 under ignore", "ignore",
            head + unknown, expected(small)),
        raw("record_at_limit", "positive", "512 bytes under ignore: key 0 and a key 9 as filler",
            "ignore", head + record_field(9, bytes(filler)), expected(small)),
    ]
    key_1 = record_field(1, bytes(4))
    too_long = TEST_MAX_VALUE + 1
    negatives = [
        ("empty_record", "zero bytes: key 0 is missing", "reject", b"", "Missing"),
        ("key_out_of_order", "key 2 before key 1", "reject",
         head + record_field(2, bytes(8)) + key_1, "KeyOrder"),
        ("duplicate_key", "key 1 twice", "reject", head + key_1 + key_1, "KeyOrder"),
        ("u32_wrong_width", "a key 1 of 3 bytes", "reject", head + record_field(1, bytes(3)),
         "Width"),
        ("bytes32_wrong_width", "a key 4 of 31 bytes", "reject",
         head + record_field(4, bytes(31)), "Width"),
        ("bytes_too_long", "a key 3 of 65 bytes", "reject",
         head + record_field(3, bytes(too_long)), "TooLong"),
        ("text_too_long", "a key 5 of 65 bytes", "reject",
         head + record_field(5, b"a" * too_long), "TooLong"),
        ("record_too_long", "513 bytes that decode under ignore: key 0 and a key 9 as filler",
         "ignore", head + record_field(9, bytes(filler + 1)), "TooLong"),
        ("truncated_length", "key 0, then 3 bytes of a field header", "reject",
         head + bytes([1, 0, 0]), "Truncated"),
        ("length_beyond_buffer", "a key 1 that declares 4 bytes and carries 3", "reject",
         head + bytes([1, 0, 0, 0, 4]) + bytes(3), "Truncated"),
        ("extra_byte", "key 0 and one byte after it", "reject", head + b"\x00", "Truncated"),
        ("unknown_key_then_extra_byte", "key 0, an extra key 9 and one byte after it, under "
         "ignore", "ignore", head + unknown + b"\x00", "Truncated"),
        ("invalid_utf8", "a key 5 holding the byte 0xff", "reject",
         head + record_field(5, b"a\xff"), "Utf8"),
        ("unknown_key_rejected", "key 0 and an extra key 9 under reject", "reject",
         head + unknown, "UnknownKey"),
    ]
    vectors += [raw(name, "negative", origin, policy, record, {"error": error})
                for name, origin, policy, record, error in negatives]
    return vectors


SECTIONS["017"] = check_s017_t13_r13_section_produces_017_json


def words() -> list[str]:
    """The English BIP-39 list, for the section of spec 014; refused unless its SHA-256 is the
    literal of 011 R17, before any file is written."""
    data = WORD_LIST.read_bytes()
    require(hashlib.sha256(data).hexdigest() == WORD_LIST_SHA256, f"{WORD_LIST} changed")
    return data.decode("ascii").splitlines()


def produce() -> dict[str, str]:
    return {
        f"{spec}.json": render(spec, [vector(**raw) for raw in section()])
        for spec, section in SECTIONS.items()
    }


# --- Self-checks ----------------------------------------------------------------


def check_s015_t04_r04_reference_script_is_independent() -> None:
    """Only standard-library imports, and the primitives reproduce their published vectors."""
    for node in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]  # a relative import has no module and is refused
        else:
            continue
        for module in modules:
            require(module.split(".")[0] in STANDARD_LIBRARY, f"import of {module!r}")
    stdlib = getattr(sys, "stdlib_module_names", None)  # Python 3.10 and later
    require(stdlib is None or set(STANDARD_LIBRARY) <= set(stdlib), "a non-standard module")

    abc = hashlib.blake2b(b"abc").hexdigest()  # RFC 7693 Appendix A
    require(abc == (
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    ), "BLAKE2b differs from RFC 7693 Appendix A")

    published = json.loads(VECTORS_010.read_text(encoding="utf-8"))["vectors"]
    by_name = {item["name"]: item for item in published}
    # Each primitive against its vector of 010.json: the arguments in call order, the output.
    checks = [
        ("aead_xchacha20poly1305_ietf", xchacha20poly1305_encrypt,
         ("key", "nonce", "aad", "plaintext"), "ciphertext"),
        ("stream_xchacha20", xchacha20_xor, ("key", "nonce", "buf"), "buf"),
        ("blake2b_256_unkeyed", blake2b_256, ("input",), "hash"),
        ("blake2b_256_keyed", blake2b_256, ("input", "key"), "hash"),
        ("kdf_subkey_0", kdf_derive, ("key", "context"), "subkey"),
    ]
    for number in (1, 2, 3):  # RFC 8032 §7.1 TEST 1–3
        name = f"ed25519_rfc8032_test{number}"
        checks += [(name, ed25519_public_key, ("seed",), "pk"),
                   (name, ed25519_sign, ("seed", "message"), "signature")]
    for name, primitive, arguments, output in checks:
        item = by_name[name]
        values = [bytes.fromhex(item["inputs"][argument]) for argument in arguments]
        require(primitive(*values).hex() == item["expected"][output], f"010 {name}: {output}")


def check_s015_t05_r05_script_writes_every_file() -> dict[str, str]:
    """Two runs give identical files, and every committed file from 011 on has a section."""
    files = produce()
    require(files == produce(), "two runs differ")
    require(set(SECTIONS) <= set(FORMAT_SPECS), f"sections outside {FORMAT_SPECS}")
    committed = {path.name for path in VECTORS_DIR.glob("[0-9][0-9][0-9].json")}
    orphans = sorted(committed - set(files) - {"010.json"})
    require(not orphans, f"committed files no section writes: {orphans}")
    return files


def main() -> int:
    check_s015_t04_r04_reference_script_is_independent()
    files = check_s015_t05_r05_script_writes_every_file()
    for name, text in files.items():
        (VECTORS_DIR / name).write_bytes(text.encode("utf-8"))
    pending = [spec for spec in FORMAT_SPECS if spec not in SECTIONS]
    print(f"vectors.py: ok, wrote {len(files)} files; sections pending: {', '.join(pending)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
