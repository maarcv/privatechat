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
import base64
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
STANDARD_LIBRARY = ("__future__", "ast", "base64", "hashlib", "json", "struct", "sys", "pathlib", "typing")


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


# --- Spec 011: channel config -------------------------------------------------------

# The config record of `docs/spec.md` §5, in key order: field → (key, type). Key 6 is optional.
CONFIG_SCHEMA = {
    "config_version": (0, "u8"), "proto_version": (1, "u8"), "k_ch": (2, "bytes32"),
    "server_url": (3, "text"), "ttl_seconds": (4, "u32"), "created_at": (5, "u64"),
    "invite_expires_at": (6, "u64"), "suggested_name": (7, "text"),
}
CONFIG_MAX_RECORD = 512  # 011 R7
CHANNEL_ID_TAG = b"privatechat/chid/v1"  # 011 R9
CHANNEL_AUTH_CONTEXT = b"chauth__"
CHANNEL_ID_LEN = 16
FILE_INVITE_MS = 86_400_000  # 011 R18
# The fixed inputs of `chatcfg_reference`, and its bytes: `pinned`, produced once by the Rust
# test T18 under libsodium 1.0.22 (011 R22), since Argon2id and XSalsa20 are not transcribed here.
CHATCFG_PASSWORD = b"abandon ability able about above absent absorb"
CHATCFG_SALT = bytes(range(0x10, 0x20))
CHATCFG_NONCE = bytes(range(0x20, 0x38))
CHATCFG_REFERENCE = bytes.fromhex(
    "5043464701101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
    "373782ccd6a107b0fc57f565f8c8ceb1f29c3adc7e1653dfd80f065d6f35c4808bfe1275ca2a0835f7da9c33"
    "ac44dd5920c915e069ae6113993de0073b0bffd78f72b81ce51f7fe6b2734753db67259b86dd59c73cd88a19"
    "b54de35fe1400492f14feb4d7aebb563857c5a68e4ef01c66e1df1d8a28ac75da134b6bf026b8dbb312d6467"
    "723f630c4c6fd390b6f1c9e98353798771a8bc4beffbacc55d9c9d554c8a4b9c4faf2bd42c13740e7cd87cdb"
    "e2a7fa0db97b90e6da0fe274f8f45aa9a9efdb87107e59f45441dbe58fadc8189b76c461e1a70135d232bcf8"
    "716fec04a7cbb3589589854345b6d68d8f79a97b9a111b4cc977ca87890362d8871013029b71fb1f0a4dadb2"
    "07c37aec09bb6194a4361b4bd4fd61bf182d41b18c763681aaca52124f1c968b553c33379a0746070ba66990"
    "0266a381e0b86f0f84d460ff06c92b8b19389f3c5acda3e72c13c2747ab1517ed26e8e424d4c1323ed7ee961"
    "eff1c8318cdac29c03a06ff7ceaec82812b77a508a377a860c81839f64fba98dd6a5d8aea3fd8f87999b3fca"
    "65c8590f6ea4ed8683df60c68919abf567035719cf128e9625ae511393a7c533803d5b389104c9363a75b896"
    "5695e70aa8ca431c9ef7fa41185b12a53381f86e076a191cac2d688307da4901bb25e014104f0878732a7372"
    "b6460e22dd60e0686254d43d3fe9f31fcc4ca556789bc8e74382e14dce3a7e0884a7262fe6d4b379bfcc3094"
    "ff6c1e44b0b647137549a8382d0e46294eee7ec54cf89d435fcf1116d9cc6687d9abf6c557cd0bfa782358ed"
    "dbb509321574a9396539f40a3c4efb7ca77858ca2b717bd63ce33c0df06a3c16ff51f09b756eee547bc10767"
    "923c74fafce0d2a74413b1c4859c31dfdcaa81af5e316f53aa13468bfae9d0be80fa89cdb48d635e8b0f20ed"
    "fd8d90a2f63ad4105c579ea1c703f9f1dc5c8d7ec4fd5531ea2915dadf317d445c6642341cad6b75180795aa"
    "fa91b222c196145d8b257c5d7b675dbeeb7e72c0839a039009201841b6ddef490520d2469312b591fbd4cb9c"
    "cef8184f4c60bf4a860e47b708e914fbecaa181dc1bd8accef1b686eaa399e274fbaaddebe12b8fabefa9a05"
    "c40984c3431d2687b316cc0b1ccff8a59c8a73fb50910f2f62e877695f107df28cf1c0e50772e62575f72807"
    "79fc0115e11deefe74ec7f9a9e3de51be129a845b28884aab44c74d9b174e8320e20a1bb78311f0af2d3e98b"
    "b06f407bddbba2a1f0657c79e22afd2d725de295c803be9193da847508b0c4f51ac09193bc6863c50cfcedc3"
    "32ed070adc9aa07d405db11240a1f0712349374158ef1d6d3a4a70cd2307fe194acf6cb13b6204fdee201c31"
    "728df43f077adb5e9b249d0177f170cf73423dd34c82e7c20c900bf06b149b8f1767c5354400fedcf86af33d"
    "aa0ab00afec82ee2e1de977cfe14cf9e4a11a6dd72b9273177dd6f6eae"
)
# A v3 onion host of 56 base32 characters (011 R5, ADR 0038).
ONION_HOST = ("abcdefghijklmnopqrstuvwxyz234567" * 2)[:56] + ".onion"


def config_record(values: dict) -> bytes:
    """The canonical record (017 R10) of `values`, which may hold values out of their ranges:
    the negatives need them, and only the width of an integer is fixed here."""
    fields = []
    for name, (key, kind) in CONFIG_SCHEMA.items():
        if name not in values:
            continue
        value = values[name]
        if kind in INTEGER_WIDTHS:
            value = value.to_bytes(INTEGER_WIDTHS[kind], "big")
        elif kind == "text":
            value = value.encode("utf-8")
        fields.append(record_field(key, value))
    return b"".join(fields)


def qr_text(record: bytes) -> bytes:
    """The QR form of 011 R11: base64url of the record, padding removed."""
    return base64.urlsafe_b64encode(record).rstrip(b"=")


def channel_identity(k_ch: bytes, ttl_seconds: int) -> tuple[bytes, bytes]:
    """`pk_ch` from `KDF(K_ch, "chauth__")` through RFC 8032, and `channel_id`, the first
    16 bytes of `BLAKE2b(tag ‖ pk_ch ‖ BE32(ttl_seconds))` (011 R8)."""
    pk_ch = ed25519_public_key(kdf_derive(k_ch, CHANNEL_AUTH_CONTEXT))
    digest = blake2b_256(CHANNEL_ID_TAG + pk_ch + struct.pack(">I", ttl_seconds))
    return pk_ch, digest[:CHANNEL_ID_LEN]


def check_s011_t22_r22_section_produces_011_json() -> list[dict]:
    """The vectors of spec 011: each positive with its record and the fields and identity it
    decodes to, each negative a one-rule edit of `config_no_invite` or `config_reference`."""
    created_at = 1_790_000_000_000
    now = U64(created_at + 60_000)
    reference = {
        "config_version": 1, "proto_version": 1, "k_ch": bytes(range(0x40, 0x60)),
        "server_url": "wss://chat.example.org:9001", "ttl_seconds": 86_400,
        "created_at": U64(created_at), "invite_expires_at": U64(created_at + 600_000),
        "suggested_name": "Família",
    }
    no_invite = {name: value for name, value in reference.items() if name != "invite_expires_at"}

    def positive(name: str, origin: str, values: dict) -> dict:
        pk_ch, channel_id = channel_identity(values["k_ch"], values["ttl_seconds"])
        expected = {name: value.encode("utf-8") if isinstance(value, str) else value
                    for name, value in values.items()}
        record = config_record(values)
        require(len(record) <= CONFIG_MAX_RECORD, f"{name}: above the record limit")
        return {"name": name, "kind": "positive", "source": "derived",
                "origin": f"spec 011: {origin}", "inputs": {"record": record, "now": now},
                "expected": {**expected, "pk_ch": pk_ch, "channel_id": channel_id}}

    def negative(name: str, origin: str, record: bytes, error: str) -> dict:
        return {"name": name, "kind": "negative", "source": "derived",
                "origin": f"spec 011: {origin}", "inputs": {"record": record, "now": now},
                "expected": {"error": error}}

    vectors = [
        positive("config_reference", "every key, the invitation expiring 10 min after creation",
                 reference),
        positive("config_no_invite", "config_reference without key 6", no_invite),
        positive("config_onion_ws", "config_no_invite on ws:// and a 56-character onion host",
                 {**no_invite, "server_url": f"ws://{ONION_HOST}"}),
        positive("channel_id_ttl_60", "config_no_invite at the lowest TTL",
                 {**no_invite, "ttl_seconds": 60}),
        positive("channel_id_ttl_2592000", "config_no_invite at the highest TTL",
                 {**no_invite, "ttl_seconds": 2_592_000}),
    ]
    # The QR text export_qr writes at created_at, whose fixed expiry is that of config_reference.
    vectors[0]["expected"]["qr"] = qr_text(config_record(reference))
    base = config_record(no_invite)
    key_0_1 = config_record({"config_version": 1, "proto_version": 1})
    swapped = {name: no_invite[name] for name in ("config_version", "proto_version", "k_ch")}
    out_of_order = (config_record(swapped)
                    + config_record({"ttl_seconds": no_invite["ttl_seconds"]})
                    + config_record({"server_url": no_invite["server_url"]})
                    + config_record({name: no_invite[name]
                                     for name in ("created_at", "suggested_name")}))
    filler = CONFIG_MAX_RECORD + 1 - len(key_0_1) - FIELD_HEADER_LEN
    negatives = [
        ("record_key_order", "key 4 before key 3", out_of_order, "BadConfig"),
        ("record_unknown_key", "config_no_invite and an extra key 8",
         base + record_field(8, b"x"), "BadConfig"),
        ("record_extra_byte", "config_no_invite and one byte after it", base + b"\x00",
         "BadConfig"),
        ("record_kch_31_bytes", "a K_ch of 31 bytes",
         config_record({**no_invite, "k_ch": bytes(31)}), "BadConfig"),
        ("record_version_2", "config_version 2",
         config_record({**no_invite, "config_version": 2}), "UnsupportedVersion"),
        ("record_proto_version_2", "proto_version 2",
         config_record({**no_invite, "proto_version": 2}), "UnsupportedVersion"),
        ("record_513_bytes", "513 bytes: keys 0 and 1, then a key 9 as filler",
         key_0_1 + record_field(9, bytes(filler)), "BadConfig"),
        ("ttl_59", "a TTL one below the range", config_record({**no_invite, "ttl_seconds": 59}),
         "BadConfig"),
        ("ttl_2592001", "a TTL one above the range",
         config_record({**no_invite, "ttl_seconds": 2_592_001}), "BadConfig"),
        ("name_65_bytes", "a suggested name of 65 bytes",
         config_record({**no_invite, "suggested_name": "a" * 65}), "BadConfig"),
        ("name_control", "a suggested name holding U+0085, a C1 control",
         config_record({**no_invite, "suggested_name": "a\u0085b"}), "BadConfig"),
        ("url_path", "a server_url with a path",
         config_record({**no_invite, "server_url": "wss://chat.example.org/path"}), "BadConfig"),
        ("url_uppercase", "a host with a capital letter",
         config_record({**no_invite, "server_url": "wss://Chat.example.org"}), "BadConfig"),
        ("url_port_443", "the port wss:// implies, written out",
         config_record({**no_invite, "server_url": "wss://chat.example.org:443"}), "BadConfig"),
        ("url_ws_not_onion", "ws:// with a host that is not an onion",
         config_record({**no_invite, "server_url": "ws://chat.example.org"}), "BadConfig"),
        ("url_ws_onion_port_80", "the port ws:// implies, written out",
         config_record({**no_invite, "server_url": f"ws://{ONION_HOST}:80"}), "BadConfig"),
        ("invite_expired", "an invitation that expired 1 ms before now",
         config_record({**reference, "invite_expires_at": U64(now - 1)}), "InviteExpired"),
    ]
    require(len(negatives[6][2]) == CONFIG_MAX_RECORD + 1, "record_513_bytes is 513 bytes")
    vectors += [negative(*item) for item in negatives]
    padded = base64.urlsafe_b64encode(base)
    unpadded = qr_text(base)
    require(padded.endswith(b"=") and len(unpadded) % 4 == 3, "config_no_invite needs padding")
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    low_bit = alphabet[alphabet.index(unpadded[-1]) | 1]  # a final sextet with a bit past the data
    qr_negatives = [
        ("qr_padding", "the QR text of config_no_invite with its = padding", padded),
        ("qr_nonzero_bits", "the QR text of config_no_invite with a non-zero final bit",
         unpadded[:-1] + bytes([low_bit])),
        ("qr_length_mod_4", "the QR text of config_reference and one more character",
         qr_text(config_record(reference)) + b"A"),
    ]
    vectors += [{"name": name, "kind": "negative", "source": "derived",
                 "origin": f"spec 011: {origin}", "inputs": {"qr": qr, "now": now},
                 "expected": {"error": "BadConfig"}} for name, origin, qr in qr_negatives]
    vectors += chatcfg_vectors(base, config_record({**no_invite, "invite_expires_at":
                                                    U64(created_at + FILE_INVITE_MS)}),
                               U64(created_at))
    return vectors


def chatcfg_vectors(record: bytes, opened_record: bytes, now: U64) -> list[dict]:
    """The pinned file of config_no_invite exported at its creation, and its mutations: one
    byte of each region of the literal, and a typed password one byte over the bound (R13)."""
    listed = words()  # refuses a changed word list before anything is written (R17, 015 R4)
    require(all(word in listed for word in CHATCFG_PASSWORD.decode("ascii").split(" ")),
            "the fixed password is 7 list words")
    inputs = {"record": record, "password": CHATCFG_PASSWORD, "salt": CHATCFG_SALT,
              "nonce": CHATCFG_NONCE, "now": now}
    vectors = [{"name": "chatcfg_reference", "kind": "positive", "source": "pinned",
                "origin": "spec 011: the PCFG file of config_no_invite exported at its creation, "
                          "produced once by T18 under libsodium 1.0.22",
                "inputs": inputs,
                "expected": {"file": CHATCFG_REFERENCE, "opened_record": opened_record}}]
    if not CHATCFG_REFERENCE:  # the first run, before T18 has printed the bytes to paste
        return vectors
    require(len(CHATCFG_REFERENCE) == 1_085, "a .chatcfg file is 1 085 bytes")

    def flipped(at: int, value: int | None = None) -> bytes:
        data = bytearray(CHATCFG_REFERENCE)
        data[at] = data[at] ^ 0x01 if value is None else value
        return bytes(data)

    mutations = [
        ("mutate_magic", "the first byte of the magic", flipped(0), CHATCFG_PASSWORD,
         "BadConfig"),
        ("mutate_version", "the version byte set to 2", flipped(4, 2), CHATCFG_PASSWORD,
         "UnsupportedVersion"),
        ("mutate_salt", "the first byte of the salt", flipped(5), CHATCFG_PASSWORD,
         "BadPassword"),
        ("mutate_nonce", "the first byte of the nonce", flipped(21), CHATCFG_PASSWORD,
         "BadPassword"),
        ("mutate_sealed", "the last byte of the sealed record", flipped(1_084),
         CHATCFG_PASSWORD, "BadPassword"),
        ("password_too_long", "the file with a typed password of 1 025 bytes",
         CHATCFG_REFERENCE, b"a" * 1_025, "BadPassword"),
    ]
    vectors += [{"name": name, "kind": "negative", "source": "derived",
                 "origin": f"spec 011: chatcfg_reference, {origin}",
                 "inputs": {"file": file, "password": password, "now": now},
                 "expected": {"error": error}}
                for name, origin, file, password, error in mutations]
    return vectors


SECTIONS["011"] = check_s011_t22_r22_section_produces_011_json


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
