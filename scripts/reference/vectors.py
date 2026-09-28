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

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent.parent
VECTORS_DIR = ROOT / "specs" / "vectors"
# The one repository file the script opens, as data for the words of spec 014 (R4).
WORD_LIST = ROOT / "crates" / "core" / "src" / "proto" / "bip39_english.txt"
WORD_LIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"  # 011 R17

PROTO_VERSION = 1
FORMAT_SPECS = ("011", "012", "013", "014", "017")
# The fields whose strings are text; every other string is hexadecimal (R1).
TEXT_FIELDS = (
    "spec", "name", "kind", "source", "origin", "error", "content", "event", "policy", "schema",
    "words",
)
# The modules this file imports, all of the standard library (R4).
STANDARD_LIBRARY = ("__future__", "hashlib", "json", "struct", "sys", "pathlib", "typing")


class U64(int):
    """A 64-bit integer, written as its big-endian 8 bytes in hexadecimal (R1)."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"vectors.py: {message}")


# --- Hashes and the KDF (hashlib) -------------------------------------------------


def blake2b_256(data: bytes, key: bytes = b"") -> bytes:
    """The unkeyed and keyed hashes of `docs/spec.md` §4."""
    return hashlib.blake2b(data, digest_size=32, key=key).digest()


def kdf_derive(key: bytes, subkey_id: int, context: bytes, length: int = 32) -> bytes:
    """`crypto_kdf_derive_from_key`, as libsodium's `crypto_kdf_blake2b_derive_from_key`."""
    salt = subkey_id.to_bytes(8, "little") + bytes(8)
    person = context + bytes(8)
    return hashlib.blake2b(b"", digest_size=length, key=key, salt=salt, person=person).digest()


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
    require(kind in ("positive", "negative"), f"{name}: kind {kind}")
    require(source in ("published", "derived", "pinned"), f"{name}: source {source}")
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


# One entry per format spec, added with its section in that spec's pull request (R5):
# the spec number and the function that returns the spec's vectors.
SECTIONS: dict[str, Callable[[], list[dict]]] = {}


def words() -> list[str]:
    """The English BIP-39 list, refused unless its SHA-256 is the literal of 011 R17."""
    data = WORD_LIST.read_bytes()
    require(hashlib.sha256(data).hexdigest() == WORD_LIST_SHA256, f"{WORD_LIST} changed")
    return data.decode("ascii").splitlines()


def produce() -> dict[str, str]:
    return {f"{spec}.json": render(spec, section()) for spec, section in SECTIONS.items()}


# --- Self-checks ----------------------------------------------------------------


def check_s015_t04_r04_reference_script_is_independent() -> None:
    """Only standard-library imports, and the primitives reproduce their published vectors."""
    for name, value in list(globals().items()):
        if name.startswith("__"):  # the interpreter's own: __loader__, __spec__, ...
            continue
        module = value.__name__ if isinstance(value, type(sys)) else getattr(value, "__module__", "")
        top = (module or "").split(".")[0]
        if top not in ("", "__main__", "builtins", "vectors"):
            require(top in STANDARD_LIBRARY, f"import of {module} outside the allow-list")
    stdlib = getattr(sys, "stdlib_module_names", None)  # Python 3.10 and later
    require(stdlib is None or set(STANDARD_LIBRARY) <= set(stdlib), "a non-standard module")

    abc = hashlib.blake2b(b"abc").hexdigest()  # RFC 7693 Appendix A
    require(abc == (
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    ), "BLAKE2b differs from RFC 7693 Appendix A")

    for number, seed, message, public_key, signature in RFC8032_TESTS:
        seed_bytes, message_bytes = bytes.fromhex(seed), bytes.fromhex(message)
        require(ed25519_public_key(seed_bytes).hex() == public_key, f"RFC 8032 TEST {number} pk")
        signed = ed25519_sign(seed_bytes, message_bytes).hex()
        require(signed == signature, f"RFC 8032 TEST {number} signature")

    key, nonce, aad, plaintext, sealed = (bytes.fromhex(x) for x in AEAD_010)
    require(xchacha20poly1305_encrypt(key, nonce, aad, plaintext) == sealed, "010 AEAD vector")
    key, nonce, buffer, stream = (bytes.fromhex(x) for x in STREAM_010)
    require(xchacha20_xor(key, nonce, buffer) == stream, "010 XChaCha20 vector")
    key, context, subkey = (bytes.fromhex(x) for x in KDF_010)
    require(kdf_derive(key, 0, context) == subkey, "010 kdf_subkey_0 vector")


def check_s015_t05_r05_script_writes_every_file() -> dict[str, str]:
    """Two runs give identical files, and every committed file of a format spec has a section."""
    files = produce()
    require(files == produce(), "two runs differ")
    require(set(SECTIONS) <= set(FORMAT_SPECS), f"sections outside {FORMAT_SPECS}")
    committed = {path.name for path in VECTORS_DIR.glob("[0-9][0-9][0-9].json")}
    orphans = sorted(committed - set(files) - {"010.json"})
    require(not orphans, f"committed files no section writes: {orphans}")
    return files


# RFC 8032 §7.1 TEST 1–3: number, seed, message, public key, signature.
RFC8032_TESTS = [
    ("1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
# The vectors of `010.json`, transcribed: the script opens no file but the word list (R4).
# aead_xchacha20poly1305_ietf: key, nonce, aad, plaintext, ciphertext.
AEAD_010 = (
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    "07000000404142434445464748494a4b4c4d4e4f50515253",
    "50515253c0c1c2c3c4c5c6c7",
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966"
    "204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468652066757475"
    "72652c2073756e73637265656e20776f756c642062652069742e",
    "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002bd127"
    "4c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef10cb1d153"
    "33a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e68420",
)
# stream_xchacha20: key, nonce, buffer, buffer after the XOR.
STREAM_010 = (
    "79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4",
    "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419",
    "0000000000000000000000000000000000000000000000000000000000",
    "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c",
)
# kdf_subkey_0: key, context, subkey.
KDF_010 = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "4b44462074657374",
    "c13fcc2e6cd0cd0f82d93b163a5696c5105378f8c629d36baf3ae0239de9c280",
)


def main() -> int:
    check_s015_t04_r04_reference_script_is_independent()
    if WORD_LIST.exists():
        words()
    files = check_s015_t05_r05_script_writes_every_file()
    for name, text in files.items():
        (VECTORS_DIR / name).write_bytes(text.encode("utf-8"))
    pending = [spec for spec in FORMAT_SPECS if spec not in SECTIONS]
    print(f"vectors.py: ok, wrote {len(files)} files; sections pending: {', '.join(pending)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
