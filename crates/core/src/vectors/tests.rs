//! Tests of spec 015: the schema check, the one loader and `check_all`.

use std::panic::catch_unwind;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Broken, Checker, FILES, Kind, Vector, all, check_all, parse};

/// One vector that carries every kind of value R1 admits.
const VECTOR: &str = r#"{
    "name": "one",
    "kind": "positive",
    "source": "derived",
    "origin": "a formula of docs/spec.md",
    "inputs": {"key": "00ff", "block": 1024, "flag": true, "list": ["00", "11"], "words": ["abandon"]},
    "expected": {"counter": "0000000000000102", "error": "BadLength"}
}"#;

/// A file of spec 999 holding these vectors.
fn file(vectors: &str) -> String {
    format!(r#"{{"spec": "999", "proto_version": 1, "vectors": [{vectors}]}}"#)
}

/// Spec 015, R1: every committed file loads under the schema.
#[test]
fn s015_t01_r01_every_committed_file_matches_the_schema() {
    for &(spec, source) in FILES {
        let vectors = parse(spec, source);
        assert!(
            matches!(&vectors, Ok(vectors) if !vectors.is_empty()),
            "{spec}.json: {:?}",
            vectors.err()
        );
    }
}

/// Spec 015, R1: each value type reads back as what the file wrote, an absent
/// optional value is a missing field, and a 64-bit field that is not 8 bytes
/// fails the test that reads it.
#[test]
fn s015_t01_r01_reads_every_value_type() {
    let vectors = parse("999", &file(VECTOR)).unwrap();
    let vector = &vectors[0];
    assert_eq!(vector.name(), "one");
    assert_eq!(vector.kind(), Kind::Positive);
    assert_eq!(vector.input("key").bytes(), [0x00, 0xff]);
    assert_eq!(vector.input("key").array::<2>(), [0x00, 0xff]);
    assert_eq!(vector.input("block").number(), 1024);
    assert!(vector.input("flag").flag());
    assert_eq!(vector.input("list").list()[1].bytes(), [0x11]);
    assert_eq!(vector.input("words").list()[0].text(), "abandon");
    assert_eq!(vector.expected("counter").u64_hex(), 0x0102);
    assert_eq!(vector.expected("error").text(), "BadLength");
    assert!(vector.has_input("key") && !vector.has_input("nonce"));
    assert!(vector.has_expected("error") && !vector.has_expected("blob"));
    assert!(catch_unwind(|| vector.input("key").u64_hex()).is_err());
}

/// Spec 015, R1: a file that breaks one rule fails to load with that rule,
/// never as an empty result.
#[test]
fn s015_t01_r01_rejects_every_broken_rule() {
    let one = file(VECTOR);
    // Each edit of the one valid file breaks exactly one rule.
    let edits = [
        ("00ff", "00FF", Broken::Hex),
        ("00ff", "0ff", Broken::Hex),
        ("00ff", "AP8=", Broken::Hex),
        ("00ff", "hello", Broken::Hex),
        ("true", "null", Broken::Null),
        ("1024", "4294967296", Broken::Number),
        ("1024", "-1", Broken::Number),
        ("1024", "1.5", Broken::Number),
        ("1024", "01024", Broken::Number),
        (
            r#""proto_version": 1"#,
            r#""proto_version": 2"#,
            Broken::ProtoVersion,
        ),
        (r#""spec": "999""#, r#""spec": "998""#, Broken::Spec),
        ("positive", "neutral", Broken::Kind),
        (r#""derived""#, r#""guessed""#, Broken::Source),
        ("a formula of docs/spec.md", " ", Broken::Origin),
        (r#""source": "derived","#, "", Broken::Shape("vector")),
        (
            r#""name": "one","#,
            r#""name": "one", "note": "x","#,
            Broken::Shape("vector"),
        ),
        ("true", "{}", Broken::Shape("value")),
        (
            r#""block": 1024"#,
            r#""block": 1024, "block": 1024"#,
            Broken::DuplicateKey,
        ),
        ("a formula", r"a\nformula", Broken::Syntax),
        ("a formula", "a\tformula", Broken::Syntax),
        (r#""00ff", "block""#, r#""00ff" "block""#, Broken::Syntax),
        (
            r#""00ff", "block""#,
            "\"00ff\",\u{a0}\"block\"",
            Broken::Syntax,
        ),
    ];
    for (from, to, expected) in edits {
        let source = one.replace(from, to);
        assert_eq!(
            parse("999", &source).err(),
            Some(expected),
            "{from} -> {to}"
        );
    }
    let duplicate = file(&format!("{VECTOR}, {VECTOR}"));
    assert_eq!(parse("999", &duplicate).err(), Some(Broken::DuplicateName));
    assert_eq!(parse("999", &file("")).err(), Some(Broken::Empty));
    assert_eq!(
        parse("999", &format!("{one} x")).err(),
        Some(Broken::Syntax)
    );
}

/// Spec 015, R2: `all` returns every vector each committed file lists; spec
/// 010's tests reach the same loader through `load`.
#[test]
fn s015_t02_r02_one_loader_serves_every_spec() {
    for &(spec, source) in FILES {
        // `origin` is a field of a vector and of nothing else.
        let listed = source.matches(r#""origin":"#).count();
        assert_eq!(all(spec).len(), listed, "{spec}.json");
    }
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

fn count_call(_: &Vector) {
    CALLS.fetch_add(1, Ordering::SeqCst);
}

/// Spec 015, R3: one entry per vector checks each vector exactly once; a
/// vector with no entry, an entry with no vector and an entry listed twice
/// each fail the test.
#[test]
fn s015_t03_r03_check_all_is_exhaustive() {
    let names: Vec<String> = all("010")
        .iter()
        .map(|vector| vector.name().to_owned())
        .collect();
    let entries: Vec<(&str, Checker)> = names
        .iter()
        .map(|name| (name.as_str(), count_call as Checker))
        .collect();
    check_all("010", &entries);
    assert_eq!(CALLS.load(Ordering::SeqCst), names.len());

    let left_out = entries[1..].to_vec();
    let mut unknown = entries.clone();
    unknown.push(("no_such_vector", count_call));
    let mut twice = entries.clone();
    twice.push(entries[0]);
    for (case, entries) in [
        ("left out", left_out),
        ("unknown", unknown),
        ("twice", twice),
    ] {
        assert!(
            catch_unwind(|| check_all("010", &entries)).is_err(),
            "{case}"
        );
    }
}
