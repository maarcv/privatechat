//! Tests of spec 022 R4–R6 and R16 on the name functions directly. T06's
//! `peers()` and `Received` half is in `peers/tests.rs`.

use proptest::collection::vec;
use proptest::prelude::{any, proptest};

use super::{INVISIBLE, clean_name, name_key, names_collide, shown_name};

/// The number of ranges of `INVISIBLE` for Unicode 17.0.0 (R5).
const INVISIBLE_RANGES: usize = 26;

/// The number of code points those ranges hold, so that a changed bound is
/// a reviewed diff too.
const INVISIBLE_CODE_POINTS: u32 = 4_209;

/// Spec 022, R4: case, white space and invisible characters collide;
/// look-alikes do not, the residual of ADR 0043.
#[test]
fn s022_t04_r04_name_key_collisions() {
    let colliding = [
        ("Alice", "ALICE"),
        ("Mike", "MIKE"),
        ("Olivia", "OLIVIA"),
        ("Al ice", "Alice"),
        ("Alice", "Ali\u{3000}ce"),
        ("Alice", "Alice\u{2800}"),
        ("Alice", "Ali\u{200B}ce"),
        ("Alice", "Ali\u{034F}ce"),
        ("Alice", "Ali\u{3164}ce"),
        ("Alice", "Ali\u{FFA0}ce"),
        ("Élodie", "ÉLODIE"),
        // The final sigma: lowercased in context, and the spaces removed
        // change the context (audit AE).
        ("Νίκος Π", "ΝΊΚΟΣ Π"),
        ("οδος α", "ΟΔΟΣ Α"),
        ("Νίκος", "ΝΊΚΟΣ"),
        ("Νίκοσ", "Νίκος"),
        // The Turkish I under caps lock (audit AE).
        ("Işık", "IŞIK"),
        ("ince", "İNCE"),
        // The Kelvin sign lowercases to k.
        ("\u{212A}elvin", "Kelvin"),
    ];
    for (first, second) in colliding {
        assert!(names_collide(first, second), "{first:?} / {second:?}");
    }
    let distinct = [
        ("Alice", "Alicia"),
        ("Alice", "\u{0410}lice"),
        ("Alice", "AIice"),
        ("Bob", "B0b"),
        ("Alice", "\u{FF21}lice"),
        ("Alice", "Ali\u{0307}ce"),
        // No fold beyond the lowercase: ß is not ss, and a capital written
        // without its accent is another name (ADR 0043).
        ("Straße", "STRASSE"),
        ("Élodie", "ELODIE"),
        ("Νίκος", "ΝΙΚΟΣ"),
    ];
    for (first, second) in distinct {
        assert!(!names_collide(first, second), "{first:?} / {second:?}");
    }
    for empty in ["   ", "\u{200B}"] {
        assert_eq!(name_key(empty), "", "{empty:?}");
        assert!(!names_collide(empty, empty), "{empty:?}");
    }
}

/// Spec 022, R5: the table holds the characters the spec names, not
/// ordinary ones, and is pinned to the toolchain's Unicode version.
#[test]
fn s022_t05_r05_invisible_table() {
    let inside = [
        0x200B, 0x200D, 0x202E, 0xFEFF, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x2028,
        0x2029,
    ];
    let contains = |code: u32| INVISIBLE.iter().any(|&(a, b)| a <= code && code <= b);
    for code in inside {
        assert!(contains(code), "U+{code:04X}");
    }
    for code in [u32::from('a'), 0x0020] {
        assert!(!contains(code), "U+{code:04X}");
    }
    assert_eq!(INVISIBLE.len(), INVISIBLE_RANGES);
    let code_points: u32 = INVISIBLE.iter().map(|&(a, b)| b - a + 1).sum();
    assert_eq!(code_points, INVISIBLE_CODE_POINTS);
    assert!(
        INVISIBLE
            .windows(2)
            .all(|pair| pair[0].0 <= pair[0].1 && pair[0].1.saturating_add(1) < pair[1].0),
        "ranges ascending, disjoint and not adjacent"
    );
    let (major, minor, update) = char::UNICODE_VERSION;
    let named = format!("Unicode {major}.{minor}.{update} (`char::UNICODE_VERSION`");
    assert!(
        include_str!("../names.rs").contains(&named),
        "the doc comment of INVISIBLE names {named}"
    );
}

/// Spec 022, R6: the cleaning on `clean_name` and `shown_name` directly.
#[test]
fn s022_t06_r06_names_are_cleaned() {
    assert_eq!(clean_name("Bob\u{202E}ecilA"), "BobecilA");
    assert_eq!(clean_name("Bob\u{0007}"), "Bob");
    assert_eq!(clean_name("Bob\u{0085}\u{009B}"), "Bob");
    assert_eq!(clean_name("Bob\u{2029}Alice"), "BobAlice");
    assert_eq!(clean_name("Bob\u{2028}Alice"), "BobAlice");
    assert_eq!(shown_name("\u{200B}\u{2800}\u{FEFF}"), None);
    assert_eq!(shown_name("   "), None);
    assert_eq!(shown_name("\u{3000}"), None);
    assert_eq!(shown_name("Al ice\u{200B}"), Some("Al ice".to_owned()));
}

/// A name that differs from another only in what `name_key` drops or folds.
fn disguise(name: &str, extra: char) -> String {
    let mut disguised: String = name.chars().flat_map(char::to_uppercase).collect();
    disguised.insert(0, extra);
    disguised.push(' ');
    disguised
}

proptest! {
    /// Spec 022, R16: the name functions never panic, and collision is
    /// symmetric, for strings of up to 256 bytes, unrelated ones and ones
    /// disguised by case, white space and an invisible character.
    #[test]
    fn s022_t16_r16_name_key_property(
        first in vec(any::<char>(), 0..=64),
        second in vec(any::<char>(), 0..=64),
        extra in proptest::sample::select(vec!['\u{200B}', '\u{3000}', '\u{2800}', '\u{FEFF}']),
    ) {
        let first: String = first.into_iter().collect();
        let second: String = second.into_iter().collect();
        let _ = clean_name(&first);
        let _ = shown_name(&first);
        assert_eq!(names_collide(&first, &second), names_collide(&second, &first));
        let disguised = disguise(&first, extra);
        assert_eq!(names_collide(&first, &disguised), names_collide(&disguised, &first));
        // Uppercasing then lowercasing is not always the identity (ß, ǅ),
        // so a disguise collides whenever the keys of the two cases agree.
        let same_case = name_key(&first) == name_key(&first.to_uppercase());
        if same_case && !name_key(&first).is_empty() {
            assert!(names_collide(&first, &disguised), "{first:?}");
        }
    }
}
