//! Names of spec 022-peers-tofu R4–R6 (ADR 0043): the key two names are
//! compared on, and the cleaning of every name the core hands to a client.
//! Standard library only (R16): no normalisation or confusable skeleton,
//! and no fold but the final sigma, so look-alikes of another script do not
//! collide, a stated residual.

/// Code points removed from every name by [`name_key`] and [`clean_name`],
/// as inclusive ranges in ascending order (R5).
///
/// The union, for Unicode 17.0.0 (`char::UNICODE_VERSION` of the pinned
/// toolchain), of:
/// - General_Category Cf, from `UnicodeData.txt`;
/// - `Default_Ignorable_Code_Point`, from `DerivedCoreProperties.txt`;
/// - U+2800 BRAILLE PATTERN BLANK, in neither, which draws an empty cell;
/// - U+3164 HANGUL FILLER and U+FFA0 HALFWIDTH HANGUL FILLER, already
///   default ignorable, listed because they are the usual way to fake a
///   blank name;
/// - U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR, which could draw
///   a second line that looks like another sender.
///
/// A change of this table, or of the toolchain's Unicode version, fails the
/// test of T05 until it is reviewed.
pub(crate) const INVISIBLE: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

fn is_invisible(character: char) -> bool {
    let code = u32::from(character);
    INVISIBLE
        .iter()
        .any(|&(first, last)| first <= code && code <= last)
}

/// The key of R4: `text` without white space and [`INVISIBLE`] characters,
/// lowercased, with the final sigma read as the medial one.
pub(crate) fn name_key(text: &str) -> String {
    text.chars()
        .filter(|&character| !character.is_whitespace() && !is_invisible(character))
        .collect::<String>()
        .to_lowercase()
        // `to_lowercase` picks ς or σ from the letters around it, which the
        // removed spaces change: "ΝΊΚΟΣ Π" would not collide with "Νίκος Π"
        // (audit AE).
        .replace('\u{03C2}', "\u{03C3}")
}

/// Whether two names collide (R4): equal, non-empty keys.
pub(crate) fn names_collide(first: &str, second: &str) -> bool {
    let key = name_key(first);
    !key.is_empty() && key == name_key(second)
}

/// `text` without Cc and [`INVISIBLE`] characters (R6), so that no client
/// renders them.
pub(crate) fn clean_name(text: &str) -> String {
    text.chars()
        .filter(|&character| !character.is_control() && !is_invisible(character))
        .collect()
}

/// An optional name as handed to a client (R6): cleaned, or `None` when its
/// key is empty, so that a name of blanks reads as no name.
pub(crate) fn shown_name(text: &str) -> Option<String> {
    if name_key(text).is_empty() {
        None
    } else {
        Some(clean_name(text))
    }
}

#[cfg(test)]
mod tests;
