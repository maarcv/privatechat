//! Loader for `specs/vectors/010.json`, the test vectors of this spec.
//!
//! The file is embedded with `include_str!`: `core` does no I/O, not even in
//! its tests (AGENTS 10). The vectors use a small subset of JSON — objects,
//! arrays, strings and unsigned integers, with no escape in any string — so
//! reading them here is shorter than a dependency would be (AGENTS 8, R16).
//! Vectors are never retyped into Rust: this is the only path to them.

const SOURCE: &str = include_str!("../../../../specs/vectors/010.json");

/// One vector of the file, with its inputs and its expected outputs.
pub(super) struct Vector {
    pub(super) name: String,
    pub(super) kind: String,
    inputs: Vec<(String, Json)>,
    expected: Vec<(String, Json)>,
}

impl Vector {
    /// An input field, as bytes.
    pub(super) fn bytes(&self, field: &str) -> Vec<u8> {
        hex(text(&self.inputs, field))
    }

    /// An input field, as a fixed-size array; the length is the check.
    pub(super) fn array<const N: usize>(&self, field: &str) -> [u8; N] {
        self.bytes(field)
            .try_into()
            .expect("an input field of the expected fixed size")
    }

    /// An input field that is a number, such as a padding block size.
    pub(super) fn number(&self, field: &str) -> usize {
        let number = match value(&self.inputs, field) {
            Json::Number(number) => Some(*number),
            _ => None,
        };
        usize::try_from(number.expect("a numeric input field")).expect("a number that fits")
    }

    /// An expected output field, as bytes.
    pub(super) fn expected_bytes(&self, field: &str) -> Vec<u8> {
        hex(text(&self.expected, field))
    }

    /// An expected output field that is text, such as the error of a negative
    /// vector.
    pub(super) fn expected_text(&self, field: &str) -> &str {
        text(&self.expected, field)
    }
}

/// The vector of this name. A missing name is a broken test, so it fails
/// here rather than silently asserting nothing.
pub(super) fn load(name: &str) -> Vector {
    let file = file();
    array(&file, "vectors")
        .iter()
        .filter_map(as_object)
        .find(|fields| text(fields, "name") == name)
        .map(|fields| Vector {
            name: name.to_owned(),
            kind: text(fields, "kind").to_owned(),
            inputs: object(fields, "inputs").to_vec(),
            expected: object(fields, "expected").to_vec(),
        })
        .expect("a vector of this name")
}

/// How many vectors the file carries, for the loader's own test.
pub(super) fn count() -> usize {
    array(&file(), "vectors").len()
}

/// The parsed file, as the fields of its root object.
fn file() -> Vec<(String, Json)> {
    let mut reader = Reader { rest: SOURCE };
    let parsed = reader.value();
    as_object(&parsed)
        .expect("the vectors file is an object")
        .to_vec()
}

/// The JSON subset the vector files use.
#[derive(Clone)]
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    Text(String),
    Number(u64),
}

struct Reader<'a> {
    rest: &'a str,
}

impl Reader<'_> {
    fn value(&mut self) -> Json {
        self.rest = self.rest.trim_start();
        match self.peek() {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Json::Text(self.text()),
            _ => self.number(),
        }
    }

    fn peek(&self) -> char {
        self.rest.chars().next().expect("a value")
    }

    fn eat(&mut self, delimiter: char) {
        self.rest = self.rest.trim_start();
        self.rest = self.rest.strip_prefix(delimiter).expect("a delimiter");
    }

    fn text(&mut self) -> String {
        self.eat('"');
        let end = self.rest.find('"').expect("a closing quote");
        let (text, rest) = self.rest.split_at(end);
        self.rest = &rest[1..];
        text.to_owned()
    }

    fn number(&mut self) -> Json {
        let end = self
            .rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(self.rest.len());
        let (digits, rest) = self.rest.split_at(end);
        self.rest = rest;
        Json::Number(digits.parse().expect("an unsigned integer"))
    }

    fn object(&mut self) -> Json {
        let mut fields = Vec::new();
        self.eat('{');
        while self.next_item('}') {
            let key = self.text();
            self.eat(':');
            fields.push((key, self.value()));
        }
        Json::Object(fields)
    }

    fn array(&mut self) -> Json {
        let mut items = Vec::new();
        self.eat('[');
        while self.next_item(']') {
            items.push(self.value());
        }
        Json::Array(items)
    }

    /// Consumes the separator and says whether another item follows.
    fn next_item(&mut self, close: char) -> bool {
        self.rest = self.rest.trim_start();
        if self.peek() == close {
            self.eat(close);
            return false;
        }
        if self.peek() == ',' {
            self.eat(',');
            self.rest = self.rest.trim_start();
        }
        true
    }
}

fn value<'a>(fields: &'a [(String, Json)], name: &str) -> &'a Json {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .expect("a field of this name")
}

fn text<'a>(fields: &'a [(String, Json)], name: &str) -> &'a str {
    match value(fields, name) {
        Json::Text(text) => Some(text.as_str()),
        _ => None,
    }
    .expect("a text field")
}

fn object<'a>(fields: &'a [(String, Json)], name: &str) -> &'a [(String, Json)] {
    as_object(value(fields, name)).expect("an object field")
}

fn array<'a>(fields: &'a [(String, Json)], name: &str) -> &'a [Json] {
    match value(fields, name) {
        Json::Array(items) => Some(items.as_slice()),
        _ => None,
    }
    .expect("an array field")
}

fn as_object(value: &Json) -> Option<&[(String, Json)]> {
    match value {
        Json::Object(fields) => Some(fields.as_slice()),
        _ => None,
    }
}

/// Lowercase hexadecimal, the encoding every vector uses.
fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    assert!(
        !text.contains(|c: char| c.is_ascii_uppercase()),
        "hex is lowercase everywhere"
    );
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(digits, 16).expect("a hex byte")
        })
        .collect()
}
