//! The one loader of `specs/vectors/NNN.json`, shared by the tests of every
//! spec (spec 015-test-vectors).
//!
//! The files are embedded with `include_str!`: `core` does no I/O, not even in
//! its tests (AGENTS 10). They use a small subset of JSON — objects, arrays,
//! strings with no escape, unsigned integers and booleans — so reading them
//! here is shorter than a dependency would be (AGENTS 8). Every file is checked
//! against the schema of `specs/vectors/README.md` as it is read, and a broken
//! file fails the test that reads it (R1). The reference script of spec 015
//! writes the files from spec 011 on and `010.json` is transcribed by hand;
//! Rust only reads and checks them.

use std::collections::HashSet;

/// Every committed file, by spec. A format spec adds its line with its file.
const FILES: &[(&str, &str)] = &[
    ("010", include_str!("../../../specs/vectors/010.json")),
    ("011", include_str!("../../../specs/vectors/011.json")),
    ("012", include_str!("../../../specs/vectors/012.json")),
    ("013", include_str!("../../../specs/vectors/013.json")),
    ("014", include_str!("../../../specs/vectors/014.json")),
    ("017", include_str!("../../../specs/vectors/017.json")),
    ("020", include_str!("../../../specs/vectors/020.json")),
    ("028", include_str!("../../../specs/vectors/028.json")),
];

/// Where a vector's values come from (`specs/vectors/README.md`).
const SOURCES: [&str; 3] = ["published", "derived", "pinned"];

/// The fields whose strings are text; every other string is hexadecimal (R1).
const TEXT_FIELDS: [&str; 11] = [
    "spec", "name", "kind", "source", "origin", "error", "content", "event", "policy", "schema",
    "words",
];

/// Whether a vector expects success or a rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Positive,
    Negative,
}

/// A value of `inputs` or `expected`, typed by the encoding rules of R1.
#[derive(Debug)]
pub(crate) enum Value {
    Hex(Vec<u8>),
    Number(u32),
    Bool(bool),
    Text(String),
    List(Vec<Value>),
}

/// One vector of a file.
pub(crate) struct Vector {
    name: String,
    kind: Kind,
    inputs: Vec<(String, Value)>,
    expected: Vec<(String, Value)>,
}

/// The rule of R1 a file breaks.
#[derive(Debug, PartialEq, Eq)]
enum Broken {
    /// Outside the JSON subset: an escape, a missing separator, trailing bytes.
    Syntax,
    Null,
    /// Negative, fractional, with a leading zero or above 2^32 − 1.
    Number,
    /// Not lowercase hexadecimal of even length, outside the text fields.
    Hex,
    /// A field missing, unknown or of the wrong type, in this object.
    Shape(&'static str),
    DuplicateKey,
    ProtoVersion,
    /// The `spec` field names another spec than the file.
    Spec,
    Kind,
    Source,
    Origin,
    /// No vector at all: a file never loads as an empty result.
    Empty,
    DuplicateName,
}

/// Checks one vector; `check_all` calls it with the vector of its name.
pub(crate) type Checker = fn(&Vector);

/// The vector of this name, for spec 010's tests only (R2, R3). A missing name
/// is a broken test, so it fails here rather than asserting nothing.
pub(crate) fn load(spec: &str, name: &str) -> Vector {
    all(spec)
        .into_iter()
        .find(|vector| vector.name == name)
        .expect("a vector of this name")
}

/// Calls each entry's checker on the vector of its name. Fails the test on a
/// vector with no entry, an entry with no vector and an entry listed twice, so
/// that no vector is checked twice and none is left unchecked (R3).
pub(crate) fn check_all(spec: &str, entries: &[(&str, Checker)]) {
    let vectors = all(spec);
    let names: HashSet<&str> = entries.iter().map(|(name, _)| *name).collect();
    assert_eq!(names.len(), entries.len(), "an entry is listed twice");
    let unchecked: Vec<&str> = vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .filter(|name| !names.contains(name))
        .collect();
    assert!(unchecked.is_empty(), "vectors with no entry: {unchecked:?}");
    let unknown: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| !vectors.iter().any(|vector| vector.name == *name))
        .collect();
    assert!(unknown.is_empty(), "entries with no vector: {unknown:?}");
    for (name, checker) in entries {
        vectors
            .iter()
            .filter(|vector| vector.name == *name)
            .for_each(checker);
    }
}

/// Every vector of the committed file of this spec.
fn all(spec: &str) -> Vec<Vector> {
    let (_, source) = FILES
        .iter()
        .find(|(file, _)| *file == spec)
        .expect("a committed file for this spec");
    parse(spec, source).expect("a file that follows the schema of spec 015 R1")
}

impl Vector {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }

    /// An input field; an absent one fails the test.
    pub(crate) fn input(&self, field: &str) -> &Value {
        find(&self.inputs, field).expect("an input field of this name")
    }

    /// An expected field; an absent one fails the test.
    pub(crate) fn expected(&self, field: &str) -> &Value {
        find(&self.expected, field).expect("an expected field of this name")
    }

    /// Whether an optional input is present.
    pub(crate) fn has_input(&self, field: &str) -> bool {
        find(&self.inputs, field).is_some()
    }

    /// Whether an optional expected value is present.
    pub(crate) fn has_expected(&self, field: &str) -> bool {
        find(&self.expected, field).is_some()
    }
}

impl Value {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Value::Hex(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
        .expect("a hexadecimal value")
    }

    /// The bytes as a fixed-size array; the length is the check.
    pub(crate) fn array<const N: usize>(&self) -> [u8; N] {
        self.bytes()
            .try_into()
            .expect("a value of the expected size")
    }

    pub(crate) fn number(&self) -> u32 {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
        .expect("a JSON number")
    }

    /// A 64-bit integer, written as its big-endian 8 bytes (R1).
    pub(crate) fn u64_hex(&self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    pub(crate) fn flag(&self) -> bool {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
        .expect("a boolean")
    }

    pub(crate) fn text(&self) -> &str {
        match self {
            Value::Text(text) => Some(text.as_str()),
            _ => None,
        }
        .expect("a value of a text field")
    }

    pub(crate) fn list(&self) -> &[Value] {
        match self {
            Value::List(items) => Some(items.as_slice()),
            _ => None,
        }
        .expect("a list")
    }
}

fn find<'a>(fields: &'a [(String, Value)], field: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value)
}

/// Reads a whole file and checks it against R1.
fn parse(spec: &str, source: &str) -> Result<Vec<Vector>, Broken> {
    let root = Reader::document(source)?;
    let [file_spec, proto_version, vectors] =
        exact(&root, ["spec", "proto_version", "vectors"], "root")?;
    if text(file_spec)? != spec {
        return Err(Broken::Spec);
    }
    if !matches!(proto_version, Json::Number(1)) {
        return Err(Broken::ProtoVersion);
    }
    let Json::Array(items) = vectors else {
        return Err(Broken::Shape("root"));
    };
    let vectors = items.iter().map(vector).collect::<Result<Vec<_>, _>>()?;
    if vectors.is_empty() {
        return Err(Broken::Empty);
    }
    let names: HashSet<&str> = vectors.iter().map(|vector| vector.name.as_str()).collect();
    if names.len() < vectors.len() {
        return Err(Broken::DuplicateName);
    }
    Ok(vectors)
}

fn vector(json: &Json) -> Result<Vector, Broken> {
    let keys = ["name", "kind", "source", "origin", "inputs", "expected"];
    let [name, kind, source, origin, inputs, expected] = exact(json, keys, "vector")?;
    let kind = match text(kind)? {
        "positive" => Kind::Positive,
        "negative" => Kind::Negative,
        _ => return Err(Broken::Kind),
    };
    if !SOURCES.contains(&text(source)?) {
        return Err(Broken::Source);
    }
    if text(origin)?.trim().is_empty() {
        return Err(Broken::Origin);
    }
    Ok(Vector {
        name: text(name)?.to_owned(),
        kind,
        inputs: values(inputs)?,
        expected: values(expected)?,
    })
}

/// The fields of `inputs` or `expected`, each typed by its key.
fn values(json: &Json) -> Result<Vec<(String, Value)>, Broken> {
    let Json::Object(fields) = json else {
        return Err(Broken::Shape("vector"));
    };
    fields
        .iter()
        .map(|(key, json)| Ok((key.clone(), value(key, json)?)))
        .collect()
}

fn value(key: &str, json: &Json) -> Result<Value, Broken> {
    match json {
        Json::Text(text) if TEXT_FIELDS.contains(&key) => Ok(Value::Text(text.clone())),
        Json::Text(text) => hex(text).map(Value::Hex),
        Json::Number(number) => Ok(Value::Number(*number)),
        Json::Bool(flag) => Ok(Value::Bool(*flag)),
        Json::Array(items) => items
            .iter()
            .map(|item| value(key, item))
            .collect::<Result<_, _>>()
            .map(Value::List),
        Json::Object(_) => Err(Broken::Shape("value")),
    }
}

/// The values of an object that has exactly these keys, in the order of `keys`.
fn exact<'a, const N: usize>(
    json: &'a Json,
    keys: [&str; N],
    object: &'static str,
) -> Result<[&'a Json; N], Broken> {
    let Json::Object(fields) = json else {
        return Err(Broken::Shape(object));
    };
    let values: Option<Vec<&Json>> = keys
        .iter()
        .map(|key| {
            fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, json)| json)
        })
        .collect();
    values
        .filter(|_| fields.len() == N)
        .and_then(|values| values.try_into().ok())
        .ok_or(Broken::Shape(object))
}

fn text(json: &Json) -> Result<&str, Broken> {
    match json {
        Json::Text(text) => Ok(text),
        _ => Err(Broken::Shape("text field")),
    }
}

/// Lowercase hexadecimal of even length, the encoding of every byte string.
fn hex(text: &str) -> Result<Vec<u8>, Broken> {
    let is_lowercase_hex = text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !is_lowercase_hex || !text.len().is_multiple_of(2) {
        return Err(Broken::Hex);
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| Broken::Hex))
        .collect()
}

/// The JSON subset the files use, before the schema gives it meaning.
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    Text(String),
    Number(u32),
    Bool(bool),
}

struct Reader<'a> {
    rest: &'a str,
}

impl Reader<'_> {
    /// One value and nothing after it.
    fn document(source: &str) -> Result<Json, Broken> {
        let mut reader = Reader { rest: source };
        let json = reader.value()?;
        reader.skip_space();
        reader.rest.is_empty().then_some(json).ok_or(Broken::Syntax)
    }

    /// JSON whitespace only, not every Unicode space.
    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\n', '\r']);
    }

    fn value(&mut self) -> Result<Json, Broken> {
        self.skip_space();
        match self.rest.chars().next() {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => self.text().map(Json::Text),
            Some('t') => self.word("true", Json::Bool(true)),
            Some('f') => self.word("false", Json::Bool(false)),
            Some('n') if self.rest.starts_with("null") => Err(Broken::Null),
            Some(first) if first.is_ascii_digit() || first == '-' => self.number(),
            _ => Err(Broken::Syntax),
        }
    }

    fn word(&mut self, word: &str, json: Json) -> Result<Json, Broken> {
        self.rest = self.rest.strip_prefix(word).ok_or(Broken::Syntax)?;
        Ok(json)
    }

    fn text(&mut self) -> Result<String, Broken> {
        self.eat('"')?;
        let (text, rest) = self.rest.split_once('"').ok_or(Broken::Syntax)?;
        if text.contains(|c: char| c == '\\' || c.is_control()) {
            return Err(Broken::Syntax);
        }
        self.rest = rest;
        Ok(text.to_owned())
    }

    fn number(&mut self) -> Result<Json, Broken> {
        let end = self
            .rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.')))
            .unwrap_or(self.rest.len());
        let (literal, rest) = self.rest.split_at(end);
        self.rest = rest;
        let is_plain = literal.bytes().all(|byte| byte.is_ascii_digit())
            && (literal == "0" || !literal.starts_with('0'));
        if !is_plain {
            return Err(Broken::Number);
        }
        let number = literal.parse().map_err(|_| Broken::Number)?;
        Ok(Json::Number(number))
    }

    fn object(&mut self) -> Result<Json, Broken> {
        let mut fields: Vec<(String, Json)> = Vec::new();
        self.sequence('{', '}', |reader| {
            let key = reader.text()?;
            if fields.iter().any(|(name, _)| *name == key) {
                return Err(Broken::DuplicateKey);
            }
            reader.eat(':')?;
            fields.push((key, reader.value()?));
            Ok(())
        })?;
        Ok(Json::Object(fields))
    }

    fn array(&mut self) -> Result<Json, Broken> {
        let mut items = Vec::new();
        self.sequence('[', ']', |reader| {
            items.push(reader.value()?);
            Ok(())
        })?;
        Ok(Json::Array(items))
    }

    /// Reads comma-separated items between `open` and `close`, the shape both
    /// containers share.
    fn sequence(
        &mut self,
        open: char,
        close: char,
        mut item: impl FnMut(&mut Self) -> Result<(), Broken>,
    ) -> Result<(), Broken> {
        self.eat(open)?;
        if self.eat(close).is_ok() {
            return Ok(());
        }
        loop {
            item(self)?;
            if self.eat(close).is_ok() {
                return Ok(());
            }
            self.eat(',')?;
        }
    }

    fn eat(&mut self, delimiter: char) -> Result<(), Broken> {
        self.skip_space();
        self.rest = self.rest.strip_prefix(delimiter).ok_or(Broken::Syntax)?;
        Ok(())
    }
}

mod tests;
