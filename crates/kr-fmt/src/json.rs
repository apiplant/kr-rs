//! Strict RFC 8259 JSON: value tree, parser, compact serializer and a pull tokenizer.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------- errors

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    UnexpectedEof,
    UnexpectedChar,
    InvalidEscape,
    InvalidUnicodeEscape,
    LoneSurrogate,
    InvalidUtf8,
    ControlCharacter,
    InvalidNumber,
    NumberOutOfRange,
    TrailingData,
    DepthExceeded,
    InputTooLarge,
}

/// A parse error with the byte offset at which it was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
}

impl Error {
    fn new(kind: ErrorKind, offset: usize) -> Self {
        Error { kind, offset }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::UnexpectedEof => "unexpected end of input",
            ErrorKind::UnexpectedChar => "unexpected character",
            ErrorKind::InvalidEscape => "invalid escape sequence",
            ErrorKind::InvalidUnicodeEscape => "invalid \\u escape",
            ErrorKind::LoneSurrogate => "lone surrogate in \\u escape",
            ErrorKind::InvalidUtf8 => "invalid UTF-8",
            ErrorKind::ControlCharacter => "unescaped control character in string",
            ErrorKind::InvalidNumber => "invalid number",
            ErrorKind::NumberOutOfRange => "number out of range",
            ErrorKind::TrailingData => "trailing data after value",
            ErrorKind::DepthExceeded => "nesting depth limit exceeded",
            ErrorKind::InputTooLarge => "input size limit exceeded",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json: {} at byte {}", self.kind, self.offset)
    }
}

/// Parser limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum nesting of arrays/objects (default 64).
    pub max_depth: usize,
    /// Maximum input size in bytes (default 32 MiB).
    pub max_input: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 64, max_input: 32 << 20 }
    }
}

// ---------------------------------------------------------------- numbers

#[derive(Clone, Copy, Debug, PartialEq)]
enum Repr {
    I(i64),
    U(u64),
    F(f64),
}

/// Why a number failed to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumError {
    /// Not a valid JSON number.
    Invalid,
    /// Valid, but not representable as a finite f64.
    OutOfRange,
}

/// A JSON number. Integers that fit are kept exact as `i64`/`u64`; everything
/// else is an `f64`. The original text is retained so serialization
/// round-trips byte-for-byte (`1.0`, `1e2`, `-0` and big integers survive).
/// Equality compares the numeric representation, not the text.
#[derive(Clone, Debug)]
pub struct Number {
    repr: Repr,
    raw: String,
}

impl PartialEq for Number {
    fn eq(&self, o: &Self) -> bool {
        self.repr == o.repr
    }
}

impl Number {
    pub fn from_i64(v: i64) -> Number {
        Number { repr: Repr::I(v), raw: alloc::format!("{}", v) }
    }
    pub fn from_u64(v: u64) -> Number {
        match i64::try_from(v) {
            Ok(i) => Number::from_i64(i),
            Err(_) => Number { repr: Repr::U(v), raw: alloc::format!("{}", v) },
        }
    }
    /// `None` for NaN and infinities (not representable in JSON).
    pub fn from_f64(v: f64) -> Option<Number> {
        if !v.is_finite() {
            return None;
        }
        Some(Number { repr: Repr::F(v), raw: alloc::format!("{}", v) })
    }

    /// Parse a complete JSON number (strict grammar, no surrounding space).
    pub fn parse(s: &str) -> Result<Number, NumError> {
        match scan_number(s.as_bytes(), 0) {
            Ok((end, is_float)) if end == s.len() => Number::from_scanned(s, is_float),
            _ => Err(NumError::Invalid),
        }
    }

    fn from_scanned(s: &str, is_float: bool) -> Result<Number, NumError> {
        let repr = if !is_float {
            if let Ok(i) = s.parse::<i64>() {
                Repr::I(i)
            } else if let Ok(u) = s.parse::<u64>() {
                Repr::U(u)
            } else {
                Repr::F(parse_f64(s)?)
            }
        } else {
            Repr::F(parse_f64(s)?)
        };
        Ok(Number { repr, raw: String::from(s) })
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self.repr {
            Repr::I(i) => Some(i),
            Repr::U(u) => i64::try_from(u).ok(),
            Repr::F(_) => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self.repr {
            Repr::I(i) => u64::try_from(i).ok(),
            Repr::U(u) => Some(u),
            Repr::F(_) => None,
        }
    }
    /// Lossy for integers above 2^53.
    pub fn as_f64(&self) -> f64 {
        match self.repr {
            Repr::I(i) => i as f64,
            Repr::U(u) => u as f64,
            Repr::F(f) => f,
        }
    }
    /// True when the value is held as an exact integer.
    pub fn is_integer(&self) -> bool {
        !matches!(self.repr, Repr::F(_))
    }
    /// The JSON text of this number.
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

fn parse_f64(s: &str) -> Result<f64, NumError> {
    match s.parse::<f64>() {
        Ok(f) if f.is_finite() => Ok(f),
        Ok(_) => Err(NumError::OutOfRange),
        Err(_) => Err(NumError::Invalid),
    }
}

fn is_digit(b: Option<&u8>) -> bool {
    matches!(b, Some(b'0'..=b'9'))
}

/// Scan the RFC 8259 number grammar starting at `start`. Returns (end, is_float)
/// or the offset of the offending byte.
fn scan_number(b: &[u8], start: usize) -> Result<(usize, bool), usize> {
    let mut i = start;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while is_digit(b.get(i)) {
                i += 1;
            }
        }
        _ => return Err(i),
    }
    let mut float = false;
    if b.get(i) == Some(&b'.') {
        i += 1;
        if !is_digit(b.get(i)) {
            return Err(i);
        }
        while is_digit(b.get(i)) {
            i += 1;
        }
        float = true;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !is_digit(b.get(i)) {
            return Err(i);
        }
        while is_digit(b.get(i)) {
            i += 1;
        }
        float = true;
    }
    Ok((i, float))
}

// ---------------------------------------------------------------- value

/// A JSON value. Objects keep insertion order and allow duplicate keys
/// (RFC 8259 leaves them undefined); `get` returns the last match.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self { Some(*b) } else { None }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(s) = self { Some(s) } else { None }
    }
    pub fn as_number(&self) -> Option<&Number> {
        if let Value::Number(n) = self { Some(n) } else { None }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(Number::as_u64)
    }
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().map(Number::as_f64)
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        if let Value::Array(a) = self { Some(a) } else { None }
    }
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        if let Value::Object(o) = self { Some(o) } else { None }
    }
    /// Look up an object member (last duplicate wins).
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Array element.
    pub fn at(&self, i: usize) -> Option<&Value> {
        self.as_array()?.get(i)
    }
    /// Follows a path of object keys.
    pub fn pointer(&self, path: &[&str]) -> Option<&Value> {
        path.iter().try_fold(self, |v, k| v.get(k))
    }
    pub fn as_object_mut(&mut self) -> Option<&mut Vec<(String, Value)>> {
        if let Value::Object(o) = self { Some(o) } else { None }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        if let Value::Array(a) = self { Some(a) } else { None }
    }
    /// Mutable member lookup (last duplicate wins, like `get`).
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.as_object_mut()?.iter_mut().rev().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Sets a member (replacing every existing entry with that key). No-op on non-objects.
    pub fn set(&mut self, key: &str, v: Value) {
        if let Some(o) = self.as_object_mut() {
            match o.iter().position(|(k, _)| k == key) {
                Some(i) => {
                    o[i].1 = v;
                    let mut j = i + 1;
                    while j < o.len() {
                        if o[j].0 == key {
                            o.remove(j);
                        } else {
                            j += 1;
                        }
                    }
                }
                None => o.push((key.into(), v)),
            }
        }
    }
    /// Removes all members named `key`, returning the last one.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let o = self.as_object_mut()?;
        let mut out = None;
        o.retain_mut(|(k, v)| {
            if k == key {
                out = Some(core::mem::replace(v, Value::Null));
                false
            } else {
                true
            }
        });
        out
    }
    /// Gets member `key`, inserting an empty object first if it is missing or not an object.
    pub fn entry_object(&mut self, key: &str) -> &mut Value {
        if !matches!(self.get(key), Some(Value::Object(_))) {
            self.set(key, Value::Object(Vec::new()));
        }
        self.get_mut(key).unwrap()
    }
    /// True if any object (at any depth) contains the same key twice.
    pub fn has_duplicate_keys(&self) -> bool {
        match self {
            Value::Object(o) => o.iter().enumerate().any(|(i, (k, v))| o[..i].iter().any(|(k2, _)| k2 == k) || v.has_duplicate_keys()),
            Value::Array(a) => a.iter().any(Value::has_duplicate_keys),
            _ => false,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_string(self))
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(String::from(s))
    }
}
impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Value {
        Value::Number(Number::from_i64(v))
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::Number(Number::from_u64(v))
    }
}

// ---------------------------------------------------------------- tokenizer

/// A token from the pull tokenizer. Strings borrow from the input unless they
/// contained escapes.
#[derive(Clone, Debug, PartialEq)]
pub enum Token<'a> {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    /// Object member name (the following token is its value).
    Key(Cow<'a, str>),
    String(Cow<'a, str>),
    /// Validated number text (RFC 8259 grammar), borrowed from the input.
    Number(&'a str),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, PartialEq)]
enum St {
    Value,
    ArrFirst,
    ObjFirst,
    ObjKey,
    AfterValue,
    Done,
}

/// Zero-copy pull tokenizer. It allocates only for the container-nesting stack
/// (one byte per level) and for strings that contain escape sequences.
pub struct Tokenizer<'a> {
    src: &'a [u8],
    pos: usize,
    limits: Limits,
    /// true = object, false = array
    stack: Vec<bool>,
    st: St,
    checked: bool,
}

impl<'a> Tokenizer<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self::with_limits(src, Limits::default())
    }
    pub fn with_limits(src: &'a [u8], limits: Limits) -> Self {
        Tokenizer { src, pos: 0, limits, stack: Vec::new(), st: St::Value, checked: false }
    }
    /// Current byte offset (just past the last token returned).
    pub fn offset(&self) -> usize {
        self.pos
    }
    /// Current container nesting depth.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    fn skip_ws(&mut self) {
        while matches!(self.src.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn err<T>(&self, kind: ErrorKind, at: usize) -> Result<T, Error> {
        Err(Error::new(kind, at))
    }

    /// Next token, `Ok(None)` at the clean end of a complete document.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Token<'a>>, Error> {
        if !self.checked {
            self.checked = true;
            if self.src.len() > self.limits.max_input {
                return self.err(ErrorKind::InputTooLarge, self.limits.max_input);
            }
        }
        self.skip_ws();
        let c = self.src.get(self.pos).copied();
        match self.st {
            St::Done => match c {
                None => Ok(None),
                Some(_) => self.err(ErrorKind::TrailingData, self.pos),
            },
            St::AfterValue => {
                let Some(c) = c else {
                    if self.stack.is_empty() {
                        self.st = St::Done;
                        return Ok(None);
                    }
                    return self.err(ErrorKind::UnexpectedEof, self.pos);
                };
                let Some(&in_obj) = self.stack.last() else {
                    return self.err(ErrorKind::TrailingData, self.pos);
                };
                match c {
                    b',' => {
                        self.pos += 1;
                        self.st = if in_obj { St::ObjKey } else { St::Value };
                        self.next()
                    }
                    b'}' if in_obj => Ok(Some(self.close(Token::ObjectEnd))),
                    b']' if !in_obj => Ok(Some(self.close(Token::ArrayEnd))),
                    _ => self.err(ErrorKind::UnexpectedChar, self.pos),
                }
            }
            St::ObjFirst if c == Some(b'}') => Ok(Some(self.close(Token::ObjectEnd))),
            St::ObjFirst | St::ObjKey => match c {
                None => self.err(ErrorKind::UnexpectedEof, self.pos),
                Some(b'"') => {
                    let k = self.string()?;
                    self.skip_ws();
                    match self.src.get(self.pos) {
                        Some(b':') => {
                            self.pos += 1;
                            self.st = St::Value;
                            Ok(Some(Token::Key(k)))
                        }
                        Some(_) => self.err(ErrorKind::UnexpectedChar, self.pos),
                        None => self.err(ErrorKind::UnexpectedEof, self.pos),
                    }
                }
                Some(_) => self.err(ErrorKind::UnexpectedChar, self.pos),
            },
            St::ArrFirst if c == Some(b']') => Ok(Some(self.close(Token::ArrayEnd))),
            St::ArrFirst | St::Value => self.value(c).map(Some),
        }
    }

    fn close(&mut self, t: Token<'a>) -> Token<'a> {
        self.pos += 1;
        self.stack.pop();
        self.st = St::AfterValue;
        t
    }

    fn value(&mut self, c: Option<u8>) -> Result<Token<'a>, Error> {
        let Some(c) = c else {
            return self.err(ErrorKind::UnexpectedEof, self.pos);
        };
        match c {
            b'{' | b'[' => {
                if self.stack.len() >= self.limits.max_depth {
                    return self.err(ErrorKind::DepthExceeded, self.pos);
                }
                self.pos += 1;
                if c == b'{' {
                    self.stack.push(true);
                    self.st = St::ObjFirst;
                    Ok(Token::ObjectStart)
                } else {
                    self.stack.push(false);
                    self.st = St::ArrFirst;
                    Ok(Token::ArrayStart)
                }
            }
            b'"' => {
                let s = self.string()?;
                self.st = St::AfterValue;
                Ok(Token::String(s))
            }
            b't' => self.literal(b"true", Token::Bool(true)),
            b'f' => self.literal(b"false", Token::Bool(false)),
            b'n' => self.literal(b"null", Token::Null),
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                match scan_number(self.src, start) {
                    Ok((end, _)) => {
                        self.pos = end;
                        self.st = St::AfterValue;
                        // The slice is ASCII by construction.
                        match core::str::from_utf8(&self.src[start..end]) {
                            Ok(s) => Ok(Token::Number(s)),
                            Err(_) => self.err(ErrorKind::InvalidNumber, start),
                        }
                    }
                    Err(at) => {
                        if at >= self.src.len() {
                            self.err(ErrorKind::UnexpectedEof, at)
                        } else {
                            self.err(ErrorKind::InvalidNumber, at)
                        }
                    }
                }
            }
            _ => self.err(ErrorKind::UnexpectedChar, self.pos),
        }
    }

    fn literal(&mut self, word: &'static [u8], tok: Token<'a>) -> Result<Token<'a>, Error> {
        let rest = &self.src[self.pos..];
        for (i, w) in word.iter().enumerate() {
            match rest.get(i) {
                Some(b) if b == w => {}
                Some(_) => return self.err(ErrorKind::UnexpectedChar, self.pos + i),
                None => return self.err(ErrorKind::UnexpectedEof, self.pos + i),
            }
        }
        self.pos += word.len();
        self.st = St::AfterValue;
        Ok(tok)
    }

    fn string(&mut self) -> Result<Cow<'a, str>, Error> {
        let src = self.src;
        let start = self.pos + 1;
        let mut i = start;
        let mut run = start;
        let mut out: Option<String> = None;
        loop {
            let Some(&b) = src.get(i) else {
                return self.err(ErrorKind::UnexpectedEof, src.len());
            };
            match b {
                b'"' => {
                    let res = match out {
                        None => Cow::Borrowed(utf8(src, run, i)?),
                        Some(mut s) => {
                            s.push_str(utf8(src, run, i)?);
                            Cow::Owned(s)
                        }
                    };
                    self.pos = i + 1;
                    return Ok(res);
                }
                0..=0x1f => return self.err(ErrorKind::ControlCharacter, i),
                b'\\' => {
                    let s = out.get_or_insert_with(String::new);
                    s.push_str(utf8(src, run, i)?);
                    let Some(&e) = src.get(i + 1) else {
                        return self.err(ErrorKind::UnexpectedEof, src.len());
                    };
                    i += 2;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let esc_at = i - 2;
                            let hi = hex4(src, i)?;
                            i += 4;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if src.get(i) == Some(&b'\\') && src.get(i + 1) == Some(&b'u') {
                                    let lo = hex4(src, i + 2)?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return self.err(ErrorKind::LoneSurrogate, esc_at);
                                    }
                                    i += 6;
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return self.err(ErrorKind::LoneSurrogate, esc_at);
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err(ErrorKind::LoneSurrogate, esc_at);
                            } else {
                                hi
                            };
                            match char::from_u32(cp) {
                                Some(c) => s.push(c),
                                None => return self.err(ErrorKind::InvalidUnicodeEscape, esc_at),
                            }
                        }
                        _ => return self.err(ErrorKind::InvalidEscape, i - 1),
                    }
                    run = i;
                }
                _ => i += 1,
            }
        }
    }
}

fn utf8(src: &[u8], from: usize, to: usize) -> Result<&str, Error> {
    core::str::from_utf8(&src[from..to])
        .map_err(|e| Error::new(ErrorKind::InvalidUtf8, from + e.valid_up_to()))
}

fn hex4(src: &[u8], at: usize) -> Result<u32, Error> {
    let mut v = 0u32;
    for k in 0..4 {
        let d = match src.get(at + k) {
            Some(c @ b'0'..=b'9') => c - b'0',
            Some(c @ b'a'..=b'f') => c - b'a' + 10,
            Some(c @ b'A'..=b'F') => c - b'A' + 10,
            Some(_) => return Err(Error::new(ErrorKind::InvalidUnicodeEscape, at + k)),
            None => return Err(Error::new(ErrorKind::UnexpectedEof, src.len())),
        };
        v = v * 16 + u32::from(d);
    }
    Ok(v)
}

// ---------------------------------------------------------------- parser

enum Frame {
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>, Option<String>),
}

/// Parse a complete document with default limits.
pub fn parse(src: &[u8]) -> Result<Value, Error> {
    parse_with(src, Limits::default())
}

/// Parse a UTF-8 string.
pub fn parse_str(src: &str) -> Result<Value, Error> {
    parse(src.as_bytes())
}

/// Parse a complete document with explicit limits.
pub fn parse_with(src: &[u8], limits: Limits) -> Result<Value, Error> {
    let mut tz = Tokenizer::with_limits(src, limits);
    let mut stack: Vec<Frame> = Vec::new();
    let mut result: Option<Value> = None;
    while let Some(tok) = tz.next()? {
        let v = match tok {
            Token::ObjectStart => {
                stack.push(Frame::Obj(Vec::new(), None));
                continue;
            }
            Token::ArrayStart => {
                stack.push(Frame::Arr(Vec::new()));
                continue;
            }
            Token::Key(k) => {
                if let Some(Frame::Obj(_, pk)) = stack.last_mut() {
                    *pk = Some(k.into_owned());
                }
                continue;
            }
            Token::ObjectEnd => match stack.pop() {
                Some(Frame::Obj(o, _)) => Value::Object(o),
                _ => return Err(Error::new(ErrorKind::UnexpectedChar, tz.offset())),
            },
            Token::ArrayEnd => match stack.pop() {
                Some(Frame::Arr(a)) => Value::Array(a),
                _ => return Err(Error::new(ErrorKind::UnexpectedChar, tz.offset())),
            },
            Token::String(s) => Value::String(s.into_owned()),
            Token::Number(t) => {
                let is_float = t.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
                match Number::from_scanned(t, is_float) {
                    Ok(n) => Value::Number(n),
                    Err(_) => {
                        return Err(Error::new(ErrorKind::NumberOutOfRange, tz.offset() - t.len()))
                    }
                }
            }
            Token::Bool(b) => Value::Bool(b),
            Token::Null => Value::Null,
        };
        match stack.last_mut() {
            None => result = Some(v),
            Some(Frame::Arr(a)) => a.push(v),
            Some(Frame::Obj(o, pk)) => o.push((pk.take().unwrap_or_default(), v)),
        }
    }
    result.ok_or(Error::new(ErrorKind::UnexpectedEof, src.len()))
}

// ---------------------------------------------------------------- serializer

/// Compact serialization.
pub fn to_string(v: &Value) -> String {
    let mut s = String::new();
    write_value(v, &mut s);
    s
}

/// Append the compact serialization of `v` to `out`.
pub fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(n.raw()),
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(e, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, e)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write_value(e, out);
            }
            out.push('}');
        }
    }
}

/// Append `s` as a quoted, escaped JSON string.
pub fn write_str(s: &str, out: &mut String) {
    use core::fmt::Write;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
