//! The subset of YAML used by Kubernetes manifests, producing [`json::Value`].
//!
//! Supported: block mappings and sequences, flow `[]`/`{}` collections, plain,
//! single- and double-quoted scalars (multi-line folding included), `|` and `>`
//! block scalars with chomping and indentation indicators, comments, and
//! multi-document streams (`---`, `...`). Scalars follow the YAML 1.2 core
//! schema, so `yes`/`no`/`on`/`off` are strings.
//!
//! Rejected with a dedicated error: anchors (`&`), aliases (`*`), tags (`!`),
//! directives (`%`), explicit keys (`? `), tab indentation, duplicate mapping
//! keys, `.inf`/`.nan`, and single-pair mappings inside flow sequences.
//! See ADR-012.

use crate::json::{self, NumError, Number, Value};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use crate::json::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// `&anchor`
    Anchor,
    /// `*alias`
    Alias,
    /// `!tag`
    Tag,
    /// `%YAML` / `%TAG`
    Directive,
    /// `? explicit key`
    ExplicitKey,
    TabIndent,
    BadIndent,
    DuplicateKey,
    InvalidEscape,
    /// Input ended inside a quoted scalar or flow collection.
    UnexpectedEof,
    /// `.inf` / `.nan` cannot be represented in JSON.
    NonFiniteFloat,
    NumberOutOfRange,
    DepthExceeded,
    InputTooLarge,
    /// `parse` was given more than one document.
    MultipleDocuments,
    Syntax(&'static str),
}

/// A YAML error with the 1-based line it was detected on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub line: usize,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::Anchor => "anchors (&) are not supported",
            ErrorKind::Alias => "aliases (*) are not supported",
            ErrorKind::Tag => "tags (!) are not supported",
            ErrorKind::Directive => "directives (%) are not supported",
            ErrorKind::ExplicitKey => "explicit keys (?) are not supported",
            ErrorKind::TabIndent => "tabs are not allowed for indentation",
            ErrorKind::BadIndent => "bad indentation",
            ErrorKind::DuplicateKey => "duplicate mapping key",
            ErrorKind::InvalidEscape => "invalid escape sequence",
            ErrorKind::UnexpectedEof => "unterminated quoted scalar or flow collection",
            ErrorKind::NonFiniteFloat => ".inf/.nan are not supported",
            ErrorKind::NumberOutOfRange => "number out of range",
            ErrorKind::DepthExceeded => "nesting depth limit exceeded",
            ErrorKind::InputTooLarge => "input size limit exceeded",
            ErrorKind::MultipleDocuments => "expected a single document, found several",
            ErrorKind::Syntax(m) => m,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "yaml: line {}: {}", self.line, self.kind)
    }
}

/// Internal error: kind plus byte offset within the scanned buffer.
type FE = (ErrorKind, usize);

// ---------------------------------------------------------------- public API

/// Parse a stream expected to hold at most one document (empty input is `null`).
pub fn parse(src: &str) -> Result<Value, Error> {
    let mut docs = parse_all(src)?;
    match docs.len() {
        0 => Ok(Value::Null),
        1 => Ok(docs.remove(0)),
        _ => Err(Error { kind: ErrorKind::MultipleDocuments, line: 1 }),
    }
}

/// Parse every document in a stream. Documents that contain only whitespace
/// and comments (for example the one before a leading `---`) are skipped.
pub fn parse_all(src: &str) -> Result<Vec<Value>, Error> {
    parse_all_with(src, Limits::default())
}

pub fn parse_all_with(src: &str, limits: Limits) -> Result<Vec<Value>, Error> {
    if src.len() > limits.max_input {
        return Err(Error { kind: ErrorKind::InputTooLarge, line: 1 });
    }
    let mut out = Vec::new();
    for lines in split_docs(src) {
        if lines.iter().all(|l| is_blank_or_comment(l.text)) {
            continue;
        }
        let mut p = P { lines, idx: 0, depth: 0, max: limits.max_depth };
        let v = p.parse_node(0, -1)?;
        p.skip_blank()?;
        if p.idx < p.lines.len() {
            return Err(p.err(ErrorKind::Syntax("unexpected content (bad indentation?)")));
        }
        out.push(v);
    }
    Ok(out)
}

// ---------------------------------------------------------------- lines

#[derive(Clone, Copy)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
    no: usize,
}

fn is_blank(t: &str) -> bool {
    t.trim_matches([' ', '\t']).is_empty()
}

fn is_blank_or_comment(t: &str) -> bool {
    let t = t.trim_start_matches([' ', '\t']);
    t.is_empty() || t.starts_with('#')
}

fn is_marker(raw: &str, m: &str) -> bool {
    raw.starts_with(m) && matches!(raw.as_bytes().get(3), None | Some(b' ' | b'\t'))
}

fn split_docs(src: &str) -> Vec<Vec<Line<'_>>> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let src = src.strip_suffix('\n').unwrap_or(src);
    let mut docs: Vec<Vec<Line<'_>>> = alloc::vec![Vec::new()];
    for (n, raw) in src.split('\n').enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let no = n + 1;
        if is_marker(raw, "---") {
            docs.push(Vec::new());
            let rest = raw[3..].trim_start_matches([' ', '\t']);
            if !rest.is_empty() && !rest.starts_with('#') {
                // Content on the marker line behaves like a line indented by 4.
                if let Some(d) = docs.last_mut() {
                    d.push(Line { indent: 4, text: rest, no });
                }
            }
            continue;
        }
        if is_marker(raw, "...") {
            docs.push(Vec::new());
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        if let Some(d) = docs.last_mut() {
            d.push(Line { indent, text: &raw[indent..], no });
        }
    }
    docs
}

fn is_seq_item(t: &str) -> bool {
    t.starts_with('-') && matches!(t.as_bytes().get(1), None | Some(b' ' | b'\t'))
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Cut a trailing ` #comment`. Returns the trimmed text and whether a comment was cut.
fn strip_comment(t: &str) -> (&str, bool) {
    let b = t.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'#' && (i == 0 || is_ws(b[i - 1])) {
            return (t[..i].trim_end_matches([' ', '\t']), true);
        }
    }
    (t.trim_end_matches([' ', '\t']), false)
}

/// If `t` is `key: rest`, return the key text and the text after the colon.
fn split_key(t: &str) -> Result<Option<(String, &str)>, ErrorKind> {
    let b = t.as_bytes();
    let Some(&c0) = b.first() else {
        return Ok(None);
    };
    match c0 {
        b'"' | b'\'' => match scan_quoted(t, 0, c0) {
            Ok((s, end)) => {
                let r = t[end..].trim_start_matches(' ');
                if r.starts_with(':') && matches!(r.as_bytes().get(1), None | Some(b' ' | b'\t')) {
                    Ok(Some((s, &r[1..])))
                } else {
                    Ok(None)
                }
            }
            Err((ErrorKind::UnexpectedEof, _)) => Ok(None),
            Err((k, _)) => Err(k),
        },
        b'[' | b'{' | b'|' | b'>' => Ok(None),
        b'&' => Err(ErrorKind::Anchor),
        b'*' => Err(ErrorKind::Alias),
        b'!' => Err(ErrorKind::Tag),
        b'%' => Err(ErrorKind::Directive),
        b'?' if matches!(b.get(1), None | Some(b' ' | b'\t')) => Err(ErrorKind::ExplicitKey),
        _ => {
            for i in 0..b.len() {
                match b[i] {
                    b':' if i + 1 == b.len() || is_ws(b[i + 1]) => {
                        let key = t[..i].trim_end_matches([' ', '\t']);
                        if key.is_empty() {
                            return Err(ErrorKind::Syntax("empty mapping key"));
                        }
                        return Ok(Some((String::from(key), &t[i + 1..])));
                    }
                    b'#' if i > 0 && is_ws(b[i - 1]) => return Ok(None),
                    _ => {}
                }
            }
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------- block parser

struct P<'a> {
    lines: Vec<Line<'a>>,
    idx: usize,
    depth: usize,
    max: usize,
}

impl<'a> P<'a> {
    fn err(&self, kind: ErrorKind) -> Error {
        let line = self.lines.get(self.idx).or(self.lines.last()).map_or(1, |l| l.no);
        Error { kind, line }
    }
    fn err_at(&self, kind: ErrorKind, line: usize) -> Error {
        Error { kind, line }
    }

    fn skip_blank(&mut self) -> Result<(), Error> {
        while self.idx < self.lines.len() && is_blank_or_comment(self.lines[self.idx].text) {
            self.idx += 1;
        }
        if self.idx < self.lines.len() && self.lines[self.idx].text.starts_with('\t') {
            return Err(self.err(ErrorKind::TabIndent));
        }
        Ok(())
    }

    fn parse_node(&mut self, min_indent: usize, parent: isize) -> Result<Value, Error> {
        self.skip_blank()?;
        let Some(&Line { indent, text, no }) = self.lines.get(self.idx) else {
            return Ok(Value::Null);
        };
        if indent < min_indent {
            return Ok(Value::Null);
        }
        if self.depth >= self.max {
            return Err(self.err(ErrorKind::DepthExceeded));
        }
        self.depth += 1;
        let r = if is_seq_item(text) {
            self.parse_seq(indent)
        } else if split_key(text).map_err(|k| self.err_at(k, no))?.is_some() {
            self.parse_map(indent)
        } else {
            self.parse_inline(text, parent)
        };
        self.depth -= 1;
        r
    }

    fn parse_seq(&mut self, indent: usize) -> Result<Value, Error> {
        let mut items = Vec::new();
        loop {
            self.skip_blank()?;
            let Some(&Line { indent: li, text, no }) = self.lines.get(self.idx) else {
                break;
            };
            if li < indent {
                break;
            }
            if li > indent {
                return Err(self.err(ErrorKind::BadIndent));
            }
            if !is_seq_item(text) {
                break;
            }
            let rest = &text[1..];
            let ws = rest.len() - rest.trim_start_matches([' ', '\t']).len();
            let rest = &rest[ws..];
            let v = if rest.is_empty() || rest.starts_with('#') {
                self.idx += 1;
                self.skip_blank()?;
                match self.lines.get(self.idx) {
                    Some(l) if l.indent > indent => self.parse_node(indent + 1, indent as isize)?,
                    _ => Value::Null,
                }
            } else {
                // Compact nesting: re-seat the line as if the item content started it.
                let ni = indent + 1 + ws;
                self.lines[self.idx] = Line { indent: ni, text: rest, no };
                self.parse_node(ni, indent as isize)?
            };
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn parse_map(&mut self, indent: usize) -> Result<Value, Error> {
        let mut entries: Vec<(String, Value)> = Vec::new();
        loop {
            self.skip_blank()?;
            let Some(&Line { indent: li, text, no }) = self.lines.get(self.idx) else {
                break;
            };
            if li < indent {
                break;
            }
            if li > indent {
                return Err(self.err(ErrorKind::BadIndent));
            }
            let Some((key, rest)) = split_key(text).map_err(|k| self.err_at(k, no))? else {
                return Err(self.err_at(ErrorKind::Syntax("expected 'key: value'"), no));
            };
            if entries.iter().any(|(k, _)| *k == key) {
                return Err(self.err_at(ErrorKind::DuplicateKey, no));
            }
            let rest = rest.trim_start_matches([' ', '\t']);
            let v = if rest.is_empty() || rest.starts_with('#') {
                self.idx += 1;
                self.skip_blank()?;
                match self.lines.get(self.idx).copied() {
                    Some(l) if l.indent > indent => self.parse_node(indent + 1, indent as isize)?,
                    Some(l) if l.indent == indent && is_seq_item(l.text) => self.parse_seq(indent)?,
                    _ => Value::Null,
                }
            } else {
                self.parse_inline(rest, indent as isize)?
            };
            entries.push((key, v));
        }
        Ok(Value::Object(entries))
    }

    /// Parse a scalar or flow value that starts with `text` on the current line.
    /// Leaves `self.idx` just past the last line consumed.
    fn parse_inline(&mut self, text: &'a str, parent: isize) -> Result<Value, Error> {
        let no = self.lines[self.idx].no;
        let b = text.as_bytes();
        let next_ws = matches!(b.get(1), None | Some(b' ' | b'\t'));
        match b[0] {
            b'|' | b'>' => return self.block_scalar(text, parent).map(Value::String),
            b'[' | b'{' => {
                let (d, m) = (self.depth, self.max);
                return self.gather(text, move |buf| {
                    let mut f = Flow { s: buf, b: buf.as_bytes(), pos: 0, depth: d, max: m };
                    let v = f.value()?;
                    Ok((v, f.pos))
                });
            }
            q @ (b'"' | b'\'') => {
                return self.gather(text, move |buf| {
                    scan_quoted(buf, 0, q).map(|(s, e)| (Value::String(s), e))
                });
            }
            b'&' => return Err(self.err_at(ErrorKind::Anchor, no)),
            b'*' => return Err(self.err_at(ErrorKind::Alias, no)),
            b'!' => return Err(self.err_at(ErrorKind::Tag, no)),
            b'%' => return Err(self.err_at(ErrorKind::Directive, no)),
            b'@' | b'`' => {
                return Err(self.err_at(ErrorKind::Syntax("reserved indicator at start of scalar"), no))
            }
            b'?' if next_ws => return Err(self.err_at(ErrorKind::ExplicitKey, no)),
            b'-' if next_ws => {
                return Err(self.err_at(ErrorKind::Syntax("sequence entry not allowed here"), no))
            }
            b':' if next_ws => {
                return Err(self.err_at(ErrorKind::Syntax("mapping value not allowed here"), no))
            }
            b',' | b']' | b'}' => {
                return Err(self.err_at(ErrorKind::Syntax("unexpected flow indicator"), no))
            }
            _ => {}
        }
        // Plain scalar, possibly folded over following more-indented lines.
        let (first, mut commented) = strip_comment(text);
        if split_key(first).map_err(|k| self.err_at(k, no))?.is_some() {
            return Err(self.err_at(ErrorKind::Syntax("mapping values are not allowed here"), no));
        }
        let mut val = String::from(first);
        let mut last = self.idx;
        let mut j = self.idx + 1;
        while !commented {
            let mut k = j;
            while k < self.lines.len() && is_blank(self.lines[k].text) {
                k += 1;
            }
            let Some(&l) = self.lines.get(k) else { break };
            if (l.indent as isize) <= parent || l.text.starts_with('#') {
                break;
            }
            let (t, c) = strip_comment(l.text);
            if split_key(t).map_err(|e| self.err_at(e, l.no))?.is_some() {
                return Err(self.err_at(ErrorKind::Syntax("mapping values are not allowed here"), l.no));
            }
            if k == j {
                val.push(' ');
            } else {
                for _ in 0..(k - j) {
                    val.push('\n');
                }
            }
            val.push_str(t);
            commented = c;
            last = k;
            j = k + 1;
        }
        self.idx = last + 1;
        resolve_plain(&val).map_err(|k| self.err_at(k, no))
    }

    /// Join following lines onto `text` until `f` succeeds (used for quoted
    /// scalars and flow collections that span lines).
    fn gather<F>(&mut self, text: &str, f: F) -> Result<Value, Error>
    where
        F: Fn(&str) -> Result<(Value, usize), FE>,
    {
        let first_no = self.lines[self.idx].no;
        let mut k = self.idx;
        let mut buf = String::from(text);
        loop {
            match f(&buf) {
                Ok((v, end)) => {
                    let tail = &buf[end..];
                    let t = tail.trim_start_matches([' ', '\t']);
                    let ok = t.is_empty() || (t.starts_with('#') && t.len() < tail.len());
                    if !ok {
                        return Err(self.err_at(
                            ErrorKind::Syntax("unexpected content after value"),
                            self.lines[k].no,
                        ));
                    }
                    self.idx = k + 1;
                    return Ok(v);
                }
                Err((ErrorKind::UnexpectedEof, _)) if k + 1 < self.lines.len() => {
                    k += 1;
                    buf.push('\n');
                    buf.push_str(self.lines[k].text);
                }
                Err((kind, off)) => {
                    let off = off.min(buf.len());
                    let extra = buf.as_bytes()[..off].iter().filter(|&&c| c == b'\n').count();
                    return Err(self.err_at(kind, first_no + extra));
                }
            }
        }
    }

    fn block_scalar(&mut self, header: &str, parent: isize) -> Result<String, Error> {
        let no = self.lines[self.idx].no;
        let literal = header.starts_with('|');
        #[derive(PartialEq, Clone, Copy)]
        enum Chomp {
            Clip,
            Strip,
            Keep,
        }
        let mut chomp = Chomp::Clip;
        let mut explicit: Option<usize> = None;
        let hb = header.as_bytes();
        let mut i = 1;
        while i < hb.len() {
            match hb[i] {
                b'+' if chomp == Chomp::Clip => chomp = Chomp::Keep,
                b'-' if chomp == Chomp::Clip => chomp = Chomp::Strip,
                d @ b'1'..=b'9' if explicit.is_none() => explicit = Some(usize::from(d - b'0')),
                b' ' | b'\t' => break,
                _ => return Err(self.err_at(ErrorKind::Syntax("invalid block scalar header"), no)),
            }
            i += 1;
        }
        let tail = header[i..].trim_start_matches([' ', '\t']);
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(self.err_at(ErrorKind::Syntax("invalid block scalar header"), no));
        }
        self.idx += 1;
        let base = parent.max(0) as usize;
        let mut ci: Option<usize> = explicit.map(|d| base + d);
        let mut body: Vec<String> = Vec::new();
        let mut j = self.idx;
        while let Some(&l) = self.lines.get(j) {
            if is_blank(l.text) && !l.text.contains('\t') || l.text.is_empty() {
                let extra = ci.map_or(0, |c| l.indent.saturating_sub(c));
                body.push(" ".repeat(extra));
                j += 1;
                continue;
            }
            match ci {
                None => {
                    if (l.indent as isize) <= parent {
                        break;
                    }
                    ci = Some(l.indent);
                }
                Some(c) => {
                    if l.indent < c {
                        break;
                    }
                }
            }
            let c = ci.unwrap_or(0);
            let mut s = " ".repeat(l.indent - c);
            s.push_str(l.text);
            body.push(s);
            j += 1;
        }
        self.idx = j;
        // Trailing blank lines are subject to chomping.
        let mut trailing = 0;
        while body.last().is_some_and(|s| s.trim_matches(' ').is_empty()) {
            body.pop();
            trailing += 1;
        }
        if body.is_empty() {
            return Ok(if chomp == Chomp::Keep { "\n".repeat(trailing) } else { String::new() });
        }
        let mut text = String::new();
        if literal {
            for (n, s) in body.iter().enumerate() {
                if n > 0 {
                    text.push('\n');
                }
                text.push_str(s);
            }
        } else {
            let mut prev_more: Option<bool> = None;
            let mut blanks = 0usize;
            for s in &body {
                if s.trim_matches(' ').is_empty() {
                    blanks += 1;
                    continue;
                }
                let more = s.starts_with(' ') || s.starts_with('\t');
                match prev_more {
                    Some(false) if !more => {
                        if blanks == 0 {
                            text.push(' ');
                        } else {
                            for _ in 0..blanks {
                                text.push('\n');
                            }
                        }
                    }
                    Some(_) => {
                        for _ in 0..=blanks {
                            text.push('\n');
                        }
                    }
                    None => {
                        for _ in 0..blanks {
                            text.push('\n');
                        }
                    }
                }
                text.push_str(s);
                prev_more = Some(more);
                blanks = 0;
            }
        }
        match chomp {
            Chomp::Strip => {}
            Chomp::Clip => text.push('\n'),
            Chomp::Keep => {
                for _ in 0..=trailing {
                    text.push('\n');
                }
            }
        }
        Ok(text)
    }
}

// ---------------------------------------------------------------- quoted scalars

fn hex_digits(b: &[u8], at: usize, n: usize) -> Option<u32> {
    let mut v = 0u32;
    for k in 0..n {
        let d = match b.get(at + k)? {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(u32::from(d))?;
    }
    Some(v)
}

/// Scan a quoted scalar starting at `s[start]` (the opening quote). Returns the
/// decoded text and the offset just past the closing quote. Line breaks fold
/// per YAML flow-scalar rules. `UnexpectedEof` means "no closing quote yet".
fn scan_quoted(s: &str, start: usize, q: u8) -> Result<(String, usize), FE> {
    let b = s.as_bytes();
    let mut i = start + 1;
    let mut out = String::new();
    let mut prot = 0usize;
    loop {
        let Some(&c) = b.get(i) else {
            return Err((ErrorKind::UnexpectedEof, s.len()));
        };
        if c == q {
            if q == b'\'' && b.get(i + 1) == Some(&b'\'') {
                out.push('\'');
                prot = out.len();
                i += 2;
                continue;
            }
            return Ok((out, i + 1));
        }
        match c {
            b'\\' if q == b'"' => {
                let Some(&n) = b.get(i + 1) else {
                    return Err((ErrorKind::UnexpectedEof, s.len()));
                };
                i += 2;
                let ch = match n {
                    b'0' => '\0',
                    b'a' => '\u{7}',
                    b'b' => '\u{8}',
                    b't' | b'\t' => '\t',
                    b'n' => '\n',
                    b'v' => '\u{b}',
                    b'f' => '\u{c}',
                    b'r' => '\r',
                    b'e' => '\u{1b}',
                    b' ' => ' ',
                    b'"' => '"',
                    b'/' => '/',
                    b'\\' => '\\',
                    b'N' => '\u{85}',
                    b'_' => '\u{a0}',
                    b'L' => '\u{2028}',
                    b'P' => '\u{2029}',
                    b'x' | b'u' | b'U' => {
                        let len = match n {
                            b'x' => 2,
                            b'u' => 4,
                            _ => 8,
                        };
                        let bad = (ErrorKind::InvalidEscape, i - 2);
                        let mut cp = hex_digits(b, i, len).ok_or(bad)?;
                        i += len;
                        if (0xD800..0xDC00).contains(&cp) {
                            // Accept an escaped surrogate pair.
                            if b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u') {
                                let lo = hex_digits(b, i + 2, 4).ok_or(bad)?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(bad);
                                }
                                i += 6;
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else {
                                return Err(bad);
                            }
                        }
                        char::from_u32(cp).ok_or(bad)?
                    }
                    b'\n' => {
                        // Escaped line break: join without a space.
                        while matches!(b.get(i), Some(b' ' | b'\t')) {
                            i += 1;
                        }
                        continue;
                    }
                    _ => return Err((ErrorKind::InvalidEscape, i - 1)),
                };
                out.push(ch);
                prot = out.len();
            }
            b'\n' => {
                while out.len() > prot && out.ends_with([' ', '\t']) {
                    out.pop();
                }
                i += 1;
                let mut nl = 1;
                loop {
                    while matches!(b.get(i), Some(b' ' | b'\t')) {
                        i += 1;
                    }
                    if b.get(i) == Some(&b'\n') {
                        nl += 1;
                        i += 1;
                    } else {
                        break;
                    }
                }
                if nl == 1 {
                    out.push(' ');
                } else {
                    for _ in 1..nl {
                        out.push('\n');
                    }
                }
                prot = out.len();
            }
            _ => {
                let Some(ch) = s[i..].chars().next() else {
                    return Err((ErrorKind::UnexpectedEof, s.len()));
                };
                out.push(ch);
                i += ch.len_utf8();
                if ch != ' ' && ch != '\t' {
                    prot = out.len();
                }
            }
        }
    }
}

// ---------------------------------------------------------------- flow collections

struct Flow<'b> {
    s: &'b str,
    b: &'b [u8],
    pos: usize,
    depth: usize,
    max: usize,
}

fn is_flow_ind(c: u8) -> bool {
    matches!(c, b',' | b'[' | b']' | b'{' | b'}')
}

impl<'b> Flow<'b> {
    fn eof<T>(&self) -> Result<T, FE> {
        Err((ErrorKind::UnexpectedEof, self.b.len()))
    }
    fn syn<T>(&self, m: &'static str) -> Result<T, FE> {
        Err((ErrorKind::Syntax(m), self.pos))
    }

    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.pos) {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                b'#' if self.pos == 0 || matches!(self.b[self.pos - 1], b' ' | b'\t' | b'\n') => {
                    while self.pos < self.b.len() && self.b[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn enter(&mut self) -> Result<(), FE> {
        if self.depth >= self.max {
            return Err((ErrorKind::DepthExceeded, self.pos));
        }
        self.depth += 1;
        Ok(())
    }

    fn value(&mut self) -> Result<Value, FE> {
        self.ws();
        let Some(&c) = self.b.get(self.pos) else {
            return self.eof();
        };
        match c {
            b'[' => self.seq(),
            b'{' => self.map(),
            b'"' | b'\'' => {
                let (s, end) = scan_quoted(self.s, self.pos, c)?;
                self.pos = end;
                Ok(Value::String(s))
            }
            b'&' => Err((ErrorKind::Anchor, self.pos)),
            b'*' => Err((ErrorKind::Alias, self.pos)),
            b'!' => Err((ErrorKind::Tag, self.pos)),
            b',' | b']' | b'}' => self.syn("empty flow entry"),
            _ => {
                let start = self.pos;
                let t = self.plain()?;
                resolve_plain(&t).map_err(|k| (k, start))
            }
        }
    }

    fn seq(&mut self) -> Result<Value, FE> {
        self.enter()?;
        self.pos += 1;
        let mut v = Vec::new();
        loop {
            self.ws();
            match self.b.get(self.pos) {
                None => return self.eof(),
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => {}
            }
            v.push(self.value()?);
            self.ws();
            match self.b.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                None => return self.eof(),
                Some(b':') => return self.syn("single-pair mappings in flow sequences are not supported"),
                _ => return self.syn("expected ',' or ']'"),
            }
        }
        self.depth -= 1;
        Ok(Value::Array(v))
    }

    fn map(&mut self) -> Result<Value, FE> {
        self.enter()?;
        self.pos += 1;
        let mut m: Vec<(String, Value)> = Vec::new();
        loop {
            self.ws();
            let Some(&c) = self.b.get(self.pos) else {
                return self.eof();
            };
            if c == b'}' {
                self.pos += 1;
                break;
            }
            let key = match c {
                b'"' | b'\'' => {
                    let (s, end) = scan_quoted(self.s, self.pos, c)?;
                    self.pos = end;
                    s
                }
                b'&' => return Err((ErrorKind::Anchor, self.pos)),
                b'*' => return Err((ErrorKind::Alias, self.pos)),
                b'!' => return Err((ErrorKind::Tag, self.pos)),
                b'[' | b'{' => return self.syn("collection keys are not supported"),
                b'?' if matches!(self.b.get(self.pos + 1), None | Some(b' ' | b'\t' | b'\n')) => {
                    return Err((ErrorKind::ExplicitKey, self.pos))
                }
                b',' | b']' => return self.syn("empty flow entry"),
                _ => self.plain()?,
            };
            self.ws();
            let v = match self.b.get(self.pos) {
                Some(b':') => {
                    self.pos += 1;
                    self.ws();
                    match self.b.get(self.pos) {
                        Some(b',' | b'}') => Value::Null,
                        None => return self.eof(),
                        _ => self.value()?,
                    }
                }
                Some(b',' | b'}') => Value::Null,
                None => return self.eof(),
                _ => return self.syn("expected ':' , ',' or '}'"),
            };
            if m.iter().any(|(k, _)| *k == key) {
                return Err((ErrorKind::DuplicateKey, self.pos));
            }
            m.push((key, v));
            self.ws();
            match self.b.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                None => return self.eof(),
                _ => return self.syn("expected ',' or '}'"),
            }
        }
        self.depth -= 1;
        Ok(Value::Object(m))
    }

    /// Plain scalar inside a flow collection; returns the raw (untyped) text.
    fn plain(&mut self) -> Result<String, FE> {
        let start = self.pos;
        let c0 = self.b[start];
        let n1 = self.b.get(start + 1).copied();
        let n1_ws = matches!(n1, None | Some(b' ' | b'\t' | b'\n' | b'\r'));
        if matches!(c0, b'|' | b'>' | b'%' | b'@' | b'`')
            || (matches!(c0, b'-' | b'?' | b':') && (n1_ws || n1.is_some_and(is_flow_ind)))
        {
            return self.syn("invalid start of plain scalar");
        }
        let mut out = String::new();
        while let Some(&c) = self.b.get(self.pos) {
            match c {
                b',' | b'[' | b']' | b'{' | b'}' => break,
                b':' if self.b.get(self.pos + 1).is_none()
                    || self.b.get(self.pos + 1).is_some_and(|&n| {
                        matches!(n, b' ' | b'\t' | b'\n' | b'\r') || is_flow_ind(n)
                    }) =>
                {
                    break
                }
                b'#' if self.pos > start && matches!(self.b[self.pos - 1], b' ' | b'\t' | b'\n') => break,
                b'\n' => {
                    while out.ends_with([' ', '\t', '\r']) {
                        out.pop();
                    }
                    let mut nl = 0;
                    let mut j = self.pos;
                    while let Some(&x) = self.b.get(j) {
                        match x {
                            b'\n' => {
                                nl += 1;
                                j += 1;
                            }
                            b' ' | b'\t' | b'\r' => j += 1,
                            _ => break,
                        }
                    }
                    self.pos = j;
                    match self.b.get(j) {
                        None | Some(b',' | b']' | b'}' | b'#') => break,
                        Some(b':') if self.b.get(j + 1).is_none_or(|&n| n == b' ' || n == b'\n' || is_flow_ind(n)) => {
                            break
                        }
                        _ => {}
                    }
                    if nl == 1 {
                        out.push(' ');
                    } else {
                        for _ in 1..nl {
                            out.push('\n');
                        }
                    }
                }
                _ => {
                    let Some(ch) = self.s[self.pos..].chars().next() else {
                        return self.eof();
                    };
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
        while out.ends_with([' ', '\t', '\r']) {
            out.pop();
        }
        if out.is_empty() {
            return self.syn("empty flow entry");
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- core schema

fn is_yaml_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        i = 1;
    }
    let digits = |i: &mut usize| {
        let st = *i;
        while b.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i - st
    };
    let n1 = digits(&mut i);
    let mut n2 = 0;
    let mut dot = false;
    if b.get(i) == Some(&b'.') {
        dot = true;
        i += 1;
        n2 = digits(&mut i);
    }
    if n1 + n2 == 0 {
        return false;
    }
    let mut exp = false;
    if matches!(b.get(i), Some(b'e' | b'E')) {
        exp = true;
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len() && (dot || exp)
}

/// Type a plain scalar by the YAML 1.2 core schema.
fn resolve_plain(s: &str) -> Result<Value, ErrorKind> {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF"
        | ".nan" | ".NaN" | ".NAN" => return Err(ErrorKind::NonFiniteFloat),
        _ => {}
    }
    match Number::parse(s) {
        Ok(n) => return Ok(Value::Number(n)),
        Err(NumError::OutOfRange) => return Err(ErrorKind::NumberOutOfRange),
        Err(NumError::Invalid) => {}
    }
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) {
        // Leading zeros and '+' are decimal ints in the 1.2 core schema.
        return match s.parse::<i128>() {
            Ok(v) => Ok(int_value(v)),
            Err(_) => match s.parse::<f64>().ok().and_then(Number::from_f64) {
                Some(n) => Ok(Value::Number(n)),
                None => Err(ErrorKind::NumberOutOfRange),
            },
        };
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8)] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if !rest.is_empty() && rest.bytes().all(|c| (c as char).is_digit(radix)) {
                return match u64::from_str_radix(rest, radix) {
                    Ok(v) => Ok(Value::Number(Number::from_u64(v))),
                    Err(_) => Err(ErrorKind::NumberOutOfRange),
                };
            }
        }
    }
    if is_yaml_float(s) {
        return match s.parse::<f64>().ok().filter(|f| f.is_finite()).and_then(Number::from_f64) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ErrorKind::NumberOutOfRange),
        };
    }
    Ok(Value::String(String::from(s)))
}

fn int_value(v: i128) -> Value {
    if let Ok(i) = i64::try_from(v) {
        Value::Number(Number::from_i64(i))
    } else if let Ok(u) = u64::try_from(v) {
        Value::Number(Number::from_u64(u))
    } else {
        // Out of 64-bit range: keep as an (inexact) float.
        match Number::from_f64(v as f64) {
            Some(n) => Value::Number(n),
            None => Value::Null,
        }
    }
}

/// Serialize a YAML-derived value to compact JSON (convenience).
pub fn to_json(v: &Value) -> String {
    json::to_string(v)
}
