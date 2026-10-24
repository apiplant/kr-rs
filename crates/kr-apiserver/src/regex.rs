//! A small backtracking regular expression engine for the ECMA-262 subset used by CRD
//! `pattern` and CEL `matches()`: literals, `.`, classes, `\d \w \s \b` (and negations),
//! anchors, groups, alternation and greedy/lazy quantifiers. Matching is unanchored (search),
//! counts steps and fails with an error beyond [`STEP_LIMIT`] so patterns cannot burn CPU.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const STEP_LIMIT: usize = 100_000;
const PROG_LIMIT: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Esc {
    Digit,
    Word,
    Space,
}

#[derive(Debug, Clone)]
enum Item {
    Range(char, char),
    Esc(Esc, bool),
}

#[derive(Debug, Clone)]
struct Class {
    neg: bool,
    items: Vec<Item>,
}

fn esc_matches(e: Esc, c: char) -> bool {
    match e {
        Esc::Digit => c.is_ascii_digit(),
        Esc::Word => c.is_ascii_alphanumeric() || c == '_',
        Esc::Space => c.is_whitespace(),
    }
}

impl Class {
    fn matches(&self, c: char) -> bool {
        let hit = self.items.iter().any(|i| match i {
            Item::Range(a, b) => *a <= c && c <= *b,
            Item::Esc(e, neg) => esc_matches(*e, c) != *neg,
        });
        hit != self.neg
    }
}

enum Node {
    Empty,
    Char(char),
    Any,
    Class(Class),
    Bol,
    Eol,
    WordB(bool),
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    Rep(Box<Node>, u32, Option<u32>, bool),
}

struct Parser {
    s: Vec<char>,
    i: usize,
}

impl Parser {
    fn alt(&mut self) -> Result<Node, String> {
        let mut alts = vec![self.cat()?];
        while self.s.get(self.i) == Some(&'|') {
            self.i += 1;
            alts.push(self.cat()?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap() } else { Node::Alt(alts) })
    }
    fn cat(&mut self) -> Result<Node, String> {
        let mut v = Vec::new();
        while let Some(&c) = self.s.get(self.i) {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            v.push(self.quant(atom)?);
        }
        Ok(match v.len() {
            0 => Node::Empty,
            1 => v.pop().unwrap(),
            _ => Node::Cat(v),
        })
    }
    fn number(&mut self) -> Option<u32> {
        let st = self.i;
        while self.s.get(self.i).is_some_and(char::is_ascii_digit) {
            self.i += 1;
        }
        self.s[st..self.i].iter().collect::<String>().parse().ok()
    }
    fn quant(&mut self, atom: Node) -> Result<Node, String> {
        let Some(&c) = self.s.get(self.i) else { return Ok(atom) };
        let (min, max) = match c {
            '*' => (0, None),
            '+' => (1, None),
            '?' => (0, Some(1)),
            '{' => {
                let save = self.i;
                self.i += 1;
                let parsed = (|| {
                    let lo = self.number()?;
                    let hi = if self.s.get(self.i) == Some(&',') {
                        self.i += 1;
                        if self.s.get(self.i) == Some(&'}') { None } else { Some(self.number()?) }
                    } else {
                        Some(lo)
                    };
                    (self.s.get(self.i) == Some(&'}')).then_some((lo, hi))
                })();
                match parsed {
                    Some((lo, hi)) => {
                        if hi.is_some_and(|h| h < lo) {
                            return Err("numbers out of order in {} quantifier".into());
                        }
                        if lo > 1000 || hi.is_some_and(|h| h > 1000) {
                            return Err("quantifier bound too large".into());
                        }
                        (lo, hi)
                    }
                    None => {
                        // Not a quantifier: a literal brace.
                        self.i = save;
                        return Ok(atom);
                    }
                }
            }
            _ => return Ok(atom),
        };
        self.i += 1;
        let greedy = if self.s.get(self.i) == Some(&'?') {
            self.i += 1;
            false
        } else {
            true
        };
        if matches!(atom, Node::Bol | Node::Eol | Node::WordB(_)) {
            return Err("nothing to repeat".into());
        }
        Ok(Node::Rep(Box::new(atom), min, max, greedy))
    }
    fn escape(&mut self) -> Result<Item, String> {
        let c = *self.s.get(self.i).ok_or("trailing backslash")?;
        self.i += 1;
        Ok(match c {
            'd' => Item::Esc(Esc::Digit, false),
            'D' => Item::Esc(Esc::Digit, true),
            'w' => Item::Esc(Esc::Word, false),
            'W' => Item::Esc(Esc::Word, true),
            's' => Item::Esc(Esc::Space, false),
            'S' => Item::Esc(Esc::Space, true),
            'n' => Item::Range('\n', '\n'),
            't' => Item::Range('\t', '\t'),
            'r' => Item::Range('\r', '\r'),
            'f' => Item::Range('\x0c', '\x0c'),
            'v' => Item::Range('\x0b', '\x0b'),
            '0' => Item::Range('\0', '\0'),
            c if c.is_ascii_digit() => return Err("backreferences are not supported".into()),
            c => Item::Range(c, c),
        })
    }
    fn class(&mut self) -> Result<Node, String> {
        let neg = self.s.get(self.i) == Some(&'^');
        if neg {
            self.i += 1;
        }
        let mut items = Vec::new();
        loop {
            let c = *self.s.get(self.i).ok_or("missing closing ]")?;
            self.i += 1;
            if c == ']' {
                break;
            }
            let lo = if c == '\\' {
                match self.escape()? {
                    Item::Range(a, _) => a,
                    e => {
                        items.push(e);
                        continue;
                    }
                }
            } else {
                c
            };
            if self.s.get(self.i) == Some(&'-') && self.s.get(self.i + 1).is_some_and(|c| *c != ']') {
                self.i += 1;
                let h = self.s[self.i];
                self.i += 1;
                let hi = if h == '\\' {
                    match self.escape()? {
                        Item::Range(a, _) => a,
                        _ => return Err("invalid character class range".into()),
                    }
                } else {
                    h
                };
                if hi < lo {
                    return Err("range out of order in character class".into());
                }
                items.push(Item::Range(lo, hi));
            } else {
                items.push(Item::Range(lo, lo));
            }
        }
        Ok(Node::Class(Class { neg, items }))
    }
    fn atom(&mut self) -> Result<Node, String> {
        let c = self.s[self.i];
        self.i += 1;
        Ok(match c {
            '.' => Node::Any,
            '^' => Node::Bol,
            '$' => Node::Eol,
            '[' => self.class()?,
            '(' => {
                if self.s.get(self.i) == Some(&'?') {
                    match self.s.get(self.i + 1) {
                        Some(':') => self.i += 2,
                        _ => return Err("lookaround and named groups are not supported".into()),
                    }
                }
                let n = self.alt()?;
                if self.s.get(self.i) != Some(&')') {
                    return Err("missing closing )".into());
                }
                self.i += 1;
                n
            }
            ')' => return Err("unexpected )".into()),
            '*' | '+' | '?' => return Err("nothing to repeat".into()),
            '\\' => {
                match self.s.get(self.i) {
                    Some('b') => {
                        self.i += 1;
                        return Ok(Node::WordB(true));
                    }
                    Some('B') => {
                        self.i += 1;
                        return Ok(Node::WordB(false));
                    }
                    _ => {}
                }
                match self.escape()? {
                    Item::Range(a, _) => Node::Char(a),
                    e => Node::Class(Class { neg: false, items: vec![e] }),
                }
            }
            c => Node::Char(c),
        })
    }
}

enum Inst {
    Char(char),
    Any,
    Class(Class),
    Split(usize, usize),
    Jmp(usize),
    Bol,
    Eol,
    WordB(bool),
    Match,
}

fn emit(n: &Node, p: &mut Vec<Inst>) -> Result<(), String> {
    if p.len() > PROG_LIMIT {
        return Err("regular expression too large".into());
    }
    match n {
        Node::Empty => {}
        Node::Char(c) => p.push(Inst::Char(*c)),
        Node::Any => p.push(Inst::Any),
        Node::Class(c) => p.push(Inst::Class(c.clone())),
        Node::Bol => p.push(Inst::Bol),
        Node::Eol => p.push(Inst::Eol),
        Node::WordB(b) => p.push(Inst::WordB(*b)),
        Node::Cat(v) => {
            for x in v {
                emit(x, p)?;
            }
        }
        Node::Alt(v) => {
            let mut jumps = Vec::new();
            for (k, x) in v.iter().enumerate() {
                if k + 1 < v.len() {
                    let split = p.len();
                    p.push(Inst::Split(split + 1, 0));
                    emit(x, p)?;
                    jumps.push(p.len());
                    p.push(Inst::Jmp(0));
                    let next = p.len();
                    p[split] = Inst::Split(split + 1, next);
                } else {
                    emit(x, p)?;
                }
            }
            let end = p.len();
            for j in jumps {
                p[j] = Inst::Jmp(end);
            }
        }
        Node::Rep(x, min, max, greedy) => {
            let split = |a: usize, b: usize| if *greedy { Inst::Split(a, b) } else { Inst::Split(b, a) };
            for _ in 0..*min {
                emit(x, p)?;
            }
            match max {
                None => {
                    let l1 = p.len();
                    p.push(Inst::Jmp(0));
                    emit(x, p)?;
                    p.push(Inst::Jmp(l1));
                    let end = p.len();
                    p[l1] = split(l1 + 1, end);
                }
                Some(max) => {
                    let mut splits = Vec::new();
                    for _ in *min..*max {
                        splits.push(p.len());
                        p.push(Inst::Jmp(0));
                        emit(x, p)?;
                    }
                    let end = p.len();
                    for s in splits {
                        p[s] = split(s + 1, end);
                    }
                }
            }
        }
    }
    Ok(())
}

pub struct Regex {
    prog: Vec<Inst>,
}

fn is_word(c: Option<&char>) -> bool {
    c.is_some_and(|c| esc_matches(Esc::Word, *c))
}

impl Regex {
    pub fn new(pat: &str) -> Result<Regex, String> {
        let mut p = Parser { s: pat.chars().collect(), i: 0 };
        let n = p.alt()?;
        if p.i < p.s.len() {
            return Err(format!("unexpected {:?} at offset {}", p.s[p.i], p.i));
        }
        let mut prog = Vec::new();
        emit(&n, &mut prog)?;
        prog.push(Inst::Match);
        Ok(Regex { prog })
    }

    /// Whether the pattern matches anywhere in `text`; `Err` when the step limit is exceeded.
    pub fn is_match(&self, text: &str) -> Result<bool, String> {
        let t: Vec<char> = text.chars().collect();
        let anchored = matches!(self.prog.first(), Some(Inst::Bol));
        let mut steps = 0usize;
        for start in 0..=t.len() {
            if self.run(&t, start, &mut steps)? {
                return Ok(true);
            }
            if anchored {
                break;
            }
        }
        Ok(false)
    }

    fn run(&self, t: &[char], start: usize, steps: &mut usize) -> Result<bool, String> {
        let mut stack = vec![(0usize, start)];
        while let Some((mut pc, mut pos)) = stack.pop() {
            loop {
                *steps += 1;
                if *steps > STEP_LIMIT {
                    return Err("regular expression exceeded the step limit".into());
                }
                match &self.prog[pc] {
                    Inst::Match => return Ok(true),
                    Inst::Char(c) => {
                        if t.get(pos) != Some(c) {
                            break;
                        }
                        pc += 1;
                        pos += 1;
                    }
                    Inst::Any => {
                        if pos >= t.len() || t[pos] == '\n' {
                            break;
                        }
                        pc += 1;
                        pos += 1;
                    }
                    Inst::Class(c) => {
                        if !t.get(pos).is_some_and(|ch| c.matches(*ch)) {
                            break;
                        }
                        pc += 1;
                        pos += 1;
                    }
                    Inst::Bol => {
                        if pos != 0 {
                            break;
                        }
                        pc += 1;
                    }
                    Inst::Eol => {
                        if pos != t.len() {
                            break;
                        }
                        pc += 1;
                    }
                    Inst::WordB(want) => {
                        let at = is_word(t.get(pos)) != (pos > 0 && is_word(t.get(pos - 1)));
                        if at != *want {
                            break;
                        }
                        pc += 1;
                    }
                    Inst::Jmp(x) => pc = *x,
                    Inst::Split(a, b) => {
                        stack.push((*b, pos));
                        pc = *a;
                    }
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Regex::new(p).unwrap().is_match(t).unwrap()
    }

    #[test]
    fn basics() {
        assert!(m("^[a-z0-9-]+$", "abc-123"));
        assert!(!m("^[a-z0-9-]+$", "abc_123"));
        assert!(m("^[^0-9]*$", "abc"));
        assert!(!m("^[^0-9]*$", "ab1"));
        assert!(m(r"^\d{3}-\d{2,}$", "123-4567"));
        assert!(!m(r"^\d{3}-\d{2,}$", "12-4567"));
        assert!(m("^(foo|bar)+baz?$", "foobarba"));
        assert!(m("ab", "xxabyy"));
        assert!(!m("^ab", "xab"));
        assert!(m(r"^\w+\s\W$", "hello !"));
        assert!(m(r"^a\.b$", "a.b"));
        assert!(!m(r"^a\.b$", "axb"));
        assert!(m("^a{2}$", "aa") && !m("^a{2}$", "aaa"));
        assert!(m("^a.c$", "abc") && m("^a+?b$", "aab"));
        assert!(m(r"\bfoo\b", "a foo b"));
        assert!(m("^$", ""));
        assert!(m(r"^[\d.]+$", "1.2"));
    }

    #[test]
    fn syntax_errors() {
        for p in ["(", "a)", "[a", "*a", "a{2,1}", "(?=a)", r"\1", "[z-a]"] {
            assert!(Regex::new(p).is_err(), "{p}");
        }
    }

    #[test]
    fn step_limit() {
        let r = Regex::new("(a+)+$").unwrap();
        let mut s = "a".repeat(40);
        s.push('b');
        assert!(r.is_match(&s).unwrap_err().contains("step limit"));
        assert_eq!(r.is_match("aaa"), Ok(true));
    }
}
