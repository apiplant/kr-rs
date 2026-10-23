use crate::json::*;
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use std::string::ToString;
use std::vec;

fn ok(s: &str) -> Value {
    match parse(s.as_bytes()) {
        Ok(v) => v,
        Err(e) => panic!("should accept {:?}: {}", s, e),
    }
}

fn bad(s: &[u8]) -> Error {
    match parse(s) {
        Ok(v) => panic!("should reject {:?}, got {}", s, v),
        Err(e) => e,
    }
}

#[test]
fn y_cases_accepted_and_roundtrip() {
    let cases: &[&str] = &[
        "[]",
        "[\"\"]",
        "[[]]",
        "[1]",
        "[false]",
        "[null, 1, \"1\", {}]",
        "[-0]",
        "[-1]",
        "[1.5]",
        "[1E22]",
        "[1e-2]",
        "[1e+2]",
        "[123e65]",
        "[0.1e1]",
        "[1E-2]",
        "[0]",
        "[-0.0]",
        "[0e0]",
        "{}",
        "{\"a\":null}",
        "{\"\":0}",
        "{\"a\":{\"b\":{\"c\":[1,2,{\"d\":true}]}}}",
        " [] ",
        "\t\n\r []\r\n",
        "\"a\"",
        "\"\"",
        "1",
        "-1",
        "true",
        "false",
        "null",
        "[\"\\u0060\\u012a\\u12AB\"]",
        "[\"\\uD801\\udc37\"]",
        "[\"\\ud83d\\ude39\\ud83d\\udc8d\"]",
        "[\"\\uDBFF\\uDFFF\"]",
        "[\"\\uFFFF\"]",
        "[\"\\u0000\"]",
        "[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]",
        "[\"a/*b*/c\"]",
        "[\"\u{e9}\u{20ac}\u{1d11e}\"]",
        "[\"\u{2028}\u{2029}\"]",
        "{\"a\":1,\"a\":2}",
        "{\"\\u0061\":1}",
        "[1,2 , 3 ,\n4]",
        "{ \"a\" : [ ] , \"b\" : { } }",
        "[123456789012345678901234567890]",
        "[9223372036854775807,9223372036854775808,18446744073709551615]",
        "[-9223372036854775808]",
        "[\"\u{10ffff}\"]",
    ];
    assert!(cases.len() >= 40);
    for c in cases {
        let v = ok(c);
        let out = to_string(&v);
        let v2 = parse(out.as_bytes()).unwrap_or_else(|e| panic!("reparse of {:?} failed: {}", out, e));
        assert_eq!(v, v2, "round trip of {:?} via {:?}", c, out);
        // Serialization is a fixed point.
        assert_eq!(out, to_string(&v2));
    }
}

#[test]
fn n_cases_rejected() {
    let cases: &[&[u8]] = &[
        b"",
        b" ",
        b"[",
        b"]",
        b"{",
        b"}",
        b"[1,]",
        b"[,1]",
        b"[1 2]",
        b"[1,,2]",
        b"[1}",
        b"{]",
        b"{\"a\":1,}",
        b"{,}",
        b"{\"a\"}",
        b"{\"a\":}",
        b"{a:1}",
        b"{'a':1}",
        b"['a']",
        b"{1:1}",
        b"{null:1}",
        b"{\"a\" 1}",
        b"{\"a\":1 \"b\":2}",
        b"{\"a\":1:2}",
        b"[\"a\":1]",
        b"[\"a\" \"b\"]",
        b"[01]",
        b"[-]",
        b"[--1]",
        b"[.5]",
        b"[1.]",
        b"[1.2.3]",
        b"[1e]",
        b"[1e+]",
        b"[+1]",
        b"[0x1]",
        b"[NaN]",
        b"[Infinity]",
        b"[-Infinity]",
        b"[tru]",
        b"[nul]",
        b"[True]",
        b"[nulll]",
        b"truefalse",
        b"[] x",
        b"[]]",
        b"{}}",
        b"{\"a\":1}x",
        b"[1]\0",
        b"\"abc",
        b"\"\\",
        b"[\"\\x41\"]",
        b"[\"\\u00G0\"]",
        b"[\"\\u12\"]",
        b"[\"\\u\"]",
        b"[\"\\uD800\"]",
        b"[\"\\uDC00\"]",
        b"[\"\\uD800\\u0041\"]",
        b"[\"\\uDBFF\\uD800\"]",
        b"[\"\\uDC00\\uD800\"]",
        b"[\"\\uD800\\\\u0000\"]",
        b"[\"a\nb\"]",
        b"[\"\t\"]",
        b"[\"\x01\"]",
        b"[\"\x7f\xff\"]",
        b"[\"\xff\"]",
        b"[\"\xc0\xaf\"]",
        b"[\"\xc0\x80\"]",
        b"[\"\xe0\x80\xaf\"]",
        b"[\"\xed\xa0\x80\"]",
        b"[\"\xf4\x90\x80\x80\"]",
        b"[\"\xc3\"]",
        b"\xef\xbb\xbf[]",
        b"//c\n[]",
        b"[1]//c",
        b"/*c*/[]",
        b"\xc2\xa0[]",
        b"[\xe2\x80\xa8]",
        b"[1,2",
        b"{\"a\":1",
        b"{\"a\"",
        b"-",
        b"[1e999]",
        b"[-1e999]",
    ];
    assert!(cases.len() >= 40);
    for c in cases {
        bad(c);
    }
}

#[test]
fn error_offsets_and_kinds() {
    assert_eq!(bad(b"[1,]"), Error { kind: ErrorKind::UnexpectedChar, offset: 3 });
    assert_eq!(bad(b"[1 2]"), Error { kind: ErrorKind::UnexpectedChar, offset: 3 });
    assert_eq!(bad(b"[01]"), Error { kind: ErrorKind::UnexpectedChar, offset: 2 });
    assert_eq!(bad(b"[1.]"), Error { kind: ErrorKind::InvalidNumber, offset: 3 });
    assert_eq!(bad(b"[1e]"), Error { kind: ErrorKind::InvalidNumber, offset: 3 });
    assert_eq!(bad(b"tru"), Error { kind: ErrorKind::UnexpectedEof, offset: 3 });
    assert_eq!(bad(b"nul!"), Error { kind: ErrorKind::UnexpectedChar, offset: 3 });
    assert_eq!(bad(b""), Error { kind: ErrorKind::UnexpectedEof, offset: 0 });
    assert_eq!(bad(b"[] x").kind, ErrorKind::TrailingData);
    assert_eq!(bad(b"[] x").offset, 3);
    assert_eq!(bad(b"{} {}").kind, ErrorKind::TrailingData);
    assert_eq!(bad(b"\"a\nb\"").kind, ErrorKind::ControlCharacter);
    assert_eq!(bad(b"\"a\nb\"").offset, 2);
    assert_eq!(bad(b"[\"\\q\"]"), Error { kind: ErrorKind::InvalidEscape, offset: 3 });
    assert_eq!(bad(b"[\"\\uD800\"]"), Error { kind: ErrorKind::LoneSurrogate, offset: 2 });
    assert_eq!(bad(b"[\"\\uDC00\"]"), Error { kind: ErrorKind::LoneSurrogate, offset: 2 });
    assert_eq!(bad(b"[\"ab\xffc\"]"), Error { kind: ErrorKind::InvalidUtf8, offset: 4 });
    assert_eq!(bad(b"[1e999]").kind, ErrorKind::NumberOutOfRange);
    assert_eq!(bad(b"[1e999]").offset, 1);
    assert_eq!(bad(b"{\"a\":1,}").offset, 7);
    let msg = bad(b"[1,]").to_string();
    assert!(msg.contains("byte 3"), "{}", msg);
}

#[test]
fn depth_and_size_limits() {
    let nest = |n: usize| {
        let mut s = String::new();
        for _ in 0..n {
            s.push('[');
        }
        for _ in 0..n {
            s.push(']');
        }
        s
    };
    assert!(parse(nest(64).as_bytes()).is_ok());
    let e = parse(nest(65).as_bytes()).unwrap_err();
    assert_eq!(e.kind, ErrorKind::DepthExceeded);
    assert_eq!(e.offset, 64);
    // Hostile input: must fail cleanly, not overflow the stack.
    let deep = "[".repeat(100_000);
    assert_eq!(parse(deep.as_bytes()).unwrap_err().kind, ErrorKind::DepthExceeded);
    let deep_obj = "{\"a\":".repeat(100_000);
    assert_eq!(parse(deep_obj.as_bytes()).unwrap_err().kind, ErrorKind::DepthExceeded);

    let lim = Limits { max_depth: 2, max_input: 1024 };
    assert!(parse_with(b"[[1]]", lim).is_ok());
    assert_eq!(parse_with(b"[[[1]]]", lim).unwrap_err().kind, ErrorKind::DepthExceeded);
    let big = alloc::format!("[{}]", "1,".repeat(600));
    assert_eq!(parse_with(big.as_bytes(), lim).unwrap_err().kind, ErrorKind::InputTooLarge);
    let lim0 = Limits { max_depth: 0, ..Limits::default() };
    assert!(parse_with(b"1", lim0).is_ok());
    assert!(parse_with(b"[]", lim0).is_err());
}

#[test]
fn numbers_keep_exact_kind_and_text() {
    let v = ok("[9223372036854775807,9223372036854775808,18446744073709551615,-9223372036854775808,-9223372036854775809,18446744073709551616,1.0,1E2,-0,0.1]");
    let a = v.as_array().unwrap();
    assert_eq!(a[0].as_i64(), Some(i64::MAX));
    assert_eq!(a[1].as_i64(), None);
    assert_eq!(a[1].as_u64(), Some(9223372036854775808));
    assert_eq!(a[2].as_u64(), Some(u64::MAX));
    assert_eq!(a[3].as_i64(), Some(i64::MIN));
    let n4 = a[4].as_number().unwrap();
    assert!(!n4.is_integer());
    assert_eq!(n4.raw(), "-9223372036854775809");
    assert!(!a[5].as_number().unwrap().is_integer());
    assert_eq!(a[6].as_number().unwrap().raw(), "1.0");
    assert_eq!(a[6].as_i64(), None);
    assert_eq!(a[6].as_f64(), Some(1.0));
    assert_eq!(a[7].as_f64(), Some(100.0));
    assert_eq!(a[8].as_i64(), Some(0));
    assert_eq!(a[8].as_number().unwrap().raw(), "-0");
    assert_eq!(
        to_string(&v),
        "[9223372036854775807,9223372036854775808,18446744073709551615,-9223372036854775808,-9223372036854775809,18446744073709551616,1.0,1E2,-0,0.1]"
    );
    assert_eq!(Number::from_i64(-5).raw(), "-5");
    assert_eq!(Number::from_u64(7).as_i64(), Some(7));
    assert_eq!(Number::from_u64(u64::MAX).raw(), "18446744073709551615");
    assert_eq!(Number::from_f64(1.5).unwrap().raw(), "1.5");
    assert!(Number::from_f64(f64::NAN).is_none());
    assert!(Number::from_f64(f64::INFINITY).is_none());
    assert_eq!(Number::parse("01"), Err(NumError::Invalid));
    assert_eq!(Number::parse("1 "), Err(NumError::Invalid));
    assert_eq!(Number::parse("1e999"), Err(NumError::OutOfRange));
    assert!(Number::parse("-12.5e-3").is_ok());
}

#[test]
fn strings_decode_and_encode() {
    let v = ok(r#""\u00e9\ud83d\ude00\n\t\"\\\/""#);
    assert_eq!(v.as_str(), Some("\u{e9}\u{1f600}\n\t\"\\/"));
    assert_eq!(to_string(&v), "\"\u{e9}\u{1f600}\\n\\t\\\"\\\\/\"");
    let ctl = Value::String("\u{0}\u{1}\u{8}\u{c}\u{1f}\u{7f}".into());
    assert_eq!(to_string(&ctl), "\"\\u0000\\u0001\\b\\f\\u001f\u{7f}\"");
    assert_eq!(parse(to_string(&ctl).as_bytes()).unwrap(), ctl);
    // Raw U+2028 survives.
    let ls = Value::String("a\u{2028}b".into());
    assert_eq!(parse(to_string(&ls).as_bytes()).unwrap(), ls);
}

#[test]
fn object_order_and_duplicates_preserved() {
    let v = ok(r#"{"z":1,"a":2,"m":3,"a":4}"#);
    let keys: Vec<&str> = v.as_object().unwrap().iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["z", "a", "m", "a"]);
    assert_eq!(v.get("a").and_then(Value::as_i64), Some(4));
    assert_eq!(to_string(&v), r#"{"z":1,"a":2,"m":3,"a":4}"#);
    assert!(v.get("nope").is_none());
}

#[test]
fn accessors_and_display() {
    let v = ok(r#"{"a":[true,null,"s",1.5]}"#);
    let a = v.get("a").unwrap();
    assert_eq!(a.at(0).and_then(Value::as_bool), Some(true));
    assert!(a.at(1).unwrap().is_null());
    assert_eq!(a.at(2).and_then(Value::as_str), Some("s"));
    assert_eq!(a.at(3).and_then(Value::as_f64), Some(1.5));
    assert!(a.at(4).is_none());
    assert_eq!(v.to_string(), r#"{"a":[true,null,"s",1.5]}"#);
    assert_eq!(Value::from("x"), Value::String("x".into()));
    assert_eq!(Value::from(3i64).as_i64(), Some(3));
    assert_eq!(parse_str(" 7 ").unwrap().as_i64(), Some(7));
}

#[test]
fn tokenizer_borrows_without_escapes() {
    let src = br#"{"key":"plain","esc":"a\nb","n":[1,-2.5e3,true,false,null]}"#;
    let mut t = Tokenizer::new(src);
    let mut toks = Vec::new();
    while let Some(tok) = t.next().unwrap() {
        toks.push(tok);
    }
    assert_eq!(toks.len(), 14);
    assert!(matches!(toks[0], Token::ObjectStart));
    assert!(matches!(&toks[1], Token::Key(Cow::Borrowed("key"))));
    assert!(matches!(&toks[2], Token::String(Cow::Borrowed("plain"))));
    assert!(matches!(&toks[3], Token::Key(Cow::Borrowed("esc"))));
    match &toks[4] {
        Token::String(Cow::Owned(s)) => assert_eq!(s, "a\nb"),
        other => panic!("expected owned string, got {:?}", other),
    }
    assert!(matches!(&toks[5], Token::Key(Cow::Borrowed("n"))));
    assert!(matches!(toks[6], Token::ArrayStart));
    assert!(matches!(toks[7], Token::Number("1")));
    assert!(matches!(toks[8], Token::Number("-2.5e3")));
    assert!(matches!(toks[9], Token::Bool(true)));
    assert!(matches!(toks[10], Token::Bool(false)));
    assert!(matches!(toks[11], Token::Null));
    assert!(matches!(toks[12], Token::ArrayEnd));
    assert!(matches!(toks[13], Token::ObjectEnd));
    // After the document: keeps returning None.
    assert_eq!(t.next().unwrap(), None);
    assert_eq!(t.next().unwrap(), None);
    assert_eq!(t.offset(), src.len());
}

#[test]
fn tokenizer_errors_mid_stream() {
    let mut t = Tokenizer::new(b"[1, 2 x]");
    assert_eq!(t.next().unwrap(), Some(Token::ArrayStart));
    assert_eq!(t.next().unwrap(), Some(Token::Number("1")));
    assert_eq!(t.next().unwrap(), Some(Token::Number("2")));
    assert_eq!(t.depth(), 1);
    assert_eq!(t.next().unwrap_err(), Error { kind: ErrorKind::UnexpectedChar, offset: 6 });
    // Scalars at top level.
    let mut t = Tokenizer::new(b"  \"x\"  ");
    assert_eq!(t.next().unwrap(), Some(Token::String(Cow::Borrowed("x"))));
    assert_eq!(t.next().unwrap(), None);
    // Truncated object.
    let mut t = Tokenizer::new(b"{\"a\":1");
    t.next().unwrap();
    t.next().unwrap();
    t.next().unwrap();
    assert_eq!(t.next().unwrap_err().kind, ErrorKind::UnexpectedEof);
}

#[test]
fn large_document_roundtrip() {
    let mut s = String::from("[");
    for i in 0..2000 {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&alloc::format!("{{\"id\":{},\"name\":\"item-{}\",\"tags\":[\"a\",\"b\"],\"ok\":{}}}", i, i, i % 2 == 0));
    }
    s.push(']');
    let v = ok(&s);
    assert_eq!(v.as_array().unwrap().len(), 2000);
    assert_eq!(to_string(&v), s);
}

#[test]
fn mutated_input_never_panics() {
    let base: &[u8] = "{\"a\":[1,-2.5e3,true,null,\"x\\u00e9\\ud83d\\ude00\\n\"],\"b\":{\"c\":\"d\"}}".as_bytes();
    let alphabet: &[u8] = b"{}[],:\"\\u0123-.eE+ \n\xffta";
    let mut x = 0x1234_5679u32;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    for _ in 0..20000 {
        let mut b = base.to_vec();
        for _ in 0..1 + rnd() % 3 {
            let at = rnd() as usize % b.len();
            match rnd() % 3 {
                0 => b[at] = alphabet[rnd() as usize % alphabet.len()],
                1 => {
                    b.remove(at);
                }
                _ => b.insert(at, alphabet[rnd() as usize % alphabet.len()]),
            }
        }
        if let Ok(v) = parse(&b) {
            // Anything accepted must serialize to something we accept again.
            assert_eq!(parse(to_string(&v).as_bytes()).unwrap(), v);
        }
    }
}
