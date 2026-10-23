use crate::quantity::*;
use alloc::string::ToString;
use core::cmp::Ordering;

fn canon(s: &str) -> alloc::string::String {
    match Quantity::parse(s) {
        Ok(q) => q.to_canonical_string(),
        Err(e) => panic!("{:?}: {}", s, e),
    }
}

#[test]
fn canonical_vectors() {
    let v: &[(&str, &str)] = &[
        ("0", "0"),
        ("-0", "0"),
        ("0.000", "0"),
        ("0Ki", "0"),
        ("1", "1"),
        ("+1", "1"),
        ("-1", "-1"),
        ("1500m", "1500m"),
        ("1000m", "1"),
        ("2000m", "2"),
        ("100m", "100m"),
        ("1.5", "1500m"),
        ("0.5", "500m"),
        (".5", "500m"),
        ("5.", "5"),
        ("0.001", "1m"),
        ("-1500m", "-1500m"),
        ("1n", "1n"),
        ("1u", "1u"),
        ("1m", "1m"),
        ("1000u", "1m"),
        ("1000000n", "1m"),
        ("1k", "1k"),
        ("1000", "1k"),
        ("1000k", "1M"),
        ("1M", "1M"),
        ("1G", "1G"),
        ("1T", "1T"),
        ("1P", "1P"),
        ("1E", "1E"),
        ("1500", "1500"),
        ("1.5k", "1500"),
        ("123456789", "123456789"),
        ("1Ki", "1Ki"),
        ("1024Ki", "1Mi"),
        ("1024Mi", "1Gi"),
        ("1024Gi", "1Ti"),
        ("1024Ti", "1Pi"),
        ("1024Pi", "1Ei"),
        ("1Ei", "1Ei"),
        ("1000Mi", "1000Mi"),
        ("2048Mi", "2Gi"),
        ("512Mi", "512Mi"),
        ("1536Ki", "1536Ki"),
        ("1.5Ki", "1536"),
        ("1.5Gi", "1536Mi"),
        ("0.5Ki", "512"),
        ("0.1Ki", "102400m"),
        ("-1Ki", "-1Ki"),
        ("-1024Ki", "-1Mi"),
        ("128974848", "128974848"),
        ("129e6", "129e6"),
        ("129M", "129M"),
        ("123Mi", "123Mi"),
        ("12e6", "12e6"),
        ("12E6", "12e6"),
        ("1e3", "1e3"),
        ("1e0", "1"),
        ("1e-3", "1e-3"),
        ("5e-1", "500e-3"),
        ("1E-2", "10e-3"),
        ("100e3", "100e3"),
        ("1e6", "1e6"),
        ("1e1", "10"),
        ("1e2", "100"),
        ("1.5e3", "1500"),
        ("1e21", "1e21"),
        ("1E3", "1e3"),
        // sub-nano precision is rounded up to 1n
        ("0.0000000001", "1n"),
        ("-0.0000000001", "-1n"),
        ("1.0000000001", "1000000001n"),
    ];
    for (i, o) in v {
        assert_eq!(canon(i), *o, "input {:?}", i);
    }
}

#[test]
fn canonical_is_idempotent() {
    for s in ["1500m", "1Mi", "12e6", "100e3", "1536", "102400m", "1n", "-3Gi", "7", "1e21", "500e-3"] {
        let c = canon(s);
        assert_eq!(canon(&c), c, "{}", s);
        assert_eq!(Quantity::parse(&c).unwrap(), Quantity::parse(s).unwrap());
    }
}

#[test]
fn parse_errors() {
    assert_eq!(Quantity::parse("").unwrap_err().kind, ErrorKind::Empty);
    for s in [
        "abc", "1x", "1 ", " 1", "1e", "1e+", "1e-", "1ki", "1K", "1KI", "1mi", "--1", "+-1", "1.2.3", "Ki", ".", "-.", "e3", "1Mii", "1Ke", "1e3k",
        "1,5", "1_000", "0x10", "1\u{b5}", "1E3.5", "1e3e3", "m",
    ] {
        let e = Quantity::parse(s).expect_err(s);
        assert_eq!(e.kind, ErrorKind::Invalid, "{:?}", s);
    }
    let big = alloc::format!("1{}", "0".repeat(40));
    assert_eq!(Quantity::parse(&big).unwrap_err().kind, ErrorKind::OutOfRange);
    assert_eq!(Quantity::parse("1e99999").unwrap_err().kind, ErrorKind::OutOfRange);
    assert_eq!(Quantity::parse("1e-99999").unwrap_err().kind, ErrorKind::OutOfRange);
    assert_eq!(Quantity::parse("99999999999999999999999999999999999999999Ei").unwrap_err().kind, ErrorKind::OutOfRange);
    assert!(Quantity::parse("1e9999").is_ok());
}

#[test]
fn values_round_away_from_zero() {
    let q = |s: &str| Quantity::parse(s).unwrap();
    assert_eq!(q("1500m").value(), Some(2));
    assert_eq!(q("-1500m").value(), Some(-2));
    assert_eq!(q("1000m").value(), Some(1));
    assert_eq!(q("1.5").milli_value(), Some(1500));
    assert_eq!(q("1Ki").milli_value(), Some(1_024_000));
    assert_eq!(q("1n").milli_value(), Some(1));
    assert_eq!(q("0").value(), Some(0));
    assert_eq!(q("2Gi").value(), Some(2 * 1024 * 1024 * 1024));
    assert_eq!(q("1Ei").value(), Some(1i128 << 60));
    assert_eq!(q("1k").scaled_value(3), Some(1));
    assert_eq!(q("1500").scaled_value(3), Some(2));
    assert_eq!(q("1n").scaled_value(-9), Some(1));
    assert_eq!(q("1e9999").value(), None);
    assert_eq!(Quantity::from_milli(250).to_string(), "250m");
    assert_eq!(Quantity::from_i64(4, Format::BinarySI).to_string(), "4");
    assert_eq!(Quantity::from_i64(4096, Format::BinarySI).to_string(), "4Ki");
    assert_eq!(q("1Ki").mantissa(), 1024);
    assert_eq!(q("1500m").mantissa(), 15);
    assert_eq!(q("1500m").scale(), -1);
    assert_eq!(q("1Gi").format(), Format::BinarySI);
    assert_eq!(q("1e3").format(), Format::DecimalExponent);
    assert_eq!(q("1k").format(), Format::DecimalSI);
    assert!(q("0.0").is_zero());
}

#[test]
fn ordering_is_numeric() {
    let q = |s: &str| Quantity::parse(s).unwrap();
    assert_eq!(q("1000m"), q("1"));
    assert_eq!(q("1Ki"), q("1024"));
    assert_eq!(q("1e3"), q("1k"));
    assert_eq!(q("0"), q("-0"));
    assert_eq!(q("0"), q("0Ki"));
    assert!(q("1Ki") > q("1k"));
    assert!(q("999m") < q("1"));
    assert!(q("-1") < q("-999m"));
    assert!(q("-1") < q("1n"));
    assert!(q("1n") > q("0"));
    assert!(q("-1n") < q("0"));
    assert!(q("1E") > q("1P"));
    assert!(q("1e9999") > q("1E"));
    assert!(q("-1e9999") < q("-1E"));
    assert_eq!(q("1.5Gi").cmp(&q("1536Mi")), Ordering::Equal);
    assert_eq!("2".parse::<Quantity>().unwrap().cmp(&q("1")), Ordering::Greater);
}

#[test]
fn display_matches_canonical() {
    assert_eq!(Quantity::parse("1024Ki").unwrap().to_string(), "1Mi");
    assert_eq!(Quantity::parse("1000m").unwrap().to_string(), "1");
}

// ------------------------------------------------------------ durations

#[test]
fn duration_go_vectors() {
    let s = 1_000_000_000i64;
    let v: &[(&str, i64)] = &[
        ("0", 0),
        ("5s", 5 * s),
        ("30s", 30 * s),
        ("1478s", 1478 * s),
        ("-5s", -5 * s),
        ("+5s", 5 * s),
        ("-0", 0),
        ("+0", 0),
        ("-0s", 0),
        ("+0s", 0),
        ("0s", 0),
        ("5.0s", 5 * s),
        ("5.6s", 5 * s + 600_000_000),
        ("5.s", 5 * s),
        (".5s", s / 2),
        ("1.0s", s),
        ("1.00s", s),
        ("1.004s", s + 4_000_000),
        ("1.0040s", s + 4_000_000),
        ("100.00100s", 100 * s + 1_000_000),
        ("10ns", 10),
        ("11us", 11_000),
        ("12\u{b5}s", 12_000),
        ("12\u{3bc}s", 12_000),
        ("13ms", 13_000_000),
        ("14s", 14 * s),
        ("15m", 15 * 60 * s),
        ("16h", 16 * 3600 * s),
        ("3h30m", 3 * 3600 * s + 30 * 60 * s),
        ("1h30m", 5400 * s),
        ("10.5s4m", 4 * 60 * s + 10 * s + 500_000_000),
        ("-2m3.4s", -(2 * 60 * s + 3 * s + 400_000_000)),
        ("1h2m3s4ms5us6ns", 3600 * s + 2 * 60 * s + 3 * s + 4_000_000 + 5_000 + 6),
        ("39h9m14.425s", 39 * 3600 * s + 9 * 60 * s + 14 * s + 425_000_000),
        ("52763797000ns", 52_763_797_000),
        ("9007199254740993ns", 9_007_199_254_740_993),
        ("9223372036854775807ns", i64::MAX),
        ("9223372036854775.807us", i64::MAX),
        ("9223372036s854775807ns", i64::MAX),
        ("-9223372036854775808ns", i64::MIN),
        ("1.5s", s + s / 2),
        ("0.000000001s", 1),
        ("0.0000000019s", 1),
        ("2562047h47m16.854775807s", i64::MAX),
    ];
    for (i, o) in v {
        match parse_duration(i) {
            Ok(got) => assert_eq!(got, *o, "input {:?}", i),
            Err(e) => panic!("{:?}: {}", i, e),
        }
    }
}

#[test]
fn duration_errors() {
    assert_eq!(parse_duration(""), Err(DurationError::Empty));
    for s in ["3", "-", "+", "s", ".", "-.", ".s", "+.s", "1s2", "- 1s", " 1s", "--1s", "h1"] {
        assert_eq!(parse_duration(s), Err(DurationError::Invalid), "{:?}", s);
    }
    for s in ["1y", "1d", "1S", "1H", "1sec", "1s ", "1 s", "1\u{b5}", "1Ms", "5xs"] {
        assert_eq!(parse_duration(s), Err(DurationError::UnknownUnit), "{:?}", s);
    }
    for s in [
        "9223372036854775808ns",
        "-9223372036854775809ns",
        "9223372036854775.808us",
        "9223372036854775808",
        "2562047h47m16.854775808s",
        "99999999999999999999999h",
        "9223372036854775807ns1ns",
    ] {
        let r = parse_duration(s);
        assert!(r == Err(DurationError::OutOfRange) || r == Err(DurationError::Invalid), "{:?} -> {:?}", s, r);
    }
    assert_eq!(parse_duration("9223372036854775808ns"), Err(DurationError::OutOfRange));
    assert_eq!(parse_duration("9223372036854775807ns1ns"), Err(DurationError::OutOfRange));
}

#[test]
fn duration_formatting_matches_go() {
    let v: &[(i64, &str)] = &[
        (0, "0s"),
        (1, "1ns"),
        (1100, "1.1\u{b5}s"),
        (2_200_000, "2.2ms"),
        (3_300_000_000, "3.3s"),
        (4 * 60_000_000_000 + 5_000_000_000, "4m5s"),
        (4 * 60_000_000_000 + 5_001_000_000, "4m5.001s"),
        (5 * 3600_000_000_000 + 6 * 60_000_000_000 + 7_001_000_000, "5h6m7.001s"),
        (8 * 3600_000_000_000 + 9 * 60_000_000_000 + 10_000_000_000 + 1, "8h9m10.000000001s"),
        (5_400_000_000_000, "1h30m0s"),
        (3_600_000_000_000, "1h0m0s"),
        (60_000_000_000, "1m0s"),
        (1_000_000_000, "1s"),
        (-1_500_000_000, "-1.5s"),
        (-1, "-1ns"),
        (999, "999ns"),
        (1000, "1\u{b5}s"),
        (999_999_999, "999.999999ms"),
        (i64::MAX, "2562047h47m16.854775807s"),
        (i64::MIN, "-2562047h47m16.854775808s"),
    ];
    for (n, s) in v {
        assert_eq!(format_duration(*n), *s, "{}", n);
    }
    for n in [0i64, 1, 999, 1000, 1_500_000, 1_000_000_000, 90_061_001_001_001, -42, i64::MAX, i64::MIN] {
        assert_eq!(parse_duration(&format_duration(n)), Ok(n), "{}", n);
    }
}
