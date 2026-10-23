use crate::base64::*;
use alloc::vec::Vec;

#[test]
fn rfc4648_vectors() {
    let v: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, enc) in v {
        assert_eq!(encode(plain.as_bytes()), *enc);
        assert_eq!(decode(enc).unwrap(), plain.as_bytes());
    }
    // Unpadded URL-safe form of the same vectors.
    assert_eq!(encode_url(b"f"), "Zg");
    assert_eq!(encode_url(b"fo"), "Zm8");
    assert_eq!(decode_url("Zm9vYg").unwrap(), b"foob");
}

#[test]
fn alphabets() {
    assert_eq!(encode(&[0xfb, 0xff]), "+/8=");
    assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
    assert_eq!(decode("+/8=").unwrap(), [0xfb, 0xff]);
    assert_eq!(decode_url("-_8").unwrap(), [0xfb, 0xff]);
    assert_eq!(decode("-_8=").unwrap_err().kind, ErrorKind::InvalidByte);
    assert_eq!(decode_url("+/8").unwrap_err().kind, ErrorKind::InvalidByte);
    assert_eq!(encode_config(&[0xfb, 0xff], Alphabet::UrlSafe, Padding::Required), "-_8=");
    assert_eq!(encode_config(&[0xfb, 0xff], Alphabet::Standard, Padding::None), "+/8");
    assert_eq!(decode_config(b"-_8=", Alphabet::UrlSafe, Padding::Required).unwrap(), [0xfb, 0xff]);
}

#[test]
fn strict_padding() {
    let cases: &[(&str, ErrorKind)] = &[
        ("Zg", ErrorKind::InvalidLength),
        ("Zg=", ErrorKind::InvalidLength),
        ("Zg===", ErrorKind::InvalidLength),
        ("Zm8", ErrorKind::InvalidLength),
        ("Zm8==", ErrorKind::InvalidLength),
        ("Zm9v=", ErrorKind::InvalidLength),
        ("Zm9vYg=", ErrorKind::InvalidLength),
        ("Z===", ErrorKind::InvalidLength),
        ("Zm9v====", ErrorKind::InvalidPadding),
        ("Zm9vY===", ErrorKind::InvalidLength),
        ("Zg=a", ErrorKind::InvalidByte),
        ("=Zg=", ErrorKind::InvalidByte),
        ("Zg==Zg==", ErrorKind::InvalidByte),
        ("====", ErrorKind::InvalidPadding),
        ("A===", ErrorKind::InvalidLength),
    ];
    for (s, k) in cases {
        let e = decode(s).expect_err(s);
        assert_eq!(e.kind, *k, "{}", s);
    }
    // Unpadded mode refuses '=' and impossible lengths.
    assert_eq!(decode_url("Zg==").unwrap_err().kind, ErrorKind::InvalidPadding);
    assert_eq!(decode_url("Z").unwrap_err().kind, ErrorKind::InvalidLength);
    assert_eq!(decode_url("Zm9vY").unwrap_err().kind, ErrorKind::InvalidLength);
}

#[test]
fn rejects_non_canonical_trailing_bits() {
    // "Zg==" is canonical, "Zh==" has stray low bits.
    assert_eq!(decode("Zh==").unwrap_err().kind, ErrorKind::NonCanonical);
    assert_eq!(decode("Zm9=").unwrap_err().kind, ErrorKind::NonCanonical);
    assert_eq!(decode("Zm+=").unwrap_err().kind, ErrorKind::NonCanonical);
    assert_eq!(decode_url("Zh").unwrap_err().kind, ErrorKind::NonCanonical);
    assert_eq!(decode_url("Zm9").unwrap_err().kind, ErrorKind::NonCanonical);
    assert!(decode("Zm8=").is_ok());
}

#[test]
fn rejects_whitespace_and_junk() {
    for s in ["Zm9v\n", " Zm9v", "Zm 9v", "Zm9v\r\n", "Zm9\u{e9}", "Zm9*", "Zm9v\0"] {
        assert!(decode(s).is_err(), "{:?}", s);
    }
    // Same length class, so the byte check is what fires.
    for s in ["Zm9\n", "Zm 9", "Z\u{e9}9", "Zm9\0"] {
        assert_eq!(decode(s).unwrap_err().kind, ErrorKind::InvalidByte, "{:?}", s);
    }
    let e = decode("Zm9*").unwrap_err();
    assert_eq!(e.offset, 3);
}

#[test]
fn roundtrip_all_lengths_and_bytes() {
    let data: Vec<u8> = (0..=255u8).collect();
    for n in 0..data.len() {
        let d = &data[..n];
        assert_eq!(decode(&encode(d)).unwrap(), d);
        assert_eq!(decode_url(&encode_url(d)).unwrap(), d);
    }
    let mut x = 0x1234_5678u32;
    for n in 0..200 {
        let d: Vec<u8> = (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        assert_eq!(decode(&encode(&d)).unwrap(), d);
    }
}
