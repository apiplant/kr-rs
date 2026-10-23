use crate::proto::*;
use alloc::vec;
use alloc::vec::Vec;

fn enc(v: u64) -> Vec<u8> {
    let mut o = Vec::new();
    encode_varint(v, &mut o);
    o
}

#[test]
fn varint_vectors() {
    assert_eq!(enc(0), [0x00]);
    assert_eq!(enc(1), [0x01]);
    assert_eq!(enc(127), [0x7f]);
    assert_eq!(enc(128), [0x80, 0x01]);
    assert_eq!(enc(150), [0x96, 0x01]);
    assert_eq!(enc(300), [0xac, 0x02]);
    assert_eq!(enc(16383), [0xff, 0x7f]);
    assert_eq!(enc(16384), [0x80, 0x80, 0x01]);
    assert_eq!(enc(u64::MAX), [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    assert_eq!(enc(1 << 63), [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    for v in [0, 1, 127, 128, 255, 300, 1 << 32, (1 << 63) - 1, 1 << 63, u64::MAX - 1, u64::MAX] {
        let e = enc(v);
        assert_eq!(e.len(), varint_len(v), "{}", v);
        assert_eq!(decode_varint(&e).unwrap(), (v, e.len()));
    }
    // Trailing bytes after the varint are left alone.
    assert_eq!(decode_varint(&[0x96, 0x01, 0xff]).unwrap(), (150, 2));
}

#[test]
fn varint_errors() {
    assert_eq!(decode_varint(&[]).unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(decode_varint(&[0x80]).unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(decode_varint(&[0xff; 9]).unwrap_err().kind, ErrorKind::Truncated);
    // 10th byte may only be 0 or 1.
    let mut b = vec![0xff; 9];
    b.push(0x02);
    assert_eq!(decode_varint(&b).unwrap_err().kind, ErrorKind::VarintOverflow);
    let mut b = vec![0xff; 9];
    b.push(0x81);
    assert_eq!(decode_varint(&b).unwrap_err().kind, ErrorKind::VarintOverflow);
    assert_eq!(decode_varint(&[0xff; 11]).unwrap_err().kind, ErrorKind::VarintOverflow);
    // Non-minimal but in range is tolerated.
    assert_eq!(decode_varint(&[0x80, 0x00]).unwrap(), (0, 2));
}

#[test]
fn zigzag() {
    for (s, u) in [(0i64, 0u64), (-1, 1), (1, 2), (-2, 3), (2, 4), (i64::MAX, u64::MAX - 1), (i64::MIN, u64::MAX)] {
        assert_eq!(zigzag_encode64(s), u);
        assert_eq!(zigzag_decode64(u), s);
    }
    for (s, u) in [(0i32, 0u32), (-1, 1), (1, 2), (-2, 3), (i32::MAX, u32::MAX - 1), (i32::MIN, u32::MAX)] {
        assert_eq!(zigzag_encode32(s), u);
        assert_eq!(zigzag_decode32(u), s);
    }
    assert_eq!(enc(zigzag_encode64(-1)), [0x01]);
    assert_eq!(enc(zigzag_encode64(-64)), [0x7f]);
    assert_eq!(enc(zigzag_encode64(64)), [0x80, 0x01]);
}

#[test]
fn tags() {
    assert_eq!(make_tag(1, WireType::Varint), 0x08);
    assert_eq!(make_tag(2, WireType::Len), 0x12);
    assert_eq!(make_tag(15, WireType::Fixed32), 0x7d);
    assert_eq!(split_tag(0x08), Ok((1, WireType::Varint)));
    assert_eq!(split_tag(0x12), Ok((2, WireType::Len)));
    assert_eq!(split_tag(make_tag(MAX_FIELD, WireType::Fixed64)), Ok((MAX_FIELD, WireType::Fixed64)));
    assert_eq!(split_tag(0x00), Err(ErrorKind::InvalidFieldNumber));
    assert_eq!(split_tag(0x02), Err(ErrorKind::InvalidFieldNumber));
    assert_eq!(split_tag(((MAX_FIELD as u64 + 1) << 3) | 0), Err(ErrorKind::InvalidFieldNumber));
    for wt in [3, 4, 6, 7] {
        assert_eq!(split_tag(8 | wt), Err(ErrorKind::InvalidWireType));
    }
}

#[test]
fn reader_spec_example() {
    // The classic example from the protobuf docs: field 1 = 150.
    let mut r = Reader::new(&[0x08, 0x96, 0x01]);
    let f = r.next().unwrap().unwrap();
    assert_eq!(f.number, 1);
    assert_eq!(f.as_varint(), Some(150));
    assert!(r.next().unwrap().is_none());
    // field 2 = "testing"
    let mut data = vec![0x12, 0x07];
    data.extend_from_slice(b"testing");
    let f = Reader::new(&data).next().unwrap().unwrap();
    assert_eq!(f.number, 2);
    assert_eq!(f.as_str(), Some("testing"));
    // field 3 = embedded { 1: 150 }
    let f = Reader::new(&[0x1a, 0x03, 0x08, 0x96, 0x01]).next().unwrap().unwrap();
    let mut inner = Reader::new(f.as_bytes().unwrap());
    assert_eq!(inner.next().unwrap().unwrap().as_varint(), Some(150));
}

#[test]
fn writer_reader_roundtrip() {
    let mut w = Writer::new();
    w.varint(1, u64::MAX)
        .int64(2, -1)
        .sint64(3, -5)
        .sint32(4, i32::MIN)
        .bool(5, true)
        .fixed32(6, 0xdead_beef)
        .fixed64(7, 0x0123_4567_89ab_cdef)
        .string(8, "héllo")
        .bytes(9, &[0, 1, 2])
        .message(10, |m| {
            m.varint(1, 7).string(2, "inner");
        })
        .packed_varints(11, &[1, 300, u64::MAX])
        .varint(1, 5);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    let mut next = || r.next().unwrap().unwrap();
    assert_eq!(next().as_varint(), Some(u64::MAX));
    assert_eq!(next().as_varint(), Some(u64::MAX)); // int64(-1) is 10 bytes of ones
    assert_eq!(next().as_sint64(), Some(-5));
    assert_eq!(zigzag_decode32(next().as_varint().unwrap() as u32), i32::MIN);
    assert_eq!(next().as_bool(), Some(true));
    assert_eq!(next().value, Value::Fixed32(0xdead_beef));
    assert_eq!(next().value, Value::Fixed64(0x0123_4567_89ab_cdef));
    assert_eq!(next().as_str(), Some("héllo"));
    assert_eq!(next().as_bytes(), Some(&[0u8, 1, 2][..]));
    let m = next();
    let mut inner = Reader::new(m.as_bytes().unwrap());
    assert_eq!(inner.next().unwrap().unwrap().as_varint(), Some(7));
    assert_eq!(inner.next().unwrap().unwrap().as_str(), Some("inner"));
    assert!(inner.next().unwrap().is_none());
    let p = next();
    assert_eq!(packed_varints(p.as_bytes().unwrap()).unwrap(), [1, 300, u64::MAX]);
    let last = next();
    assert_eq!((last.number, last.as_varint()), (1, Some(5)));
    assert!(r.is_empty());
}

#[test]
fn negative_int64_is_ten_bytes() {
    let mut w = Writer::new();
    w.int64(1, -1);
    assert_eq!(w.as_bytes().len(), 1 + 10);
    let mut w = Writer::new();
    w.sint64(1, -1);
    assert_eq!(w.as_bytes(), [0x08, 0x01]);
}

#[test]
fn reader_errors() {
    // Truncated payloads.
    assert_eq!(Reader::new(&[0x12, 0x05, b'a']).next().unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(Reader::new(&[0x08]).next().unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(Reader::new(&[0x0d, 1, 2, 3]).next().unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(Reader::new(&[0x09, 1, 2, 3, 4, 5, 6, 7]).next().unwrap_err().kind, ErrorKind::Truncated);
    // Field 0, groups, reserved wire types.
    assert_eq!(Reader::new(&[0x00, 0x01]).next().unwrap_err().kind, ErrorKind::InvalidFieldNumber);
    assert_eq!(Reader::new(&[0x0b]).next().unwrap_err().kind, ErrorKind::InvalidWireType);
    assert_eq!(Reader::new(&[0x0c]).next().unwrap_err().kind, ErrorKind::InvalidWireType);
    assert_eq!(Reader::new(&[0x0e]).next().unwrap_err().kind, ErrorKind::InvalidWireType);
    // Length limit is checked before bounds.
    let mut data = vec![0x12];
    encode_varint(1 << 40, &mut data);
    assert_eq!(Reader::new(&data).next().unwrap_err().kind, ErrorKind::LengthLimit);
    let lim = Limits { max_len: 3 };
    let ok = [0x12, 0x03, 1, 2, 3];
    assert!(Reader::with_limits(&ok, lim).next().is_ok());
    let big = [0x12, 0x04, 1, 2, 3, 4];
    let e = Reader::with_limits(&big, lim).next().unwrap_err();
    assert_eq!((e.kind, e.offset), (ErrorKind::LengthLimit, 1));
    // Error offset of a bad varint inside a field.
    let e = Reader::new(&[0x08, 0x80]).next().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Truncated);
    assert_eq!(e.offset, 2);
    // Invalid UTF-8 string accessor.
    let f = Reader::new(&[0x0a, 0x01, 0xff]).next().unwrap().unwrap();
    assert_eq!(f.as_str(), None);
    assert_eq!(utf8_field(&f, 2).unwrap_err().kind, ErrorKind::InvalidUtf8);
    assert_eq!(packed_varints(&[0x80]).unwrap_err().kind, ErrorKind::Truncated);
}
