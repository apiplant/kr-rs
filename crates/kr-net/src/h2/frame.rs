//! HTTP/2 frame header parsing and serialisation (RFC 9113 section 4).

use alloc::vec::Vec;

pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const PRIORITY: u8 = 2;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PUSH_PROMISE: u8 = 5;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;
pub const CONTINUATION: u8 = 9;

pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;
pub const PADDED: u8 = 0x8;
pub const PRIORITY_FLAG: u8 = 0x20;

pub const NO_ERROR: u32 = 0;
pub const PROTOCOL_ERROR: u32 = 1;
pub const INTERNAL_ERROR: u32 = 2;
pub const FLOW_CONTROL_ERROR: u32 = 3;
pub const STREAM_CLOSED: u32 = 5;
pub const FRAME_SIZE_ERROR: u32 = 6;
pub const REFUSED_STREAM: u32 = 7;
pub const CANCEL: u32 = 8;
pub const COMPRESSION_ERROR: u32 = 9;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
pub const SETTINGS_ENABLE_PUSH: u16 = 2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;

pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Largest frame payload we accept (the protocol default; we never raise it).
pub const MAX_FRAME: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub len: usize,
    pub ty: u8,
    pub flags: u8,
    pub sid: u32,
}

pub fn parse_head(b: &[u8]) -> Head {
    Head {
        len: (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize,
        ty: b[3],
        flags: b[4],
        sid: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
    }
}

pub fn put(out: &mut Vec<u8>, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
    let n = payload.len() as u32;
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags]);
    out.extend_from_slice(&(sid & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Removes padding when the PADDED flag is set; `None` if the pad length is invalid.
pub fn strip_padding(flags: u8, p: &[u8]) -> Option<&[u8]> {
    if flags & PADDED == 0 {
        return Some(p);
    }
    let (&pad, rest) = p.split_first()?;
    let pad = pad as usize;
    if pad > rest.len() {
        return None;
    }
    Some(&rest[..rest.len() - pad])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_padding() {
        let mut o = Vec::new();
        put(&mut o, DATA, END_STREAM, 5, b"abc");
        let h = parse_head(&o);
        assert_eq!(h, Head { len: 3, ty: DATA, flags: 1, sid: 5 });
        assert_eq!(strip_padding(PADDED, &[2, b'x', 0, 0]), Some(&b"x"[..]));
        assert_eq!(strip_padding(PADDED, &[3, b'x', 0]), None);
        assert_eq!(strip_padding(PADDED, &[]), None);
        assert_eq!(strip_padding(0, b"ab"), Some(&b"ab"[..]));
    }
}
