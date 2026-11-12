//! The backup archive written by `kr snapshot save`: a plain ustar tarball (readable with
//! `tar tf`), regular files only, names of at most 100 bytes. The datastore itself is a
//! [`crate::Store::image`] (the `KRSNAP1` format) stored as one member.

use alloc::string::String;
use alloc::vec::Vec;

const BLOCK: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a tar archive, truncated, or a checksum does not match.
    Corrupt(&'static str),
    /// Member name or kind that `kr snapshot restore` refuses (absolute, `..`, links, ...).
    Unsafe(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Member {
    pub name: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

fn octal(field: &mut [u8], v: u64) {
    let n = field.len() - 1;
    for i in 0..n {
        field[n - 1 - i] = b'0' + ((v >> (3 * i)) & 7) as u8;
    }
    field[n] = 0;
}

fn parse_octal(f: &[u8]) -> Option<u64> {
    let t: Vec<u8> = f.iter().copied().take_while(|&b| b != 0).filter(|&b| b != b' ').collect();
    if t.is_empty() {
        return Some(0);
    }
    t.iter().try_fold(0u64, |a, &b| if (b'0'..=b'7').contains(&b) { a.checked_mul(8)?.checked_add((b - b'0') as u64) } else { None })
}

fn checksum(h: &[u8]) -> u64 {
    h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { b' ' as u64 } else { b as u64 }).sum()
}

/// Encodes `members` (`mtime` is stored in every header).
pub fn encode(members: &[Member], mtime: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for m in members {
        let mut h = [0u8; BLOCK];
        let nb = m.name.as_bytes();
        assert!(nb.len() <= 100, "tar member name too long");
        h[..nb.len()].copy_from_slice(nb);
        octal(&mut h[100..108], m.mode as u64);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], m.data.len() as u64);
        octal(&mut h[136..148], mtime);
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let c = checksum(&h);
        octal(&mut h[148..155], c);
        h[154] = 0;
        h[155] = b' ';
        out.extend_from_slice(&h);
        out.extend_from_slice(&m.data);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

/// Decodes an archive written by [`encode`] (or GNU tar with regular files only).
pub fn decode(buf: &[u8]) -> Result<Vec<Member>, Error> {
    let (mut pos, mut out) = (0usize, Vec::new());
    loop {
        let Some(h) = buf.get(pos..pos + BLOCK) else { return Err(Error::Corrupt("truncated archive (no end marker)")) };
        if h.iter().all(|&b| b == 0) {
            return Ok(out);
        }
        if parse_octal(&h[148..156]) != Some(checksum(h)) {
            return Err(Error::Corrupt("header checksum"));
        }
        let name_end = h[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = core::str::from_utf8(&h[..name_end]).map_err(|_| Error::Corrupt("member name"))?;
        let size = parse_octal(&h[124..136]).ok_or(Error::Corrupt("member size"))? as usize;
        let mode = parse_octal(&h[100..108]).ok_or(Error::Corrupt("member mode"))? as u32;
        if !matches!(h[156], b'0' | 0) {
            return Err(Error::Unsafe(String::from(name)));
        }
        if name.is_empty() || name.starts_with('/') || name.split('/').any(|c| c == ".." || c.is_empty()) {
            return Err(Error::Unsafe(String::from(name)));
        }
        pos += BLOCK;
        let data = buf.get(pos..pos.checked_add(size).ok_or(Error::Corrupt("member size"))?).ok_or(Error::Corrupt("truncated member"))?;
        out.push(Member { name: String::from(name), mode: mode & 0o777, data: data.to_vec() });
        pos += size.div_ceil(BLOCK) * BLOCK;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn m(n: &str, d: &[u8]) -> Member {
        Member { name: n.to_string(), mode: 0o600, data: d.to_vec() }
    }

    #[test]
    fn round_trip_including_empty_and_block_sized() {
        let ms = vec![m("kr-snapshot/META", b"x=1\n"), m("kr-snapshot/empty", b""), m("kr-snapshot/store", &[7u8; 512]), m("kr-snapshot/pki/ca.key", &[9u8; 1000])];
        let tar = encode(&ms, 1_700_000_000);
        assert_eq!(tar.len() % 512, 0);
        assert_eq!(decode(&tar).unwrap(), ms);
    }

    #[test]
    fn rejects_damage_and_unsafe_names() {
        let tar = encode(&[m("a/b", b"hello")], 0);
        let mut bad = tar.clone();
        bad[3] ^= 1;
        assert!(matches!(decode(&bad), Err(Error::Corrupt(_))));
        assert!(matches!(decode(&tar[..tar.len() - 1024 - 100]), Err(Error::Corrupt(_))));
        assert!(matches!(decode(&tar[..600]), Err(Error::Corrupt(_))));
        assert!(matches!(decode(&encode(&[m("../etc/x", b"")], 0)), Err(Error::Unsafe(_))));
        assert!(matches!(decode(&encode(&[m("/abs", b"")], 0)), Err(Error::Unsafe(_))));
        let mut link = encode(&[m("l", b"")], 0);
        link[156] = b'2';
        let c = checksum(&link[..512]);
        octal(&mut link[148..155], c);
        link[154] = 0;
        link[155] = b' ';
        assert!(matches!(decode(&link), Err(Error::Unsafe(_))));
    }

    #[test]
    fn store_image_through_from_files() {
        let mut s = crate::Store::in_memory();
        s.create("/a", b"1".to_vec()).unwrap();
        s.create("/b", b"2".to_vec()).unwrap();
        s.delete("/a", None).unwrap();
        let img = s.image();
        let r = crate::Store::from_files(Some(&img), &[]).unwrap();
        assert_eq!(r.revision(), 3);
        assert!(r.get("/a").is_none());
        assert_eq!(&*r.get("/b").unwrap().value, b"2");
        assert!(crate::Store::from_files(Some(b"nope"), &[]).is_err());
    }
}
