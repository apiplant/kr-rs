//! CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320), slice-by-8.

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 8 {
            c = t[0][(c & 0xff) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

static T: [[u32; 256]; 8] = make_tables();

/// Incremental CRC-32.
#[derive(Clone, Copy, Debug)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub const fn new() -> Self {
        Crc32(!0)
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        let (chunks, rest) = data.as_chunks::<8>();
        for ch in chunks {
            let lo = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]) ^ c;
            let hi = u32::from_le_bytes([ch[4], ch[5], ch[6], ch[7]]);
            c = T[7][(lo & 0xff) as usize]
                ^ T[6][((lo >> 8) & 0xff) as usize]
                ^ T[5][((lo >> 16) & 0xff) as usize]
                ^ T[4][(lo >> 24) as usize]
                ^ T[3][(hi & 0xff) as usize]
                ^ T[2][((hi >> 8) & 0xff) as usize]
                ^ T[1][((hi >> 16) & 0xff) as usize]
                ^ T[0][(hi >> 24) as usize];
        }
        for &b in rest {
            c = T[0][((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    pub fn value(&self) -> u32 {
        !self.0
    }
}

/// One-shot CRC-32.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.value()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        let mut c = Crc32::new();
        c.update(b"1234");
        c.update(b"56789");
        assert_eq!(c.value(), 0xCBF4_3926);
    }
}
