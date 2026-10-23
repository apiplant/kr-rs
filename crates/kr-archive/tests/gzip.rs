mod common;
use common::*;
use kr_archive::crc32::crc32;
use kr_archive::gzip::GzDecoder;
use kr_archive::inflate::{Inflater, Status};
use kr_archive::Error;

fn gunzip(data: &[u8], mode: usize, seed: u64) -> Result<Vec<u8>, Error> {
    let mut rng = Rng(seed);
    let mut d = GzDecoder::new();
    let mut out = Vec::new();
    for c in chunks(data, mode, &mut rng) {
        d.feed(c, &mut |b| {
            out.extend_from_slice(b);
            Ok::<(), ()>(())
        })
        .map_err(|e| e.erase())?;
    }
    d.finish()?;
    Ok(out)
}

#[test]
fn roundtrip_levels_and_chunkings() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let sizes = [0usize, 1, 2, 100, 4096, 70_000, 400_000];
    for &n in &sizes {
        let orig = mixed(&mut rng, n);
        for level in [1u8, 6, 9] {
            let gz = gzip(&orig, level);
            for mode in [0usize, 1, 3, 17, 1000, 70_000] {
                if mode == 1 && n > 100_000 {
                    continue;
                }
                let got = gunzip(&gz, mode, 99 + mode as u64).unwrap();
                assert!(got == orig, "n={n} level={level} mode={mode}");
            }
        }
    }
}

#[test]
fn random_data_uses_stored_blocks() {
    let mut rng = Rng(77);
    let orig = rng.bytes(300_000);
    let gz = gzip(&orig, 1);
    // Incompressible: output is barely larger than input => stored blocks.
    assert!(gz.len() < orig.len() + 2000 && gz.len() > orig.len());
    for mode in [0usize, 1, 5, 4096] {
        assert!(gunzip(&gz, mode, 5).unwrap() == orig);
    }
}

#[test]
fn highly_repetitive_overlapping_matches() {
    let orig: Vec<u8> = b"abc".iter().cycle().take(1_000_000).copied().collect();
    let gz = gzip(&orig, 9);
    assert!(gz.len() < 10_000);
    assert!(gunzip(&gz, 0, 1).unwrap() == orig);
    assert!(gunzip(&gz, 7, 1).unwrap() == orig);
}

#[test]
fn multi_member() {
    let mut rng = Rng(5);
    let a = mixed(&mut rng, 50_000);
    let b = Vec::new();
    let c = text(&mut rng, 80_000);
    let mut gz = gzip(&a, 6);
    gz.extend(gzip(&b, 6));
    gz.extend(gzip(&c, 1));
    let mut want = a.clone();
    want.extend(&c);
    for mode in [0usize, 1, 13] {
        let mut d = GzDecoder::new();
        let mut out = Vec::new();
        let mut r = Rng(3);
        for ch in chunks(&gz, mode, &mut r) {
            d.feed(ch, &mut |x| {
                out.extend_from_slice(x);
                Ok::<(), ()>(())
            })
            .unwrap();
        }
        d.finish().unwrap();
        assert_eq!(d.members(), 3);
        assert!(out == want);
    }
}

#[test]
fn header_fields_extra_name_comment_hcrc() {
    let orig = b"hello hello hello hello gzip header fields".to_vec();
    let gz = gzip(&orig, 6); // stdin => FLG=0, 10-byte header
    assert_eq!(gz[3], 0);
    let body = &gz[10..];
    let mut hdr = vec![0x1f, 0x8b, 8, 4 | 8 | 16 | 2, 1, 2, 3, 4, 0, 3];
    hdr.extend([5u8, 0]); // xlen
    hdr.extend(b"ABxyz");
    hdr.extend(b"some/file.txt\0");
    hdr.extend(b"a comment\0");
    let h = (crc32(&hdr) & 0xffff) as u16;
    hdr.extend(h.to_le_bytes());
    let mut full = hdr.clone();
    full.extend(body);
    for mode in [0usize, 1, 4] {
        assert!(gunzip(&full, mode, 8).unwrap() == orig);
    }
    // Bad header CRC.
    let mut bad = full.clone();
    let k = hdr.len() - 1;
    bad[k] ^= 0x55;
    assert_eq!(gunzip(&bad, 0, 1), Err(Error::HeaderCrc));
    // Reserved flag.
    let mut bad = full.clone();
    bad[3] |= 0x20;
    assert_eq!(gunzip(&bad, 0, 1), Err(Error::ReservedFlags));
}

#[test]
fn rejects_bad_magic_method_and_garbage() {
    assert_eq!(gunzip(b"\x1f\x8c\x08\0\0\0\0\0\0\0", 0, 1), Err(Error::BadMagic));
    assert_eq!(gunzip(b"\x1f\x8b\x07\0\0\0\0\0\0\0", 0, 1), Err(Error::UnsupportedMethod));
    let mut gz = gzip(b"data data data", 6);
    gz.extend(b"garbage");
    assert_eq!(gunzip(&gz, 0, 1), Err(Error::TrailingGarbage));
    assert_eq!(gunzip(b"", 0, 1), Err(Error::Truncated));
}

#[test]
fn corrupted_crc_and_size_rejected() {
    let mut rng = Rng(9);
    let orig = mixed(&mut rng, 100_000);
    let gz = gzip(&orig, 6);
    let n = gz.len();
    for mode in [0usize, 1, 100] {
        for i in 0..4 {
            let mut bad = gz.clone();
            bad[n - 8 + i] ^= 1;
            assert_eq!(gunzip(&bad, mode, 1), Err(Error::Crc32Mismatch));
        }
        for i in 0..4 {
            let mut bad = gz.clone();
            bad[n - 4 + i] ^= 1;
            assert_eq!(gunzip(&bad, mode, 1), Err(Error::SizeMismatch));
        }
    }
}

#[test]
fn truncated_input_rejected() {
    let mut rng = Rng(10);
    let orig = mixed(&mut rng, 60_000);
    let gz = gzip(&orig, 6);
    let mut cuts: Vec<usize> = (0..40).collect();
    cuts.extend((1..60).map(|k| gz.len() * k / 60));
    cuts.extend(gz.len() - 12..gz.len());
    for cut in cuts {
        if cut >= gz.len() {
            continue;
        }
        assert!(gunzip(&gz[..cut], 0, 1).is_err(), "cut {cut}");
        assert!(gunzip(&gz[..cut], 1, 1).is_err(), "cut {cut} 1-byte");
    }
}

#[test]
fn sink_error_propagates() {
    let gz = gzip(&vec![b'x'; 100_000], 6);
    let mut d = GzDecoder::new();
    let r = d.feed(&gz, &mut |_| Err("boom"));
    assert_eq!(r, Err(Error::Sink("boom")));
    assert_eq!(d.feed(b"x", &mut |_| Ok::<(), ()>(())), Err(Error::Failed));
}

// ---- raw inflate with hand-built streams ----

struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}
impl Bits {
    fn new() -> Self {
        Bits { out: vec![], acc: 0, n: 0 }
    }
    fn put(&mut self, v: u32, bits: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    /// Huffman codes are packed MSB first.
    fn code(&mut self, c: u32, len: u32) {
        for i in (0..len).rev() {
            self.put((c >> i) & 1, 1);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

fn raw(data: &[u8], mode: usize) -> Result<(Vec<u8>, Status), Error> {
    let mut inf = Inflater::new();
    let mut out = Vec::new();
    let mut st = Status::NeedInput;
    let mut r = Rng(1);
    for c in chunks(data, mode, &mut r) {
        let s = inf
            .feed(c, &mut |b| {
                out.extend_from_slice(b);
                Ok::<(), ()>(())
            })
            .map_err(|e| e.erase())?;
        if !matches!(st, Status::Done { .. }) {
            st = s;
        }
    }
    Ok((out, st))
}

#[test]
fn raw_fixed_block_and_consumed_count() {
    // Fixed block: literal 'a' (code 0x30+0x61 = 8 bits), EOB (7 zero bits).
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    b.code(0x30 + b'a' as u32, 8);
    b.code(0, 7);
    let mut s = b.finish();
    let len = s.len();
    s.extend(b"TRAILER");
    for mode in [0usize, 1] {
        let (out, st) = raw(&s, mode).unwrap();
        assert_eq!(out, b"a");
        // consumed is relative to the call that finished the stream.
        assert_eq!(st, Status::Done { consumed: if mode == 0 { len } else { 1 } });
    }
}

#[test]
fn raw_rejects_bad_blocks() {
    // Block type 3.
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(3, 2);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::InvalidBlockType));
    // Stored with wrong NLEN.
    let s = [0x01, 5, 0, 0, 0, 1, 2, 3, 4, 5];
    assert_eq!(raw(&s, 0).map(|_| ()), Err(Error::StoredLenMismatch));
    // Stored OK.
    let s = [0x01, 5, 0, 0xfa, 0xff, 1, 2, 3, 4, 5];
    for mode in [0usize, 1] {
        assert_eq!(raw(&s, mode).unwrap().0, [1, 2, 3, 4, 5]);
    }
    // Distance before start: fixed block, length code 257 (len 3), dist code 0.
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    b.code(1, 7); // symbol 257
    b.code(0, 5); // distance 1, nothing written yet
    b.code(0, 7);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::DistanceTooFar));
    // Reserved length symbol 286 in fixed block: 8-bit code 0xC0+6.
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    b.code(0x30 + b'a' as u32, 8);
    b.code(0xC0 + 6, 8);
    b.code(0, 5);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::InvalidLengthSymbol));
    // Reserved distance symbol 30.
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    b.code(0x30 + b'a' as u32, 8);
    b.code(1, 7);
    b.code(30, 5);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::InvalidDistanceSymbol));
}

fn dynamic_header(hlit: u32, hdist: u32, cl_lens: &[u32]) -> Bits {
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(2, 2);
    b.put(hlit - 257, 5);
    b.put(hdist - 1, 5);
    b.put(cl_lens.len() as u32 - 4, 4);
    for &l in cl_lens {
        b.put(l, 3);
    }
    b
}

#[test]
fn raw_rejects_bad_dynamic_trees() {
    // Code-length code with 19 symbols of length 1 each: over-subscribed.
    let b = dynamic_header(257, 1, &[1; 19]);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::OversubscribedCode));
    // Code-length code with a single symbol of length 1: incomplete (strict for CL).
    let b = dynamic_header(257, 1, &[0, 0, 0, 1]);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::IncompleteCode));
    // Too many literal/length codes.
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(2, 2);
    b.put(30, 5); // 287
    b.put(0, 5);
    b.put(0, 4);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::InvalidCodeLengths));
    // Valid CL code (symbols 0 and 8, one bit each) but EOB length is zero.
    // CL order: 16 17 18 0 8 ...; lens for sym 0 (idx 3) and 8 (idx 4) = 1.
    let mut b = dynamic_header(257, 1, &[0, 0, 0, 1, 1]);
    for _ in 0..258 {
        b.code(0, 1); // length 0 for all 258 symbols
    }
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::MissingEndOfBlock));
    // Over-subscribed literal tree: 257 symbols all of length 8 (sym 8 code '1').
    let mut b = dynamic_header(257, 1, &[0, 0, 0, 1, 1]);
    for _ in 0..257 {
        b.code(1, 1);
    }
    b.code(1, 1); // dist len 8
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::OversubscribedCode));
    // Repeat-previous (16) as the first length.
    let mut b = dynamic_header(257, 1, &[1, 0, 0, 1]);
    // CL syms 16 and 0 have length 1: sym 0 -> code 0, sym 16 -> code 1.
    b.code(1, 1);
    b.put(0, 2);
    assert_eq!(raw(&b.finish(), 0).map(|_| ()), Err(Error::InvalidCodeLengthRepeat));
}

#[test]
fn raw_single_code_special_case_ok() {
    // Dynamic block: literal tree = EOB (len 1) + 'a'... Build: lit/len with
    // exactly two codes (complete), dist tree with a single 1-bit code.
    // CL alphabet: sym 0 and sym 1 and sym 2 etc. Use CL syms {0,1} of len 1.
    // lens: 97 zeros, 'a'=1 (sym 97), zeros to 256, EOB=1, then 1 dist len 1.
    let mut b = dynamic_header(257, 1, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // CL syms with len: sym 0 (idx3) and sym 1 (idx 17). Codes: 0 -> '0', 1 -> '1'.
    for i in 0..257 {
        b.code(if i == 97 || i == 256 { 1 } else { 0 }, 1);
    }
    b.code(1, 1); // dist: one code of length 1
    // Data: 'a' (code 0), 'a', EOB (code 1).
    b.code(0, 1);
    b.code(0, 1);
    b.code(1, 1);
    assert_eq!(raw(&b.finish(), 0).unwrap().0, b"aa");
}

// ---- robustness ----

#[test]
fn mutation_fuzz_never_panics() {
    let mut rng = Rng(0xdead_beef_cafe);
    let src = mixed(&mut rng, 30_000);
    let gz = gzip(&src, 6);
    let gz9 = gzip(&text(&mut rng, 20_000), 9);
    let gz1 = gzip(&rng.bytes(5_000), 1);
    let mut errs = 0;
    for iter in 0..3000 {
        let base = match iter % 3 {
            0 => &gz,
            1 => &gz9,
            _ => &gz1,
        };
        let mut m = base.clone();
        let nmut = 1 + rng.below(4);
        for _ in 0..nmut {
            let i = rng.below(m.len());
            match rng.below(4) {
                0 => m[i] ^= 1 << rng.below(8),
                1 => m[i] = rng.next() as u8,
                2 => {
                    m.truncate(i.max(1));
                }
                _ => {
                    m.insert(i, rng.next() as u8);
                }
            }
        }
        let mode = [0usize, 1, 9][rng.below(3)];
        if gunzip(&m, mode, iter as u64).is_err() {
            errs += 1;
        }
    }
    assert!(errs > 1000);
    // Pure random garbage into the raw inflater.
    for i in 0..2000 {
        let n = 1 + rng.below(200);
        let g = rng.bytes(n);
        let _ = raw(&g, if i % 2 == 0 { 0 } else { 1 });
    }
}

#[test]
#[ignore]
fn bench_throughput() {
    let mut rng = Rng(42);
    let mut data = Vec::with_capacity(50 << 20);
    while data.len() < 50 << 20 {
        // Alternate random and text, ~25% random by size.
        if rng.below(4) == 0 {
            data.extend(rng.bytes(64 * 1024));
        } else {
            data.extend(text(&mut rng, 64 * 1024));
        }
    }
    data.truncate(50 << 20);
    let gz = gzip(&data, 6);
    println!("bench: input {} MB -> gzip {} MB", data.len() >> 20, gz.len() >> 20);
    let mut best = 0f64;
    for _ in 0..5 {
        let mut d = GzDecoder::new();
        let mut total = 0usize;
        let t = std::time::Instant::now();
        for c in gz.chunks(64 * 1024) {
            d.feed(c, &mut |b| {
                total += b.len();
                Ok::<(), ()>(())
            })
            .unwrap();
        }
        d.finish().unwrap();
        let s = t.elapsed().as_secs_f64();
        assert_eq!(total, data.len());
        best = best.max(total as f64 / s / 1e6);
        println!("bench: {:.1} MB/s (decompressed, incl. crc32)", total as f64 / s / 1e6);
    }
    println!("bench: best {best:.1} MB/s");
}
