//! Minimal runtime: `_start`, panic handler, allocator, mem* intrinsics, print helpers.
//!
//! The allocator is SINGLE-THREADED. There are no threads in phase 0; do not call into it
//! from more than one thread.
#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod exec;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

// ---------- entry ----------

#[cfg(all(target_arch = "x86_64", not(any(test, feature = "host"))))]
core::arch::global_asm!(
    ".globl _start",
    ".type _start,@function",
    "_start:",
    "xor ebp, ebp",
    "mov rdi, rsp",
    "and rsp, -16",
    "call kr_rt_start",
    "ud2",
);

#[cfg(all(target_arch = "aarch64", not(any(test, feature = "host"))))]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "mov x29, xzr",
    "mov x0, sp",
    "and sp, x0, #-16",
    "bl kr_rt_start",
    "brk #0",
);

/// Iterator over argv entries (without the trailing NUL).
#[derive(Clone)]
pub struct Args {
    argv: *const *const u8,
    argc: usize,
    idx: usize,
}

impl Args {
    pub fn len(&self) -> usize {
        self.argc
    }
    pub fn is_empty(&self) -> bool {
        self.argc == 0
    }
}

impl Iterator for Args {
    type Item = &'static [u8];
    fn next(&mut self) -> Option<&'static [u8]> {
        if self.idx >= self.argc {
            return None;
        }
        // SAFETY: argv has argc valid NUL-terminated pointers set up by the kernel, living for
        // the whole process.
        let p = unsafe { *self.argv.add(self.idx) };
        self.idx += 1;
        let mut n = 0;
        // SAFETY: the string is NUL-terminated.
        unsafe {
            while core::ptr::read_volatile(p.add(n)) != 0 {
                n += 1;
            }
            Some(core::slice::from_raw_parts(p, n))
        }
    }
}

#[cfg(not(any(test, feature = "host")))]
extern "Rust" {
    fn kr_main(args: Args) -> i32;
}

/// # Safety
/// Called only from `_start` with the original stack pointer.
#[cfg(not(any(test, feature = "host")))]
#[no_mangle]
pub unsafe extern "C" fn kr_rt_start(sp: *const usize) -> ! {
    // SAFETY: at process entry sp points to argc followed by argv pointers.
    let argc = unsafe { *sp };
    let argv = unsafe { sp.add(1) } as *const *const u8;
    // SAFETY: kr_main is defined by the binary.
    let code = unsafe { kr_main(Args { argv, argc, idx: 0 }) };
    kr_sys::exit_group(code)
}

// ---------- output ----------

fn write_all(fd: i32, mut b: &[u8]) {
    while !b.is_empty() {
        match kr_sys::write(fd, b) {
            Ok(0) => return,
            Ok(n) => b = &b[n..],
            Err(kr_sys::Errno(kr_sys::EINTR)) => {}
            Err(_) => return,
        }
    }
}

pub fn print(b: &[u8]) {
    write_all(1, b)
}

pub fn eprint(b: &[u8]) {
    write_all(2, b)
}

/// Formats `n` in decimal into `buf`, returning the used tail.
pub fn fmt_u64(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

// ---------- panic ----------

#[cfg_attr(any(test, feature = "host"), allow(dead_code))]
struct Stderr;
impl core::fmt::Write for Stderr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        eprint(s.as_bytes());
        Ok(())
    }
}

/// The precompiled `core` is built with unwinding, so unoptimised builds still reference the
/// personality routine even though we use panic=abort. It is never called.
#[cfg(not(any(test, feature = "host")))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Referenced by landing pads in the precompiled `alloc` (e.g. `format_inner`). With panic=abort
/// no unwind ever starts, so reaching this is a bug: abort.
#[cfg(not(any(test, feature = "host")))]
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    kr_sys::exit_group(134)
}

#[cfg(not(any(test, feature = "host")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let _ = Stderr.write_str("panic: ");
    let _ = write!(Stderr, "{}", info.message());
    if let Some(l) = info.location() {
        let _ = write!(Stderr, " at {}:{}", l.file(), l.line());
    }
    let _ = Stderr.write_str("\n");
    kr_sys::exit_group(101)
}

// ---------- allocator ----------
//
// Small blocks (<= 2 KiB) come from 64 KiB chunks, each dedicated to one size class and aligned
// to 64 KiB so a block's chunk is `ptr & !(CHUNK-1)`. The chunk header holds a per-chunk free
// list, bump offset and live-block count. When a chunk's live count drops to zero it is reset and
// (unless it is the class's current chunk) its pages are returned with MADV_DONTNEED; the mapping
// is kept and reused, so there is no mmap churn.

const MIN_SHIFT: usize = 4; // 16
const MAX_SHIFT: usize = 11; // 2048
const NCLASS: usize = MAX_SHIFT - MIN_SHIFT + 1;
const CHUNK: usize = 64 * 1024;
const PAGE: usize = 4096;

#[repr(C)]
struct Chunk {
    next: *mut Chunk,
    free: *mut u8,
    bump: u32,
    live: u32,
    class: u8,
    in_list: bool,
}

struct State {
    /// Per class: stack of chunks with room; the head is the current chunk.
    avail: [*mut Chunk; NCLASS],
    madvised: usize,
}

pub struct KrAlloc {
    st: UnsafeCell<State>,
}

// SAFETY: the runtime is single-threaded (documented at crate level).
unsafe impl Sync for KrAlloc {}

impl KrAlloc {
    pub const fn new() -> Self {
        KrAlloc { st: UnsafeCell::new(State { avail: [core::ptr::null_mut(); NCLASS], madvised: 0 }) }
    }

    /// Number of chunk-release (madvise) calls made so far.
    pub fn madvise_count(&self) -> usize {
        // SAFETY: single-threaded.
        unsafe { (*self.st.get()).madvised }
    }
}

impl Default for KrAlloc {
    fn default() -> Self {
        Self::new()
    }
}

fn map(len: usize) -> *mut u8 {
    // SAFETY: anonymous private mapping at a kernel-chosen address; no existing memory affected.
    match unsafe {
        kr_sys::mmap(0, len, kr_sys::PROT_READ | kr_sys::PROT_WRITE, kr_sys::MAP_PRIVATE | kr_sys::MAP_ANONYMOUS, -1, 0)
    } {
        Ok(p) => p as *mut u8,
        Err(_) => core::ptr::null_mut(),
    }
}

/// Maps `len` bytes aligned to `align` (a power of two, >= PAGE) by over-allocating and trimming.
fn map_aligned(len: usize, align: usize) -> *mut u8 {
    let total = match len.checked_add(align) {
        Some(t) => t,
        None => return core::ptr::null_mut(),
    };
    let base = map(total);
    if base.is_null() {
        return base;
    }
    let b = base as usize;
    let a = (b + align - 1) & !(align - 1);
    // SAFETY: both ranges lie inside the mapping just created and are unreferenced.
    unsafe {
        if a > b {
            let _ = kr_sys::munmap(b, a - b);
        }
        let end = b + total;
        if end > a + len {
            let _ = kr_sys::munmap(a + len, end - (a + len));
        }
    }
    a as *mut u8
}

#[inline]
fn class_of(layout: &Layout) -> Option<usize> {
    let sz = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    if sz > (1 << MAX_SHIFT) {
        return None;
    }
    Some(sz.next_power_of_two().trailing_zeros() as usize - MIN_SHIFT)
}

#[inline]
fn large_len(layout: &Layout) -> usize {
    (layout.size() + PAGE - 1) & !(PAGE - 1)
}

/// First usable offset in a chunk of class `c`: the header rounded up to the block size.
#[inline]
fn data_start(c: usize) -> u32 {
    let sz = 1usize << (c + MIN_SHIFT);
    ((core::mem::size_of::<Chunk>() + sz - 1) & !(sz - 1)) as u32
}

fn new_chunk(c: usize) -> *mut Chunk {
    let p = map_aligned(CHUNK, CHUNK) as *mut Chunk;
    if !p.is_null() {
        // SAFETY: fresh zeroed, writable, suitably aligned memory.
        unsafe {
            (*p).bump = data_start(c);
            (*p).class = c as u8;
        }
    }
    p
}

unsafe impl GlobalAlloc for KrAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match class_of(&layout) {
            Some(c) => {
                // SAFETY: single-threaded, so exclusive access to the state and chunk headers.
                let st = unsafe { &mut *self.st.get() };
                let sz = 1usize << (c + MIN_SHIFT);
                loop {
                    let ch = st.avail[c];
                    if ch.is_null() {
                        let n = new_chunk(c);
                        if n.is_null() {
                            return n as *mut u8;
                        }
                        // SAFETY: n is a valid fresh chunk.
                        unsafe { (*n).in_list = true };
                        st.avail[c] = n;
                        continue;
                    }
                    // SAFETY: ch is a live chunk header; free-list nodes keep next in word 0.
                    unsafe {
                        let head = (*ch).free;
                        if !head.is_null() {
                            (*ch).free = *(head as *mut *mut u8);
                            (*ch).live += 1;
                            return head;
                        }
                        let b = (*ch).bump as usize;
                        if b + sz <= CHUNK {
                            (*ch).bump = (b + sz) as u32;
                            (*ch).live += 1;
                            return (ch as *mut u8).add(b);
                        }
                        // Full: drop it from the available stack (re-added on the next free).
                        st.avail[c] = (*ch).next;
                        (*ch).in_list = false;
                    }
                }
            }
            None if layout.align() > PAGE => map_aligned(large_len(&layout), layout.align()),
            None => map(large_len(&layout)),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match class_of(&layout) {
            Some(c) => {
                // SAFETY: single-threaded; ptr belongs to a chunk of class c, 64 KiB aligned.
                let st = unsafe { &mut *self.st.get() };
                let ch = (ptr as usize & !(CHUNK - 1)) as *mut Chunk;
                unsafe {
                    (*ch).live -= 1;
                    if (*ch).live == 0 {
                        (*ch).free = core::ptr::null_mut();
                        (*ch).bump = data_start(c);
                        let head = st.avail[c];
                        if !(*ch).in_list {
                            if head.is_null() {
                                (*ch).next = core::ptr::null_mut();
                                st.avail[c] = ch;
                            } else {
                                (*ch).next = (*head).next;
                                (*head).next = ch;
                            }
                            (*ch).in_list = true;
                        }
                        if ch != st.avail[c] {
                            // Keep the header page; release the rest back to the OS.
                            let _ = kr_sys::madvise(ch as usize + PAGE, CHUNK - PAGE, kr_sys::MADV_DONTNEED);
                            st.madvised += 1;
                        }
                    } else {
                        *(ptr as *mut *mut u8) = (*ch).free;
                        (*ch).free = ptr;
                        if !(*ch).in_list {
                            // Insert behind the current chunk so it stays the hot one.
                            let head = st.avail[c];
                            if head.is_null() {
                                (*ch).next = core::ptr::null_mut();
                                st.avail[c] = ch;
                            } else {
                                (*ch).next = (*head).next;
                                (*head).next = ch;
                            }
                            (*ch).in_list = true;
                        }
                    }
                }
            }
            None => {
                // SAFETY: ptr/len match the (trimmed) mapping created in alloc.
                let _ = unsafe { kr_sys::munmap(ptr as usize, large_len(&layout)) };
            }
        }
    }
}

#[cfg(not(any(test, feature = "host")))]
#[global_allocator]
static ALLOC: KrAlloc = KrAlloc::new();

#[cfg(test)]
mod alloc_tests {
    use super::*;
    use std::vec::Vec;

    fn rss_pages() -> usize {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap();
        s.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    #[test]
    fn mixed_sizes_stress() {
        let a = KrAlloc::new();
        let mut live: Vec<(*mut u8, Layout, u8)> = Vec::new();
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for i in 0..60_000usize {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if live.len() < 50 || x % 3 != 0 {
                let size = match x % 7 {
                    0 => 1 + (x >> 8) as usize % 16,
                    1 => 1 + (x >> 8) as usize % 200,
                    2 => 1 + (x >> 8) as usize % 2048,
                    3 => 2049 + (x >> 8) as usize % 6000,
                    _ => 1 + (x >> 8) as usize % 100,
                };
                let align = 1usize << ((x >> 40) % 7);
                let l = Layout::from_size_align(size, align).unwrap();
                let p = unsafe { a.alloc(l) };
                assert!(!p.is_null());
                assert_eq!(p as usize % align, 0);
                let tag = (i & 0xff) as u8;
                unsafe { core::ptr::write_bytes(p, tag, size) };
                live.push((p, l, tag));
            } else {
                let k = (x >> 20) as usize % live.len();
                let (p, l, tag) = live.swap_remove(k);
                for j in 0..l.size() {
                    assert_eq!(unsafe { *p.add(j) }, tag);
                }
                unsafe { a.dealloc(p, l) };
            }
        }
        for (p, l, tag) in live {
            for j in 0..l.size() {
                assert_eq!(unsafe { *p.add(j) }, tag);
            }
            unsafe { a.dealloc(p, l) };
        }
    }

    #[test]
    fn large_alignment_up_to_1mib() {
        let a = KrAlloc::new();
        let mut sh = 12;
        while sh <= 20 {
            let align = 1usize << sh;
            for size in [1usize, 100, 4096, 5000, 3 * 4096 + 1] {
                let l = Layout::from_size_align(size, align).unwrap();
                let p = unsafe { a.alloc(l) };
                assert!(!p.is_null());
                assert_eq!(p as usize % align, 0, "align {align} size {size}");
                unsafe { core::ptr::write_bytes(p, 0x5a, size) };
                unsafe { a.dealloc(p, l) };
            }
            sh += 1;
        }
        // The freed ranges must really be unmapped: re-mapping must still work and nothing crashes.
        let l = Layout::from_size_align(8192, 1 << 20).unwrap();
        let p = unsafe { a.alloc(l) };
        assert_eq!(p as usize % (1 << 20), 0);
        unsafe { a.dealloc(p, l) };
    }

    #[test]
    fn freed_chunks_are_released() {
        let a = KrAlloc::new();
        let l = Layout::from_size_align(64, 8).unwrap();
        let n = 200_000; // ~12.8 MB
        let base = rss_pages();
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let p = unsafe { a.alloc(l) };
            assert!(!p.is_null());
            unsafe { core::ptr::write_bytes(p, 1, 64) };
            v.push(p);
        }
        let peak = rss_pages();
        assert!(peak > base + 2500, "burst should raise RSS: {base} -> {peak}");
        for p in v {
            unsafe { a.dealloc(p, l) };
        }
        let after = rss_pages();
        assert!(a.madvise_count() > 100, "madvise calls: {}", a.madvise_count());
        assert!(after < base + (peak - base) / 2, "RSS did not drop: base {base} peak {peak} after {after}");
        // Chunks remain usable after release.
        let p = unsafe { a.alloc(l) };
        unsafe { core::ptr::write_bytes(p, 2, 64) };
        unsafe { a.dealloc(p, l) };
    }
}

// ---------- mem* ----------
// Gated off under the `host` feature, where the host libc provides these symbols. Under `test`
// the functions are compiled (so they can be exercised) but not exported.
#[cfg(any(test, not(feature = "host")))]
mod mem {
use core::ffi::c_void;

// Implemented with inline asm / non-inlined loops with volatile accesses so the compiler cannot
// recognise the pattern and turn it back into a call to the same symbol. Stores (memcpy, memmove,
// memset) and the `a` loads (memcmp) are volatile; the other side may use unaligned loads.

#[allow(dead_code)]
const W: usize = core::mem::size_of::<usize>();

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: caller guarantees non-overlapping valid regions of n bytes.
    unsafe {
        core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") dst => _, inout("rsi") src => _, options(nostack, preserves_flags));
    }
    dst
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    // SAFETY: caller guarantees dst is valid for n bytes.
    unsafe {
        core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") dst => _, in("al") c as u8, options(nostack, preserves_flags));
    }
    dst
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if (dst as usize).wrapping_sub(src as usize) >= n {
        // A forward copy is safe (no overlap, or dst < src).
        // SAFETY: valid regions per caller contract.
        unsafe {
            core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") dst => _, inout("rsi") src => _, options(nostack, preserves_flags));
        }
    } else {
        // Overlap with dst > src: copy backwards with DF set.
        // SAFETY: valid regions; DF is cleared again before leaving the asm block (ABI requires DF=0).
        unsafe {
            core::arch::asm!(
                "std",
                "rep movsb",
                "cld",
                inout("rcx") n => _,
                inout("rdi") (dst as *mut u8).add(n).wrapping_sub(1) => _,
                inout("rsi") (src as *const u8).add(n).wrapping_sub(1) => _,
                options(nostack),
            );
        }
    }
    dst
}

/// Forward word-at-a-time copy; also correct for overlap when dst < src.
#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn copy_fwd(d: *mut u8, s: *const u8, n: usize) {
    let mut i = 0;
    // SAFETY (all accesses below): in-bounds per caller contract; volatile stores prevent
    // loop-idiom recognition.
    if n >= 2 * W {
        while (d as usize + i) % W != 0 {
            unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
            i += 1;
        }
        while i + W <= n {
            unsafe { core::ptr::write_volatile(d.add(i) as *mut usize, core::ptr::read_unaligned(s.add(i) as *const usize)) };
            i += W;
        }
    }
    while i < n {
        unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
        i += 1;
    }
}

/// Backward word-at-a-time copy for overlapping regions with dst > src.
#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn copy_bwd(d: *mut u8, s: *const u8, n: usize) {
    let mut i = n;
    // SAFETY (all accesses below): in-bounds per caller contract.
    if n >= 2 * W {
        while (d as usize + i) % W != 0 {
            i -= 1;
            unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
        }
        while i >= W {
            i -= W;
            unsafe { core::ptr::write_volatile(d.add(i) as *mut usize, core::ptr::read_unaligned(s.add(i) as *const usize)) };
        }
    }
    while i > 0 {
        i -= 1;
        unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(not(test), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: caller guarantees valid non-overlapping regions.
    unsafe { copy_fwd(dst as *mut u8, src as *const u8, n) };
    dst
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(not(test), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dst as *mut u8;
    let mut i = 0;
    // SAFETY (all accesses below): caller guarantees dst valid for n bytes.
    if n >= 2 * W {
        let word = (c as u8 as usize) * (usize::MAX / 255);
        while (d as usize + i) % W != 0 {
            unsafe { core::ptr::write_volatile(d.add(i), c as u8) };
            i += 1;
        }
        while i + W <= n {
            unsafe { core::ptr::write_volatile(d.add(i) as *mut usize, word) };
            i += W;
        }
    }
    while i < n {
        unsafe { core::ptr::write_volatile(d.add(i), c as u8) };
        i += 1;
    }
    dst
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(not(test), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let (d, s) = (dst as *mut u8, src as *const u8);
    // SAFETY: valid regions per caller contract; the direction is chosen to be overlap-safe.
    unsafe {
        if (d as usize).wrapping_sub(s as usize) >= n {
            copy_fwd(d, s, n);
        } else {
            copy_bwd(d, s, n);
        }
    }
    dst
}

#[cfg_attr(not(test), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let (a, b) = (a as *const u8, b as *const u8);
    let mut i = 0;
    // SAFETY (all accesses below): caller guarantees both regions valid for n bytes; volatile
    // loads of `a` block idiom recognition.
    if n >= 2 * W {
        while (a as usize + i) % W != 0 {
            let (x, y) = unsafe { (core::ptr::read_volatile(a.add(i)), core::ptr::read_volatile(b.add(i))) };
            if x != y {
                return x as i32 - y as i32;
            }
            i += 1;
        }
        while i + W <= n {
            let (x, y) = unsafe {
                (core::ptr::read_volatile(a.add(i) as *const usize), core::ptr::read_unaligned(b.add(i) as *const usize))
            };
            if x != y {
                break; // locate the differing byte below
            }
            i += W;
        }
    }
    while i < n {
        let (x, y) = unsafe { (core::ptr::read_volatile(a.add(i)), core::ptr::read_volatile(b.add(i))) };
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[cfg_attr(not(test), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    // SAFETY: same contract as memcmp.
    unsafe { memcmp(a, b, n) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn pat(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn copy_set_cmp_exhaustive() {
        for len in 0..=64usize {
            for so in 0..8 {
                for dof in 0..8 {
                    let src = pat(len + 16, 7);
                    let mut dst = std::vec![0xEEu8; len + 16];
                    let mut want = dst.clone();
                    want[dof..dof + len].copy_from_slice(&src[so..so + len]);
                    unsafe { memcpy(dst.as_mut_ptr().add(dof) as _, src.as_ptr().add(so) as _, len) };
                    assert_eq!(dst, want, "memcpy len={len} so={so} do={dof}");

                    let mut dst = std::vec![0x11u8; len + 16];
                    let mut want = dst.clone();
                    for b in &mut want[dof..dof + len] {
                        *b = 0xA5;
                    }
                    unsafe { memset(dst.as_mut_ptr().add(dof) as _, 0xA5, len) };
                    assert_eq!(dst, want, "memset len={len} do={dof}");

                    // memcmp with different relative alignments, equal then a difference at each byte.
                    let a = pat(len + 16, 3);
                    let mut b = std::vec![0u8; len + 16];
                    b[dof..dof + len].copy_from_slice(&a[so..so + len]);
                    let (pa, pb) = (unsafe { a.as_ptr().add(so) }, unsafe { b.as_ptr().add(dof) });
                    assert_eq!(unsafe { memcmp(pa as _, pb as _, len) }, 0);
                    assert_eq!(unsafe { bcmp(pa as _, pb as _, len) }, 0);
                    for k in 0..len {
                        b[dof + k] = b[dof + k].wrapping_add(1);
                        let r = unsafe { memcmp(pa as _, pb as _, len) };
                        assert_eq!(r, a[so + k] as i32 - b[dof + k] as i32, "memcmp len={len} so={so} k={k}");
                        assert_ne!(unsafe { bcmp(pa as _, pb as _, len) }, 0);
                        b[dof + k] = b[dof + k].wrapping_sub(1);
                    }
                }
            }
        }
    }

    #[test]
    fn memmove_overlap_both_directions() {
        for len in 0..=64usize {
            for so in 0..8 {
                for dof in (0..8).chain([9, 15, 16, 17]) {
                    let mut buf = pat(len + 24, 9);
                    let mut want = buf.clone();
                    want.copy_within(so..so + len, dof);
                    let p = buf.as_mut_ptr();
                    unsafe { memmove(p.add(dof) as _, p.add(so) as _, len) };
                    assert_eq!(buf, want, "memmove len={len} so={so} do={dof}");
                }
            }
        }
    }
}
}
