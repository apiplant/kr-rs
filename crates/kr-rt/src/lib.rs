//! Minimal runtime: `_start`, panic handler, allocator, mem* intrinsics, print helpers.
//!
//! The allocator is SINGLE-THREADED. There are no threads in phase 0; do not call into it
//! from more than one thread.
#![no_std]

extern crate alloc;

pub mod exec;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

// ---------- entry ----------

#[cfg(all(target_arch = "x86_64", not(feature = "host")))]
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

#[cfg(all(target_arch = "aarch64", not(feature = "host")))]
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

#[cfg(not(feature = "host"))]
extern "Rust" {
    fn kr_main(args: Args) -> i32;
}

/// # Safety
/// Called only from `_start` with the original stack pointer.
#[cfg(not(feature = "host"))]
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

const MIN_SHIFT: usize = 4; // 16
const MAX_SHIFT: usize = 11; // 2048
const NCLASS: usize = MAX_SHIFT - MIN_SHIFT + 1;
const CHUNK: usize = 64 * 1024;
const PAGE: usize = 4096;

struct State {
    free: [*mut u8; NCLASS],
    bump: usize,
    bump_end: usize,
}

pub struct KrAlloc {
    st: UnsafeCell<State>,
}

// SAFETY: the runtime is single-threaded (documented at crate level).
unsafe impl Sync for KrAlloc {}

impl KrAlloc {
    pub const fn new() -> Self {
        KrAlloc { st: UnsafeCell::new(State { free: [core::ptr::null_mut(); NCLASS], bump: 0, bump_end: 0 }) }
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

unsafe impl GlobalAlloc for KrAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match class_of(&layout) {
            Some(c) => {
                // SAFETY: single-threaded, so exclusive access to the state.
                let st = unsafe { &mut *self.st.get() };
                let head = st.free[c];
                if !head.is_null() {
                    // SAFETY: free-list nodes store the next pointer in their first word.
                    st.free[c] = unsafe { *(head as *mut *mut u8) };
                    return head;
                }
                let sz = 1usize << (c + MIN_SHIFT);
                let mut aligned = (st.bump + sz - 1) & !(sz - 1);
                if aligned + sz > st.bump_end {
                    let p = map(CHUNK);
                    if p.is_null() {
                        return p;
                    }
                    // Remainder of the old chunk is abandoned (bounded waste < 2 KiB).
                    st.bump_end = p as usize + CHUNK;
                    aligned = p as usize; // page aligned, hence sz aligned
                }
                st.bump = aligned + sz;
                aligned as *mut u8
            }
            None => map(large_len(&layout)),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match class_of(&layout) {
            Some(c) => {
                // SAFETY: single-threaded; block is at least 16 bytes and 8-aligned.
                let st = unsafe { &mut *self.st.get() };
                unsafe { *(ptr as *mut *mut u8) = st.free[c] };
                st.free[c] = ptr;
            }
            None => {
                // SAFETY: ptr/len match the mapping created in alloc.
                let _ = unsafe { kr_sys::munmap(ptr as usize, large_len(&layout)) };
            }
        }
    }
}

#[cfg(not(feature = "host"))]
#[global_allocator]
static ALLOC: KrAlloc = KrAlloc::new();

// ---------- mem* ----------
// Gated off under the `host` feature, where the host libc provides these symbols.
#[cfg(not(feature = "host"))]
mod mem {
use core::ffi::c_void;

// Implemented with inline asm / non-inlined volatile loops so the compiler cannot recognise
// the pattern and turn it back into a call to the same symbol.

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: caller guarantees non-overlapping valid regions of n bytes.
    unsafe {
        core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") dst => _, inout("rsi") src => _, options(nostack, preserves_flags));
    }
    dst
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    // SAFETY: caller guarantees dst is valid for n bytes.
    unsafe {
        core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") dst => _, in("al") c as u8, options(nostack, preserves_flags));
    }
    dst
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
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

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let (d, s) = (dst as *mut u8, src as *const u8);
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees valid regions; volatile prevents loop-idiom recognition.
        unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
        i += 1;
    }
    dst
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dst as *mut u8;
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees dst valid for n bytes.
        unsafe { core::ptr::write_volatile(d.add(i), c as u8) };
        i += 1;
    }
    dst
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let (d, s) = (dst as *mut u8, src as *const u8);
    if (d as usize) <= (s as usize) {
        let mut i = 0;
        while i < n {
            // SAFETY: valid regions per caller contract.
            unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            // SAFETY: valid regions per caller contract.
            unsafe { core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i))) };
        }
    }
    dst
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let (a, b) = (a as *const u8, b as *const u8);
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees both regions valid for n bytes; volatile blocks idiom recognition.
        let (x, y) = unsafe { (core::ptr::read_volatile(a.add(i)), core::ptr::read_volatile(b.add(i))) };
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    // SAFETY: same contract as memcmp.
    unsafe { memcmp(a, b, n) }
}
}
