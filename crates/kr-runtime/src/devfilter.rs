//! Device access control for containers: a `BPF_PROG_TYPE_CGROUP_DEVICE` program on the
//! container's cgroup that allows only the standard container devices (`/dev/null`, `zero`, `full`,
//! `random`, `urandom`, `tty`, `console`, `ptmx`, the container's own `pts`) and the device nodes the
//! container was given (GPUs from CDI or a device plugin, `hostPath` device nodes), the way runc,
//! containerd and Docker do. `mknod` itself stays allowed (the nodes it makes cannot be opened), so
//! images that create nodes at start keep working. Privileged containers get no filter.
//!
//! The program is `ctx = {access_type: u32 (low 16 = BPF_DEVCG_DEV_BLOCK 1 / CHAR 2, high 16 = access
//! mask MKNOD 1, READ 2, WRITE 4), major: u32, minor: u32}` -> 1 allow, 0 deny: for each rule, skip
//! to the next unless type, major and minor match and the access is a subset of the rule's.

use alloc::vec::Vec;
use kr_sys::{ns, Errno, Fd};

pub const READ: u32 = 2;
pub const WRITE: u32 = 4;
pub const MKNOD: u32 = 1;
const BLOCK: u32 = 1;
const CHAR: u32 = 2;

/// One allowed device. `None` is a wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// `b'c'` or `b'b'`; `None` = either.
    pub kind: Option<u8>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub access: u32,
}

/// What every container may use, plus `mknod` of anything (it creates a useless node).
pub fn defaults() -> Vec<Rule> {
    let mut r = alloc::vec![Rule { kind: None, major: None, minor: None, access: MKNOD }];
    for (maj, min) in [(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0), (5, 1), (5, 2)] {
        r.push(Rule { kind: Some(b'c'), major: Some(maj), minor: Some(min), access: READ | WRITE | MKNOD });
    }
    // devpts (newinstance): major 136, any minor.
    r.push(Rule { kind: Some(b'c'), major: Some(136), minor: None, access: READ | WRITE | MKNOD });
    r
}

/// The rule that gives access to the device node `path` on the host (None if it is not a device
/// node). `read_only` limits it to reads.
pub fn rule_for(path: &[u8], read_only: bool) -> Option<Rule> {
    let mut p = path.to_vec();
    p.push(0);
    let st = kr_sys::fs::newfstatat(ns::AT_FDCWD, &p, 0).ok()?;
    let kind = match st.mode & kr_sys::fs::S_IFMT {
        0o020000 => b'c',
        0o060000 => b'b',
        _ => return None,
    };
    let r = st.rdev;
    let major = (((r >> 8) & 0xfff) | ((r >> 32) & !0xfff)) as u32;
    let minor = ((r & 0xff) | ((r >> 12) & !0xff)) as u32;
    Some(Rule { kind: Some(kind), major: Some(major), minor: Some(minor), access: if read_only { READ } else { READ | WRITE } })
}

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = code;
    b[1] = (src << 4) | (dst & 0xf);
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

/// Compiles `rules` (default deny) to eBPF bytecode.
pub fn program(rules: &[Rule]) -> Vec<u8> {
    const LDX_W: u8 = 0x61;
    const MOV_R: u8 = 0xbf;
    const MOV_K: u8 = 0xb7;
    const AND_K: u8 = 0x57;
    const RSH_K: u8 = 0x77;
    const JNE_K: u8 = 0x55;
    const EXIT: u8 = 0x95;
    let mut p: Vec<[u8; 8]> = Vec::new();
    p.push(insn(LDX_W, 2, 1, 0, 0)); // r2 = access_type
    p.push(insn(MOV_R, 3, 2, 0, 0)); // r3 = r2
    p.push(insn(AND_K, 3, 0, 0, 0xffff)); // r3 = device type
    p.push(insn(RSH_K, 2, 0, 0, 16)); // r2 = access mask
    p.push(insn(LDX_W, 4, 1, 4, 0)); // r4 = major
    p.push(insn(LDX_W, 5, 1, 8, 0)); // r5 = minor
    for r in rules {
        let conds: Vec<(u8, i32)> = [
            r.kind.map(|k| (3u8, if k == b'b' { BLOCK } else { CHAR } as i32)),
            r.major.map(|m| (4u8, m as i32)),
            r.minor.map(|m| (5u8, m as i32)),
        ]
        .into_iter()
        .flatten()
        .collect();
        // conds + (mov, and, jne) + (mov r0, exit)
        let len = conds.len() + 5;
        let mut i = 0usize;
        for (reg, imm) in &conds {
            p.push(insn(JNE_K, *reg, 0, (len - 1 - i) as i16, *imm));
            i += 1;
        }
        p.push(insn(MOV_R, 6, 2, 0, 0)); // r6 = access
        p.push(insn(AND_K, 6, 0, 0, !(r.access as i32))); // r6 = access outside the rule's
        i += 2;
        p.push(insn(JNE_K, 6, 0, (len - 1 - i) as i16, 0)); // not a subset: next rule
        p.push(insn(MOV_K, 0, 0, 0, 1));
        p.push(insn(EXIT, 0, 0, 0, 0));
    }
    p.push(insn(MOV_K, 0, 0, 0, 0));
    p.push(insn(EXIT, 0, 0, 0, 0));
    p.concat()
}

/// Loads the filter and attaches it to the cgroup directory `cgroup`. Call before any process
/// enters the cgroup.
pub fn attach(cgroup: &Fd, rules: &[Rule]) -> Result<(), Errno> {
    let prog = ns::bpf_load_cgroup_device(&program(rules))?;
    ns::bpf_attach_cgroup_device(&prog, cgroup)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the subset of eBPF the compiler emits.
    fn run(prog: &[u8], kind: u32, access: u32, major: u32, minor: u32) -> u64 {
        let mut reg = [0u64; 11];
        let ctx = [kind | (access << 16), major, minor];
        let n = prog.len() / 8;
        let mut pc = 0;
        while pc < n {
            let i = &prog[pc * 8..pc * 8 + 8];
            let (code, dst, src) = (i[0], (i[1] & 0xf) as usize, (i[1] >> 4) as usize);
            let off = i16::from_le_bytes([i[2], i[3]]);
            let imm = i32::from_le_bytes([i[4], i[5], i[6], i[7]]);
            pc += 1;
            match code {
                0x61 => reg[dst] = ctx[(off / 4) as usize] as u64,
                0xbf => reg[dst] = reg[src],
                0xb7 => reg[dst] = imm as i64 as u64,
                0x57 => reg[dst] &= imm as i64 as u64,
                0x77 => reg[dst] >>= imm,
                0x55 => {
                    if reg[dst] != imm as i64 as u64 {
                        pc += off as usize;
                    }
                }
                0x95 => return reg[0],
                c => panic!("opcode {c:#x}"),
            }
        }
        panic!("fell off the program");
    }

    #[test]
    fn policy() {
        let mut rules = defaults();
        rules.push(Rule { kind: Some(b'c'), major: Some(195), minor: Some(0), access: READ | WRITE });
        rules.push(Rule { kind: Some(b'c'), major: Some(226), minor: Some(0), access: READ });
        let p = program(&rules);
        let allow = |k, a, ma, mi| run(&p, k, a, ma, mi) == 1;
        // standard devices
        assert!(allow(CHAR, READ | WRITE, 1, 3));
        assert!(allow(CHAR, READ, 136, 7));
        assert!(allow(CHAR, READ | WRITE, 5, 2));
        // granted
        assert!(allow(CHAR, READ | WRITE, 195, 0));
        assert!(allow(CHAR, READ, 226, 0));
        assert!(!allow(CHAR, WRITE, 226, 0), "read-only grant");
        // not granted: other minor, other major, block device, disk
        assert!(!allow(CHAR, READ, 195, 1));
        assert!(!allow(CHAR, READ, 195, 255));
        assert!(!allow(BLOCK, READ | WRITE, 8, 0));
        assert!(!allow(BLOCK, READ, 195, 0), "a block device with a granted number");
        assert!(!allow(CHAR, READ, 1, 1), "/dev/mem");
        // mknod of anything is allowed, opening what it made is not
        assert!(allow(BLOCK, MKNOD, 8, 0));
        assert!(allow(CHAR, MKNOD, 195, 3));
        assert!(!allow(BLOCK, MKNOD | READ, 8, 0));
        assert!(!allow(BLOCK, READ, 8, 0));
    }
}
