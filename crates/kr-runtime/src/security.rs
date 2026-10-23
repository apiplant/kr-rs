//! Capability bounding and the default seccomp profile (ADR-018).
//!
//! The profile is a deny-list on top of the reduced capability set. With CAP_SYS_ADMIN dropped,
//! most dangerous calls already fail; the filter adds defence in depth for kernel attack surface
//! reachable without capabilities (io_uring, userfaultfd, bpf, keyrings, nested user namespaces).

use alloc::vec::Vec;
use kr_sys::ns::{self, SockFilter};
use kr_sys::Errno;

/// Docker's default capability set.
pub const DEFAULT_CAPS: &[u32] = &[
    0,  // CHOWN
    1,  // DAC_OVERRIDE
    3,  // FOWNER
    4,  // FSETID
    5,  // KILL
    6,  // SETGID
    7,  // SETUID
    8,  // SETPCAP
    10, // NET_BIND_SERVICE
    13, // NET_RAW
    18, // SYS_CHROOT
    27, // MKNOD
    29, // AUDIT_WRITE
    31, // SETFCAP
];

/// Highest capability number we try to drop; unknown ones return EINVAL and are skipped.
const CAP_LAST: u32 = 63;

/// Drops every capability not in `keep` from the bounding set, clears ambient and inheritable
/// sets, and limits effective/permitted to `keep`.
pub fn drop_caps(keep: &[u32]) -> Result<(), Errno> {
    let mut mask = 0u64;
    for &c in keep {
        mask |= 1 << c;
    }
    for c in 0..=CAP_LAST {
        if mask & (1 << c) == 0 {
            match ns::prctl(ns::PR_CAPBSET_DROP, c as usize) {
                Ok(()) | Err(Errno(22)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    ns::prctl(ns::PR_CAP_AMBIENT, ns::PR_CAP_AMBIENT_CLEAR_ALL)?;
    ns::capset(mask)
}

#[cfg(target_arch = "x86_64")]
mod arch {
    pub const AUDIT_ARCH: u32 = 0xC000_003E;
    /// x32 ABI syscalls have this bit set; they bypass a native-number filter, so kill them.
    pub const X32_BIT: Option<u32> = Some(0x4000_0000);
    pub const CLONE: u32 = 56;
    pub const DENY: &[u32] = &[
        250, 248, 249, // keyctl, add_key, request_key
        321, 298, // bpf, perf_event_open
        246, 320, 175, 313, 176, // kexec_load, kexec_file_load, init/finit/delete_module
        303, 304, // name_to_handle_at, open_by_handle_at
        323, // userfaultfd
        425, 426, 427, // io_uring_setup/enter/register
        163, 167, 168, 169, // acct, swapon, swapoff, reboot
        164, 227, 305, 159, // settimeofday, clock_settime, clock_adjtime, adjtimex
        155, 165, 166, // pivot_root, mount, umount2
        428, 429, 430, 431, 432, 433, 442, // open_tree, move_mount, fsopen..fspick, mount_setattr
        179, 212, 172, 173, 134, 156, 103, // quotactl, lookup_dcookie, iopl, ioperm, uselib, _sysctl, syslog
        308, 272, // setns, unshare
        312, 310, 311, // kcmp, process_vm_readv/writev
        174, 177, 178, 180, // create_module, get_kernel_syms, query_module, nfsservctl
    ];
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub const AUDIT_ARCH: u32 = 0xC000_00B7;
    pub const X32_BIT: Option<u32> = None;
    pub const CLONE: u32 = 220;
    pub const DENY: &[u32] = &[
        219, 217, 218, // keyctl, add_key, request_key
        280, 241, // bpf, perf_event_open
        104, 294, 105, 273, 106, // kexec_load, kexec_file_load, init/finit/delete_module
        264, 265, // name_to_handle_at, open_by_handle_at
        282, // userfaultfd
        425, 426, 427, // io_uring_setup/enter/register
        89, 224, 225, 142, // acct, swapon, swapoff, reboot
        170, 112, 266, 171, // settimeofday, clock_settime, clock_adjtime, adjtimex
        41, 40, 39, // pivot_root, mount, umount2
        428, 429, 430, 431, 432, 433, 442, // open_tree, move_mount, fsopen..fspick, mount_setattr
        60, 18, 116, // quotactl, lookup_dcookie, syslog
        268, 97, // setns, unshare
        272, 270, 271, // kcmp, process_vm_readv/writev
        42, // nfsservctl
    ];
}

const CLONE3: u32 = 435;
/// Namespace-creating clone flags (CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET).
const CLONE_NS_MASK: u32 = 0x7E02_0000;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const fn ret_errno(e: u32) -> u32 {
    0x0005_0000 | e
}
const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

// struct seccomp_data offsets.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16; // little-endian low half of args[0]

fn ins(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Builds the default filter. Layout: arch check, x32 kill, deny-list (EPERM), clone3 -> ENOSYS
/// (libc falls back to clone, whose flags we *can* inspect), clone with namespace flags -> EPERM.
pub fn default_filter() -> Vec<SockFilter> {
    let mut p = Vec::new();
    p.push(ins(LD_W_ABS, 0, 0, OFF_ARCH));
    p.push(ins(JEQ_K, 1, 0, arch::AUDIT_ARCH));
    p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    if let Some(bit) = arch::X32_BIT {
        p.push(ins(JGE_K, 0, 1, bit));
        p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    }
    for &nr in arch::DENY {
        p.push(ins(JEQ_K, 0, 1, nr));
        p.push(ins(RET_K, 0, 0, ret_errno(EPERM)));
    }
    p.push(ins(JEQ_K, 0, 1, CLONE3));
    p.push(ins(RET_K, 0, 0, ret_errno(ENOSYS)));
    p.push(ins(JEQ_K, 0, 3, arch::CLONE));
    p.push(ins(LD_W_ABS, 0, 0, OFF_ARG0_LO));
    p.push(ins(JSET_K, 0, 1, CLONE_NS_MASK));
    p.push(ins(RET_K, 0, 0, ret_errno(EPERM)));
    p.push(ins(RET_K, 0, 0, RET_ALLOW));
    p
}
