//! `securityContext.seccompProfile` of type `Localhost`: an OCI/Docker seccomp profile
//! (`defaultAction`, `syscalls[{names, action, errnoRet, args}]`) compiled to a classic-BPF filter
//! for the running architecture (ADR-055).
//!
//! Supported: the actions ALLOW, ERRNO, KILL, KILL_THREAD, KILL_PROCESS, TRAP and LOG; per-rule
//! `includes`/`excludes` on `caps` and `arches`; argument conditions on the low 32 bits of an
//! argument (EQ, NE, LT, LE, GT, GE, MASKED_EQ). Unknown syscall names are skipped (profiles list
//! calls of other architectures and kernels). Rules with argument conditions are evaluated before
//! plain ones, then the default action decides.

use crate::syscalls;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};
use kr_sys::ns::SockFilter;

#[cfg(target_arch = "x86_64")]
const TABLE: &[(&str, u32)] = syscalls::X86_64;
#[cfg(target_arch = "aarch64")]
const TABLE: &[(&str, u32)] = syscalls::AARCH64;
#[cfg(target_arch = "x86_64")]
const ARCH_NAMES: &[&str] = &["amd64", "x86_64", "x86-64", "SCMP_ARCH_X86_64"];
#[cfg(target_arch = "aarch64")]
const ARCH_NAMES: &[&str] = &["arm64", "aarch64", "SCMP_ARCH_AARCH64"];

const LD_W_ABS: u16 = 0x20;
const ALU_AND_K: u16 = 0x54;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;

fn ins(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn number(name: &str) -> Option<u32> {
    TABLE.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// A seccomp return value for an action name.
fn action(name: &str, errno: Option<u64>) -> Result<u32, String> {
    Ok(match name {
        "SCMP_ACT_ALLOW" => 0x7fff_0000,
        "SCMP_ACT_ERRNO" => 0x0005_0000 | (errno.unwrap_or(1) as u32 & 0xffff),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => 0,
        "SCMP_ACT_KILL_PROCESS" => 0x8000_0000,
        "SCMP_ACT_TRAP" => 0x0003_0000,
        "SCMP_ACT_LOG" => 0x7ffc_0000,
        other => return Err(format!("unsupported action {other:?}")),
    })
}

struct Cond {
    index: u32,
    op: String,
    value: u64,
    value_two: u64,
}

struct Rule {
    nrs: Vec<u32>,
    ret: u32,
    conds: Vec<Cond>,
}

fn str_list<'a>(v: Option<&'a Value>) -> Vec<&'a str> {
    v.and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect()
}

/// Whether the rule applies to a container whose bounding capabilities are `caps`.
fn applies(call: &Value, caps: &[u32]) -> Result<bool, String> {
    let has = |name: &str| -> Result<bool, String> {
        let n = crate::security::cap_number_pub(name).ok_or_else(|| format!("unknown capability {name:?}"))?;
        Ok(caps.contains(&n))
    };
    let arch_ok = |l: &[&str]| l.iter().any(|a| ARCH_NAMES.contains(a));
    if let Some(inc) = call.get("includes") {
        let a = str_list(inc.get("arches"));
        if !a.is_empty() && !arch_ok(&a) {
            return Ok(false);
        }
        for c in str_list(inc.get("caps")) {
            if !has(c)? {
                return Ok(false);
            }
        }
    }
    if let Some(exc) = call.get("excludes") {
        let a = str_list(exc.get("arches"));
        if !a.is_empty() && arch_ok(&a) {
            return Ok(false);
        }
        for c in str_list(exc.get("caps")) {
            if has(c)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Compiles the profile `text` for a container with the bounding capabilities `caps`.
pub fn compile(text: &str, caps: &[u32]) -> Result<Vec<SockFilter>, String> {
    let v = json::parse(text.as_bytes()).map_err(|_| String::from("not valid JSON"))?;
    let default = {
        let a = v.get("defaultAction").and_then(Value::as_str).ok_or("no defaultAction")?;
        action(a, v.get("defaultErrnoRet").and_then(Value::as_u64))?
    };
    let mut rules: Vec<Rule> = Vec::new();
    let calls: Vec<&Value> = v.get("syscalls").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    for call in calls {
        if !applies(call, caps)? {
            continue;
        }
        let name = call.get("action").and_then(Value::as_str).ok_or("a syscalls entry has no action")?;
        let ret = action(name, call.get("errnoRet").and_then(Value::as_u64))?;
        let mut names = str_list(call.get("names"));
        if let Some(n) = call.get("name").and_then(Value::as_str) {
            names.push(n);
        }
        let nrs: Vec<u32> = names.iter().filter_map(|n| number(n)).collect();
        let mut conds = Vec::new();
        for a in call.get("args").and_then(Value::as_array).unwrap_or(&[]) {
            let index = a.get("index").and_then(Value::as_u64).ok_or("an argument condition has no index")? as u32;
            if index > 5 {
                return Err(format!("argument index {index} out of range"));
            }
            let op = a.get("op").and_then(Value::as_str).ok_or("an argument condition has no op")?.to_string();
            if !matches!(op.as_str(), "SCMP_CMP_EQ" | "SCMP_CMP_NE" | "SCMP_CMP_LT" | "SCMP_CMP_LE" | "SCMP_CMP_GT" | "SCMP_CMP_GE" | "SCMP_CMP_MASKED_EQ") {
                return Err(format!("unsupported argument operator {op:?}"));
            }
            conds.push(Cond { index, op, value: a.get("value").and_then(Value::as_u64).unwrap_or(0), value_two: a.get("valueTwo").and_then(Value::as_u64).unwrap_or(0) });
        }
        if !nrs.is_empty() {
            rules.push(Rule { nrs, ret, conds });
        }
    }
    let mut p: Vec<SockFilter> = Vec::new();
    // Wrong architecture (a 32-bit call gate): killed, whatever the profile says.
    p.push(ins(LD_W_ABS, 0, 0, 4));
    p.push(ins(JEQ_K, 1, 0, crate::security::AUDIT_ARCH));
    p.push(ins(RET_K, 0, 0, 0x8000_0000));
    if let Some(bit) = crate::security::X32_BIT {
        p.push(ins(LD_W_ABS, 0, 0, 0));
        p.push(ins(JGE_K, 0, 1, bit));
        p.push(ins(RET_K, 0, 0, 0x8000_0000));
    }
    p.push(ins(LD_W_ABS, 0, 0, 0));
    // Rules with argument conditions first (they are the narrower ones), then the plain ones.
    for pass_args in [true, false] {
        for r in rules.iter().filter(|r| r.conds.is_empty() != pass_args) {
            for &nr in &r.nrs {
                if r.conds.is_empty() {
                    p.push(ins(JEQ_K, 0, 1, nr));
                    p.push(ins(RET_K, 0, 0, r.ret));
                    continue;
                }
                // JEQ nr; then each condition loads its argument and falls through to the
                // reload of the syscall number when it does not hold; all hold -> the action.
                let mut block: Vec<SockFilter> = Vec::new();
                // Distances are patched below: `fail` = index of the reload instruction.
                let mut fails: Vec<usize> = Vec::new();
                for c in &r.conds {
                    block.push(ins(LD_W_ABS, 0, 0, 16 + 8 * c.index));
                    let (v, v2) = (c.value as u32, c.value_two as u32);
                    match c.op.as_str() {
                        "SCMP_CMP_EQ" => {
                            fails.push(block.len());
                            block.push(ins(JEQ_K, 0, 0, v)); // jf patched
                        }
                        "SCMP_CMP_NE" => {
                            fails.push(block.len());
                            block.push(ins(JEQ_K, 0, 0, v)); // jt patched (fail when equal)
                        }
                        "SCMP_CMP_MASKED_EQ" => {
                            block.push(ins(ALU_AND_K, 0, 0, v));
                            fails.push(block.len());
                            block.push(ins(JEQ_K, 0, 0, v2));
                        }
                        "SCMP_CMP_GE" => {
                            fails.push(block.len());
                            block.push(ins(JGE_K, 0, 0, v));
                        }
                        "SCMP_CMP_GT" => {
                            fails.push(block.len());
                            block.push(ins(JGT_K, 0, 0, v));
                        }
                        "SCMP_CMP_LT" => {
                            fails.push(block.len());
                            block.push(ins(JGE_K, 0, 0, v)); // jt patched (fail when >=)
                        }
                        _ => {
                            fails.push(block.len());
                            block.push(ins(JGT_K, 0, 0, v)); // LE: jt patched (fail when >)
                        }
                    }
                }
                block.push(ins(RET_K, 0, 0, r.ret));
                let reload = block.len();
                block.push(ins(LD_W_ABS, 0, 0, 0));
                for (ci, &at) in fails.iter().enumerate() {
                    let to_fail = (reload - at - 1) as u8;
                    let op = r.conds[ci].op.as_str();
                    let k = &mut block[at];
                    if matches!(op, "SCMP_CMP_NE" | "SCMP_CMP_LT" | "SCMP_CMP_LE") {
                        k.jt = to_fail; // the "bad" outcome is the jump-if-true one
                        k.jf = 0;
                    } else {
                        k.jt = 0;
                        k.jf = to_fail;
                    }
                }
                // JEQ nr: on a different number skip the block *including* the reload (A is still nr).
                p.push(ins(JEQ_K, 0, (block.len() - 1) as u8, nr));
                p.extend(block);
            }
        }
    }
    p.push(ins(RET_K, 0, 0, default));
    if p.len() > 4096 {
        return Err(format!("the profile compiles to {} instructions (the kernel takes 4096)", p.len()));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the filter in the kernel's interpreter: a tiny BPF evaluator for these programs.
    fn run(p: &[SockFilter], nr: u32, args: [u64; 6]) -> u32 {
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let i = p[pc];
            pc += 1;
            match i.code {
                LD_W_ABS => {
                    a = match i.k {
                        0 => nr,
                        4 => crate::security::AUDIT_ARCH,
                        k @ 16..=63 => (args[((k - 16) / 8) as usize]) as u32,
                        _ => panic!("offset {}", i.k),
                    }
                }
                ALU_AND_K => a &= i.k,
                RET_K => return i.k,
                c @ (JEQ_K | JGT_K | JGE_K) => {
                    let t = match c {
                        JEQ_K => a == i.k,
                        JGT_K => a > i.k,
                        _ => a >= i.k,
                    };
                    pc += if t { i.jt } else { i.jf } as usize;
                }
                c => panic!("opcode {c:#x}"),
            }
        }
    }

    const ALLOW: u32 = 0x7fff_0000;
    fn eperm() -> u32 {
        0x0005_0000 | 1
    }

    #[test]
    fn allow_list_with_errno_default() {
        let p = compile(r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","write","exit_group","not_a_syscall"],"action":"SCMP_ACT_ALLOW"}]}"#, &[]).unwrap();
        let (read, write, mount) = (number("read").unwrap(), number("write").unwrap(), number("mount").unwrap());
        assert_eq!((run(&p, read, [0; 6]), run(&p, write, [0; 6])), (ALLOW, ALLOW));
        assert_eq!(run(&p, mount, [0; 6]), eperm());
    }

    #[test]
    fn deny_list_with_custom_errno_and_kill() {
        let p = compile(r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["mount"],"action":"SCMP_ACT_ERRNO","errnoRet":13},{"names":["ptrace"],"action":"SCMP_ACT_KILL_PROCESS"}]}"#, &[]).unwrap();
        assert_eq!(run(&p, number("mount").unwrap(), [0; 6]), 0x0005_0000 | 13);
        assert_eq!(run(&p, number("ptrace").unwrap(), [0; 6]), 0x8000_0000);
        assert_eq!(run(&p, number("getpid").unwrap(), [0; 6]), ALLOW);
    }

    #[test]
    fn argument_conditions_and_masks() {
        // socket(AF_NETLINK=16, ...) is refused; personality only with 0 or 8; clone without CLONE_NEWUSER (0x10000000).
        let prof = r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
            {"names":["socket"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":16,"op":"SCMP_CMP_EQ"}]},
            {"names":["personality"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":0,"op":"SCMP_CMP_NE"},{"index":0,"value":8,"op":"SCMP_CMP_NE"}]},
            {"names":["clone"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]},
            {"names":["dup2"],"action":"SCMP_ACT_ERRNO","args":[{"index":1,"value":10,"op":"SCMP_CMP_GE"}]},
            {"names":["dup3"],"action":"SCMP_ACT_ERRNO","args":[{"index":1,"value":10,"op":"SCMP_CMP_LT"}]}
        ]}"#;
        let p = compile(prof, &[]).unwrap();
        let n = |s: &str| number(s).unwrap();
        assert_eq!(run(&p, n("socket"), [16, 0, 0, 0, 0, 0]), eperm());
        assert_eq!(run(&p, n("socket"), [2, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&p, n("personality"), [0, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&p, n("personality"), [8, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&p, n("personality"), [5, 0, 0, 0, 0, 0]), eperm(), "both conditions hold (5 is neither 0 nor 8): refused");
        assert_eq!(run(&p, n("clone"), [0x1000_0011, 0, 0, 0, 0, 0]), eperm());
        assert_eq!(run(&p, n("clone"), [0x0000_0011, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&p, n("dup2"), [0, 10, 0, 0, 0, 0]), eperm());
        assert_eq!(run(&p, n("dup2"), [0, 9, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&p, n("dup3"), [0, 9, 0, 0, 0, 0]), eperm());
        assert_eq!(run(&p, n("dup3"), [0, 10, 0, 0, 0, 0]), ALLOW);
    }

    #[test]
    fn capability_and_arch_conditions() {
        let prof = r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
            {"names":["read"],"action":"SCMP_ACT_ALLOW"},
            {"names":["mount"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}},
            {"names":["chroot"],"action":"SCMP_ACT_ALLOW","excludes":{"caps":["CAP_SYS_CHROOT"]}},
            {"names":["getpid"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["s390x"]}}]}"#;
        let (without, with) = (compile(prof, &[]).unwrap(), compile(prof, &[21, 18]).unwrap());
        let n = |s: &str| number(s).unwrap();
        assert_eq!((run(&without, n("mount"), [0; 6]), run(&with, n("mount"), [0; 6])), (eperm(), ALLOW));
        assert_eq!((run(&without, n("chroot"), [0; 6]), run(&with, n("chroot"), [0; 6])), (ALLOW, eperm()));
        assert_eq!(run(&with, n("getpid"), [0; 6]), eperm(), "a rule for another architecture is dropped");
    }

    #[test]
    fn bad_profiles_are_refused() {
        assert!(compile("{", &[]).is_err());
        assert!(compile(r#"{"syscalls":[]}"#, &[]).unwrap_err().contains("defaultAction"));
        assert!(compile(r#"{"defaultAction":"SCMP_ACT_NOTIFY"}"#, &[]).unwrap_err().contains("unsupported action"));
        assert!(compile(r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["read"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":1,"op":"SCMP_CMP_XX"}]}]}"#, &[]).unwrap_err().contains("operator"));
    }
}
