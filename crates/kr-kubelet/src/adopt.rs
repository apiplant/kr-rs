//! Pods that outlive the kubelet. Sandboxes and containers do not die with this process (root
//! mode); the pod directory keeps a small record of their pids so that, after a restart, the
//! kubelet takes them over instead of killing and recreating them.
//!
//! Format of `<pod dir>/.adopt` (one record per line, `\n` separated). Compatibility rule for
//! upgrades: a newer kubelet may append fields to a record and add record kinds, never change or
//! remove the existing ones; readers ignore trailing fields and unknown lines.
//! ```text
//! v1
//! sb <pid> <start-ticks> <hostnetwork 0|1> <pod ipv4 | -> <userns 0|1> [<pod ipv6 as 32 hex digits | ->]
//! c <name> <pid> <start-ticks> <container id> <seq> <started-at> <shim pid> <io fd | -1> <tty 0|1>
//! ```
//! `start-ticks` (field 22 of `/proc/<pid>/stat`) tells the process from a recycled pid.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const FILE: &str = ".adopt";

#[derive(Debug, PartialEq)]
pub struct Sb {
    pub pid: i32,
    pub start: u64,
    pub host_net: bool,
    pub ip: Option<[u8; 4]>,
    pub userns: bool,
    /// The pod's IPv6 address, kept for pods whose network comes from a CNI plugin (the kubelet
    /// cannot derive it from its own pod network then). Absent in records of older kubelets.
    pub ip6: Option<[u8; 16]>,
}

#[derive(Debug, PartialEq)]
pub struct Ctr {
    pub name: String,
    pub pid: i32,
    pub start: u64,
    pub cid: String,
    pub seq: u32,
    pub started_at: i64,
    /// The shim that is the container's parent, and the descriptor in it that holds the stdin
    /// socket / pty master (`-1` when the container has none).
    pub shim: i32,
    pub io_fd: i32,
    pub tty: bool,
}

pub fn encode(sb: &Sb, ctrs: &[Ctr]) -> String {
    let ip = sb.ip.map_or("-".to_string(), |i| alloc::format!("{}.{}.{}.{}", i[0], i[1], i[2], i[3]));
    let ip6 = sb.ip6.map_or("-".to_string(), |a| a.iter().map(|b| alloc::format!("{b:02x}")).collect::<String>());
    let mut out = alloc::format!("v1\nsb {} {} {} {ip} {} {ip6}\n", sb.pid, sb.start, sb.host_net as u8, sb.userns as u8);
    for c in ctrs {
        out.push_str(&alloc::format!("c {} {} {} {} {} {} {} {} {}\n", c.name, c.pid, c.start, c.cid, c.seq, c.started_at, c.shim, c.io_fd, c.tty as u8));
    }
    out
}

fn ipv4(s: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut it = s.split('.');
    for b in o.iter_mut() {
        *b = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(o)
}

fn ipv6_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut o = [0u8; 16];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(o)
}

pub fn decode(text: &str) -> Option<(Sb, Vec<Ctr>)> {
    let mut sb = None;
    let mut ctrs = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f.as_slice() {
            ["sb", pid, start, hn, ip, un, ..] => {
                let ip6 = f.get(6).and_then(|a| ipv6_hex(a));
                sb = Some(Sb { pid: pid.parse().ok()?, start: start.parse().ok()?, host_net: *hn == "1", ip: if *ip == "-" { None } else { Some(ipv4(ip)?) }, userns: *un == "1", ip6 });
            }
            ["sb", pid, start, hn, ip, ..] => {
                sb = Some(Sb { pid: pid.parse().ok()?, start: start.parse().ok()?, host_net: *hn == "1", ip: if *ip == "-" { None } else { Some(ipv4(ip)?) }, userns: true, ip6: None });
            }
            ["c", name, pid, start, cid, seq, started, shim, io_fd, tty, ..] => {
                ctrs.push(Ctr { name: name.to_string(), pid: pid.parse().ok()?, start: start.parse().ok()?, cid: cid.to_string(), seq: seq.parse().ok()?, started_at: started.parse().ok()?, shim: shim.parse().ok()?, io_fd: io_fd.parse().ok()?, tty: *tty == "1" });
            }
            _ => {}
        }
    }
    Some((sb?, ctrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let sb = Sb { pid: 42, start: 9000, host_net: false, ip: Some([10, 88, 0, 7]), userns: true, ip6: Some([0xfd, 0, 0, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]) };
        let cs = alloc::vec![Ctr { name: "app".into(), pid: 43, start: 9001, cid: "u-app-2".into(), seq: 2, started_at: 1_800_000_000, shim: 40, io_fd: 7, tty: true }];
        let (sb2, cs2) = decode(&encode(&sb, &cs)).unwrap();
        assert_eq!(sb2, sb);
        assert_eq!(cs2, cs);
        let hn = Sb { pid: 1, start: 2, host_net: true, ip: None, userns: false, ip6: None };
        // CNI pods: no kr lease, address and IPv6 come from the plugin.
        let cni = Sb { pid: 3, start: 4, host_net: false, ip: Some([10, 244, 141, 59]), userns: false, ip6: None };
        assert_eq!(decode(&encode(&cni, &[])).unwrap().0, cni);
        // A record written before the ip6 field existed.
        assert_eq!(decode("v1\nsb 5 6 0 10.88.0.9 1\n").unwrap().0.ip6, None);
        assert_eq!(decode(&encode(&hn, &[])).unwrap().0, hn);
        assert!(decode("garbage\n").is_none());
        // A newer kubelet's record: extra trailing fields, an unknown record kind and a newer version.
        let newer = "v2\nsb 42 9000 0 10.88.0.7 future-field\nx something new\nc app 43 9001 u-app-2 2 1800000000 40 7 1 more fields\n";
        let (sb3, cs3) = decode(newer).unwrap();
        assert_eq!((sb3.pid, cs3.len(), cs3[0].io_fd), (42, 1, 7));
    }
}
