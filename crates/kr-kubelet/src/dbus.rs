//! A minimal D-Bus client for the system bus (graceful node shutdown, #363): SASL EXTERNAL
//! authentication with unix fd passing, method calls with string/bool/int arguments, replies
//! carrying a unix fd (`Inhibit`) or a variant (`Properties.Get`), and signals. Little-endian
//! messages only (what sd-bus and dbus-daemon send on x86_64 and arm64).

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_rt::exec::Async;
use kr_sys::{Errno, Fd};

pub const SYSTEM_BUS: &[u8] = b"/run/dbus/system_bus_socket";

pub const METHOD_CALL: u8 = 1;
pub const METHOD_RETURN: u8 = 2;
pub const ERROR: u8 = 3;
pub const SIGNAL: u8 = 4;

/// Body encoder (and the header's). Offsets are relative to the start of the buffer, which is
/// 8-aligned in the message for both the header and the body.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    fn align(&mut self, n: usize) {
        while self.0.len() % n != 0 {
            self.0.push(0);
        }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.u32(v as u32)
    }
    #[cfg(test)]
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u32(v as u32)
    }
    /// `s` or `o`.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
    /// `g`.
    pub fn sig(&mut self, s: &str) -> &mut Self {
        self.0.push(s.len() as u8);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
}

/// Body decoder.
pub struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> R<'a> {
        R { b, pos: 0 }
    }
    fn align(&mut self, n: usize) {
        self.pos = self.pos.div_ceil(n) * n;
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.align(4);
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.align(8);
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn bool(&mut self) -> Option<bool> {
        self.u32().map(|v| v != 0)
    }
    pub fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        let s = String::from_utf8(self.take(n)?.to_vec()).ok()?;
        self.take(1)?;
        Some(s)
    }
    pub fn sig(&mut self) -> Option<String> {
        let n = self.u8()? as usize;
        let s = String::from_utf8(self.take(n)?.to_vec()).ok()?;
        self.take(1)?;
        Some(s)
    }
    /// A variant holding an unsigned integer (`t`, `u`, `y`) or a boolean.
    pub fn variant_u64(&mut self) -> Option<u64> {
        match self.sig()?.as_str() {
            "t" | "x" => self.u64(),
            "u" | "i" => self.u32().map(u64::from),
            "b" => self.bool().map(u64::from),
            "y" => self.u8().map(u64::from),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Message {
    pub ty: u8,
    pub serial: u32,
    pub reply_serial: Option<u32>,
    pub path: String,
    pub interface: String,
    pub member: String,
    pub error_name: String,
    pub destination: String,
    pub sender: String,
    pub signature: String,
    pub unix_fds: u32,
    pub body: Vec<u8>,
}

/// Encodes a message (header fields in the order path, interface, member, error name, reply
/// serial, destination, sender, signature, unix fds; the ones that are empty are left out).
pub fn encode(m: &Message) -> Vec<u8> {
    let mut w = W::default();
    w.u8(b'l').u8(m.ty).u8(0).u8(1).u32(m.body.len() as u32).u32(m.serial);
    let len_at = w.0.len();
    w.u32(0);
    let start = w.0.len();
    let field = |w: &mut W, code: u8, sig: &str| {
        w.align(8);
        w.u8(code).sig(sig);
    };
    for (code, sig, v) in [(1, "o", &m.path), (2, "s", &m.interface), (3, "s", &m.member), (4, "s", &m.error_name)] {
        if !v.is_empty() {
            field(&mut w, code, sig);
            w.str(v);
        }
    }
    if let Some(r) = m.reply_serial {
        field(&mut w, 5, "u");
        w.u32(r);
    }
    for (code, v) in [(6, &m.destination), (7, &m.sender)] {
        if !v.is_empty() {
            field(&mut w, code, "s");
            w.str(v);
        }
    }
    if !m.signature.is_empty() {
        field(&mut w, 8, "g");
        w.sig(&m.signature);
    }
    if m.unix_fds > 0 {
        field(&mut w, 9, "u");
        w.u32(m.unix_fds);
    }
    let len = (w.0.len() - start) as u32;
    w.0[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    w.align(8);
    w.0.extend_from_slice(&m.body);
    w.0
}

/// The length of the message at the start of `b`, once its fixed header is there.
pub fn message_len(b: &[u8]) -> Option<usize> {
    let mut r = R::new(b.get(..16)?);
    r.take(4)?;
    let body = r.u32()? as usize;
    r.u32()?;
    let fields = r.u32()? as usize;
    Some((16 + fields).div_ceil(8) * 8 + body)
}

/// Decodes one complete message (`b` holds exactly it). Err for a malformed or big-endian one.
pub fn decode(b: &[u8]) -> Result<Message, ()> {
    if b.len() < 16 || b[0] != b'l' || b[3] != 1 {
        return Err(());
    }
    let total = message_len(b).ok_or(())?;
    if b.len() != total {
        return Err(());
    }
    let mut r = R::new(b);
    r.take(1).ok_or(())?;
    let mut m = Message { ty: r.u8().ok_or(())?, ..Default::default() };
    r.u8().ok_or(())?;
    r.u8().ok_or(())?;
    let body_len = r.u32().ok_or(())? as usize;
    m.serial = r.u32().ok_or(())?;
    let fields_end = 16 + r.u32().ok_or(())? as usize;
    while r.pos < fields_end {
        r.align(8);
        if r.pos >= fields_end {
            break;
        }
        let code = r.u8().ok_or(())?;
        let sig = r.sig().ok_or(())?;
        match (code, sig.as_str()) {
            (1, "o") => m.path = r.str().ok_or(())?,
            (2, "s") => m.interface = r.str().ok_or(())?,
            (3, "s") => m.member = r.str().ok_or(())?,
            (4, "s") => m.error_name = r.str().ok_or(())?,
            (5, "u") => m.reply_serial = Some(r.u32().ok_or(())?),
            (6, "s") => m.destination = r.str().ok_or(())?,
            (7, "s") => m.sender = r.str().ok_or(())?,
            (8, "g") => m.signature = r.sig().ok_or(())?,
            (9, "u") => m.unix_fds = r.u32().ok_or(())?,
            (_, "s" | "o") => drop(r.str().ok_or(())?),
            (_, "g") => drop(r.sig().ok_or(())?),
            (_, "u") => drop(r.u32().ok_or(())?),
            _ => return Err(()),
        }
    }
    let body_at = fields_end.div_ceil(8) * 8;
    m.body = b.get(body_at..body_at + body_len).ok_or(())?.to_vec();
    Ok(m)
}

/// The SASL EXTERNAL line for `uid` (the bus checks it against the socket's credentials).
pub fn auth_external(uid: u32) -> Vec<u8> {
    let mut v = b"\0AUTH EXTERNAL ".to_vec();
    for d in uid.to_string().bytes() {
        v.extend_from_slice(alloc::format!("{d:02x}").as_bytes());
    }
    v.extend_from_slice(b"\r\n");
    v
}

/// A connection to the bus.
pub struct Bus {
    io: Async<Fd>,
    rx: Vec<u8>,
    fds: VecDeque<Fd>,
    serial: u32,
    signals: VecDeque<Message>,
}

impl Bus {
    /// Connects to the system bus, authenticates and says Hello.
    pub async fn system() -> Result<Bus, String> {
        let fd = kr_sys::ns::unix_connect(SYSTEM_BUS).map_err(|e| alloc::format!("cannot connect to the system bus (errno {})", e.0))?;
        kr_sys::ns::set_nonblocking(fd.raw()).map_err(|e| alloc::format!("errno {}", e.0))?;
        let io = Async::new(fd).map_err(|e| alloc::format!("errno {}", e.0))?;
        let mut bus = Bus { io, rx: Vec::new(), fds: VecDeque::new(), serial: 0, signals: VecDeque::new() };
        bus.send_raw(&auth_external(kr_sys::ns::getuid())).await?;
        let ok = bus.line().await?;
        if !ok.starts_with("OK ") {
            return Err(alloc::format!("system bus refused authentication: {ok}"));
        }
        bus.send_raw(b"NEGOTIATE_UNIX_FD\r\n").await?;
        let fds = bus.line().await?;
        if fds != "AGREE_UNIX_FD" {
            return Err(alloc::format!("system bus does not pass file descriptors: {fds}"));
        }
        bus.send_raw(b"BEGIN\r\n").await?;
        bus.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", Vec::new()).await?;
        Ok(bus)
    }

    async fn send_raw(&self, b: &[u8]) -> Result<(), String> {
        self.io.write_all(b).await.map_err(|e| alloc::format!("system bus write failed (errno {})", e.0))
    }

    async fn read_more(&mut self) -> Result<(), String> {
        let mut buf = [0u8; 4096];
        loop {
            match kr_sys::ns::recv_fd(self.io.get_ref().raw(), &mut buf) {
                Ok((0, _)) => return Err("the system bus closed the connection".into()),
                Ok((n, fd)) => {
                    self.rx.extend_from_slice(&buf[..n]);
                    self.fds.extend(fd);
                    return Ok(());
                }
                Err(Errno(kr_sys::EAGAIN)) => self.io.wait_readable().await,
                Err(Errno(4)) => {}
                Err(e) => return Err(alloc::format!("system bus read failed (errno {})", e.0)),
            }
        }
    }

    async fn line(&mut self) -> Result<String, String> {
        loop {
            if let Some(i) = self.rx.windows(2).position(|w| w == b"\r\n") {
                let l: Vec<u8> = self.rx.drain(..i + 2).take(i).collect();
                return Ok(String::from_utf8_lossy(&l).into_owned());
            }
            if self.rx.len() > 4096 {
                return Err("system bus sent an overlong line".into());
            }
            self.read_more().await?;
        }
    }

    /// The next message, with the descriptor it carries.
    async fn next(&mut self) -> Result<(Message, Option<Fd>), String> {
        loop {
            if let Some(n) = message_len(&self.rx) {
                if n > 1 << 24 {
                    return Err("system bus message too large".into());
                }
                if self.rx.len() >= n {
                    let raw: Vec<u8> = self.rx.drain(..n).collect();
                    let m = decode(&raw).map_err(|_| String::from("malformed message from the system bus"))?;
                    let fd = if m.unix_fds > 0 { self.fds.pop_front() } else { None };
                    return Ok((m, fd));
                }
            }
            self.read_more().await?;
        }
    }

    /// Calls a method and waits for its reply (signals that arrive meanwhile are kept).
    pub async fn call(&mut self, dest: &str, path: &str, iface: &str, member: &str, sig: &str, body: Vec<u8>) -> Result<(Message, Option<Fd>), String> {
        self.serial += 1;
        let m = Message { ty: METHOD_CALL, serial: self.serial, path: path.into(), interface: iface.into(), member: member.into(), destination: dest.into(), signature: sig.into(), body, ..Default::default() };
        self.send_raw(&encode(&m)).await?;
        loop {
            let (r, fd) = self.next().await?;
            match r.ty {
                SIGNAL => self.signals.push_back(r),
                METHOD_RETURN if r.reply_serial == Some(m.serial) => return Ok((r, fd)),
                ERROR if r.reply_serial == Some(m.serial) => {
                    let why = if r.signature.starts_with('s') { R::new(&r.body).str().unwrap_or_default() } else { String::new() };
                    return Err(alloc::format!("{member}: {} {why}", r.error_name));
                }
                _ => {}
            }
        }
    }

    pub async fn next_signal(&mut self) -> Result<Message, String> {
        loop {
            if let Some(s) = self.signals.pop_front() {
                return Ok(s);
            }
            let (m, _) = self.next().await?;
            if m.ty == SIGNAL {
                return Ok(m);
            }
        }
    }
}

// ------------------------------------------------------------------ logind

pub const LOGIND: &str = "org.freedesktop.login1";
pub const LOGIND_PATH: &str = "/org/freedesktop/login1";
pub const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";

/// Body of `Inhibit("shutdown", who, why, "delay")`.
pub fn inhibit_body(who: &str, why: &str) -> Vec<u8> {
    let mut w = W::default();
    w.str("shutdown").str(who).str(why).str("delay");
    w.0
}

/// Takes a delay inhibitor lock for shutdown; the lock is held while the descriptor is open.
pub async fn inhibit(bus: &mut Bus, who: &str, why: &str) -> Result<Fd, String> {
    let (_, fd) = bus.call(LOGIND, LOGIND_PATH, LOGIND_MANAGER, "Inhibit", "ssss", inhibit_body(who, why)).await?;
    fd.ok_or_else(|| String::from("Inhibit returned no file descriptor"))
}

/// logind's `InhibitDelayMaxUSec`, in seconds.
pub async fn inhibit_delay_max(bus: &mut Bus) -> Result<u64, String> {
    let mut w = W::default();
    w.str(LOGIND_MANAGER).str("InhibitDelayMaxUSec");
    let (r, _) = bus.call(LOGIND, LOGIND_PATH, "org.freedesktop.DBus.Properties", "Get", "ss", w.0).await?;
    R::new(&r.body).variant_u64().map(|us| us / 1_000_000).ok_or_else(|| String::from("InhibitDelayMaxUSec is not an integer"))
}

/// Subscribes to logind's `PrepareForShutdown`.
pub async fn watch_shutdown(bus: &mut Bus) -> Result<(), String> {
    let mut w = W::default();
    w.str("type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForShutdown'");
    bus.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch", "s", w.0).await.map(|_| ())
}

/// `PrepareForShutdown(active)` if `m` is that signal.
pub fn prepare_for_shutdown(m: &Message) -> Option<bool> {
    (m.ty == SIGNAL && m.interface == LOGIND_MANAGER && m.member == "PrepareForShutdown" && m.signature == "b").then(|| R::new(&m.body).bool()).flatten()
}

/// Makes logind re-read its configuration (upstream: SIGHUP through systemd's KillUnit).
pub async fn reload_logind(bus: &mut Bus) -> Result<(), String> {
    let mut w = W::default();
    w.str("systemd-logind.service").str("all").i32(1);
    bus.call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "KillUnit", "ssi", w.0).await.map(|_| ())
}

/// The logind drop-in upstream writes to raise `InhibitDelayMaxSec`.
pub const LOGIND_DROPIN: &str = "/etc/systemd/logind.conf.d/99-kubelet.conf";

pub fn logind_dropin(secs: u64) -> String {
    alloc::format!("# Kubelet logind override\n[Login]\nInhibitDelayMaxSec={secs}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_matches_the_reference_encoding() {
        let m = Message { ty: METHOD_CALL, serial: 1, path: "/org/freedesktop/DBus".into(), interface: "org.freedesktop.DBus".into(), member: "Hello".into(), destination: "org.freedesktop.DBus".into(), ..Default::default() };
        let want: &[u8] = b"l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00m\x00\x00\x00\x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00\x06\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00";
        let got = encode(&m);
        assert_eq!(got, want);
        assert_eq!(message_len(&got), Some(got.len()));
        assert_eq!(decode(&got).unwrap(), m);
    }

    #[test]
    fn inhibit_call_and_fd_reply() {
        let body = inhibit_body("kubelet", "Kubelet needs time to handle node shutdown");
        let call = Message { ty: METHOD_CALL, serial: 2, path: LOGIND_PATH.into(), interface: LOGIND_MANAGER.into(), member: "Inhibit".into(), destination: LOGIND.into(), signature: "ssss".into(), body: body.clone(), ..Default::default() };
        let enc = encode(&call);
        let back = decode(&enc).unwrap();
        assert_eq!(back, call);
        let mut r = R::new(&back.body);
        assert_eq!([r.str(), r.str(), r.str(), r.str()].map(Option::unwrap), ["shutdown", "kubelet", "Kubelet needs time to handle node shutdown", "delay"]);
        // The reply: `h` (index 0) plus one passed descriptor.
        let mut w = W::default();
        w.u32(0);
        let reply = Message { ty: METHOD_RETURN, serial: 9, reply_serial: Some(2), sender: ":1.5".into(), signature: "h".into(), unix_fds: 1, body: w.0, ..Default::default() };
        let mut enc = encode(&reply);
        let d = decode(&enc).unwrap();
        assert_eq!((d.reply_serial, d.unix_fds, d.signature.as_str(), d.sender.as_str()), (Some(2), 1, "h", ":1.5"));
        // Truncated or big-endian input is an error, not a panic.
        enc.pop();
        assert!(decode(&enc).is_err());
        let mut be = encode(&call);
        be[0] = b'B';
        assert!(decode(&be).is_err());
        assert!(decode(b"l\x01").is_err());
    }

    #[test]
    fn signal_and_variant_bodies() {
        let mut w = W::default();
        w.bool(true);
        let sig = Message { ty: SIGNAL, serial: 7, path: LOGIND_PATH.into(), interface: LOGIND_MANAGER.into(), member: "PrepareForShutdown".into(), signature: "b".into(), body: w.0, ..Default::default() };
        let d = decode(&encode(&sig)).unwrap();
        assert_eq!(prepare_for_shutdown(&d), Some(true));
        let other = Message { member: "PrepareForSleep".into(), ..d.clone() };
        assert_eq!(prepare_for_shutdown(&other), None);
        // Properties.Get reply: variant `t` (aligned to 8 after the signature).
        let mut w = W::default();
        w.sig("t");
        w.align(8);
        w.0.extend_from_slice(&(5_000_000u64).to_le_bytes());
        assert_eq!(R::new(&w.0).variant_u64(), Some(5_000_000));
        assert_eq!(auth_external(1000), b"\0AUTH EXTERNAL 31303030\r\n");
        assert_eq!(auth_external(0), b"\0AUTH EXTERNAL 30\r\n");
        assert!(logind_dropin(30).contains("InhibitDelayMaxSec=30"));
    }
}
