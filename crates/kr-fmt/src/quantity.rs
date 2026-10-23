//! Kubernetes `resource.Quantity` and Go `time.ParseDuration` parsing.
//!
//! A [`Quantity`] is held exactly as `mantissa * 10^scale` with an `i128`
//! mantissa (binary suffixes are folded into the mantissa, so `1.5Ki` is
//! exactly 1536). Parsing fails with `OutOfRange` instead of losing precision,
//! with one deliberate exception that mirrors Kubernetes: values with more
//! than nano (10^-9) precision are rounded up (away from zero) to 1n.

use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Empty,
    /// Not a number, or a bad/unknown suffix.
    Invalid,
    /// Mantissa or exponent does not fit.
    OutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ErrorKind::Empty => "quantity: empty string",
            ErrorKind::Invalid => "quantity: invalid format",
            ErrorKind::OutOfRange => "quantity: value out of range",
        })
    }
}

fn e<T>(kind: ErrorKind) -> Result<T, Error> {
    Err(Error { kind })
}

/// Output style, chosen by the suffix used when parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `m`, `k`, `M`, ... (or no suffix)
    DecimalSI,
    /// `Ki`, `Mi`, ...
    BinarySI,
    /// `e3`, `E-2`
    DecimalExponent,
}

/// An exact Kubernetes quantity.
#[derive(Clone, Copy, Debug)]
pub struct Quantity {
    mantissa: i128,
    scale: i32,
    format: Format,
}

const MAX_EXP: i32 = 9999;

fn pow10(n: u32) -> Option<i128> {
    10i128.checked_pow(n)
}

impl Quantity {
    pub fn new(mantissa: i128, scale: i32, format: Format) -> Quantity {
        Quantity { mantissa, scale, format }.normalized()
    }
    pub fn from_i64(v: i64, format: Format) -> Quantity {
        Quantity::new(i128::from(v), 0, format)
    }
    pub fn from_milli(v: i64) -> Quantity {
        Quantity::new(i128::from(v), -3, Format::DecimalSI)
    }
    pub fn mantissa(&self) -> i128 {
        self.mantissa
    }
    pub fn scale(&self) -> i32 {
        self.scale
    }
    pub fn format(&self) -> Format {
        self.format
    }
    pub fn is_zero(&self) -> bool {
        self.mantissa == 0
    }

    /// Strip trailing zeros of the mantissa into the scale.
    fn normalized(mut self) -> Quantity {
        if self.mantissa == 0 {
            self.scale = 0;
            return self;
        }
        while self.mantissa % 10 == 0 {
            self.mantissa /= 10;
            self.scale += 1;
        }
        self
    }

    pub fn parse(s: &str) -> Result<Quantity, Error> {
        let b = s.as_bytes();
        if b.is_empty() {
            return e(ErrorKind::Empty);
        }
        let mut i = 0;
        let neg = match b[0] {
            b'-' => {
                i = 1;
                true
            }
            b'+' => {
                i = 1;
                false
            }
            _ => false,
        };
        let int_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let int_digits = &b[int_start..i];
        let mut frac_digits: &[u8] = &[];
        if i < b.len() && b[i] == b'.' {
            i += 1;
            let fs = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            frac_digits = &b[fs..i];
        }
        if int_digits.is_empty() && frac_digits.is_empty() {
            return e(ErrorKind::Invalid);
        }
        // Trailing zeros of the fraction carry no information.
        let mut fl = frac_digits.len();
        while fl > 0 && frac_digits[fl - 1] == b'0' {
            fl -= 1;
        }
        let frac_digits = &frac_digits[..fl];
        let mut m: i128 = 0;
        for &d in int_digits.iter().chain(frac_digits) {
            m = match m.checked_mul(10).and_then(|x| x.checked_add(i128::from(d - b'0'))) {
                Some(x) => x,
                None => return e(ErrorKind::OutOfRange),
            };
        }
        let mut scale = -(frac_digits.len() as i32);
        let suffix = &s[i..];
        let format;
        let mut exp10 = 0i32;
        let mut shift2 = 0u32;
        match suffix {
            "" => format = Format::DecimalSI,
            "n" => (format, exp10) = (Format::DecimalSI, -9),
            "u" => (format, exp10) = (Format::DecimalSI, -6),
            "m" => (format, exp10) = (Format::DecimalSI, -3),
            "k" => (format, exp10) = (Format::DecimalSI, 3),
            "M" => (format, exp10) = (Format::DecimalSI, 6),
            "G" => (format, exp10) = (Format::DecimalSI, 9),
            "T" => (format, exp10) = (Format::DecimalSI, 12),
            "P" => (format, exp10) = (Format::DecimalSI, 15),
            "E" => (format, exp10) = (Format::DecimalSI, 18),
            "Ki" => (format, shift2) = (Format::BinarySI, 10),
            "Mi" => (format, shift2) = (Format::BinarySI, 20),
            "Gi" => (format, shift2) = (Format::BinarySI, 30),
            "Ti" => (format, shift2) = (Format::BinarySI, 40),
            "Pi" => (format, shift2) = (Format::BinarySI, 50),
            "Ei" => (format, shift2) = (Format::BinarySI, 60),
            _ => {
                let sb = suffix.as_bytes();
                if sb[0] != b'e' && sb[0] != b'E' {
                    return e(ErrorKind::Invalid);
                }
                let mut j = 1;
                let eneg = match sb.get(1) {
                    Some(b'-') => {
                        j = 2;
                        true
                    }
                    Some(b'+') => {
                        j = 2;
                        false
                    }
                    _ => false,
                };
                if j >= sb.len() {
                    return e(ErrorKind::Invalid);
                }
                let mut x = 0i32;
                for &d in &sb[j..] {
                    if !d.is_ascii_digit() {
                        return e(ErrorKind::Invalid);
                    }
                    x = x * 10 + i32::from(d - b'0');
                    if x > MAX_EXP {
                        return e(ErrorKind::OutOfRange);
                    }
                }
                format = Format::DecimalExponent;
                exp10 = if eneg { -x } else { x };
            }
        }
        if shift2 > 0 {
            m = match m.checked_mul(1i128 << shift2) {
                Some(x) => x,
                None => return e(ErrorKind::OutOfRange),
            };
        }
        scale += exp10;
        if neg {
            m = -m;
        }
        let mut q = Quantity { mantissa: m, scale, format }.normalized();
        // Kubernetes does not keep sub-nano precision: round away from zero.
        if q.scale < -9 {
            let drop = (-9 - q.scale) as u32;
            q.mantissa = match pow10(drop) {
                Some(p) => {
                    let (d, r) = (q.mantissa / p, q.mantissa % p);
                    if r != 0 { d + q.mantissa.signum() } else { d }
                }
                None => q.mantissa.signum(),
            };
            q.scale = -9;
            q = q.normalized();
        }
        if q.scale > MAX_EXP {
            return e(ErrorKind::OutOfRange);
        }
        Ok(q)
    }

    /// The value in units of `10^scale`, rounded away from zero. `None` on overflow.
    pub fn scaled_value(&self, scale: i32) -> Option<i128> {
        let diff = i64::from(self.scale) - i64::from(scale);
        if self.mantissa == 0 {
            return Some(0);
        }
        if diff >= 0 {
            let p = pow10(u32::try_from(diff).ok()?)?;
            self.mantissa.checked_mul(p)
        } else {
            let d = u32::try_from(-diff).ok()?;
            match pow10(d) {
                Some(p) => {
                    let (q, r) = (self.mantissa / p, self.mantissa % p);
                    Some(if r != 0 { q + self.mantissa.signum() } else { q })
                }
                None => Some(self.mantissa.signum()),
            }
        }
    }
    /// Whole units, rounded away from zero.
    pub fn value(&self) -> Option<i128> {
        self.scaled_value(0)
    }
    /// Milli-units, rounded away from zero.
    pub fn milli_value(&self) -> Option<i128> {
        self.scaled_value(-3)
    }

    /// Exact integer value, if it is one.
    fn exact_int(&self) -> Option<i128> {
        if self.scale >= 0 {
            self.value()
        } else {
            let p = pow10(u32::try_from(-self.scale).ok()?)?;
            if self.mantissa % p == 0 { Some(self.mantissa / p) } else { None }
        }
    }

    /// Canonical string, following the Kubernetes rules: decimal forms use the
    /// largest exponent that is a multiple of three, binary forms use the
    /// largest power of 1024 that divides evenly, small or fractional binary
    /// values fall back to decimal.
    pub fn to_canonical_string(&self) -> String {
        use alloc::format;
        if self.mantissa == 0 {
            return String::from("0");
        }
        let sign = if self.mantissa < 0 { "-" } else { "" };
        let mut format = self.format;
        if format == Format::BinarySI {
            match self.exact_int() {
                Some(mut v) if v.unsigned_abs() >= 1024 => {
                    let mut n = 0;
                    while n < 6 && v % 1024 == 0 {
                        v /= 1024;
                        n += 1;
                    }
                    let suf = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"][n];
                    return format!("{}{}", v, suf);
                }
                // |v| < 1024 or not an integer: show as decimal, losing nothing.
                _ => format = Format::DecimalSI,
            }
        }
        // Decimal: mantissa without trailing zeros, exponent a multiple of 3.
        let mut m = self.mantissa.unsigned_abs();
        let mut exp = i64::from(self.scale);
        while m.is_multiple_of(10) {
            m /= 10;
            exp += 1;
        }
        let r = exp.rem_euclid(3);
        if r != 0 {
            let p = if r == 1 { 10 } else { 100 };
            if let Some(x) = m.checked_mul(p) {
                m = x;
                exp -= r;
            }
        }
        let suffix: String = if format == Format::DecimalSI {
            match exp {
                -9 => "n".into(),
                -6 => "u".into(),
                -3 => "m".into(),
                0 => "".into(),
                3 => "k".into(),
                6 => "M".into(),
                9 => "G".into(),
                12 => "T".into(),
                15 => "P".into(),
                18 => "E".into(),
                _ => format!("e{}", exp),
            }
        } else if exp == 0 {
            "".into()
        } else {
            format!("e{}", exp)
        };
        format!("{}{}{}", sign, m, suffix)
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl FromStr for Quantity {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Quantity::parse(s)
    }
}

impl PartialEq for Quantity {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for Quantity {}
impl PartialOrd for Quantity {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Quantity {
    /// Exact numeric comparison (format is ignored).
    fn cmp(&self, o: &Self) -> Ordering {
        let (a, b) = (self.normalized(), o.normalized());
        let (sa, sb) = (a.mantissa.signum(), b.mantissa.signum());
        if sa != sb {
            return sa.cmp(&sb);
        }
        if sa == 0 {
            return Ordering::Equal;
        }
        // Same nonzero sign: compare magnitudes, then flip for negatives.
        let mag = |x: &Quantity, y: &Quantity| -> Ordering {
            let (xm, ym) = (x.mantissa.unsigned_abs(), y.mantissa.unsigned_abs());
            let diff = i64::from(x.scale) - i64::from(y.scale);
            if diff >= 0 {
                // scale x up to y's scale
                match u32::try_from(diff).ok().and_then(|d| 10u128.checked_pow(d)).and_then(|p| xm.checked_mul(p)) {
                    Some(xs) => xs.cmp(&ym),
                    None => Ordering::Greater,
                }
            } else {
                match u32::try_from(-diff).ok().and_then(|d| 10u128.checked_pow(d)).and_then(|p| ym.checked_mul(p)) {
                    Some(ys) => xm.cmp(&ys),
                    None => Ordering::Less,
                }
            }
        };
        let o = mag(&a, &b);
        if sa < 0 { o.reverse() } else { o }
    }
}

// ---------------------------------------------------------------- durations

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurationError {
    Empty,
    /// Missing number, missing unit or stray characters.
    Invalid,
    UnknownUnit,
    /// Exceeds the int64 nanosecond range.
    OutOfRange,
}

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DurationError::Empty => "duration: empty string",
            DurationError::Invalid => "duration: invalid format",
            DurationError::UnknownUnit => "duration: unknown unit",
            DurationError::OutOfRange => "duration: out of range",
        })
    }
}

/// Parse a Go-style duration (`1h30m`, `1.5s`, `-250ms`, `0`) into nanoseconds.
/// Units: `ns us µs μs ms s m h`.
pub fn parse_duration(s: &str) -> Result<i64, DurationError> {
    let orig = s;
    if orig.is_empty() {
        return Err(DurationError::Empty);
    }
    let mut rest = s;
    let mut neg = false;
    if let Some(r) = rest.strip_prefix('-') {
        neg = true;
        rest = r;
    } else if let Some(r) = rest.strip_prefix('+') {
        rest = r;
    }
    if rest == "0" {
        return Ok(0);
    }
    if rest.is_empty() {
        return Err(DurationError::Invalid);
    }
    let limit: u128 = if neg { 1u128 << 63 } else { (1u128 << 63) - 1 };
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let b = rest.as_bytes();
        let mut i = 0;
        let mut int: u128 = 0;
        let mut pre = false;
        while i < b.len() && b[i].is_ascii_digit() {
            int = int * 10 + u128::from(b[i] - b'0');
            if int > u128::from(u64::MAX) {
                return Err(DurationError::OutOfRange);
            }
            pre = true;
            i += 1;
        }
        let mut frac: u128 = 0;
        let mut fscale: u128 = 1;
        let mut post = false;
        if i < b.len() && b[i] == b'.' {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                // Go stops accumulating on overflow and ignores further digits.
                if frac < 1u128 << 62 {
                    frac = frac * 10 + u128::from(b[i] - b'0');
                    fscale *= 10;
                }
                post = true;
                i += 1;
            }
        }
        if !pre && !post {
            return Err(DurationError::Invalid);
        }
        let ustart = i;
        while i < b.len() && b[i] != b'.' && !b[i].is_ascii_digit() {
            i += 1;
        }
        if ustart == i {
            return Err(DurationError::Invalid);
        }
        let unit: u128 = match &rest[ustart..i] {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3600 * 1_000_000_000,
            _ => return Err(DurationError::UnknownUnit),
        };
        let v = int * unit + frac * unit / fscale;
        total += v;
        if total > limit {
            return Err(DurationError::OutOfRange);
        }
        rest = &rest[i..];
    }
    Ok(if neg { (total as i128).wrapping_neg() as i64 } else { total as i64 })
}

/// Format nanoseconds like Go's `Duration.String()` (`1h30m0s`, `1.5s`, `100ms`).
pub fn format_duration(ns: i64) -> String {
    use alloc::format;
    if ns == 0 {
        return String::from("0s");
    }
    let neg = ns < 0;
    let u = ns.unsigned_abs();
    let sign = if neg { "-" } else { "" };
    // value / 10^prec with trailing-zero-trimmed fraction
    fn frac(v: u64, prec: u32) -> (String, u64) {
        let p = 10u64.pow(prec);
        let (whole, f) = (v / p, v % p);
        if f == 0 {
            return (String::new(), whole);
        }
        let mut s = format!("{:0width$}", f, width = prec as usize);
        while s.ends_with('0') {
            s.pop();
        }
        (format!(".{}", s), whole)
    }
    if u < 1_000_000_000 {
        let (prec, unit) = if u < 1_000 {
            (0, "ns")
        } else if u < 1_000_000 {
            (3, "\u{b5}s")
        } else {
            (6, "ms")
        };
        let (f, w) = frac(u, prec);
        return format!("{}{}{}{}", sign, w, f, unit);
    }
    let (f, secs) = frac(u, 9);
    let mut out = format!("{}s", format_args!("{}{}", secs % 60, f));
    let mins = secs / 60;
    if mins > 0 {
        out = format!("{}m{}", mins % 60, out);
        let hours = mins / 60;
        if hours > 0 {
            out = format!("{}h{}", hours, out);
        }
    }
    format!("{}{}", sign, out)
}
