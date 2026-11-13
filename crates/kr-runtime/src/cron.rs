//! Cron schedules for scheduled snapshots.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// A five-field cron expression (`minute hour day-of-month month day-of-week`, UTC) with `*`,
/// numbers, ranges `a-b`, lists `a,b`, steps `*/n` and `a-b/n`, month and weekday names, and the
/// macros `@hourly`, `@daily`, `@weekly`, `@monthly`, `@yearly`. As in cron, when both
/// day-of-month and day-of-week are restricted a day matching either runs.
#[derive(Clone, Debug, PartialEq)]
pub struct Cron {
    min: u64,
    hour: u64,
    dom: u64,
    mon: u64,
    dow: u64,
    dom_star: bool,
    dow_star: bool,
}

impl Cron {
    pub fn parse(s: &str) -> Result<Cron, String> {
        let s = match s.trim() {
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@monthly" => "0 0 1 * *",
            "@weekly" => "0 0 * * 0",
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            t => t,
        };
        let f: Vec<&str> = s.split_whitespace().collect();
        if f.len() != 5 {
            return Err(format!("{s:?}: want 5 fields (minute hour day-of-month month day-of-week)"));
        }
        const MON: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
        const DOW: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
        let mut dow = field(f[4], 0, 7, &DOW, 0)?;
        if dow & (1 << 7) != 0 {
            dow |= 1; // 7 is Sunday too
        }
        Ok(Cron { min: field(f[0], 0, 59, &[], 0)?, hour: field(f[1], 0, 23, &[], 0)?, dom: field(f[2], 1, 31, &[], 0)?, mon: field(f[3], 1, 12, &MON, 1)?, dow, dom_star: f[2].starts_with('*'), dow_star: f[4].starts_with('*') })
    }

    /// The first matching minute strictly after `now` (Unix seconds), within about five years.
    pub fn next_after(&self, now: i64) -> Option<i64> {
        let mut t = (now.div_euclid(60) + 1) * 60;
        let end = t + 5 * 366 * 86400;
        while t < end {
            let (y, mo, d) = civil(t.div_euclid(86400));
            let wd = (t.div_euclid(86400) + 4).rem_euclid(7) as u32; // 1970-01-01 was a Thursday
            let day_ok = match (self.dom_star, self.dow_star) {
                (false, false) => bit(self.dom, d) || bit(self.dow, wd),
                _ => bit(self.dom, d) && bit(self.dow, wd),
            };
            if !bit(self.mon, mo) || !day_ok {
                t = (t.div_euclid(86400) + 1) * 86400; // next day
                let _ = y;
                continue;
            }
            let h = (t.rem_euclid(86400) / 3600) as u32;
            if !bit(self.hour, h) {
                t = (t.div_euclid(3600) + 1) * 3600;
                continue;
            }
            let m = (t.rem_euclid(3600) / 60) as u32;
            if bit(self.min, m) {
                return Some(t);
            }
            t += 60;
        }
        None
    }
}

fn bit(set: u64, v: u32) -> bool {
    set & (1u64 << v) != 0
}

/// One cron field as a bit set. `names[i]` stands for `i + name_base`.
fn field(s: &str, lo: u32, hi: u32, names: &[&str], name_base: u32) -> Result<u64, String> {
    let num = |t: &str| -> Result<u32, String> {
        let l = t.to_ascii_lowercase();
        if let Some(i) = names.iter().position(|n| *n == l) {
            return Ok(i as u32 + name_base);
        }
        t.parse::<u32>().ok().filter(|v| (lo..=hi).contains(v)).ok_or_else(|| format!("{t:?} is not in {lo}-{hi}"))
    };
    let mut set = 0u64;
    for part in s.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, st)) => (r, st.parse::<u32>().ok().filter(|v| *v > 0).ok_or_else(|| format!("bad step in {part:?}"))?),
            None => (part, 1),
        };
        let (a, b) = if range == "*" {
            (lo, hi)
        } else if let Some((a, b)) = range.split_once('-') {
            (num(a)?, num(b)?)
        } else {
            let v = num(range)?;
            (v, if part.contains('/') { hi } else { v })
        };
        if a > b {
            return Err(format!("{part:?}: range goes backwards"));
        }
        let mut v = a;
        while v <= b {
            set |= 1u64 << v;
            v += step;
        }
    }
    Ok(set)
}

/// Days since 1970-01-01 -> (year, month 1-12, day 1-31) (proleptic Gregorian).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod cron_tests {
    use super::*;

    const T0: i64 = 1_767_225_600; // 2026-01-01 00:00:00 UTC, a Thursday

    #[test]
    fn next_times() {
        let c = Cron::parse("0 */12 * * *").unwrap();
        assert_eq!(c.next_after(T0), Some(T0 + 12 * 3600));
        assert_eq!(c.next_after(T0 - 1), Some(T0));
        let c = Cron::parse("30 2 * * mon").unwrap(); // next Monday is Jan 5
        assert_eq!(c.next_after(T0), Some(T0 + 4 * 86400 + 2 * 3600 + 1800));
        let c = Cron::parse("0 0 29 feb *").unwrap(); // 2028 is the next leap year
        assert_eq!(civil(c.next_after(T0).unwrap() / 86400), (2028, 2, 29));
        let c = Cron::parse("@daily").unwrap();
        assert_eq!(c.next_after(T0 + 5), Some(T0 + 86400));
        // dom and dow both restricted: either matches (Jan 1 is the 1st; Jan 3 is a Saturday)
        let c = Cron::parse("0 0 1 * 6").unwrap();
        assert_eq!(c.next_after(T0), Some(T0 + 2 * 86400));
        let c = Cron::parse("0 0 * * 7").unwrap(); // 7 = Sunday, Jan 4
        assert_eq!(c.next_after(T0), Some(T0 + 3 * 86400));
        assert_eq!(Cron::parse("0 0 31 2 *").unwrap().next_after(T0), None);
    }

    #[test]
    fn rejects_bad_expressions() {
        for bad in ["", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "5-1 * * * *", "*/0 * * * *", "x * * * *"] {
            assert!(Cron::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(T0 / 86400), (2026, 1, 1));
    }
}
