//! The CronJob controller: creates Jobs on a cron schedule.
//!
//! * **Schedule.** Standard 5-field cron ([`Schedule`]): lists, ranges, steps, `*`/`?`, month and
//!   weekday names, `@hourly`/`@daily`/`@midnight`/`@weekly`/`@monthly`/`@yearly`/`@annually`.
//!   When both day-of-month and day-of-week are restricted either may match (as in Vixie cron).
//!   Times are UTC only; a `spec.timeZone` other than empty/`UTC`/`Etc/UTC` (or a `CRON_TZ=`
//!   prefix) sets status condition `UnknownTimeZone` and the CronJob is skipped; an unparsable
//!   schedule sets `InvalidSchedule`. Time comes from `Config::now`.
//! * **Scheduling.** The latest schedule time `t` in `(earliest, now]` is started, where
//!   `earliest` is `status.lastScheduleTime` (else the creation time), raised to
//!   `now - startingDeadlineSeconds` when that is set. Older missed times are dropped. The Job
//!   is `<cronjob>-<t in unix minutes>` with annotation
//!   `batch.kubernetes.io/cronjob-scheduled-timestamp`; if it exists already it is only recorded.
//!   `concurrencyPolicy`: `Allow` (default) always starts, `Forbid` skips while a Job is active,
//!   `Replace` deletes the active Jobs first. `suspend` stops new Jobs.
//! * **Status.** `active` (references to unfinished Jobs), `lastScheduleTime` and
//!   `lastSuccessfulTime` (latest `completionTime` of a Complete Job seen).
//! * **History.** Finished Jobs beyond `successfulJobsHistoryLimit` (3) and
//!   `failedJobsHistoryLimit` (1) are deleted, oldest first (their pods follow via the GC).
//!
//! The reconciler asks to run again at the next schedule time; the periodic resync covers a
//! clock that is stepped.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const SCHEDULED_ANNOTATION: &str = "batch.kubernetes.io/cronjob-scheduled-timestamp";

// ---- cron expressions ----

/// A parsed 5-field cron schedule as bit sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    minute: u64,
    hour: u32,
    dom: u32,
    month: u16,
    dow: u8,
    dom_star: bool,
    dow_star: bool,
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn parse_value(s: &str, names: &[&str], names_base: u32) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Some(n);
    }
    let lower = s.to_ascii_lowercase();
    names.iter().position(|n| *n == lower).map(|i| i as u32 + names_base)
}

/// One field into a bit set over `min..=max`; returns `(bits, starred)`.
fn parse_field(f: &str, min: u32, max: u32, names: &[&str], names_base: u32) -> Option<(u64, bool)> {
    let mut bits = 0u64;
    let mut star = false;
    for part in f.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" || range == "?" {
            star = true;
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (parse_value(a, names, names_base)?, parse_value(b, names, names_base)?)
        } else {
            let v = parse_value(range, names, names_base)?;
            (v, if part.contains('/') { max } else { v })
        };
        if lo < min || hi > max || lo > hi {
            return None;
        }
        let mut v = lo;
        while v <= hi {
            bits |= 1 << v;
            v += step;
        }
    }
    (bits != 0).then_some((bits, star))
}

impl Schedule {
    pub fn parse(spec: &str) -> core::result::Result<Schedule, String> {
        let spec = spec.trim();
        if spec.starts_with("CRON_TZ=") || spec.starts_with("TZ=") {
            return Err("time zone prefixes are not supported".to_string());
        }
        let expanded = match spec {
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@monthly" => "0 0 1 * *",
            "@weekly" => "0 0 * * 0",
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            s => s,
        };
        let f: Vec<&str> = expanded.split_whitespace().collect();
        if f.len() != 5 {
            return Err(alloc::format!("expected 5 fields, found {}", f.len()));
        }
        let bad = |what: &str| alloc::format!("invalid {what} field");
        let (minute, _) = parse_field(f[0], 0, 59, &[], 0).ok_or_else(|| bad("minute"))?;
        let (hour, _) = parse_field(f[1], 0, 23, &[], 0).ok_or_else(|| bad("hour"))?;
        let (dom, dom_star) = parse_field(f[2], 1, 31, &[], 0).ok_or_else(|| bad("day-of-month"))?;
        let (month, _) = parse_field(f[3], 1, 12, &MONTHS, 1).ok_or_else(|| bad("month"))?;
        let (mut dow, dow_star) = parse_field(f[4], 0, 7, &DAYS, 0).ok_or_else(|| bad("day-of-week"))?;
        if dow & (1 << 7) != 0 {
            dow = (dow | 1) & !(1 << 7);
        }
        Ok(Schedule { minute, hour: hour as u32, dom: dom as u32, month: month as u16, dow: dow as u8, dom_star, dow_star })
    }

    fn day_matches(&self, y: i64, m: u32, d: u32, wd: u32) -> bool {
        let _ = y;
        if self.month & (1 << m) == 0 {
            return false;
        }
        let (dm, dw) = (self.dom & (1 << d) != 0, self.dow & (1 << wd) != 0);
        if self.dom_star || self.dow_star {
            dm && dw
        } else {
            dm || dw
        }
    }

    /// The first matching minute strictly after `t` (unix seconds), within 8 years.
    pub fn next_after(&self, t: i64) -> Option<i64> {
        let start = (t.div_euclid(60) + 1) * 60;
        let first_day = start.div_euclid(86400);
        for day in first_day..first_day + 366 * 8 {
            let (y, m, d) = civil_from_days(day);
            let wd = (day + 4).rem_euclid(7) as u32; // 1970-01-01 was a Thursday
            if !self.day_matches(y, m, d, wd) {
                continue;
            }
            for h in 0..24u32 {
                if self.hour & (1 << h) == 0 {
                    continue;
                }
                for mi in 0..60u32 {
                    if self.minute & (1 << mi) == 0 {
                        continue;
                    }
                    let cand = day * 86400 + h as i64 * 3600 + mi as i64 * 60;
                    if cand >= start {
                        return Some(cand);
                    }
                }
            }
        }
        None
    }
}

/// (year, month 1-12, day 1-31) of a day count since 1970-01-01 (H. Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

// ---- controller ----

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), cronjobs(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), jobs(None), String::new(), cfg, move |_, j| {
        if let Some(r) = controller_ref(j).filter(|r| str_at(r, &["kind"]) == "CronJob") {
            q2.add(&alloc::format!("{}/{}", namespace(j), str_at(r, &["name"])));
        }
    })));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move {
                let (ns, n) = split_key(&key);
                reconcile(&c, &cfg, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&cronjobs(None), "").await {
                    for j in items(&l) {
                        q.add(&key_of(&j));
                    }
                }
            }
        },
    )
    .await
}

fn job_finished(j: &Value) -> Option<bool> {
    if has_condition(j, "Complete") {
        Some(true)
    } else if has_condition(j, "Failed") {
        Some(false)
    } else {
        None
    }
}

fn job_ref(j: &Value) -> Value {
    obj(alloc::vec![("apiVersion", Value::from("batch/v1")), ("kind", Value::from("Job")), ("name", Value::from(name(j))), ("namespace", Value::from(namespace(j))), ("uid", Value::from(uid(j)))])
}

fn new_job(cj: &Value, scheduled: i64) -> Value {
    let tpl = cj.pointer(&["spec", "jobTemplate"]).cloned().unwrap_or(Value::Null);
    let mut meta = obj(alloc::vec![("name", Value::String(alloc::format!("{}-{}", name(cj), scheduled / 60))), ("namespace", Value::from(namespace(cj)))]);
    if let Some(l) = tpl.pointer(&["metadata", "labels"]) {
        meta.set("labels", l.clone());
    }
    let mut ann = tpl.pointer(&["metadata", "annotations"]).cloned().unwrap_or(Value::Object(Vec::new()));
    ann.set(SCHEDULED_ANNOTATION, Value::String(rfc3339(scheduled)));
    meta.set("annotations", ann);
    meta.set("ownerReferences", Value::Array(alloc::vec![owner_ref(cj, "batch/v1", "CronJob")]));
    obj(alloc::vec![("apiVersion", Value::from("batch/v1")), ("kind", Value::from("Job")), ("metadata", meta), ("spec", tpl.get("spec").cloned().unwrap_or(Value::Null))])
}

fn ms_until(secs: i64) -> u64 {
    (secs.max(0) as u64) * 1000 + 50
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str, cname: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{cname}", cronjobs(Some(ns)));
    let Some(cj) = get_opt(c, &path).await? else { return Ok(None) };
    if deleting(&cj) {
        return Ok(None);
    }
    let now = (cfg.now)();
    let cuid = uid(&cj).to_string();
    let mine: Vec<Value> = items(&c.list(&jobs(Some(ns)), "").await?).into_iter().filter(|j| controlled_by(j, &cuid) && !deleting(j)).collect();

    // Active set and last successful time from the Jobs that exist.
    let mut active: Vec<Value> = Vec::new();
    let mut last_success = parse_time(str_at(&cj, &["status", "lastSuccessfulTime"]));
    for j in &mine {
        match job_finished(j) {
            None => active.push(j.clone()),
            Some(true) => {
                if let Some(t) = parse_time(str_at(j, &["status", "completionTime"])) {
                    last_success = Some(last_success.map_or(t, |l| l.max(t)));
                }
            }
            Some(false) => {}
        }
    }
    active.sort_by(|a, b| name(a).cmp(name(b)));

    // History.
    for (ok, key, def) in [(true, "successfulJobsHistoryLimit", 3), (false, "failedJobsHistoryLimit", 1)] {
        let limit = int_at(&cj, &["spec", key], def).max(0) as usize;
        let mut done: Vec<&Value> = mine.iter().filter(|j| job_finished(j) == Some(ok)).collect();
        if done.len() > limit {
            done.sort_by_key(|j| (str_at(j, &["metadata", "creationTimestamp"]).to_string(), name(j).to_string()));
            for j in done.iter().take(done.len() - limit) {
                delete_ok(c, &alloc::format!("{}/{}", jobs(Some(ns)), name(j))).await?;
            }
        }
    }

    let mut last_schedule = str_at(&cj, &["status", "lastScheduleTime"]).to_string();
    let mut problem: Option<(&'static str, String)> = None;
    let mut wait = None;
    let tz = str_at(&cj, &["spec", "timeZone"]);
    let sched = Schedule::parse(str_at(&cj, &["spec", "schedule"]));
    if !matches!(tz, "" | "UTC" | "Etc/UTC") {
        problem = Some(("UnknownTimeZone", alloc::format!("time zone \"{tz}\" is not supported, only UTC")));
    } else if let Err(e) = &sched {
        problem = Some(("InvalidSchedule", e.clone()));
    } else if let Ok(sched) = &sched {
        let suspended = cj.pointer(&["spec", "suspend"]).and_then(Value::as_bool) == Some(true);
        let mut earliest = parse_time(&last_schedule).or_else(|| parse_time(str_at(&cj, &["metadata", "creationTimestamp"]))).unwrap_or(now);
        if let Some(d) = cj.pointer(&["spec", "startingDeadlineSeconds"]).and_then(Value::as_i64) {
            earliest = earliest.max(now - d.max(0) - 1);
        }
        let mut latest = None;
        let mut next = sched.next_after(earliest);
        let mut guard = 0;
        while let Some(t) = next.filter(|t| *t <= now) {
            latest = Some(t);
            next = sched.next_after(t);
            guard += 1;
            if guard > 5_000_000 {
                break;
            }
        }
        if !suspended {
            if let Some(t) = latest {
                let policy = str_at(&cj, &["spec", "concurrencyPolicy"]);
                let jname = alloc::format!("{cname}-{}", t / 60);
                if mine.iter().any(|j| name(j) == jname) {
                    last_schedule = rfc3339(t); // already created for this time
                } else if policy == "Forbid" && !active.is_empty() {
                    // skipped; try again once the active job is gone
                } else {
                    if policy == "Replace" {
                        for j in &active {
                            delete_ok(c, &alloc::format!("{}/{}", jobs(Some(ns)), name(j))).await?;
                        }
                        active.clear();
                    }
                    match c.create(&jobs(Some(ns)), &new_job(&cj, t)).await {
                        Ok(j) => active.push(j),
                        Err(e) if e.code == 409 => {}
                        Err(e) => return Err(e),
                    }
                    last_schedule = rfc3339(t);
                }
            }
            if let Some(n) = next {
                wait = Some(ms_until(n - now));
            }
        }
    }

    let (active_refs, last_schedule2) = (Value::Array(active.iter().map(job_ref).collect()), last_schedule.clone());
    put_status(c, &path, |o| {
        let old_conds: Vec<Value> = o.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds: Vec<Value> = old_conds.iter().filter(|x| !matches!(str_at(x, &["type"]), "UnknownTimeZone" | "InvalidSchedule")).cloned().collect();
        if let Some((ty, msg)) = &problem {
            conds.push(merge_condition(&old_conds, condition(ty, true, ty, msg, now)));
        }
        let mut st = obj(alloc::vec![("active", active_refs.clone())]);
        if !last_schedule2.is_empty() {
            st.set("lastScheduleTime", Value::from(last_schedule2.as_str()));
        }
        if let Some(t) = last_success {
            st.set("lastSuccessfulTime", Value::String(rfc3339(t)));
        }
        if !conds.is_empty() {
            st.set("conditions", Value::Array(conds));
        }
        st
    })
    .await?;
    Ok(wait)
}

#[cfg(test)]
mod unit {
    use super::*;

    // 2027-01-15 08:00:00 UTC, a Friday.
    const T: i64 = 1_800_000_000;

    fn next(spec: &str, t: i64) -> Option<i64> {
        Schedule::parse(spec).unwrap().next_after(t)
    }

    #[test]
    fn next_times() {
        let cases: &[(&str, i64, i64)] = &[
            ("* * * * *", T, T + 60),
            ("* * * * *", T + 30, T + 60),
            ("*/5 * * * *", T, T + 300),
            ("30 8 * * *", T, T + 1800),
            ("0 8 * * *", T, T + 86400),
            ("@hourly", T, T + 3600),
            ("@daily", T, T + 16 * 3600),
            ("@midnight", T, T + 16 * 3600),
            ("@weekly", T, T + 86400 + 16 * 3600), // next Sunday 00:00 (Jan 17)
            ("@monthly", T, 1_801_440_000),            // 2027-02-01
            ("@yearly", T, 1_830_297_600),             // 2028-01-01
            ("@annually", T, 1_830_297_600),
            ("0 12 * * mon", T, T + 3 * 86400 + 4 * 3600), // Monday 2027-01-18 12:00
            ("0 12 * * 1-5", T, T + 4 * 3600),             // today, Friday
            ("15,45 9-10 * * *", T, T + 3600 + 900),
            ("0 0 29 feb *", T, 1_835_395_200), // 2028-02-29
            ("0 0 * * 7", T, T + 86400 + 16 * 3600), // 7 is Sunday too
            ("10-20/5 * * * *", T, T + 600),
            ("5/20 * * * *", T, T + 300),
        ];
        for (spec, from, want) in cases {
            assert_eq!(next(spec, *from), Some(*want), "{spec}: got {}", next(spec, *from).map(rfc3339).unwrap_or_default());
        }
    }

    #[test]
    fn names_and_lists() {
        assert_eq!(rfc3339(next("0 0 1 jan,jul *", T).unwrap()), "2027-07-01T00:00:00Z");
        assert_eq!(rfc3339(next("0 0 1 MAR-MAY/2 *", T).unwrap()), "2027-03-01T00:00:00Z");
        assert_eq!(rfc3339(next("30 6 * * sat,SUN", T).unwrap()), "2027-01-16T06:30:00Z");
    }

    #[test]
    fn dom_or_dow() {
        // Both restricted: the 20th OR any Monday. Friday 2027-01-15 -> Monday 18th comes first.
        assert_eq!(rfc3339(next("0 0 20 * 1", T).unwrap()), "2027-01-18T00:00:00Z");
        // Only dom restricted.
        assert_eq!(rfc3339(next("0 0 20 * *", T).unwrap()), "2027-01-20T00:00:00Z");
        // Star dom with restricted dow is AND (dom always true).
        assert_eq!(rfc3339(next("0 0 * * 1", T).unwrap()), "2027-01-18T00:00:00Z");
    }

    #[test]
    fn rejects_bad_specs() {
        for s in ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "* * * foo *", "@sometimes", "CRON_TZ=UTC * * * * *", ", * * * *"] {
            assert!(Schedule::parse(s).is_err(), "{s:?} should not parse");
        }
        for s in ["* * * * *", "0 0 1 1 *", "*/15 0-6/2 1,15 JAN-MAR mon-fri", "  0   0 * * 0 "] {
            assert!(Schedule::parse(s).is_ok(), "{s:?} should parse");
        }
    }

    #[test]
    fn civil() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(T / 86400), (2027, 1, 15));
    }
}
