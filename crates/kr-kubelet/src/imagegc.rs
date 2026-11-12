//! Image garbage collection (#130), as upstream's kubelet does it: when the filesystem holding
//! the image store is fuller than `KR_IMAGE_GC_HIGH` percent (default 85), remove images that no
//! pod on this node names, least recently used first, until usage is at or below
//! `KR_IMAGE_GC_LOW` (default 80). Images younger than `KR_IMAGE_GC_MIN_AGE` seconds (default
//! 120) are never removed. `KR_IMAGE_GC_HIGH=100` turns it off.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_runtime::store::ImageId;

pub struct Thresholds {
    pub high: u64,
    pub low: u64,
    pub min_age: i64,
}

impl Thresholds {
    pub fn from_env() -> Thresholds {
        let n = |k: &str, d: u64| kr_runtime::store::env_var(k).and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(d);
        let high = n("KR_IMAGE_GC_HIGH", 85).min(100);
        Thresholds { high, low: n("KR_IMAGE_GC_LOW", 80).min(high), min_age: n("KR_IMAGE_GC_MIN_AGE", 120) as i64 }
    }
}

/// `df`-style usage percent from `statfs` values (block size, blocks, free, available, ...).
pub fn usage_percent(st: &[u64; 6]) -> u64 {
    let used = st[1].saturating_sub(st[2]);
    let denom = used + st[3];
    if denom == 0 { 0 } else { (used * 100).div_ceil(denom) }
}

/// Images that may be removed, least recently used first.
pub fn candidates(images: &[(ImageId, i64)], in_use: &BTreeSet<String>, now: i64, min_age: i64) -> Vec<ImageId> {
    let mut v: Vec<&(ImageId, i64)> = images.iter().filter(|(id, used)| !in_use.contains(&id.0) && now - used >= min_age).collect();
    v.sort_by_key(|(_, used)| *used);
    v.into_iter().map(|(id, _)| id.clone()).collect()
}

/// Image references named by a pod: containers of every kind and image volumes.
pub fn pod_images(pod: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for k in ["initContainers", "containers", "ephemeralContainers"] {
        for c in pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]) {
            if let Some(i) = c.get("image").and_then(Value::as_str) {
                out.push(String::from(i));
            }
        }
    }
    for v in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
        if let Some(i) = v.pointer(&["image", "reference"]).and_then(Value::as_str) {
            out.push(String::from(i));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_matches_df() {
        assert_eq!(usage_percent(&[4096, 1000, 100, 100, 0, 0]), 90); // 900 used of 900+100
        assert_eq!(usage_percent(&[4096, 0, 0, 0, 0, 0]), 0);
    }

    #[test]
    fn oldest_unused_first_and_young_or_used_ones_stay() {
        let id = |s: &str| ImageId(s.into());
        let images = [(id("a"), 100), (id("b"), 50), (id("c"), 990), (id("d"), 10)];
        let used: BTreeSet<String> = ["d".into()].into();
        let got: Vec<String> = candidates(&images, &used, 1000, 120).into_iter().map(|i| i.0).collect();
        assert_eq!(got, ["b", "a"], "d is in use, c is younger than the minimum age");
    }

    #[test]
    fn pod_images_cover_all_container_kinds_and_image_volumes() {
        let p = kr_fmt::json::parse_str(r#"{"spec":{"initContainers":[{"image":"i"}],"containers":[{"image":"c"}],"ephemeralContainers":[{"image":"e"}],"volumes":[{"image":{"reference":"v"}},{"emptyDir":{}}]}}"#).unwrap();
        assert_eq!(pod_images(&p), ["i", "c", "e", "v"]);
    }
}
