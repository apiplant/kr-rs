//! Install-time node settings (`--node-label`, `--node-taint`, ADR-060): parsing, and the patch
//! that applies them to an existing Node.
//!
//! k3s semantics: they are applied when the node registers. Later starts leave the Node alone
//! unless the configured set changed (what was applied is recorded in the annotations
//! [`ANN_LABELS`] and [`ANN_TAINTS`]), so labels and taints an administrator edits with `kubectl`
//! stay as they are. When the set changed, the labels and taints kr applied earlier but no longer
//! configured are removed, and the configured ones are set.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

pub const ANN_LABELS: &str = "kr.io/node-labels";
pub const ANN_TAINTS: &str = "kr.io/node-taints";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Taint {
    pub key: String,
    pub value: String,
    pub effect: String,
}

impl Taint {
    pub fn render(&self) -> String {
        if self.value.is_empty() { alloc::format!("{}:{}", self.key, self.effect) } else { alloc::format!("{}={}:{}", self.key, self.value, self.effect) }
    }

    pub fn to_value(&self) -> Value {
        let mut o = Value::Object(Vec::new());
        o.set("key", Value::from(self.key.as_str()));
        if !self.value.is_empty() {
            o.set("value", Value::from(self.value.as_str()));
        }
        o.set("effect", Value::from(self.effect.as_str()));
        o
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.as_bytes()[0].is_ascii_alphanumeric() && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A qualified name: `name` or `prefix/name` (prefix a DNS subdomain).
fn key_ok(k: &str) -> bool {
    match k.split_once('/') {
        Some((p, n)) => !p.is_empty() && p.len() <= 253 && p.split('.').all(|l| !l.is_empty()) && name_ok(n),
        None => name_ok(k),
    }
}

fn value_ok(v: &str) -> bool {
    v.is_empty() || name_ok(v)
}

/// `key=value` or `key` (empty value).
pub fn parse_label(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').unwrap_or((s, ""));
    if !key_ok(k) {
        return Err(alloc::format!("invalid node label key in {s:?}"));
    }
    if !value_ok(v) {
        return Err(alloc::format!("invalid node label value in {s:?}"));
    }
    Ok((k.to_string(), v.to_string()))
}

/// `key=value:Effect` or `key:Effect`; Effect is NoSchedule, PreferNoSchedule or NoExecute.
pub fn parse_taint(s: &str) -> Result<Taint, String> {
    let (kv, effect) = s.rsplit_once(':').ok_or_else(|| alloc::format!("node taint {s:?} must look like key=value:Effect"))?;
    if !matches!(effect, "NoSchedule" | "PreferNoSchedule" | "NoExecute") {
        return Err(alloc::format!("node taint {s:?}: effect must be NoSchedule, PreferNoSchedule or NoExecute"));
    }
    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
    if !key_ok(k) || !value_ok(v) {
        return Err(alloc::format!("invalid node taint {s:?}"));
    }
    Ok(Taint { key: k.to_string(), value: v.to_string(), effect: effect.to_string() })
}

/// Parses a comma separated list (the `KR_NODE_LABELS` form), sorted and de-duplicated by key
/// (the last occurrence wins).
pub fn parse_labels(list: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = parse_label(item)?;
        out.retain(|(ek, _)| *ek != k);
        out.push((k, v));
    }
    out.sort();
    Ok(out)
}

pub fn parse_taints(list: &str) -> Result<Vec<Taint>, String> {
    let mut out: Vec<Taint> = Vec::new();
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let t = parse_taint(item)?;
        out.retain(|e| !(e.key == t.key && e.effect == t.effect));
        out.push(t);
    }
    out.sort();
    Ok(out)
}

pub fn labels_annotation(labels: &[(String, String)]) -> String {
    labels.iter().map(|(k, v)| if v.is_empty() { k.clone() } else { alloc::format!("{k}={v}") }).collect::<Vec<_>>().join(",")
}

pub fn taints_annotation(taints: &[Taint]) -> String {
    taints.iter().map(Taint::render).collect::<Vec<_>>().join(",")
}

fn obj(items: Vec<(&str, Value)>) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The fields of a new Node: `(labels, taints, annotations)` to merge into its metadata and spec.
pub fn for_new_node(labels: &[(String, String)], taints: &[Taint]) -> (Vec<(String, String)>, Vec<Taint>, Vec<(String, String)>) {
    let mut ann = Vec::new();
    if !labels.is_empty() {
        ann.push((ANN_LABELS.to_string(), labels_annotation(labels)));
    }
    if !taints.is_empty() {
        ann.push((ANN_TAINTS.to_string(), taints_annotation(taints)));
    }
    (labels.to_vec(), taints.to_vec(), ann)
}

/// The merge patch that brings an existing `node` in line with the configuration, or `None` when
/// the configured set is the one applied before.
pub fn reconcile(node: &Value, labels: &[(String, String)], taints: &[Taint]) -> Option<Value> {
    let ann = |k: &str| node.pointer(&["metadata", "annotations", k]).and_then(Value::as_str);
    let (want_l, want_t) = (labels_annotation(labels), taints_annotation(taints));
    let (have_l, have_t) = (ann(ANN_LABELS).unwrap_or(""), ann(ANN_TAINTS).unwrap_or(""));
    let (l_changed, t_changed) = (want_l != have_l, want_t != have_t);
    if !l_changed && !t_changed {
        return None;
    }
    let mut meta = Vec::new();
    let mut spec = Vec::new();
    let mut ann_patch = Vec::new();
    if l_changed {
        let mut lp: Vec<(String, Value)> = Vec::new();
        // Labels applied before and not configured now are removed.
        if let Ok(prev) = parse_labels(have_l) {
            for (k, _) in prev.iter().filter(|(k, _)| !labels.iter().any(|(wk, _)| wk == k)) {
                lp.push((k.clone(), Value::Null));
            }
        }
        for (k, v) in labels {
            lp.push((k.clone(), Value::from(v.as_str())));
        }
        meta.push(("labels", Value::Object(lp)));
        ann_patch.push((ANN_LABELS.to_string(), if want_l.is_empty() { Value::Null } else { Value::from(want_l) }));
    }
    if t_changed {
        let prev = parse_taints(have_t).unwrap_or_default();
        let current = node.pointer(&["spec", "taints"]).and_then(Value::as_array).unwrap_or(&[]);
        let mut out: Vec<Value> = Vec::new();
        for t in current {
            let (k, e) = (t.get("key").and_then(Value::as_str).unwrap_or(""), t.get("effect").and_then(Value::as_str).unwrap_or(""));
            let was_ours = prev.iter().any(|p| p.key == k && p.effect == e);
            let replaced = taints.iter().any(|p| p.key == k && p.effect == e);
            if !was_ours && !replaced {
                out.push(t.clone());
            }
        }
        out.extend(taints.iter().map(Taint::to_value));
        spec.push(("taints", Value::Array(out)));
        ann_patch.push((ANN_TAINTS.to_string(), if want_t.is_empty() { Value::Null } else { Value::from(want_t) }));
    }
    meta.push(("annotations", Value::Object(ann_patch)));
    let mut patch = Vec::new();
    patch.push(("metadata", obj(meta)));
    if !spec.is_empty() {
        patch.push(("spec", obj(spec)));
    }
    Some(obj(patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    #[test]
    fn labels() {
        assert_eq!(parse_label("a=b").unwrap(), ("a".into(), "b".into()));
        assert_eq!(parse_label("example.com/role=db").unwrap(), ("example.com/role".into(), "db".into()));
        assert_eq!(parse_label("flag").unwrap(), ("flag".into(), "".into()));
        assert!(parse_label("=x").is_err());
        assert!(parse_label("a=b c").is_err());
        assert!(parse_label("-a=b").is_err());
        assert_eq!(parse_labels("b=1, a=2,b=3").unwrap(), [("a".into(), "2".into()), ("b".into(), "3".into())]);
    }

    #[test]
    fn taints() {
        let t = parse_taint("dedicated=cp:NoSchedule").unwrap();
        assert_eq!((t.key.as_str(), t.value.as_str(), t.effect.as_str()), ("dedicated", "cp", "NoSchedule"));
        assert_eq!(t.render(), "dedicated=cp:NoSchedule");
        assert_eq!(parse_taint("k:NoExecute").unwrap().value, "");
        assert_eq!(parse_taint("k:NoExecute").unwrap().render(), "k:NoExecute");
        assert!(parse_taint("k=v").is_err());
        assert!(parse_taint("k=v:Nope").is_err());
        assert!(parse_taint(":NoSchedule").is_err());
        assert_eq!(parse_taints("a=1:NoSchedule,a=2:NoSchedule,b:NoExecute").unwrap().len(), 2);
    }

    fn node(s: &str) -> Value {
        json::parse_str(s).unwrap()
    }

    #[test]
    fn reconcile_applies_only_on_change() {
        let labels = parse_labels("role=db").unwrap();
        let taints = parse_taints("ded=db:NoSchedule").unwrap();
        // Fresh registration without recorded config: applied.
        let n = node(r#"{"metadata":{"name":"n"},"spec":{"taints":[{"key":"mine","effect":"NoExecute"}]}}"#);
        let p = reconcile(&n, &labels, &taints).unwrap();
        let s = json::to_string(&p);
        assert!(s.contains(r#""role":"db""#) && s.contains(r#""kr.io/node-taints":"ded=db:NoSchedule""#), "{s}");
        assert!(s.contains(r#""key":"mine""#), "foreign taints stay: {s}");
        // Same config recorded: left alone (even if an admin edited the node).
        let n = node(r#"{"metadata":{"annotations":{"kr.io/node-labels":"role=db","kr.io/node-taints":"ded=db:NoSchedule"}},"spec":{}}"#);
        assert!(reconcile(&n, &labels, &taints).is_none());
        // Changed: old applied ones are removed.
        let p = reconcile(&n, &parse_labels("zone=a").unwrap(), &[]).unwrap();
        let s = json::to_string(&p);
        assert!(s.contains(r#""role":null"#) && s.contains(r#""zone":"a""#) && s.contains(r#""kr.io/node-taints":null"#) && s.contains(r#""taints":[]"#), "{s}");
        // Nothing configured, nothing recorded: no patch.
        assert!(reconcile(&node(r#"{"metadata":{}}"#), &[], &[]).is_none());
    }
}
