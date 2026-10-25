//! ValidatingAdmissionPolicy and MutatingAdmissionPolicy (admissionregistration.k8s.io/v1):
//! CEL admission evaluated in the API server, run by [`crate::webhook`]'s admission pass
//! (mutating policies before mutating webhooks, validating policies before validating webhooks,
//! as upstream orders the plugins).
//!
//! A policy applies through each binding that names it. Both narrow the requests they match
//! (`matchConstraints`, then the binding's `matchResources`); `matchConditions` filter further.
//! Variables: `object`, `oldObject`, `request`, `params`, `namespaceObject`, `variables`
//! (evaluated in order; one that fails is absent). `authorizer` is not supported (expressions
//! using it fail to compile, so `failurePolicy` applies).
//!
//! Not done: audit annotations (kr has no audit log), `reinvocationPolicy: IfNeeded` (mutating
//! policies run once), apply configurations merge like a strategic merge patch rather than
//! structured-merge-diff, and type checking covers operator overloads only.

use crate::api::{ApiServer, Route};
use crate::cel::Program;
use crate::object::{obj, ApiError};
use crate::resources::Resource;
use crate::webhook::{label_selector, rule_matches};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use kr_fmt::json::{self, Value};

/// A policy with the bindings that name it.
pub struct Bound {
    pub policy: Value,
    pub bindings: Vec<Value>,
}

fn name(v: &Value) -> &str {
    v.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("")
}

fn s<'a>(v: &'a Value, p: &[&str]) -> &'a str {
    v.pointer(p).and_then(Value::as_str).unwrap_or("")
}

/// Pairs policies with their bindings, both in name order.
pub fn bind(mut policies: Vec<Value>, mut bindings: Vec<Value>) -> Vec<Bound> {
    policies.sort_by(|a, b| name(a).cmp(name(b)));
    bindings.sort_by(|a, b| name(a).cmp(name(b)));
    policies
        .into_iter()
        .map(|p| {
            let n = name(&p).to_string();
            let bindings = bindings.iter().filter(|b| s(b, &["spec", "policyName"]) == n).cloned().collect();
            Bound { policy: p, bindings }
        })
        .filter(|b| !b.bindings.is_empty())
        .collect()
}

/// The request being admitted.
pub struct Req<'a> {
    pub rt: &'a Route,
    pub op: &'a str,
    pub request: Value,
    pub ns: Option<&'a Value>,
    pub warns: &'a RefCell<Vec<String>>,
}

fn rules(mr: &Value, key: &str) -> Vec<Value> {
    mr.get(key).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default()
}

fn named_rule_matches(rule: &Value, r: &Req, exact: bool, obj_name: &str) -> bool {
    let names: Vec<&str> = rule.get("resourceNames").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    rule_matches(rule, r.rt, r.op, exact) && (names.is_empty() || names.contains(&obj_name))
}

/// Whether `mr` (MatchResources) selects the request. An absent `mr` (a binding without
/// `matchResources`) or one without resourceRules (only allowed on bindings) selects all.
fn selects(mr: Option<&Value>, r: &Req, cur: &Value, old: &Value) -> bool {
    let Some(mr) = mr else { return true };
    let exact = s(mr, &["matchPolicy"]) == "Exact";
    let obj_name = s(&r.request, &["name"]);
    let incl = rules(mr, "resourceRules");
    if !incl.is_empty() && !incl.iter().any(|x| named_rule_matches(x, r, exact, obj_name)) {
        return false;
    }
    if rules(mr, "excludeResourceRules").iter().any(|x| named_rule_matches(x, r, exact, obj_name)) {
        return false;
    }
    let Some(ns_sel) = label_selector(mr.get("namespaceSelector")) else { return false };
    if !ns_sel.is_empty() {
        let target = if r.rt.res.plural == "namespaces" { Some(if cur.is_null() { old } else { cur }) } else if r.rt.res.namespaced { r.ns } else { None };
        if target.is_some_and(|t| !ns_sel.matches(t)) {
            return false;
        }
    }
    let Some(obj_sel) = label_selector(mr.get("objectSelector")) else { return false };
    obj_sel.is_empty() || (!cur.is_null() && obj_sel.matches(cur)) || (!old.is_null() && obj_sel.matches(old))
}

/// Whether any binding of `b` could apply to requests on `rt` (resource rules only), so the
/// admission pass is skipped cheaply for everything else.
pub fn may_apply(b: &[Bound], rt: &Route, op: &str) -> bool {
    b.iter().any(|b| {
        let mc = b.policy.pointer(&["spec", "matchConstraints"]);
        let exact = mc.map(|m| s(m, &["matchPolicy"]) == "Exact").unwrap_or(false);
        mc.is_some_and(|m| rules(m, "resourceRules").iter().any(|x| rule_matches(x, rt, op, exact)))
    })
}

const VARS: [&str; 6] = ["object", "oldObject", "request", "params", "namespaceObject", "variables"];

/// The objects each binding evaluates against: one per parameter (`Null` without `paramKind`).
/// `Err` is a misconfiguration (failurePolicy applies); an empty list with `Ok` means a
/// `parameterNotFoundAction: Allow` binding without parameters (skipped).
fn params(api: &ApiServer, policy: &Value, binding: &Value, r: &Req) -> Result<Vec<Value>, String> {
    let Some(pk) = policy.pointer(&["spec", "paramKind"]) else { return Ok(alloc::vec![Value::Null]) };
    let (av, kind) = (s(pk, &["apiVersion"]), s(pk, &["kind"]));
    let (g, v) = av.rsplit_once('/').unwrap_or(("", av));
    let all = api.all_resources();
    let res: &Resource = all.iter().copied().find(|x| x.group == g && x.version == v && x.kind == kind).ok_or_else(|| format!("failed to find resource referenced by paramKind: '{av}, Kind={kind}'"))?;
    let pr = binding.pointer(&["spec", "paramRef"]).ok_or("paramRef is required when paramKind is set")?;
    let ns = if res.namespaced {
        let n = s(pr, &["namespace"]);
        let n = if n.is_empty() { s(&r.request, &["namespace"]) } else { n };
        if n.is_empty() {
            return Err("cannot use a namespaced paramKind for a cluster-scoped request without paramRef.namespace".into());
        }
        Some(n.to_string())
    } else {
        None
    };
    let found: Vec<Value> = match pr.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
        Some(n) => api.list_values(res, ns.as_deref()).into_iter().filter(|o| name(o) == n).collect(),
        None => {
            let sel = label_selector(pr.get("selector")).ok_or("invalid paramRef.selector")?;
            api.list_values(res, ns.as_deref()).into_iter().filter(|o| sel.matches(o)).collect()
        }
    };
    if found.is_empty() && s(pr, &["parameterNotFoundAction"]) != "Allow" {
        return Err("no params found for policy binding with `Deny` parameterNotFoundAction".into());
    }
    Ok(found)
}

/// One evaluation environment: the fixed variables plus `variables` built in order.
struct Env {
    fixed: [(String, Value); 5],
    variables: Value,
}

impl Env {
    fn new(policy: &Value, r: &Req, cur: &Value, old: &Value, param: &Value) -> Env {
        let mut e = Env {
            fixed: [
                ("object".into(), cur.clone()),
                ("oldObject".into(), old.clone()),
                ("request".into(), r.request.clone()),
                ("params".into(), param.clone()),
                ("namespaceObject".into(), r.ns.cloned().unwrap_or(Value::Null)),
            ],
            variables: obj(Vec::new()),
        };
        for var in policy.pointer(&["spec", "variables"]).and_then(Value::as_array).unwrap_or(&[]) {
            let n = s(var, &["name"]);
            if let Ok(v) = Program::compile(s(var, &["expression"]), &VARS).and_then(|p| e.eval(&p)) {
                e.variables.set(n, v);
            }
        }
        e
    }

    fn eval(&self, p: &Program) -> Result<Value, String> {
        let mut vars: Vec<(&str, &Value)> = self.fixed.iter().map(|(k, v)| (k.as_str(), v)).collect();
        vars.push(("variables", &self.variables));
        p.eval(&vars)
    }

    fn eval_str(&self, expr: &str) -> Result<Value, String> {
        self.eval(&Program::compile(expr, &VARS)?)
    }

    fn eval_bool(&self, expr: &str) -> Result<bool, String> {
        match self.eval_str(expr)? {
            Value::Bool(b) => Ok(b),
            _ => Err("expression must evaluate to a bool".into()),
        }
    }
}

/// `matchConditions`: all true to apply. `Err`: an evaluation error (failurePolicy applies).
fn conditions(policy: &Value, env: &Env) -> Result<bool, String> {
    for c in policy.pointer(&["spec", "matchConditions"]).and_then(Value::as_array).unwrap_or(&[]) {
        if !env.eval_bool(s(c, &["expression"])).map_err(|e| format!("matchCondition '{}': {e}", s(c, &["name"])))? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ignore(policy: &Value) -> bool {
    s(policy, &["spec", "failurePolicy"]) == "Ignore"
}

fn status_code(reason: &str) -> (u16, &'static str) {
    match reason {
        "Unauthorized" => (401, "Unauthorized"),
        "Forbidden" => (403, "Forbidden"),
        "RequestEntityTooLarge" => (413, "RequestEntityTooLarge"),
        _ => (422, "Invalid"),
    }
}

/// Runs the validating policies. `Err`: denied.
pub fn validate(api: &ApiServer, bound: &[Bound], r: &Req, cur: &Value, old: &Value) -> Result<(), ApiError> {
    for b in bound {
        let p = &b.policy;
        let pname = name(p);
        if !selects(p.pointer(&["spec", "matchConstraints"]), r, cur, old) {
            continue;
        }
        for bd in &b.bindings {
            if !selects(bd.pointer(&["spec", "matchResources"]), r, cur, old) {
                continue;
            }
            let bname = name(bd);
            let actions: Vec<&str> = bd.pointer(&["spec", "validationActions"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let prefix = format!("ValidatingAdmissionPolicy '{pname}' with binding '{bname}' denied request");
            let report = |msg: String, code: (u16, &'static str)| -> Result<(), ApiError> {
                if actions.contains(&"Warn") {
                    r.warns.borrow_mut().push(format!("Validation failed for ValidatingAdmissionPolicy '{pname}' with binding '{bname}': {msg}"));
                }
                if actions.contains(&"Deny") {
                    return Err(ApiError::new(code.0, code.1, format!("{prefix}: {msg}")));
                }
                Ok(())
            };
            let ps = match params(api, p, bd, r) {
                Ok(ps) => ps,
                Err(e) if ignore(p) => {
                    let _ = e;
                    continue;
                }
                Err(e) => {
                    report(e, (403, "Forbidden"))?;
                    continue;
                }
            };
            for param in &ps {
                let env = Env::new(p, r, cur, old, param);
                match conditions(p, &env) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) if ignore(p) => continue,
                    Err(e) => {
                        report(e, (403, "Forbidden"))?;
                        continue;
                    }
                }
                for v in p.pointer(&["spec", "validations"]).and_then(Value::as_array).unwrap_or(&[]) {
                    let ex = s(v, &["expression"]);
                    let code = status_code(s(v, &["reason"]));
                    match env.eval_bool(ex) {
                        Ok(true) => {}
                        Ok(false) => {
                            let msg = v
                                .get("messageExpression")
                                .and_then(Value::as_str)
                                .and_then(|m| env.eval_str(m).ok())
                                .and_then(|m| m.as_str().map(|x| x.trim().to_string()))
                                .filter(|m| !m.is_empty() && !m.contains('\n'))
                                .or_else(|| v.get("message").and_then(Value::as_str).filter(|m| !m.is_empty()).map(String::from))
                                .unwrap_or_else(|| format!("failed expression: {ex}"));
                            report(msg, code)?;
                        }
                        Err(_) if ignore(p) => {}
                        Err(e) => report(format!("expression '{ex}' resulted in error: {e}"), code)?,
                    }
                }
            }
        }
    }
    Ok(())
}

/// Runs the mutating policies over `cur`. `Err`: a failed mutation under `failurePolicy: Fail`.
pub fn mutate(api: &ApiServer, bound: &[Bound], r: &Req, cur: &mut Value, old: &Value) -> Result<(), ApiError> {
    for b in bound {
        let p = &b.policy;
        let pname = name(p);
        for bd in &b.bindings {
            if !selects(p.pointer(&["spec", "matchConstraints"]), r, cur, old) || !selects(bd.pointer(&["spec", "matchResources"]), r, cur, old) {
                continue;
            }
            let fail = |e: String| ApiError::new(403, "Forbidden", format!("policy '{pname}' with binding '{}' denied request: {e}", name(bd)));
            let ps = match params(api, p, bd, r) {
                Ok(ps) => ps,
                Err(_) if ignore(p) => continue,
                Err(e) => return Err(fail(e)),
            };
            for param in &ps {
                let env = Env::new(p, r, cur, old, param);
                match conditions(p, &env) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) if ignore(p) => continue,
                    Err(e) => return Err(fail(e)),
                }
                for m in p.pointer(&["spec", "mutations"]).and_then(Value::as_array).unwrap_or(&[]) {
                    // Later mutations see the earlier ones.
                    let env = Env::new(p, r, cur, old, param);
                    match apply_mutation(m, &env, cur) {
                        Ok(()) => {}
                        Err(_) if ignore(p) => {}
                        Err(e) => return Err(fail(e)),
                    }
                }
            }
        }
    }
    Ok(())
}

fn apply_mutation(m: &Value, env: &Env, cur: &mut Value) -> Result<(), String> {
    match s(m, &["patchType"]) {
        "ApplyConfiguration" => {
            let v = env.eval_str(s(m, &["applyConfiguration", "expression"]))?;
            if !matches!(v, Value::Object(_)) {
                return Err("applyConfiguration must evaluate to an Object".into());
            }
            let mut n = cur.clone();
            crate::patch::strategic_merge(&mut n, &v).map_err(|e| e.0)?;
            *cur = n;
            Ok(())
        }
        "JSONPatch" => {
            let v = env.eval_str(s(m, &["jsonPatch", "expression"]))?;
            if !matches!(v, Value::Array(_)) {
                return Err("jsonPatch must evaluate to a list of JSONPatch".into());
            }
            let mut n = cur.clone();
            crate::patch::json_patch(&mut n, &v).map_err(|e| e.0)?;
            *cur = n;
            Ok(())
        }
        t => Err(format!("unsupported patchType {t:?}")),
    }
}

// ---- type checking (status.typeChecking) ----

/// CEL type of `path` in an OpenAPI v3 schema (custom resources).
fn schema_type(mut sch: &Value, path: &[&str]) -> Option<&'static str> {
    for (i, k) in path.iter().enumerate() {
        if sch.get("x-kubernetes-preserve-unknown-fields").and_then(Value::as_bool) == Some(true) && sch.pointer(&["properties", k]).is_none() {
            return None;
        }
        sch = sch.pointer(&["properties", k])?;
        if i + 1 == path.len() {
            if sch.get("x-kubernetes-int-or-string").and_then(Value::as_bool) == Some(true) {
                return None;
            }
            return match s(sch, &["type"]) {
                "integer" => Some("int"),
                "number" => Some("double"),
                "string" => Some(if sch.get("format").and_then(Value::as_str).is_some_and(|f| matches!(f, "date-time" | "date" | "duration" | "byte")) { return None } else { "string" }),
                "boolean" => Some("bool"),
                "array" => Some("list"),
                "object" if sch.get("properties").is_none() => Some("map"),
                _ => None,
            };
        }
    }
    None
}

/// The kinds the policy's resource rules name (exact groups, versions and resources only;
/// wildcards are not expanded, as type checking them would be meaningless).
fn rule_kinds(api: &ApiServer, policy: &Value) -> Vec<&'static Resource> {
    let all = api.all_resources();
    let mut out: Vec<&'static Resource> = Vec::new();
    let mc = policy.pointer(&["spec", "matchConstraints"]);
    for rule in mc.map(|m| rules(m, "resourceRules")).unwrap_or_default() {
        let l = |k: &str| rule.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect::<Vec<_>>()).unwrap_or_default();
        let (gs, vs, rs) = (l("apiGroups"), l("apiVersions"), l("resources"));
        if gs.iter().chain(&vs).chain(&rs).any(|x| x.contains('*')) {
            continue;
        }
        for r in &all {
            if gs.iter().any(|g| g == r.group) && vs.iter().any(|v| v == r.version) && rs.iter().any(|x| x == r.plural) && !out.iter().any(|o| core::ptr::eq(*o, *r)) {
                out.push(r);
            }
        }
    }
    out
}

/// `status` for a ValidatingAdmissionPolicy: observedGeneration and type-checking warnings
/// (`spec.validations[i].expression` / `.messageExpression`), per matched kind.
pub fn type_check_status(api: &ApiServer, policy: &Value) -> Value {
    let kinds = rule_kinds(api, policy);
    let vars = policy.pointer(&["spec", "variables"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    let mut warnings: Vec<Value> = Vec::new();
    let mut add = |field: String, expr: &str, per_kind: &dyn Fn(&Program, &Resource) -> Vec<String>| {
        let Ok(p) = Program::compile(expr, &VARS) else { return };
        let mut msgs = Vec::new();
        for r in &kinds {
            for w in per_kind(&p, r) {
                msgs.push(format!("{}, Kind={}: ERROR: <input>: {w}\n | {expr}", r.group_version(), r.kind));
            }
        }
        if !msgs.is_empty() {
            warnings.push(obj(alloc::vec![("fieldRef", Value::String(field)), ("warning", Value::String(msgs.join("\n")))]));
        }
    };
    let check = |p: &Program, r: &Resource| -> Vec<String> {
        let schema = if crate::resources::RESOURCES.iter().any(|x| core::ptr::eq(x, r)) { None } else { api.custom_schema(r.group, r.version, r.kind) };
        let field = |path: &[&str]| -> Option<&'static str> {
            match &schema {
                Some(sc) => schema_type(sc, path),
                None => crate::fieldval::cel_type(&r.group_version(), r.kind, path),
            }
        };
        // Variable types, in order (each may use the earlier ones).
        let mut vtypes: Vec<(String, &'static str)> = Vec::new();
        for v in &vars {
            let t = Program::compile(s(v, &["expression"]), &VARS).map(|vp| {
                vp.static_type(&|root: &str, path: &[&str]| match root {
                    "object" | "oldObject" => field(path),
                    "variables" if path.len() == 1 => vtypes.iter().find(|(n, _)| n == path[0]).map(|(_, t)| *t),
                    _ => None,
                })
            });
            vtypes.push((s(v, &["name"]).to_string(), t.unwrap_or("dyn")).clone());
        }
        let vt = vtypes;
        p.type_warnings(&|root: &str, path: &[&str]| match root {
            "object" | "oldObject" => field(path),
            "variables" if path.len() == 1 => vt.iter().find(|(n, _)| n == path[0]).map(|(_, t)| *t).filter(|t| *t != "dyn"),
            _ => None,
        })
    };
    for (i, v) in policy.pointer(&["spec", "validations"]).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        add(format!("spec.validations[{i}].expression"), s(v, &["expression"]), &check);
        if let Some(m) = v.get("messageExpression").and_then(Value::as_str) {
            add(format!("spec.validations[{i}].messageExpression"), m, &check);
        }
    }
    let generation = policy.pointer(&["metadata", "generation"]).cloned().unwrap_or(Value::Number(json::Number::from_i64(1)));
    obj(alloc::vec![("observedGeneration", generation), ("typeChecking", obj(alloc::vec![("expressionWarnings", Value::Array(warnings))]))])
}
