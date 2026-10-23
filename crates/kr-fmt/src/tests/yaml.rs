use crate::json::{self, Value};
use crate::yaml::*;
use alloc::string::String;
use alloc::vec::Vec;

fn y(s: &str) -> String {
    match parse(s) {
        Ok(v) => json::to_string(&v),
        Err(e) => panic!("should parse {:?}: {}", s, e),
    }
}

fn fail(s: &str) -> Error {
    match parse_all(s) {
        Ok(v) => panic!("should reject {:?}, got {:?}", s, v),
        Err(e) => e,
    }
}

const DEPLOYMENT: &str = "\
# A realistic Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx   # trailing comment
  namespace: \"default\"
  labels:
    app: nginx
    tier: 'frontend'
  annotations:
    description: |
      Line one
        indented
      Line three

    kubectl.kubernetes.io/note: >-
      folded text
      continues here
spec:
  replicas: 3
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: nginx
  strategy:
    rollingUpdate: {maxSurge: 25%, maxUnavailable: \"25%\"}
    type: RollingUpdate
  template:
    metadata:
      labels: {app: nginx, version: \"1.0\"}
    spec:
      terminationGracePeriodSeconds: 30
      containers:
      - name: nginx
        image: nginx:1.25.3
        imagePullPolicy: IfNotPresent
        args: [\"--port\", \"80\", '--verbose', -v]
        ports:
        - containerPort: 80
          protocol: TCP
        env:
          - name: MODE
            value: yes
          - name: ENABLED
            value: \"true\"
          - name: EMPTY
            value:
          - name: PI
            value: 3.14
        resources:
          limits:
            cpu: 500m
            memory: 128Mi
          requests: {cpu: 250m, memory: 64Mi}
        command:
          - /bin/sh
          - -c
          - |
            echo hello
            exec nginx -g 'daemon off;'
        livenessProbe:
          httpGet:
            path: /healthz
            port: 80
          initialDelaySeconds: 5
      - name: sidecar
        image: busybox
        command: [\"sleep\", \"3600\"]
      volumes: []
      nodeSelector: {}
";

#[test]
#[allow(clippy::approx_constant)] // 3.14 is a YAML scalar under test, not PI
fn deployment_manifest() {
    let v = parse(DEPLOYMENT).unwrap();
    assert_eq!(v.get("apiVersion").and_then(Value::as_str), Some("apps/v1"));
    assert_eq!(v.get("kind").and_then(Value::as_str), Some("Deployment"));
    let md = v.get("metadata").unwrap();
    assert_eq!(md.get("name").and_then(Value::as_str), Some("nginx"));
    assert_eq!(md.get("namespace").and_then(Value::as_str), Some("default"));
    assert_eq!(md.get("labels").unwrap().get("tier").and_then(Value::as_str), Some("frontend"));
    let ann = md.get("annotations").unwrap();
    assert_eq!(ann.get("description").and_then(Value::as_str), Some("Line one\n  indented\nLine three\n"));
    assert_eq!(
        ann.get("kubectl.kubernetes.io/note").and_then(Value::as_str),
        Some("folded text continues here")
    );
    let spec = v.get("spec").unwrap();
    assert_eq!(spec.get("replicas").and_then(Value::as_i64), Some(3));
    assert_eq!(spec.get("selector").unwrap().get("matchLabels").unwrap().get("app").and_then(Value::as_str), Some("nginx"));
    let ru = spec.get("strategy").unwrap().get("rollingUpdate").unwrap();
    assert_eq!(ru.get("maxSurge").and_then(Value::as_str), Some("25%"));
    assert_eq!(ru.get("maxUnavailable").and_then(Value::as_str), Some("25%"));
    let pod = spec.get("template").unwrap().get("spec").unwrap();
    assert_eq!(pod.get("terminationGracePeriodSeconds").and_then(Value::as_u64), Some(30));
    let labels = spec.get("template").unwrap().get("metadata").unwrap().get("labels").unwrap();
    assert_eq!(labels.get("version").and_then(Value::as_str), Some("1.0"));
    let cs = pod.get("containers").unwrap().as_array().unwrap();
    assert_eq!(cs.len(), 2);
    let c = &cs[0];
    assert_eq!(c.get("image").and_then(Value::as_str), Some("nginx:1.25.3"));
    let args: Vec<&str> = c.get("args").unwrap().as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
    assert_eq!(args, ["--port", "80", "--verbose", "-v"]);
    let port = &c.get("ports").unwrap().as_array().unwrap()[0];
    assert_eq!(port.get("containerPort").and_then(Value::as_i64), Some(80));
    assert_eq!(port.get("protocol").and_then(Value::as_str), Some("TCP"));
    let env = c.get("env").unwrap().as_array().unwrap();
    assert_eq!(env.len(), 4);
    assert_eq!(env[0].get("value").and_then(Value::as_str), Some("yes")); // YAML 1.2: not a bool
    assert_eq!(env[1].get("value").and_then(Value::as_str), Some("true"));
    assert!(env[2].get("value").unwrap().is_null());
    assert_eq!(env[3].get("value").and_then(Value::as_f64), Some(3.14));
    let res = c.get("resources").unwrap();
    assert_eq!(res.get("limits").unwrap().get("cpu").and_then(Value::as_str), Some("500m"));
    assert_eq!(res.get("limits").unwrap().get("memory").and_then(Value::as_str), Some("128Mi"));
    assert_eq!(res.get("requests").unwrap().get("cpu").and_then(Value::as_str), Some("250m"));
    let cmd = c.get("command").unwrap().as_array().unwrap();
    assert_eq!(cmd[0].as_str(), Some("/bin/sh"));
    assert_eq!(cmd[1].as_str(), Some("-c"));
    assert_eq!(cmd[2].as_str(), Some("echo hello\nexec nginx -g 'daemon off;'\n"));
    assert_eq!(c.get("livenessProbe").unwrap().get("httpGet").unwrap().get("port").and_then(Value::as_i64), Some(80));
    assert_eq!(cs[1].get("name").and_then(Value::as_str), Some("sidecar"));
    assert_eq!(cs[1].get("command").unwrap().as_array().unwrap().len(), 2);
    assert_eq!(pod.get("volumes").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(pod.get("nodeSelector").unwrap().as_object().unwrap().len(), 0);
    // Key order is source order.
    let keys: Vec<&str> = v.as_object().unwrap().iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["apiVersion", "kind", "metadata", "spec"]);
}

#[test]
fn deployment_survives_json_roundtrip() {
    let v = parse(DEPLOYMENT).unwrap();
    let s = json::to_string(&v);
    assert_eq!(json::parse_str(&s).unwrap(), v);
}

#[test]
fn multi_document() {
    let src = "\
# leading comment
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
data:
  k: v
---
apiVersion: v1
kind: Service
metadata:
  name: b
...
---
# only a comment
---
- 1
- 2
--- scalar doc
---
key: value
";
    let docs = parse_all(src).unwrap();
    assert_eq!(docs.len(), 5);
    assert_eq!(docs[0].get("kind").and_then(Value::as_str), Some("ConfigMap"));
    assert_eq!(docs[1].get("kind").and_then(Value::as_str), Some("Service"));
    assert_eq!(json::to_string(&docs[2]), "[1,2]");
    assert_eq!(docs[3].as_str(), Some("scalar doc"));
    assert_eq!(docs[4].get("key").and_then(Value::as_str), Some("value"));
    // No leading marker.
    assert_eq!(parse_all("a: 1\n---\nb: 2\n").unwrap().len(), 2);
    // `parse` insists on one document.
    assert_eq!(parse("a: 1\n---\nb: 2\n").unwrap_err().kind, ErrorKind::MultipleDocuments);
    assert_eq!(parse("---\na: 1\n").unwrap().get("a").and_then(Value::as_i64), Some(1));
    // Empty input.
    assert!(parse("").unwrap().is_null());
    assert!(parse("# nothing\n\n").unwrap().is_null());
    assert_eq!(parse_all("---\n---\n").unwrap().len(), 0);
    // Markers inside text are not boundaries.
    assert_eq!(y("a: ---\nb: '--- x'\n"), r#"{"a":"---","b":"--- x"}"#);
    assert_eq!(y("--- # c\na: 1\n"), r#"{"a":1}"#);
    assert_eq!(parse_all("--- |\n  text\n---\nb: 1\n").unwrap()[0].as_str(), Some("text\n"));
}

#[test]
fn core_schema_typing() {
    let cases: &[(&str, &str)] = &[
        ("a: null", r#"{"a":null}"#),
        ("a: Null", r#"{"a":null}"#),
        ("a: NULL", r#"{"a":null}"#),
        ("a: ~", r#"{"a":null}"#),
        ("a:", r#"{"a":null}"#),
        ("a: true", r#"{"a":true}"#),
        ("a: True", r#"{"a":true}"#),
        ("a: FALSE", r#"{"a":false}"#),
        ("a: yes", r#"{"a":"yes"}"#),
        ("a: No", r#"{"a":"No"}"#),
        ("a: on", r#"{"a":"on"}"#),
        ("a: off", r#"{"a":"off"}"#),
        ("a: y", r#"{"a":"y"}"#),
        ("a: n", r#"{"a":"n"}"#),
        ("a: tRUE", r#"{"a":"tRUE"}"#),
        ("a: 0", r#"{"a":0}"#),
        ("a: 42", r#"{"a":42}"#),
        ("a: -42", r#"{"a":-42}"#),
        ("a: +42", r#"{"a":42}"#),
        ("a: 007", r#"{"a":7}"#),
        ("a: 0o17", r#"{"a":15}"#),
        ("a: 0x1F", r#"{"a":31}"#),
        ("a: 0xff", r#"{"a":255}"#),
        ("a: 0b101", r#"{"a":"0b101"}"#),
        ("a: 0o9", r#"{"a":"0o9"}"#),
        ("a: 1_000", r#"{"a":"1_000"}"#),
        ("a: 1:30", r#"{"a":"1:30"}"#),
        ("a: 18446744073709551615", r#"{"a":18446744073709551615}"#),
        ("a: 1.5", r#"{"a":1.5}"#),
        ("a: -1.5", r#"{"a":-1.5}"#),
        ("a: .5", r#"{"a":0.5}"#),
        ("a: 5.", r#"{"a":5}"#),
        ("a: +1.5", r#"{"a":1.5}"#),
        ("a: 1e3", r#"{"a":1e3}"#),
        ("a: 1.5E-2", r#"{"a":1.5E-2}"#),
        ("a: 1e", r#"{"a":"1e"}"#),
        ("a: .", r#"{"a":"."}"#),
        ("a: 1.2.3", r#"{"a":"1.2.3"}"#),
        ("a: 1.0", r#"{"a":1.0}"#),
        ("a: v1.2", r#"{"a":"v1.2"}"#),
        ("a: 10m", r#"{"a":"10m"}"#),
        ("a: 1Gi", r#"{"a":"1Gi"}"#),
        ("a: 12345678901234567890123", r#"{"a":12345678901234567890123}"#),
        ("a: \"123\"", r#"{"a":"123"}"#),
        ("a: '1.5'", r#"{"a":"1.5"}"#),
        ("a: \"null\"", r#"{"a":"null"}"#),
        ("a: \"\"", r#"{"a":""}"#),
        ("a: ''", r#"{"a":""}"#),
        ("a: hello world", r#"{"a":"hello world"}"#),
        ("a: http://x.y/z?q=1#frag", r#"{"a":"http://x.y/z?q=1#frag"}"#),
        ("a: b:c", r#"{"a":"b:c"}"#),
        ("a: -dash", r#"{"a":"-dash"}"#),
        ("a: a#b", r#"{"a":"a#b"}"#),
        ("a: a #b", r#"{"a":"a"}"#),
        ("a: 'it''s'", r#"{"a":"it's"}"#),
        ("a: \"tab\\there\"", r#"{"a":"tab\there"}"#),
        ("a: \"\\u00e9\\x41\\U0001F600\\ud83d\\ude00\"", "{\"a\":\"\u{e9}A\u{1f600}\u{1f600}\"}"),
        ("a: \"q\\\"uote\\\\ \\/ \\0\"", r#"{"a":"q\"uote\\ / \u0000"}"#),
        ("a: 'single \\n stays'", r#"{"a":"single \\n stays"}"#),
        ("1: one", r#"{"1":"one"}"#),
        ("true: x", r#"{"true":"x"}"#),
        ("'quoted key': 1", r#"{"quoted key":1}"#),
        ("\"dq\\tkey\": 1", r#"{"dq\tkey":1}"#),
        ("a.b/c: 1", r#"{"a.b/c":1}"#),
        ("\u{e9}: \u{1f600}", "{\"\u{e9}\":\"\u{1f600}\"}"),
        ("key:    spaced   ", r#"{"key":"spaced"}"#),
    ];
    for (i, o) in cases {
        assert_eq!(y(i), *o, "input {:?}", i);
    }
    assert_eq!(y("42"), "42");
    assert_eq!(y("hello"), "\"hello\"");
    assert_eq!(y("true"), "true");
    assert_eq!(y("- 1\n- a\n- null\n- 2.5\n"), r#"[1,"a",null,2.5]"#);
}

#[test]
fn block_structure() {
    assert_eq!(y("a:\n  b:\n    c: 1\n  d: 2\ne: 3\n"), r#"{"a":{"b":{"c":1},"d":2},"e":3}"#);
    // Sequence at the same indent as its key.
    assert_eq!(y("a:\n- 1\n- 2\nb: x\n"), r#"{"a":[1,2],"b":"x"}"#);
    // Indented sequence.
    assert_eq!(y("a:\n  - 1\n  - 2\nb: x\n"), r#"{"a":[1,2],"b":"x"}"#);
    // Compact maps in sequences, nested sequences.
    assert_eq!(
        y("- name: a\n  v: 1\n- name: b\n  v: 2\n"),
        r#"[{"name":"a","v":1},{"name":"b","v":2}]"#
    );
    assert_eq!(y("- - 1\n  - 2\n- - 3\n"), r#"[[1,2],[3]]"#);
    assert_eq!(y("-\n  a: 1\n-\n  - x\n- \n"), r#"[{"a":1},["x"],null]"#);
    assert_eq!(y("- a: 1\n  b:\n    - x\n    - y\n  c: 2\n"), r#"[{"a":1,"b":["x","y"],"c":2}]"#);
    assert_eq!(y("a:\n\n  b: 1\n\n\n  c: 2\n"), r#"{"a":{"b":1,"c":2}}"#);
    assert_eq!(y("a: 1\r\nb:\r\n  - x\r\n"), r#"{"a":1,"b":["x"]}"#);
    assert_eq!(y("\u{feff}a: 1\n"), r#"{"a":1}"#);
    assert_eq!(y("a: 1"), r#"{"a":1}"#);
    assert_eq!(y("# c\na: 1 # c\n# c\nb: 2\n  # indented comment\nc: 3\n"), r#"{"a":1,"b":2,"c":3}"#);
    assert_eq!(y("a: # comment\n  b: 1\n"), r#"{"a":{"b":1}}"#);
    assert_eq!(y("a:\n# c\n  - 1 # c\n"), r#"{"a":[1]}"#);
    assert_eq!(y("a:\nb:\nc: 1\n"), r#"{"a":null,"b":null,"c":1}"#);
    assert_eq!(y("-1: x\n-a: y\n"), r#"{"-1":"x","-a":"y"}"#);
    assert_eq!(y("- -1\n- --x\n"), r#"[-1,"--x"]"#);
    assert_eq!(y("a: [1]\n"), r#"{"a":[1]}"#);
}

#[test]
fn plain_and_quoted_multiline() {
    assert_eq!(y("a: one\n  two\n  three\nb: x\n"), r#"{"a":"one two three","b":"x"}"#);
    assert_eq!(y("a: one\n\n  two\nb: x\n"), r#"{"a":"one\ntwo","b":"x"}"#);
    assert_eq!(y("- one\n  two\n- three\n"), r#"["one two","three"]"#);
    assert_eq!(y("a: \"one\n  two\"\nb: 1\n"), r#"{"a":"one two","b":1}"#);
    assert_eq!(y("a: \"one  \n\n  two\"\n"), "{\"a\":\"one\\ntwo\"}");
    assert_eq!(y("a: 'one\n  two'\n"), r#"{"a":"one two"}"#);
    assert_eq!(y("a: \"one \\\n   two\"\n"), r#"{"a":"one two"}"#);
    assert_eq!(y("a: \"keep\\  \n  space\"\n"), r#"{"a":"keep  space"}"#);
    assert_eq!(y("a: \"x\" # comment\n"), r#"{"a":"x"}"#);
    assert_eq!(y("a: 'x'   \n"), r#"{"a":"x"}"#);
    assert_eq!(y("- \"a: b\"\n- 'c: d'\n"), r#"["a: b","c: d"]"#);
    assert_eq!(y("\"a\": 1\n'b': 2\n"), r#"{"a":1,"b":2}"#);
    assert_eq!(y("multi word plain\n"), "\"multi word plain\"");
    assert_eq!(y("top\nlevel\n"), "\"top level\"");
}

#[test]
fn block_scalars() {
    assert_eq!(y("a: |\n  x\n  y\nb: 1\n"), r#"{"a":"x\ny\n","b":1}"#);
    assert_eq!(y("a: |-\n  x\n  y\nb: 1\n"), r#"{"a":"x\ny","b":1}"#);
    assert_eq!(y("a: |+\n  x\n  y\n\n\nb: 1\n"), "{\"a\":\"x\\ny\\n\\n\\n\",\"b\":1}");
    assert_eq!(y("a: |\n  x\n  y\n\n\nb: 1\n"), "{\"a\":\"x\\ny\\n\",\"b\":1}");
    assert_eq!(y("a: |\n  x\n\n  y\n"), "{\"a\":\"x\\n\\ny\\n\"}");
    assert_eq!(y("a: |\n\n  x\n"), "{\"a\":\"\\nx\\n\"}");
    assert_eq!(y("a: |\n  # not a comment\n  - not a seq\n  k: v\n"), "{\"a\":\"# not a comment\\n- not a seq\\nk: v\\n\"}");
    assert_eq!(y("a: |2\n    x\n"), "{\"a\":\"  x\\n\"}");
    assert_eq!(y("a: |2-\n    x\n"), "{\"a\":\"  x\"}");
    assert_eq!(y("a: |-2\n    x\n"), "{\"a\":\"  x\"}");
    assert_eq!(y("a: | # comment\n  x\n"), "{\"a\":\"x\\n\"}");
    assert_eq!(y("a: |\nb: 1\n"), r#"{"a":"","b":1}"#);
    assert_eq!(y("a: |+\nb: 1\n"), r#"{"a":"","b":1}"#);
    assert_eq!(y("a: |+\n\nb: 1\n"), "{\"a\":\"\\n\",\"b\":1}");
    assert_eq!(y("a: |\n  x   \n"), "{\"a\":\"x   \\n\"}");
    assert_eq!(y("a: |\n  tab\there\n"), "{\"a\":\"tab\\there\\n\"}");
    assert_eq!(y("a: |\n  x"), "{\"a\":\"x\\n\"}");
    // Folded.
    assert_eq!(y("a: >\n  one\n  two\n\n  three\n"), "{\"a\":\"one two\\nthree\\n\"}");
    assert_eq!(y("a: >-\n  one\n  two\n"), r#"{"a":"one two"}"#);
    assert_eq!(y("a: >+\n  one\n\n"), "{\"a\":\"one\\n\\n\"}");
    assert_eq!(y("a: >\n  one\n\n\n  two\n"), "{\"a\":\"one\\n\\ntwo\\n\"}");
    assert_eq!(y("a: >\n  text\n    more indented\n    keeps\n  back\n"), "{\"a\":\"text\\n  more indented\\n  keeps\\nback\\n\"}");
    assert_eq!(y("a: >\n\n  text\n"), "{\"a\":\"\\ntext\\n\"}");
    // Inside sequences, and at top level.
    assert_eq!(y("- |\n  x\n  y\n- >\n  p\n  q\n"), r#"["x\ny\n","p q\n"]"#);
    assert_eq!(y("- a: |\n    x\n  b: 1\n"), r#"[{"a":"x\n","b":1}]"#);
    assert_eq!(y("|\n  top\n  level\n"), r#""top\nlevel\n""#);
    assert_eq!(y("a:\n  b: |\n    x\n  c: 1\n"), r#"{"a":{"b":"x\n","c":1}}"#);
}

#[test]
fn flow_collections() {
    assert_eq!(y("[]"), "[]");
    assert_eq!(y("{}"), "{}");
    assert_eq!(y("[1, 2, 3]"), "[1,2,3]");
    assert_eq!(y("[1, 2, 3,]"), "[1,2,3]");
    assert_eq!(y("[ a , b c , 'd' , \"e\" ]"), r#"["a","b c","d","e"]"#);
    assert_eq!(y("{a: 1, b: [x, y], c: {d: e}}"), r#"{"a":1,"b":["x","y"],"c":{"d":"e"}}"#);
    assert_eq!(y("{a: 1, b}"), r#"{"a":1,"b":null}"#);
    assert_eq!(y("{a: , b: 2}"), r#"{"a":null,"b":2}"#);
    assert_eq!(y("{\"a\":1,'b':2}"), r#"{"a":1,"b":2}"#);
    assert_eq!(y("{a: 'x, y', b: \"]\"}"), r#"{"a":"x, y","b":"]"}"#);
    assert_eq!(y("[a:b, c/d, http://x, 1.5, true, null, ~]"), r#"["a:b","c/d","http://x",1.5,true,null,null]"#);
    assert_eq!(y("[[1, 2], [3], []]"), "[[1,2],[3],[]]");
    assert_eq!(y("k: [a, b] # comment\n"), r#"{"k":["a","b"]}"#);
    assert_eq!(y("- [a, b]\n- {c: d}\n"), r#"[["a","b"],{"c":"d"}]"#);
    // Multi-line flow collections, with comments between entries.
    assert_eq!(y("k: [a,\n  b,\n  # note\n  c]\nz: 1\n"), r#"{"k":["a","b","c"],"z":1}"#);
    assert_eq!(y("k: {\n  a: 1,\n  b: 2\n}\n"), r#"{"k":{"a":1,"b":2}}"#);
    assert_eq!(y("k: [one\n  two, three]\n"), r#"{"k":["one two","three"]}"#);
    assert_eq!(y("k: [\n]\n"), r#"{"k":[]}"#);
    assert_eq!(y("ports: [80, 443]\nlabels: {a: b}\n"), r#"{"ports":[80,443],"labels":{"a":"b"}}"#);
    assert_eq!(y("{a: -1, b: -x, c: 0x10}"), r#"{"a":-1,"b":"-x","c":16}"#);
}

#[test]
fn rejected_features() {
    assert_eq!(fail("a: &x 1\nb: *x\n").kind, ErrorKind::Anchor);
    assert_eq!(fail("a: *x\n").kind, ErrorKind::Alias);
    assert_eq!(fail("a: !!str 1\n").kind, ErrorKind::Tag);
    assert_eq!(fail("a: !custom x\n").kind, ErrorKind::Tag);
    assert_eq!(fail("!!map\na: 1\n").kind, ErrorKind::Tag);
    assert_eq!(fail("&anchor a: 1\n").kind, ErrorKind::Anchor);
    assert_eq!(fail("- &x a\n- *x\n").kind, ErrorKind::Anchor);
    assert_eq!(fail("- *x\n").kind, ErrorKind::Alias);
    assert_eq!(fail("base: &b {x: 1}\nd:\n  <<: *b\n").kind, ErrorKind::Anchor);
    assert_eq!(fail("a: [&x 1, 2]\n").kind, ErrorKind::Anchor);
    assert_eq!(fail("a: [*x]\n").kind, ErrorKind::Alias);
    assert_eq!(fail("a: [!!str x]\n").kind, ErrorKind::Tag);
    assert_eq!(fail("{a: &x 1}").kind, ErrorKind::Anchor);
    assert_eq!(fail("%YAML 1.2\n---\na: 1\n").kind, ErrorKind::Directive);
    assert_eq!(fail("%TAG ! tag:x,2000:\n---\na: 1\n").kind, ErrorKind::Directive);
    assert_eq!(fail("? a\n: b\n").kind, ErrorKind::ExplicitKey);
    assert_eq!(fail("a: 1\n? b\n").kind, ErrorKind::ExplicitKey);
    assert_eq!(fail("a: ? b\n").kind, ErrorKind::ExplicitKey);
    assert_eq!(fail("a: .inf\n").kind, ErrorKind::NonFiniteFloat);
    assert_eq!(fail("a: -.inf\n").kind, ErrorKind::NonFiniteFloat);
    assert_eq!(fail("a: .NaN\n").kind, ErrorKind::NonFiniteFloat);
    assert_eq!(fail("a: 1e999\n").kind, ErrorKind::NumberOutOfRange);
    assert_eq!(fail("a: 0xFFFFFFFFFFFFFFFFF\n").kind, ErrorKind::NumberOutOfRange);
}

#[test]
fn rejected_syntax() {
    assert_eq!(fail("a:\n\tb: 1\n").kind, ErrorKind::TabIndent);
    assert_eq!(fail("a: 1\n\tb: 2\n").kind, ErrorKind::TabIndent);
    assert_eq!(fail("a: 1\na: 2\n").kind, ErrorKind::DuplicateKey);
    assert_eq!(fail("a:\n  b: 1\n  b: 2\n").kind, ErrorKind::DuplicateKey);
    assert_eq!(fail("{a: 1, a: 2}").kind, ErrorKind::DuplicateKey);
    assert_eq!(fail("\"a\": 1\na: 2\n").kind, ErrorKind::DuplicateKey);
    assert_eq!(fail("a: \"unterminated\n").kind, ErrorKind::UnexpectedEof);
    assert_eq!(fail("a: 'unterminated\n").kind, ErrorKind::UnexpectedEof);
    assert_eq!(fail("a: [1, 2\n").kind, ErrorKind::UnexpectedEof);
    assert_eq!(fail("a: {x: 1\n").kind, ErrorKind::UnexpectedEof);
    assert_eq!(fail("a: \"bad \\q escape\"\n").kind, ErrorKind::InvalidEscape);
    assert_eq!(fail("a: \"\\u12\"\n").kind, ErrorKind::InvalidEscape);
    assert_eq!(fail("a: \"\\ud800\"\n").kind, ErrorKind::InvalidEscape);
    assert_eq!(fail("a: \"\\udc00\"\n").kind, ErrorKind::InvalidEscape);
    assert_eq!(fail("a:\n    b: 1\n  c: 2\n").kind, ErrorKind::BadIndent);
    assert_eq!(fail("a: 1\n  b: 2\n").kind, ErrorKind::Syntax("mapping values are not allowed here"));
    assert_eq!(fail("a:\n  - 1\n - 2\n").kind, ErrorKind::BadIndent);
    assert_eq!(fail("a: b: c\n").kind, ErrorKind::Syntax("mapping values are not allowed here"));
    assert_eq!(fail("a: - b\n").kind, ErrorKind::Syntax("sequence entry not allowed here"));
    assert_eq!(fail("- a\nb: 1\n").kind, ErrorKind::Syntax("unexpected content (bad indentation?)"));
    assert_eq!(fail("a: 1\n- b\n").kind, ErrorKind::Syntax("expected 'key: value'"));
    assert_eq!(fail("a: \"x\" y\n").kind, ErrorKind::Syntax("unexpected content after value"));
    assert_eq!(fail("a: [1] x\n").kind, ErrorKind::Syntax("unexpected content after value"));
    assert_eq!(fail("a: [1, 2]]\n").kind, ErrorKind::Syntax("unexpected content after value"));
    assert_eq!(fail("a: [1,, 2]\n").kind, ErrorKind::Syntax("empty flow entry"));
    assert_eq!(fail("a: [x: 1]\n").kind, ErrorKind::Syntax("single-pair mappings in flow sequences are not supported"));
    assert_eq!(fail("a: [1 2 ] ]\n").kind, ErrorKind::Syntax("unexpected content after value"));
    assert_eq!(fail("a: |x\n  t\n").kind, ErrorKind::Syntax("invalid block scalar header"));
    assert_eq!(fail("a: @x\n").kind, ErrorKind::Syntax("reserved indicator at start of scalar"));
    assert_eq!(fail("a: `x`\n").kind, ErrorKind::Syntax("reserved indicator at start of scalar"));
    assert_eq!(fail(": x\n").kind, ErrorKind::Syntax("empty mapping key"));
    assert_eq!(fail("a: ]\n").kind, ErrorKind::Syntax("unexpected flow indicator"));
}

#[test]
fn error_lines() {
    assert_eq!(fail("a: 1\nb: 2\nc: &x 3\n").line, 3);
    assert_eq!(fail("a: 1\n\n\nb: 2\nb: 3\n").line, 5);
    assert_eq!(fail("k: [a,\n  b,\n  &x c]\n").line, 3);
    assert_eq!(fail("a: 1\n---\nb: !!int 2\n").line, 3);
    let msg = alloc::format!("{}", fail("a: &x 1\n"));
    assert!(msg.contains("line 1") && msg.contains("anchors"), "{}", msg);
    let msg = alloc::format!("{}", fail("a: !!str 1\n"));
    assert!(msg.contains("tags"), "{}", msg);
}

#[test]
fn limits() {
    let mut deep = String::new();
    for i in 0..200 {
        for _ in 0..i * 2 {
            deep.push(' ');
        }
        deep.push_str("k:\n");
    }
    assert_eq!(fail(&deep).kind, ErrorKind::DepthExceeded);
    let flow = "[".repeat(200) + &"]".repeat(200);
    assert_eq!(fail(&alloc::format!("a: {}\n", flow)).kind, ErrorKind::DepthExceeded);
    let seq = "- ".repeat(200) + "x";
    assert_eq!(fail(&seq).kind, ErrorKind::DepthExceeded);
    let lim = Limits { max_depth: 3, max_input: 64 };
    assert!(parse_all_with("a:\n  b:\n    c: 1\n", lim).is_ok());
    assert_eq!(parse_all_with("a:\n  b:\n    c:\n      d: 1\n", lim).unwrap_err().kind, ErrorKind::DepthExceeded);
    let big = "a: 1\n".repeat(20);
    assert_eq!(parse_all_with(&big, lim).unwrap_err().kind, ErrorKind::InputTooLarge);
}

#[test]
fn matches_json_for_json_documents() {
    // YAML 1.2 is a superset of JSON for these.
    for s in [
        r#"{"a": [1, 2.5, "x", null, true], "b": {"c": "d"}}"#,
        r#"[{"a":1},{"b":[]}]"#,
        r#""just a string""#,
        r#"{"esc": "line\nbreak \u00e9 \"q\""}"#,
    ] {
        assert_eq!(parse(s).unwrap(), json::parse_str(s).unwrap(), "{}", s);
    }
}

#[test]
fn mutated_input_never_panics() {
    // Deterministic mutation fuzz: whatever happens, return Ok or Err.
    let alphabet: &[u8] = b" \t\n:-#[]{},'\"|>&*!%@`?\\0aZ9.~\r";
    let base = DEPLOYMENT.as_bytes();
    let mut x = 0x9e37_79b9u32;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    for _ in 0..4000 {
        let mut b = base.to_vec();
        for _ in 0..1 + rnd() % 4 {
            let at = rnd() as usize % b.len();
            match rnd() % 3 {
                0 => b[at] = alphabet[rnd() as usize % alphabet.len()],
                1 => {
                    b.remove(at);
                }
                _ => b.insert(at, alphabet[rnd() as usize % alphabet.len()]),
            }
        }
        if let Ok(s) = core::str::from_utf8(&b) {
            let _ = parse_all(s);
        }
    }
}
