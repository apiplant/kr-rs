#!/usr/bin/env python3
"""Generates crates/kr-apiserver/src/proto_schema.rs: the Kubernetes protobuf field tables.

Dev tooling only (ADR-020): the shipped code has no dependencies.

Inputs are the upstream `generated.proto` files (k8s.io/api, k8s.io/apimachinery) and, for the
JSON-only facts the .proto files do not carry, the matching `types.go` files:
  * `json:",inline"` embedding (Probe.handler, Volume.volumeSource, ...), which merges the
    embedded message's fields into the parent object;
  * pointer / `omitempty`, i.e. whether a zero scalar is emitted by encoding/json.
The proto field name is the JSON name for every field except those two inline cases and
DaemonEndpoint ("Port"), which the types.go tag overrides; the script verifies this and fails on
any other mismatch.

Run:  python3 -I tools/gen_k8s_proto_schema.py --fetch SCRATCH_DIR     (download, then generate)
      python3 -I tools/gen_k8s_proto_schema.py SCRATCH_DIR             (reuse downloaded files)
SCRATCH_DIR must be outside the repository.
"""
import os, re, sys, urllib.request

VERSION = "v0.37.0"
RAW = "https://raw.githubusercontent.com/kubernetes/%s/" + VERSION + "/%s"
API_GROUPS = ["core/v1", "apps/v1", "batch/v1", "coordination/v1", "discovery/v1", "networking/v1",
              "policy/v1", "scheduling/v1", "rbac/v1", "autoscaling/v1", "authentication/v1", "authorization/v1", "scheduling/v1alpha3"]
# local name -> (repo, path inside repo, proto package prefix, go package basename)
SOURCES = {}
for _g in API_GROUPS:
    _n = _g.replace("/", "_")
    SOURCES[_n] = ("api", _g, "k8s.io.api." + _g.replace("/", "."))
for _n, _p, _pkg in [("meta_v1", "pkg/apis/meta/v1", "k8s.io.apimachinery.pkg.apis.meta.v1"),
                     ("runtime", "pkg/runtime", "k8s.io.apimachinery.pkg.runtime"),
                     ("intstr", "pkg/util/intstr", "k8s.io.apimachinery.pkg.util.intstr"),
                     ("resource", "pkg/api/resource", "k8s.io.apimachinery.pkg.api.resource")]:
    SOURCES[_n] = ("apimachinery", _p, _pkg)

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(REPO, "crates", "kr-apiserver", "src", "proto_schema.rs")
RESOURCES_RS = os.path.join(REPO, "crates", "kr-apiserver", "src", "resources.rs")

META = "k8s.io.apimachinery.pkg.apis.meta.v1"
# Messages with a hand-written JSON form; proto.rs dispatches on these indices.
SPECIAL = {
    "TIME": META + ".Time", "MICRO_TIME": META + ".MicroTime", "DURATION": META + ".Duration",
    "FIELDS_V1": META + ".FieldsV1", "INT_OR_STRING": "k8s.io.apimachinery.pkg.util.intstr.IntOrString",
    "QUANTITY": "k8s.io.apimachinery.pkg.api.resource.Quantity",
    "RAW_EXTENSION": "k8s.io.apimachinery.pkg.runtime.RawExtension",
}
# Extra top-level kinds beyond resources.rs: (apiVersion, kind, message).
EXTRA_ROOTS = [("v1", "DeleteOptions", META + ".DeleteOptions"),
               ("autoscaling/v1", "Scale", "k8s.io.api.autoscaling.v1.Scale"),
               ("authentication.k8s.io/v1", "TokenRequest", "k8s.io.api.authentication.v1.TokenRequest"),
               ("authentication.k8s.io/v1", "TokenReview", "k8s.io.api.authentication.v1.TokenReview"),
               ("authorization.k8s.io/v1", "SelfSubjectAccessReview", "k8s.io.api.authorization.v1.SelfSubjectAccessReview"),
               ("authorization.k8s.io/v1", "SubjectAccessReview", "k8s.io.api.authorization.v1.SubjectAccessReview")]
# Fields whose JSON name legitimately differs from the proto name (message, number) -> json name.
NAME_OVERRIDES = {("k8s.io.api.authentication.v1.BoundObjectReference", 4): "uid", ("k8s.io.api.networking.v1.IngressClassParametersReference", 1): "apiGroup"}

SCALARS = {"string": "STRING", "bytes": "BYTES", "int32": "INT32", "int64": "INT64", "bool": "BOOL",
           "double": "DOUBLE", "float": "FLOAT", "uint32": "UINT32", "uint64": "UINT64"}
KIND_ORDER = ["STRING", "BYTES", "INT32", "INT64", "BOOL", "DOUBLE", "FLOAT", "UINT32", "UINT64", "MESSAGE", "MAP"]
K = {n: i for i, n in enumerate(KIND_ORDER)}
F_REPEATED, F_KEEP_ZERO, F_INLINE = 0x10, 0x20, 0x40


def fetch(scratch):
    for name, (repo, path, _) in SOURCES.items():
        for fname, dst in (("generated.proto", name + ".proto"), ("types.go", name + ".go")):
            dest = os.path.join(scratch, dst)
            try:
                with urllib.request.urlopen(RAW % (repo, path + "/" + fname)) as r:
                    data = r.read()
            except Exception as e:  # types.go is optional for the small helper packages
                if fname == "types.go":
                    continue
                sys.exit("fetch %s: %s" % (path, e))
            with open(dest, "wb") as f:
                f.write(data)


# ---------------------------------------------------------------- .proto parser

def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def parse_proto(path, package):
    """Returns {full message name: [(number, name, type, repeated)]} where type is a scalar name,
    a fully-qualified message name, or ('map', key, value)."""
    src = strip_comments(open(path).read())
    pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.M).group(1)
    assert pkg == package, (pkg, package)
    msgs = {}
    for m in re.finditer(r"\bmessage\s+(\w+)\s*\{([^{}]*)\}", src):
        name, body = m.group(1), m.group(2)
        fields = []
        for stmt in body.split(";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            mm = re.match(r"map\s*<\s*([\w.]+)\s*,\s*([\w.]+)\s*>\s+(\w+)\s*=\s*(\d+)", stmt)
            if mm:
                fields.append((int(mm.group(4)), mm.group(3), ("map", resolve(mm.group(1), pkg), resolve(mm.group(2), pkg)), False))
                continue
            mm = re.match(r"(optional|repeated|required)\s+([\w.]+)\s+(\w+)\s*=\s*(\d+)", stmt)
            if not mm:
                sys.exit("unparsed proto statement in %s.%s: %r" % (pkg, name, stmt))
            fields.append((int(mm.group(4)), mm.group(3), resolve(mm.group(2), pkg), mm.group(1) == "repeated"))
        msgs[pkg + "." + name] = fields
    return msgs


def resolve(t, pkg):
    if t in SCALARS:
        return t
    return t[1:] if t.startswith(".") else pkg + "." + t


# ---------------------------------------------------------------- types.go (inline / omitempty)

def parse_go(path, package):
    """Returns {full message name: {number: (json name or None, inline, keep_zero)}}."""
    out = {}
    cur = None
    for line in open(path):
        m = re.match(r"type (\w+) struct", line)
        if m:
            cur = {}
            out[package + "." + m.group(1)] = cur
            continue
        if line.startswith("}"):
            cur = None
            continue
        if cur is None or "`" not in line:
            continue
        tag = line.split("`")[1]
        pb = re.search(r'protobuf:"[a-z0-9]+,(\d+),', tag)
        js = re.search(r'json:"([^"]*)"', tag)
        if not pb or not js:
            continue
        parts = js.group(1).split(",")
        # Embedded struct fields are inlined by encoding/json; newer k8s tags them `json:""`
        # instead of `json:",inline"`. An embedded field has only a type before the tag.
        embedded = bool(re.match(r"\s*\*?[\w.]+\s+`", line))
        inline = "inline" in parts[1:] or (embedded and parts[0] == "")
        pointer = bool(re.match(r"\s*\w+\s+\*", line))
        cur[int(pb.group(1))] = (parts[0] or None, inline, pointer or "omitempty" not in parts[1:])
    return out


# ---------------------------------------------------------------- model

def build(scratch):
    protos, gos = {}, {}
    for name, (_, _, pkg) in SOURCES.items():
        protos.update(parse_proto(os.path.join(scratch, name + ".proto"), pkg))
        gp = os.path.join(scratch, name + ".go")
        if os.path.exists(gp):
            gos.update(parse_go(gp, pkg))
    return protos, gos


def roots(protos):
    out = []
    src = open(RESOURCES_RS).read()
    for m in re.finditer(r'r!\("([^"]*)",\s*"([^"]+)",\s*"([^"]+)"', src):
        g, v, kind = m.groups()
        pkg = "k8s.io.api." + (g.split(".")[0] if g else "core") + "." + v
        out.append(((g + "/" + v) if g else v, kind, pkg + "." + kind))
    out += EXTRA_ROOTS
    for av, kind, full in out:
        if full not in protos:
            sys.exit("root message missing: %s (%s %s)" % (full, av, kind))
    return out


def reachable(protos, root_msgs):
    order, seen = [], set()
    for m in list(root_msgs) + list(SPECIAL.values()):
        if m in seen:
            continue
        seen.add(m)
        order.append(m)
    i = 0
    while i < len(order):
        for _, _, t, _ in protos[order[i]]:
            for ref in (t[1:] if isinstance(t, tuple) else [t]):
                if ref not in SCALARS and ref not in seen:
                    if ref not in protos:
                        sys.exit("unresolved type %s in %s" % (ref, order[i]))
                    seen.add(ref)
                    order.append(ref)
        i += 1
    return order


def main():
    args = sys.argv[1:]
    do_fetch = "--fetch" in args
    args = [a for a in args if a != "--fetch"]
    if len(args) != 1:
        sys.exit(__doc__)
    scratch = os.path.abspath(args[0])
    if os.path.commonpath([scratch, os.path.abspath(REPO)]) == os.path.abspath(REPO):
        sys.exit("SCRATCH_DIR must be outside the repository")
    os.makedirs(scratch, exist_ok=True)
    if do_fetch:
        fetch(scratch)
    protos, gos = build(scratch)
    rts = roots(protos)
    order = reachable(protos, [r[2] for r in rts])
    index = {m: i for i, m in enumerate(order)}

    names, name_off = "", {}

    def pool(s):
        nonlocal names
        if s not in name_off:
            i = names.find(s)  # reuse substrings already in the pool
            if i < 0:
                i = len(names)
                names += s
            name_off[s] = i
        return name_off[s]

    maps = []
    fields = []
    starts = []
    warnings = 0
    for m in order:
        starts.append(len(fields))
        go = gos.get(m, {})
        for num, pname, t, rep in sorted(protos[m]):
            jname, inline, keep = go.get(num, (None, False, True))
            if num not in go and m not in SPECIAL.values():
                warnings += 1
                print("warning: no types.go tag for %s field %d (%s)" % (m, num, pname), file=sys.stderr)
            if inline:
                jname = ""
            elif (m, num) in NAME_OVERRIDES:
                jname = NAME_OVERRIDES[(m, num)]
            elif jname and jname != pname and m not in SPECIAL.values():
                sys.exit("JSON name mismatch %s.%d proto=%s json=%s" % (m, num, pname, jname))
            else:
                jname = pname
            flags = (F_REPEATED if rep else 0) | (F_KEEP_ZERO if keep else 0) | (F_INLINE if inline else 0)
            if isinstance(t, tuple):
                kk, kv = scalar_or_msg(t[1], index), scalar_or_msg(t[2], index)
                spec = (kk, kv)
                if spec not in maps:
                    maps.append(spec)
                kind, arg = K["MAP"], maps.index(spec)
            elif t in SCALARS:
                kind, arg = K[SCALARS[t]], 0
            else:
                kind, arg = K["MESSAGE"], index[t]
            fields.append((num, pool(jname) if jname else 0, len(jname), kind | flags, arg))
    starts.append(len(fields))
    assert len(names) < 65536 and len(order) < 65535 and all(f[0] < 65536 for f in fields)

    o = []
    w = o.append
    w("//! Kubernetes protobuf field tables (generated; do not edit).\n")
    w("//!\n//! Generated by `tools/gen_k8s_proto_schema.py` from the k8s.io/api and k8s.io/apimachinery\n")
    w("//! %s `generated.proto` files (plus `types.go` for inline embedding and omitempty).\n" % VERSION)
    w("//! %d messages, %d fields. Consumed by [`crate::proto`].\n\n" % (len(order), len(fields)))
    w("/// One field of a message: number, JSON name (a slice of [`NAMES`]), kind and flags.\n")
    w("#[derive(Clone, Copy)]\npub struct Field {\n    pub num: u16,\n    pub name_off: u16,\n    pub name_len: u8,\n")
    w("    /// Low nibble: one of the `K_*` kinds; high bits: `F_*` flags.\n    pub kind: u8,\n")
    w("    /// Message index (for `K_MESSAGE`) or [`MAPS`] index (for `K_MAP`).\n    pub arg: u16,\n}\n\n")
    for i, n in enumerate(KIND_ORDER):
        w("pub const K_%s: u8 = %d;\n" % (n, i))
    w("pub const K_MASK: u8 = 0x0f;\n")
    w("/// Repeated field.\npub const F_REPEATED: u8 = 0x%02x;\n" % F_REPEATED)
    w("/// Scalar is emitted even when zero (pointer or no `omitempty` in the Go type).\npub const F_KEEP_ZERO: u8 = 0x%02x;\n" % F_KEEP_ZERO)
    w("/// `json:\",inline\"`: the embedded message's fields are merged into the parent object.\npub const F_INLINE: u8 = 0x%02x;\n\n" % F_INLINE)
    for n, full in SPECIAL.items():
        w("/// Message index of `%s`.\npub const M_%s: u16 = %d;\n" % (full.rsplit(".", 1)[1], n, index[full]))
    w("\nconst fn f(num: u16, name_off: u16, name_len: u8, kind: u8, arg: u16) -> Field {\n    Field { num, name_off, name_len, kind, arg }\n}\n\n")
    w("/// Pool of JSON field names.\npub static NAMES: &str = \"%s\";\n\n" % names)
    w("/// Map field specs: (key kind, key arg, value kind, value arg).\npub static MAPS: [(u8, u16, u8, u16); %d] = [\n" % len(maps))
    for (kk, kv) in maps:
        w("    (%d, %d, %d, %d),\n" % (kk[0], kk[1], kv[0], kv[1]))
    w("];\n\n")
    w("/// `MSG_START[i]..MSG_START[i + 1]` is the slice of [`FIELDS`] for message `i`, sorted by number.\n")
    w("pub static MSG_START: [u16; %d] = [" % len(starts))
    w(",".join(str(s) for s in starts))
    w("];\n\n")
    w("/// All fields of all messages.\npub static FIELDS: [Field; %d] = [\n" % len(fields))
    for fl in fields:
        w("    f(%d, %d, %d, 0x%02x, %d),\n" % fl)
    w("];\n\n")
    w("/// (apiVersion, kind) to top-level message index, for every served kind.\n")
    w("pub static KINDS: [(&str, &str, u16); %d] = [\n" % len(rts))
    for av, kind, full in rts:
        w("    (\"%s\", \"%s\", %d),\n" % (av, kind, index[full]))
    w("];\n")
    text = "".join(o)
    with open(OUT, "w") as fh:
        fh.write(text)
    data_bytes = len(fields) * 8 + len(starts) * 2 + len(names) + len(maps) * 8 + len(rts) * 36
    print("wrote %s: %d bytes of source, %d messages, %d fields, ~%d bytes of static data, %d warnings"
          % (OUT, len(text), len(order), len(fields), data_bytes, warnings))


def scalar_or_msg(t, index):
    if t in SCALARS:
        return (K[SCALARS[t]], 0)
    return (K["MESSAGE"], index[t])


main()
