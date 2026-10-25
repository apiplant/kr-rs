#!/usr/bin/env python3
"""Generates crates/kr-apiserver/src/openapi_meta.json from upstream's api/openapi-spec/swagger.json.

Usage: python3 -I tools/gen_openapi_meta.py <swagger.json>

Output: {"definitions": {...}, "props": {...}}
  definitions: ObjectMeta and everything it references (v2 "#/definitions/" refs; the server
               rewrites them for v3), for the OpenAPI documents of custom resources.
  props:       the apiVersion/kind/metadata properties upstream adds to every CRD schema, taken
               from the Pod definition so the descriptions match exactly.
"""
import json
import os
import sys

META = "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"


def refs(v, out):
    if isinstance(v, dict):
        r = v.get("$ref")
        if isinstance(r, str) and r.startswith("#/definitions/"):
            out.add(r[len("#/definitions/"):])
        for x in v.values():
            refs(x, out)
    elif isinstance(v, list):
        for x in v:
            refs(x, out)


def main():
    defs = json.load(open(sys.argv[1]))["definitions"]
    want, todo = {}, [META]
    while todo:
        n = todo.pop()
        if n in want:
            continue
        want[n] = defs[n]
        found = set()
        refs(defs[n], found)
        todo.extend(sorted(found))
    pod = defs["io.k8s.api.core.v1.Pod"]["properties"]
    props = {k: pod[k] for k in ("apiVersion", "kind", "metadata")}
    # apiextensions-apiserver's builder (metadataDescription) words it differently from Pod.
    props["metadata"] = dict(props["metadata"], description="Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata")
    out = {"definitions": dict(sorted(want.items())), "props": props}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "kr-apiserver", "src", "openapi_meta.json")
    with open(path, "w") as f:
        json.dump(out, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    print(f"{len(want)} definitions -> {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
