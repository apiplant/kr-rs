#!/usr/bin/env python3
"""Regroups docs/KNOWN_ISSUES.md by status: needs work, accepted, resolved.

Items keep their numbers; within each group they stay under their subsystem heading.
Status is the `— *...*` marker on an item's first line: fixed* -> Resolved (except
"fixed for root"), accepted*/note -> Accepted, anything else -> Needs work.
Run: python3 -I tools/sort_known_issues.py
"""
import os
import re

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "KNOWN_ISSUES.md")
INTRO = ("Living list, grouped by what still needs doing. Each item: **status**, impact, plan. Numbers are "
         "stable (other docs cite them); new items get the next number. When an item is resolved, mark it "
         "*fixed* with the commit and run `python3 -I tools/sort_known_issues.py`.")
TITLES = {"work": "Needs work (open or partial)", "accepted": "Accepted limitations (by design, or not planned for now)", "fixed": "Resolved"}


def cls(first):
    m = re.search(r"— \*([^*]+)\*", first)
    st = m.group(1) if m else ""
    if st.startswith("fixed for root"):
        return "work"
    if st.startswith("fixed"):
        return "fixed"
    if st.startswith("accepted") or st == "note":
        return "accepted"
    return "work"


def main():
    lines = open(P).read().split("\n")
    order, items, section, item = [], [], None, None
    for l in lines:
        if l.startswith("# "):
            continue
        if l.startswith("## "):
            section = l[3:].strip()
            if section not in order:
                order.append(section)
            item = None
        elif re.match(r"^\d+\. ", l):
            item = [l]
            items.append((section, item))
        elif item is not None:
            item.append(l)
    out = ["# Known Issues & Potential Problems", "", INTRO, ""]
    for g in ("work", "accepted", "fixed"):
        out += ["# " + TITLES[g], ""]
        for sec in order:
            its = [it for sc, it in items if sc == sec and cls(it[0]) == g]
            if not its:
                continue
            out.append("## " + sec)
            for it in sorted(its, key=lambda x: int(re.match(r"\d+", x[0]).group())):
                while it and not it[-1].strip():
                    it.pop()
                out += it
            out.append("")
    open(P, "w").write("\n".join(out).rstrip("\n") + "\n")


main()
