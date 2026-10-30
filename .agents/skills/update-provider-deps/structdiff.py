#!/usr/bin/env python3
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
"""structdiff.py <old_dir> <new_dir> [--types-from <provider_dir>]

Diff the struct fields of two extracted SDK versions. This answers both halves of an
upgrade at once: fields that appeared are candidate schema additions, fields that were
removed or retyped are breaking changes the release notes may not mention.

Point it at directories produced by modfetch.sh:

    OLD=$(./modfetch.sh github.com/cloudflare/cloudflare-go/v6 v6.10.0)
    NEW=$(./modfetch.sh github.com/cloudflare/cloudflare-go/v7 v7.8.0)
    python3 structdiff.py "$OLD" "$NEW" --types-from providers/cloudflare

--types-from is what makes the output usable. An SDK diff across a major runs to tens of
thousands of lines, nearly all of it types the provider has never touched. Restricting to
types the provider source actually mentions turns that into a page you can read, and it
is exactly the right filter for the two questions being asked: what can we expose on
resources we already ship, and what did we break.

Drop --types-from to see NEW TYPES as well, which is how you spot whole services the SDK
gained. That list is long and mostly noise, so read it after the restricted pass.

Two limits worth knowing before trusting the output:

  * Parsing is line-oriented rather than a real Go parse. Field *names* are reliable;
    a comment line that begins with a capitalized word can be misread as a field, so
    exotic-looking types (`UUID:of`, `Indicates:whether`) are parser noise, not schema.
  * Types are keyed by bare name across the whole module. In a multi-package SDK such as
    google.golang.org/api or cloudflare-go, generic names like `User`, `Identity` and
    `Schedule` exist in several packages and get merged into one entry. Treat those
    results as indicative and confirm against the package you actually import.
  * Embedded structs are invisible. FIELD_RE wants a name and a type, so a bare embedded
    line such as `DeprecatableResource` never matches and neither it nor the fields it
    carries are reported. A release that adds capability by embedding therefore shows as
    no change at all: hcloud-go v2.48.0 embedded DeprecatableResource into hcloud.Image,
    giving it Deprecation, and this tool reported nothing for the module. When the notes
    mention a change you cannot see here, read the type's source before concluding the
    release was empty. EMBED_RE below is defined for this case but not yet wired in.
"""
import os
import re
import sys

TYPE_RE = re.compile(r"^type\s+([A-Z][A-Za-z0-9_]*)\s+struct\s*\{")
FIELD_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s+([^\s/]+)")
EMBED_RE = re.compile(r"^\s*(\*?[A-Za-z0-9_.]+)\s*(//.*)?$")


def parse(dirpath):
    """-> {TypeName: {field: gotype}}"""
    out = {}
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in ("vendor", "testdata", "examples", "internal")]
        for name in files:
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            try:
                src = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            lines = src.splitlines()
            i = 0
            while i < len(lines):
                m = TYPE_RE.match(lines[i])
                if not m:
                    i += 1
                    continue
                tname = m.group(1)
                fields = out.setdefault(tname, {})
                depth = 1
                i += 1
                while i < len(lines) and depth > 0:
                    line = lines[i]
                    depth += line.count("{") - line.count("}")
                    if depth > 0:
                        fm = FIELD_RE.match(line)
                        if fm and not line.strip().startswith("//"):
                            fields[fm.group(1)] = fm.group(2)
                    i += 1
    return out


def used_types(provider_dir):
    """Type names our provider source mentions (SDK-qualified or bare)."""
    seen = set()
    pat = re.compile(r"\b[a-z][a-z0-9_]*\.([A-Z][A-Za-z0-9_]*)\b")
    for root, dirs, files in os.walk(provider_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if not name.endswith(".go"):
                continue
            try:
                src = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            seen.update(pat.findall(src))
    return seen


def main():
    if len(sys.argv) < 3 or "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__)
        sys.exit(0 if len(sys.argv) > 1 else 2)

    old_dir, new_dir = sys.argv[1], sys.argv[2]
    for d in (old_dir, new_dir):
        if not os.path.isdir(d):
            print(f"not a directory: {d}\nExtract SDK versions with modfetch.sh first.", file=sys.stderr)
            sys.exit(2)

    restrict = None
    if "--types-from" in sys.argv:
        i = sys.argv.index("--types-from") + 1
        if i >= len(sys.argv):
            print("--types-from needs a provider directory", file=sys.stderr)
            sys.exit(2)
        restrict = used_types(sys.argv[i])

    old, new = parse(old_dir), parse(new_dir)

    added_types, changed = [], []
    for tname, nf in sorted(new.items()):
        if tname.startswith("Mock") or tname.endswith("Call"):
            continue
        if restrict is not None and tname not in restrict:
            continue
        of = old.get(tname)
        if of is None:
            added_types.append((tname, len(nf)))
            continue
        gained = sorted(set(nf) - set(of))
        lost = sorted(set(of) - set(nf))
        retyped = sorted(f for f in set(nf) & set(of) if nf[f] != of[f])
        if gained or lost or retyped:
            changed.append((tname, gained, lost, retyped))

    if changed:
        print("## CHANGED TYPES (fields gained / lost / retyped)")
        for tname, gained, lost, retyped in changed:
            print(f"\n{tname}")
            if gained:
                print(f"  + {', '.join(f'{g}:{new[tname][g]}' for g in gained)}")
            if lost:
                print(f"  - REMOVED: {', '.join(lost)}")
            if retyped:
                print(f"  ~ RETYPED: {', '.join(f'{r} {old[tname][r]}->{new[tname][r]}' for r in retyped)}")
    if added_types and restrict is None:
        print(f"\n## NEW TYPES ({len(added_types)})")
        for tname, n in added_types:
            print(f"  {tname} ({n} fields)")


if __name__ == "__main__":
    main()
