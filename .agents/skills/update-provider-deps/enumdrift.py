#!/usr/bin/env python3
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
"""Find .lr field comments that enumerate values the SDK no longer agrees with.

    python3 enumdrift.py <provider.lr> <extracted-sdk-dir> [--field NAME]

Why this exists: `.lr` comments routinely spell out a field's possible values
("One of Primary, Readonly, Guard, or Temp"). Those lists are a promise to the
person writing a policy -- they decide which `where(state == "...")` clauses get
written -- and nothing keeps them honest when an SDK upgrade adds a state. The
list silently becomes wrong, and a policy that enumerates the documented values
starts missing rows it should match.

The check is a *comparison aid*, not a linter. It pairs each enumerated comment
with the SDK constant block whose values it quotes, then reports what the SDK has
that the comment does not. Read the pairs before editing: a comment can list a
deliberate subset (the values we actually map), and the matcher can pair the
wrong constant block when several enums share vocabulary. Both are for a human
to judge, which is why the output is a report rather than a diff to apply.

Only comments that *claim* completeness are reported. "One of A, B, or C" is a
promise and a missing value breaks it; "such as A or B" is explicitly an example
and is allowed to be partial forever. Without that distinction the handful of
real defects drown in every field that happens to give an example. Pass
--include-illustrative to see the example-phrased ones too, which is worth doing
when deciding whether one of them ought to become exhaustive.

Matching is case-sensitive on purpose. Enum values carry their case (`gitHub`,
not `GITHUB`), so an exact match is good evidence the comment is quoting that
constant rather than coincidentally sharing a word -- and a discriminator whose
values this provider invents itself will not pair with an unrelated SDK enum.

Scope limit worth knowing up front: this only works on SDKs that declare typed
string constants. Azure, Databricks, GCP and Nutanix do; several
OpenAPI-generated ones -- go-github, okta, the Atlas SDK -- type every enum field
as a plain string, and there is nothing to compare against. The tool says so
rather than reporting a clean run, because "0 drifted" and "nothing to check"
mean very different things.

Typical use, after extracting both SDK versions with modfetch.sh:

    python3 enumdrift.py providers/aws/resources/aws.lr mods/<new-sdk-dir>

Restrict to one field while iterating:

    python3 enumdrift.py providers/okta/resources/okta.lr mods/<dir> --field status
"""
import argparse
import os
import re
import sys

# Values enumerated in prose. `.lr` comments write these several ways:
#   One of A, B, or C.        One of "A" or "B".
#   such as A or B            (A, B, or C)
# Captured loosely, then split on separators, because the goal is to notice a
# missing value rather than to parse English.
# Two kinds of enumerating clause, and the difference decides whether a missing value
# is a defect at all. "One of A, B, or C" claims completeness, so a value the SDK has
# and the comment lacks is drift a policy author can be misled by. "such as A or B" is
# explicitly illustrative and is allowed to be partial forever. Reporting both as drift
# buries the handful of real defects under every field that gives an example.
EXHAUSTIVE_LEAD = r"one of|either|values? are|valid values|possible values"
ILLUSTRATIVE_LEAD = r"such as|for example|e\.g\.|including|includes|include"

ENUM_PROSE_RE = re.compile(
    rf"(?P<lead>{EXHAUSTIVE_LEAD}|{ILLUSTRATIVE_LEAD}):?\s+(?P<body>[^.]*)", re.IGNORECASE
)
EXHAUSTIVE_RE = re.compile(rf"^({EXHAUSTIVE_LEAD})$", re.IGNORECASE)

# A candidate value inside that prose: BAREWORD, "quoted", or `backticked`.
# Enum values in these APIs are overwhelmingly single tokens.
VALUE_RE = re.compile(r'[`"]?([A-Za-z][A-Za-z0-9_.-]{1,60})[`"]?')

# Connective words that appear inside an enumeration but are not values. Matched
# against the all-lowercase form only, never case-insensitively, because several of
# these also ship as real constants in SCREAMING_CASE. Filtering "none" without regard
# to case hid a genuine NONE from the Databricks access-mode comment and reported the
# comment as missing a value it already documented.
STOPWORDS = {
    "one", "of", "or", "and", "either", "such", "as", "the", "a", "an", "is", "are",
    "value", "values", "for", "to", "in", "on", "when", "which", "that", "this",
    "empty", "null", "unset", "none", "other", "others", "kinds", "etc", "example",
    "instance", "default", "defaults", "set", "not", "it", "its", "be", "by", "with",
    "include", "includes", "including", "disables", "enables", "means", "only",
}

# A `.lr` field declaration: `name type`, `name() type`, either with @tags between.
FIELD_DECL_RE = re.compile(r"^\s*([a-z][A-Za-z0-9_]*)\s*(?:\(\))?\s*(?:@[^\s]+\s*)*(?:[\[\]A-Za-z]|map)")

# type X string  +  const XFoo X = "FOO" / `FOO`
GO_CONST_RE = re.compile(
    r"^\s*(?:const\s+)?([A-Za-z][A-Za-z0-9_]*)\s+([A-Za-z][A-Za-z0-9_.]*)\s*=\s*[`\"]([^`\"]+)[`\"]",
    re.MULTILINE,
)


def lr_fields_with_enums(lr_path: str):
    """Yield (field, line_no, values, comment) for each .lr field whose doc enumerates values."""
    lines = open(lr_path, encoding="utf-8", errors="replace").read().splitlines()
    out = []
    buf = []
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("//"):
            buf.append(s.lstrip("/").strip())
            continue
        m = FIELD_DECL_RE.match(s)
        if m and buf:
            comment = " ".join(buf)
            cands, exhaustive = extract_candidates(comment)
            if cands:
                out.append((m.group(1), i + 1, cands, exhaustive, comment))
        if not s.startswith("//"):
            buf = []
    return out


def extract_candidates(comment: str):
    """Pull every plausible value token out of an enumerating doc comment.

    Deliberately permissive. An earlier version tried to tell values from prose by
    their shape -- SCREAMING_CASE or camelCase in, bare lowercase words out -- and
    threw away real values in the process: `anthropic`, `cohere`, `openai` and `palm`
    are all genuine Databricks constants and all look exactly like English words.

    Rather than guess, this hands everything to the matcher and lets the SDK decide.
    A token that is really prose will not appear in any constant block, so it drops
    out on its own; a lowercase token that is really a value gets matched. The only
    filtering here is of connectives that would otherwise pad the candidate set.
    """
    m = ENUM_PROSE_RE.search(comment)
    if not m:
        return set(), False
    cands = {c for c in VALUE_RE.findall(m.group("body")) if c not in STOPWORDS}
    exhaustive = bool(EXHAUSTIVE_RE.match(m.group("lead").strip()))
    return (cands, exhaustive) if len(cands) >= 2 else (set(), False)


def sdk_const_groups(sdk_dir: str):
    """-> {type_name: {value, ...}} for every Go string-const enum in the tree."""
    groups = {}
    for root, dirs, files in os.walk(sdk_dir):
        dirs[:] = [d for d in dirs if d not in ("vendor", "testdata", "examples")]
        for name in files:
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            try:
                src = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for _const_name, type_name, value in GO_CONST_RE.findall(src):
                groups.setdefault(type_name, set()).add(value)
    return {k: v for k, v in groups.items() if len(v) >= 2}


def best_match(candidates, groups):
    """Pick the SDK enum that best explains the comment's tokens.

    Matching is case-SENSITIVE, which does real work here. Enum values carry their
    case (`gitHub`, not `GITHUB`), so an exact match is strong evidence the comment is
    quoting that constant. It also keeps provider-invented vocabulary from pairing with
    an unrelated SDK enum: a discriminator whose values this provider defines itself in
    snake_case will not match an SDK enum spelling them in SCREAMING_CASE, and so is
    correctly left alone instead of being reported as drifted.

    Ranked on the number of values matched first, since that is what makes an enum a
    plausible explanation at all, then on tightness of fit, because unrelated enums
    share vocabulary -- USER, GROUP and SERVICE_PRINCIPAL appear in half a dozen types
    -- and the enum with least left over is the likeliest one.
    """
    best, best_score, best_hits = None, (0, 0.0), set()
    for type_name, sdk_vals in groups.items():
        hits = candidates & sdk_vals
        if len(hits) < 2:
            continue
        score = (len(hits), len(hits) / len(sdk_vals))
        if score > best_score:
            best, best_score, best_hits = type_name, score, hits
    return best, best_hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lr_file")
    ap.add_argument("sdk_dir")
    ap.add_argument("--field", help="only report this field name")
    ap.add_argument(
        "--include-illustrative",
        action="store_true",
        help="also report comments phrased as examples (\"such as A or B\"), which are "
        "allowed to be partial. Useful when deciding whether one should become exhaustive.",
    )
    ap.add_argument(
        "--min-values",
        type=int,
        default=2,
        help="how many of an SDK enum's values a comment must quote exactly before the two "
        "are considered the same enum (default: 2)",
    )
    args = ap.parse_args()

    fields = lr_fields_with_enums(args.lr_file)
    if not fields:
        print(f"no .lr fields with enumerated values found in {args.lr_file}", file=sys.stderr)
        return
    if args.field:
        fields = [f for f in fields if f[0] == args.field]
        if not fields:
            # Distinguish "that field has no enumerated comment" from "that field does
            # not exist here", which otherwise reads the same and sends you looking in
            # the wrong place.
            exists = any(
                (m := FIELD_DECL_RE.match(line)) and m.group(1) == args.field
                for line in open(args.lr_file, encoding="utf-8", errors="replace")
            )
            why = "does not enumerate values in its comment" if exists else f"is not declared in {args.lr_file}"
            print(f"{args.field} {why}", file=sys.stderr)
            return

    groups = sdk_const_groups(args.sdk_dir)
    if not groups:
        # Not a failure, and not a clean bill of health either. Plenty of SDKs --
        # most OpenAPI-generated ones, including go-github, okta and atlas -- model
        # every enum as a plain string with no constants to compare against. Say so,
        # so nobody reads silence as "the comments were checked and were fine".
        print(
            f"no Go string-const enums declared in {args.sdk_dir}.\n"
            "This SDK types its enum fields as plain strings, so there is nothing to compare\n"
            "comments against here. Verify enumerated values against the vendor's API docs\n"
            "instead; this check cannot cover them.",
            file=sys.stderr,
        )
        return

    drifted, checked, unpaired, illustrative = 0, 0, 0, 0
    for field, line, candidates, exhaustive, comment in fields:
        match, hits = best_match(candidates, groups)
        if not match or len(hits) < args.min_values:
            unpaired += 1
            continue
        checked += 1
        sdk_vals = groups[match]
        missing = sorted(sdk_vals - hits)
        if not missing:
            continue
        if not exhaustive and not args.include_illustrative:
            illustrative += 1
            continue
        drifted += 1
        kind = "" if exhaustive else "  [illustrative: allowed to be partial]"
        print(f"\n{args.lr_file}:{line}  {field}{kind}")
        print(f"  comment quotes: {', '.join(sorted(hits))}")
        print(f"  SDK enum      : {match} ({len(hits)}/{len(sdk_vals)} values documented)")
        print(f"  not documented: {', '.join(missing)}")

    print(
        f"\n# {checked} enumerated field(s) paired with an SDK enum, {drifted} reported, "
        f"{illustrative} skipped as illustrative, {unpaired} unpaired (no confident match).",
        file=sys.stderr,
    )
    if drifted:
        print(
            "# Each hit is a candidate, not a verdict. Confirm the paired enum is the one the "
            "field actually carries, and that the omission is not deliberate, before editing.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
