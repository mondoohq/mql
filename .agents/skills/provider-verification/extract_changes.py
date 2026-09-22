#!/usr/bin/env python3
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
"""Extract changed mql provider resources and fields from a PR or commit range.

Parses the unified diff of a pull request (via `gh pr diff`) or a commit range
(via `git diff`) and reports, grouped by provider:

  * `.lr` schema changes  - added/modified resource blocks and fields, which is
                            what needs real infrastructure to verify;
  * provider `.go` files  - changed implementation files (a PR can change
                            behaviour without touching the `.lr` schema).

This is the deterministic first step of the provider-verification skill: it
turns a diff into a concrete checklist of what to provision and query.

Usage:
    extract_changes.py --pr 7701
    extract_changes.py --pr 7701 --pr 7705        # several PRs at once
    extract_changes.py --range 7bfc8787a..HEAD
    extract_changes.py --json                     # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from collections import defaultdict

# A diff file header: "diff --git a/<path> b/<path>".
FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)")
# A hunk header; the trailing text is the enclosing context (often the resource).
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@(.*)$")
# Path of a provider resource file: providers/<provider>/resources/<file>.
PROVIDER_PATH_RE = re.compile(r"providers/([^/]+)/resources/")
# A resource declaration line, e.g. "oci.dataSafe {" or
# "private azure.x.y @defaults(\"...\") {". Resource names are dotted idents.
RESOURCE_RE = re.compile(r"^(?:private\s+)?([a-zA-Z][\w.]*)\b.*\{\s*$")
# The enclosing resource named in a hunk's "@@ ... @@" context line. git
# truncates that line, so unlike RESOURCE_RE this does not require a "{".
CONTEXT_RE = re.compile(r"^(?:private\s+)?([a-zA-Z][\w.]+)")
# A field declaration line: "name type", "name() type", "name @maturity(..) t".
FIELD_RE = re.compile(r"^([a-zA-Z]\w*)(\(\))?\s+\S")


def run(cmd: list[str]) -> str:
    """Run a command and return stdout, raising RuntimeError on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {shlex.join(cmd)}\n{result.stderr.strip()}"
        )
    return result.stdout


def get_diff(prs: list[str], commit_range: str | None) -> str:
    """Collect the combined unified diff for the given PRs and/or range.

    A failure on one input (a missing PR, say) is reported to stderr and the
    remaining inputs are still processed — verifying three PRs should not be
    aborted by a typo in the fourth. The run only aborts if *nothing* was
    retrieved.
    """
    chunks: list[str] = []
    failures: list[str] = []
    sources = [(["gh", "pr", "diff", pr, "--repo", "mondoohq/mql"], f"PR {pr}")
               for pr in prs]
    if commit_range:
        sources.append((["git", "diff", commit_range], f"range {commit_range}"))

    for cmd, label in sources:
        try:
            chunks.append(run(cmd))
        except RuntimeError as err:
            failures.append(f"{label}: {err}")
            print(f"warning: skipping {label} — {err}", file=sys.stderr)

    if not chunks:
        sys.exit("no diffs could be retrieved:\n" + "\n".join(failures))
    return "\n".join(chunks)


def is_lr_schema(path: str) -> bool:
    """True for a `.lr` schema file (not generated `.lr.go` / `.lr.versions`)."""
    return path.endswith(".lr")


def is_provider_go(path: str) -> bool:
    """True for a hand-written provider `.go` file (not generated `.lr.go`)."""
    return (
        path.endswith(".go")
        and not path.endswith(".lr.go")
        and "/resources/" in path
        and not path.endswith("_test.go")
    )


def parse(diff: str) -> dict:
    """Walk the diff and bucket schema/code changes by provider."""
    # provider -> {"resources": {name: [fields]}, "go_files": set, "lr_files": set}
    out: dict[str, dict] = defaultdict(
        lambda: {"resources": defaultdict(list), "go_files": set(), "lr_files": set()}
    )

    path = provider = None
    in_lr = False
    current_resource = None

    for line in diff.splitlines():
        header = FILE_RE.match(line)
        if header:
            path = header.group(2)
            m = PROVIDER_PATH_RE.search(path)
            provider = m.group(1) if m else None
            in_lr = bool(provider) and is_lr_schema(path)
            current_resource = None
            if provider and is_provider_go(path):
                out[provider]["go_files"].add(path)
            if in_lr:
                out[provider]["lr_files"].add(path)
            continue

        if not in_lr or provider is None:
            continue

        hunk = HUNK_RE.match(line)
        if hunk:
            # The context after "@@" names the enclosing resource - this is how
            # fields added to an *existing* resource get attributed (the
            # resource's own header line is unchanged, so it never appears as
            # an added line).
            ctx = CONTEXT_RE.match(hunk.group(1).strip())
            current_resource = ctx.group(1) if ctx else None
            continue

        # Consider added lines ("+", new schema) and unchanged context lines
        # (" "). Context lines never record a field, but their resource
        # headers update the current resource: when a hunk adds fields right
        # after an existing resource's "{" line, that header is unchanged
        # context, and the stale "@@" context would otherwise misattribute the
        # fields to the *previous* resource.
        added = line.startswith("+") and not line.startswith("+++")
        context = line.startswith(" ")
        if not (added or context):
            continue
        body = line[1:].strip()
        if not body or body.startswith("//") or body in ("{", "}"):
            continue

        res = RESOURCE_RE.match(body)
        if res:
            current_resource = res.group(1)
            if added:
                # A new resource block - record it even if no fields follow.
                out[provider]["resources"].setdefault(current_resource, [])
            continue

        if not added:
            continue  # context lines only reposition current_resource
        field = FIELD_RE.match(body)
        if field and current_resource:
            name = field.group(1) + (field.group(2) or "")
            fields = out[provider]["resources"][current_resource]
            if name not in fields:
                fields.append(name)

    return out


def to_plain(parsed: dict) -> dict:
    """Convert defaultdicts/sets into plain JSON-serialisable structures."""
    return {
        provider: {
            "resources": {r: f for r, f in data["resources"].items()},
            "go_files": sorted(data["go_files"]),
            "lr_files": sorted(data["lr_files"]),
        }
        for provider, data in sorted(parsed.items())
    }


def render(parsed: dict) -> str:
    """Render a human-readable checklist of what to verify."""
    if not parsed:
        return "No provider resource changes found in the diff."
    lines: list[str] = []
    for provider, data in parsed.items():
        lines.append(f"## {provider}")
        if data["resources"]:
            lines.append("  .lr schema changes:")
            for resource, fields in sorted(data["resources"].items()):
                if fields:
                    lines.append(f"    - {resource}: {', '.join(fields)}")
                else:
                    lines.append(f"    - {resource} (new resource / no new fields)")
        else:
            lines.append("  .lr schema changes: none (code-only change)")
        if data["go_files"]:
            lines.append("  changed provider .go files:")
            for f in data["go_files"]:
                lines.append(f"    - {f}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pr", action="append", default=[], metavar="N",
                    help="pull request number or URL (repeatable)")
    ap.add_argument("--range", dest="commit_range", metavar="A..B",
                    help="commit range, e.g. 7bfc8787a..HEAD")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    if not args.pr and not args.commit_range:
        ap.error("provide --pr and/or --range")

    parsed = to_plain(parse(get_diff(args.pr, args.commit_range)))
    if args.json:
        print(json.dumps(parsed, indent=2))
    else:
        print(render(parsed))


if __name__ == "__main__":
    main()
