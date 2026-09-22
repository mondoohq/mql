#!/usr/bin/env python3
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
"""Fetch the release notes and CHANGELOG sections a module crossed between two versions.

    python3 changelog.py <module-path> <from-version> <to-version> [--full]

Read this before touching call sites. The API diff tells you *what* changed; the release
notes tell you *why* and, often, exactly how the vendor wants you to migrate -- Cloudflare
ships a v7 migration guide with before/after code, go-github lists every breaking change
with the PR that made it. Skipping them means rediscovering the same information from
compiler errors, one at a time.

It also tells you what the diff cannot: which changes are deprecations rather than
removals, and which "new" fields only populate when you pass an extra request flag. Both
decide whether a field is safe to expose.

Where it looks, in order, stopping when something useful comes back:

  1. GitHub Releases for the tags in range. Best source when present: SDKs that generate
     releases usually put the breaking-change list and migration links here.
  2. CHANGELOG.md beside the module (monorepos keep one per module) and at the repo root.
  3. Migration guide files referenced from either, fetched and inlined.

Examples:

    python3 changelog.py github.com/cloudflare/cloudflare-go/v6 v6.10.0 v7.8.0
    python3 changelog.py github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v7.0.0 v8.0.0
    python3 changelog.py go.mongodb.org/atlas-sdk/v20250312006 v20250312006.1.0 v20250312023.1.0

Pass the *old* module path; crossing a major is the normal case and the tool follows it.
Patch and minor bumps rarely need this -- most SDKs promise compatibility within a major,
so spend the time on the majors.
"""
import argparse
import http.client
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

UA = {"User-Agent": "mql-update-provider-deps"}

# Go module paths do not say where the source lives. These map the non-obvious hosts to
# (owner, repo, path-inside-repo). Anything on github.com is derived directly instead.
VANITY_REPOS = {
    "go.mongodb.org/atlas-sdk": ("mongodb", "atlas-sdk-go", ""),
    "go.mongodb.org/mongo-driver": ("mongodb", "mongo-go-driver", ""),
    "google.golang.org/api": ("googleapis", "google-api-go-client", ""),
    "google.golang.org/grpc": ("grpc", "grpc-go", ""),
    "google.golang.org/protobuf": ("protocolbuffers", "protobuf-go", ""),
    "tailscale.com": ("tailscale", "tailscale", ""),
    "helm.sh/helm": ("helm", "helm", ""),
}


def strip_major(path: str) -> str:
    return re.sub(r"/v\d+$", "", path)


def resolve_repo(module_path: str):
    """-> (owner, repo, subdir) or None. subdir is the module's path inside the repo."""
    base = strip_major(module_path)

    if base.startswith("github.com/"):
        parts = base.split("/")
        if len(parts) < 3:
            return None
        return parts[1], parts[2], "/".join(parts[3:])

    for prefix, (owner, repo, sub) in VANITY_REPOS.items():
        if base == prefix or base.startswith(prefix + "/"):
            rest = base[len(prefix):].lstrip("/")
            return owner, repo, (f"{sub}/{rest}".strip("/") if sub or rest else "")

    if base.startswith("cloud.google.com/go"):
        rest = base[len("cloud.google.com/go"):].lstrip("/")
        return "googleapis", "google-cloud-go", rest

    if base.startswith("k8s.io/"):
        return "kubernetes", base.split("/")[1], ""

    if base.startswith("sigs.k8s.io/"):
        return "kubernetes-sigs", base.split("/")[1], ""

    return None


def get(url: str, accept_404=True):
    """Fetch a URL as text, or None.

    Prefers curl. Release listings and CHANGELOGs for busy repos run to megabytes, and
    urllib gives up on those with IncompleteRead when the connection is proxied, which is
    the normal case in a sandbox. curl handles the same responses without complaint, so
    urllib is only the fallback for environments without it.
    """
    if shutil.which("curl"):
        try:
            p = subprocess.run(
                ["curl", "-sSL", "--max-time", "60", "-H", f"User-Agent: {UA['User-Agent']}",
                 "-w", "\n%{http_code}", url],
                capture_output=True, text=True, timeout=90,
            )
            if p.returncode == 0:
                text, _, code = p.stdout.rpartition("\n")
                if code.strip() == "200":
                    return text
                if code.strip() == "404" and accept_404:
                    return None
                if code.strip() in ("403", "429"):
                    print(f"# rate limited fetching {url}", file=sys.stderr)
                    return None
                print(f"# HTTP {code.strip()} fetching {url}", file=sys.stderr)
                return None
        except Exception as e:
            print(f"# curl failed on {url}: {e}", file=sys.stderr)

    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            print(f"# rate limited fetching {url}", file=sys.stderr)
        elif not (accept_404 and e.code == 404):
            print(f"# HTTP {e.code} fetching {url}", file=sys.stderr)
        return None
    except http.client.IncompleteRead as e:
        # Partial content still parses well enough to be useful.
        return e.partial.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"# error fetching {url}: {e}", file=sys.stderr)
        return None


def semver_key(v: str):
    """Sort/compare key. Stable sorts above a prerelease of the same numbers."""
    v = v.lstrip("v")
    main, _, pre = v.partition("-")
    nums = []
    for n in main.split("."):
        m = re.match(r"\d+", n)
        nums.append(int(m.group()) if m else 0)
    # pre == "" (stable) must rank above any prerelease, hence the flag.
    return (nums, 1 if pre == "" else 0, pre)


def in_range(v: str, lo: str, hi: str) -> bool:
    return semver_key(lo) < semver_key(v) <= semver_key(hi)


def version_from_tag(tag: str, subdir: str):
    """Pull the version out of a tag, handling monorepo `<subdir>/vX.Y.Z` forms."""
    t = tag
    if subdir and t.startswith(subdir + "/"):
        t = t[len(subdir) + 1:]
    t = t.rsplit("/", 1)[-1]
    return t if re.match(r"^v?\d", t) else None


def fetch_releases(owner, repo, subdir, from_ver, to_ver):
    """-> list of (version, title, body) for releases in range."""
    out = []
    for page in range(1, 6):
        body = get(f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100&page={page}")
        if not body:
            break
        try:
            rels = json.loads(body)
        except ValueError:
            break
        if not rels:
            break
        for r in rels:
            tag = r.get("tag_name") or ""
            # A monorepo tags every module; keep only this module's tags, or the
            # bare-version tags used by single-module repos.
            if subdir and "/" in tag and not tag.startswith(subdir + "/"):
                continue
            ver = version_from_tag(tag, subdir)
            if not ver or not in_range(ver, from_ver, to_ver):
                continue
            out.append((ver, r.get("name") or tag, r.get("body") or ""))
        # Releases come newest first; stop once we are below the floor.
        oldest = version_from_tag(rels[-1].get("tag_name") or "", subdir)
        if oldest and semver_key(oldest) < semver_key(from_ver):
            break
    out.sort(key=lambda x: semver_key(x[0]))
    return out


def fetch_changelog(owner, repo, subdir, from_ver, to_ver):
    """-> list of (version, body) from a CHANGELOG.md beside the module or at the root."""
    candidates = []
    for branch in ("main", "master"):
        if subdir:
            candidates.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{subdir}/CHANGELOG.md")
        candidates.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/CHANGELOG.md")

    text = None
    for url in candidates:
        text = get(url)
        if text:
            break
    if not text:
        return []

    sections = []
    for part in re.split(r"^##+ ", text, flags=re.MULTILINE)[1:]:
        head, _, body = part.partition("\n")
        m = re.search(r"(v?\d+\.\d+\.\d+[^\s)\]]*)", head)
        if not m:
            continue
        ver = m.group(1)
        if in_range(ver, from_ver, to_ver):
            sections.append((ver, body.rstrip()))
    sections.sort(key=lambda x: semver_key(x[0]))
    return sections


def find_guide_links(texts, owner, repo):
    """Release bodies often point at a migration guide instead of inlining it."""
    links = set()
    for t in texts:
        for m in re.finditer(r"\(([^)\s]*migration[^)\s]*\.md)\)", t, re.IGNORECASE):
            links.add(m.group(1))
        for m in re.finditer(r"(https://github\.com/\S*?migration\S*?\.md)", t, re.IGNORECASE):
            links.add(m.group(1))
    out = []
    for link in sorted(links):
        if link.startswith("http"):
            raw = link.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        else:
            rel = link.lstrip("./")
            raw = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{rel}"
        body = get(raw)
        if body:
            out.append((link, body))
    return out


BREAKING_RE = re.compile(r"(breaking|removed|renamed|deprecat|migrat|no longer|BREAKING CHANGE)", re.IGNORECASE)


def summarize(body: str, full: bool) -> str:
    """Release bodies can be enormous; keep the lines that decide migration work."""
    if full:
        return body
    lines = body.splitlines()
    keep, hits = [], 0
    for i, line in enumerate(lines):
        if BREAKING_RE.search(line):
            hits += 1
            start = max(0, i - 1)
            keep.extend(range(start, min(len(lines), i + 3)))
    if not hits:
        return "\n".join(lines[:25]) + ("\n  ...(truncated, pass --full)" if len(lines) > 25 else "")
    idx = sorted(set(keep))
    out, prev = [], None
    for i in idx:
        if prev is not None and i > prev + 1:
            out.append("  ...")
        out.append(lines[i])
        prev = i
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module")
    ap.add_argument("from_version")
    ap.add_argument("to_version")
    ap.add_argument("--full", action="store_true", help="print whole bodies instead of the breaking-change excerpts")
    args = ap.parse_args()

    resolved = resolve_repo(args.module)
    if not resolved:
        print(
            f"# could not map {args.module} to a source repo.\n"
            f"# Add it to VANITY_REPOS, or read the notes by hand -- `go doc {args.module}` names the project.",
            file=sys.stderr,
        )
        sys.exit(1)

    owner, repo, subdir = resolved
    print(f"# {args.module}: {args.from_version} -> {args.to_version}")
    print(f"# source: github.com/{owner}/{repo}" + (f" (module at {subdir}/)" if subdir else ""))

    bodies = []

    releases = fetch_releases(owner, repo, subdir, args.from_version, args.to_version)
    if releases:
        print(f"\n{'=' * 70}\n## GitHub Releases ({len(releases)} in range)\n{'=' * 70}")
        for ver, title, body in releases:
            print(f"\n### {ver}  {title}")
            print(summarize(body, args.full))
            bodies.append(body)
    else:
        print("\n# no GitHub Releases matched this range", file=sys.stderr)

    sections = fetch_changelog(owner, repo, subdir, args.from_version, args.to_version)
    if sections:
        print(f"\n{'=' * 70}\n## CHANGELOG.md ({len(sections)} sections in range)\n{'=' * 70}")
        for ver, body in sections:
            print(f"\n### {ver}")
            print(summarize(body, args.full))
            bodies.append(body)
    elif not releases:
        print("# no CHANGELOG.md sections matched either", file=sys.stderr)

    for link, body in find_guide_links(bodies, owner, repo):
        print(f"\n{'=' * 70}\n## Migration guide: {link}\n{'=' * 70}")
        print(body if args.full else summarize(body, full=True)[:8000])

    if not releases and not sections:
        print(
            f"\n# Nothing found. Some generated SDKs publish neither. Fall back to:\n"
            f"#   ./apidiff.sh {args.module} {args.from_version} <new-path> {args.to_version}\n"
            f"#   https://github.com/{owner}/{repo}/compare/{args.from_version}...{args.to_version}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
