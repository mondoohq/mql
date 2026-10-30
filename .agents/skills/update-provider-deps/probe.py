#!/usr/bin/env python3
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
"""Probe (and optionally apply) SDK upgrades for mql providers.

Why this exists: `go get path@latest` only finds bumps within the *current* major (it
won't discover that the dep is now published at `path/v3`). For Azure SDK Go, OCI, and
the MongoDB Atlas date-stamped majors in particular, new majors live at a new path and
require import-path rewrites. This script probes proxy.golang.org for higher-major
paths, applies them across the source tree, and runs `go mod tidy && go build`.

Run it from the mql root. Paths below assume the skill directory:

  P=.agents/skills/update-provider-deps/probe.py

  python3 $P                            # probe every known provider's go.mod
  python3 $P --provider=aws,oci         # only these (providers/aws, providers/oci)
  python3 $P --provider=github --apply  # ...and upgrade them
  python3 $P --list                     # every known provider and the prefixes it scans
  python3 $P --json                     # machine-readable rows, for scripted follow-up
  python3 $P --root /path/to/mql        # locate providers/<name>/go.mod under this root
  python3 $P <path/to/go.mod>           # single-file mode: probe one go.mod
  python3 $P <path/to/go.mod> --provider=azure --apply   # ...scanned for those prefixes

Single-file mode is the escape hatch for a provider that is not in the table below
(a DB driver, a network device client): point it at that provider's go.mod directly.

When no go.mod path is given, each requested provider maps to
<root>/providers/<name>/go.mod; with no --provider, every known provider is processed.

Newest is not always correct. A provider SDK is a client for a server the customer runs, so
the version to target is the oldest one within the major that still covers our feature set --
a newer client can demand a newer server. This script cannot reason about that, so any
provider whose SDK version is constrained by server compatibility is kept out of the table
below and updated by hand. See the `nutanix` note in PROVIDER_PREFIXES.

Output legend (probe mode):
  UP   <path>@<old> -> <newpath>@<new>     stable upgrade available
  OK   <path>@<ver>                        already on latest stable major
  BETA <path>@<ver>                        new major exists only as beta/pseudo

BETA rows are reported and never applied. A new major that has only ever shipped as
beta churns its API for months before GA, and adopting one means re-doing the migration
when it stabilizes. Surface them to the user as a separate list rather than folding them
into the upgrade set.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


# Each cloud is matched by one or more module path prefixes. The probe logic is identical
# across clouds; the prefixes just decide which deps to scan. A key must equal the mql
# provider's directory name, since discovery mode resolves it to providers/<key>/go.mod.
#
# Only providers that vendor a real platform SDK are listed. Providers that talk to their
# API over hand-rolled HTTP (vercel, netlify, neon, nextdns, proxmox, clickhousecloud,
# mistral, huggingface, vllm, grafana, iru, artifactory, bitwarden, jumpcloud, keycloak,
# zoom) have nothing to probe. Deliberately out of scope: DB drivers (mysqldb, postgresdb,
# redisdb, mssql, cassandra, clickhousedb), network and hardware protocol clients (arista,
# mikrotik, redfish, ipmi, opcua, nmap, activedirectory) and IaC tooling (terraform, helm,
# kustomize, cloudformation, ansible) — pass their go.mod in single-file mode if you ever
# want them.
#
# equinix vendors github.com/packethost/packngo but the provider is queued for removal
# (PR #9734), so it is left out rather than wired up.
#
# nutanix is EXCLUDED ON PURPOSE — do not add it back. Its SDK version is dictated by the
# Prism Central release the customer runs, not by what is newest: the v4.1+ clients request
# /api/<svc>/v4.2/... paths that GA Prism Central answers with 404, which breaks every
# non-IAM resource (customer issue #222, PR #8917). providers/nutanix/go.mod holds the
# require lines at v4.0.x with `// pin` markers and backs them with replace directives;
# this script reads neither, so pointing it at that file only desynchronizes the two.
# Nutanix bumps are a manual change, gated on the minimum supported Prism Central.
PROVIDER_PREFIXES = {
    # --- hyperscalers / IaaS ---
    "oci":            ("github.com/oracle/oci-go-sdk",),
    "aws":            ("github.com/aws/",),
    "azure":          ("github.com/Azure/", "github.com/AzureAD/"),
    "gcp":            ("cloud.google.com/go", "google.golang.org/api"),
    "alicloud":       ("github.com/alibabacloud-go/", "github.com/aliyun/"),
    "digitalocean":   ("github.com/digitalocean/godo",),
    "hetzner":        ("github.com/hetznercloud/hcloud-go",),
    "openstack":      ("github.com/gophercloud/",),
    "stackit":        ("github.com/stackitcloud/stackit-sdk-go",),
    "hcp":            ("github.com/hashicorp/hcp-sdk-go",),

    # --- private cloud / virtualization ---
    "vsphere":        ("github.com/vmware/govmomi",),
    "vcd":            ("github.com/vmware/go-vcloud-director",),
    "portainer":      ("github.com/portainer/",),

    # --- kubernetes ---
    "k8s":            ("k8s.io/", "sigs.k8s.io/"),

    # --- identity / productivity SaaS ---
    "ms365":          ("github.com/microsoftgraph/", "github.com/microsoft/kiota", "github.com/Azure/"),
    "google-workspace": ("google.golang.org/api",),
    "okta":           ("github.com/okta/okta-sdk-golang",),
    "auth0":          ("github.com/auth0/go-auth0",),
    "jamf":           ("github.com/deploymenttheory/go-api-sdk-jamfpro",),
    "atlassian":      ("github.com/ctreminiom/go-atlassian",),
    "slack":          ("github.com/slack-go/slack",),
    # community-maintained, not published by Dropbox: read the repo's commit history
    # before treating a quiet release feed as "current".
    "dropbox":        ("github.com/dropbox/dropbox-sdk-go-unofficial",),

    # --- devops / SCM SaaS ---
    "github":         ("github.com/google/go-github/", "github.com/bradleyfalzon/ghinstallation"),
    "gitlab":         ("gitlab.com/gitlab-org/",),
    "databricks":     ("github.com/databricks/databricks-sdk-go",),
    "datadog":        ("github.com/DataDog/",),
    "cloudflare":     ("github.com/cloudflare/cloudflare-go",),
    "tailscale":      ("tailscale.com/",),

    # --- data platforms ---
    "snowflake":      ("github.com/snowflakedb/gosnowflake", "github.com/Snowflake-Labs/"),
    "mongodbatlas":   ("go.mongodb.org/atlas-sdk",),
    "mongo":          ("go.mongodb.org/mongo-driver",),
    "elasticsearch":  ("github.com/elastic/",),
    "opensearch":     ("github.com/opensearch-project/",),
    "weaviate":       ("github.com/weaviate/",),

    # --- AI platforms ---
    "openai":         ("github.com/openai/openai-go",),
    "claude":         ("github.com/anthropics/",),
    "together":       ("github.com/togethercomputer/",),
    "ollama":         ("github.com/ollama/ollama",),

    # --- intel / misc APIs ---
    "shodan":         ("github.com/shadowscatcher/shodan",),
    "ipinfo":         ("github.com/ipinfo/go",),
}

# Providers whose SDK version is pinned by something this script cannot see, keyed to
# the reason. Naming one is an error rather than a no-op, because the failure mode is
# silent: the bump builds fine and breaks only against the customer's server.
HELD_BACK = {
    "nutanix": (
        "its SDK version is set by the Prism Central release the customer runs, not by "
        "what is newest. The v4.1+ clients request /api/<svc>/v4.2/... paths that GA "
        "Prism Central answers with 404, breaking every non-IAM resource (customer issue "
        "#222, PR #8917). providers/nutanix/go.mod holds the require lines at v4.0.x with "
        "`// pin` markers backed by replace directives, and this script reads neither. "
        "Bump it by hand, gated on the minimum supported Prism Central."
    ),
}

PSEUDO_RE = re.compile(r"-\d{14}-[0-9a-f]{12}$")
PRERELEASE_RE = re.compile(r"-(alpha|beta|rc|pre|dev)")
# How many majors above the current one to probe. The probe loop stops at the first 404,
# so this is only an upper bound, not a per-dep cost: a dep already on its highest major
# spends exactly one wasted request regardless. It has to be generous because some SDKs
# version by date stamp and rev the major constantly — MongoDB Atlas alone sits ~10 majors
# above what we pin (v20250312006 -> v2025031201x), which a cap of 5 silently under-reports.
PROBE_MAJOR_RANGE = 30


def is_stable(version: str) -> bool:
    if not version or not version.startswith("v"):
        return False
    if PSEUDO_RE.search(version):
        return False
    if PRERELEASE_RE.search(version):
        return False
    return True


def encode_proxy_path(path: str) -> str:
    """proxy.golang.org requires capitals in module paths to be `!lowercase`."""
    return "".join(("!" + c.lower()) if c.isupper() else c for c in path)


def _fetch(url: str, retries: int = 2):
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return None
            if attempt == retries - 1:
                return None
        except Exception:
            if attempt == retries - 1:
                return None
        time.sleep(0.4 * (attempt + 1))
    return None


def fetch_latest(path: str):
    body = _fetch(f"https://proxy.golang.org/{encode_proxy_path(path)}/@latest")
    if not body:
        return None
    try:
        return json.loads(body).get("Version")
    except Exception:
        return None


def fetch_versions(path: str):
    body = _fetch(f"https://proxy.golang.org/{encode_proxy_path(path)}/@v/list")
    if not body:
        return []
    return [v for v in body.decode().splitlines() if v]


def _semver_key(s: str):
    parts = s.lstrip("v").split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return out


def stable_from_versions(path: str):
    versions = [v for v in fetch_versions(path) if is_stable(v)]
    if not versions:
        return None
    versions.sort(key=_semver_key)
    return versions[-1]


def probe_path(path: str):
    """Return (latest_any, latest_stable). Both None if path doesn't exist."""
    latest_any = fetch_latest(path)
    if latest_any is None:
        return None, None
    if is_stable(latest_any):
        return latest_any, latest_any
    return latest_any, stable_from_versions(path)


def parse_path(full_path: str):
    """Split 'github.com/foo/bar/v3' -> ('github.com/foo/bar', 3)."""
    m = re.match(r"^(.+)/v(\d+)$", full_path)
    if m:
        return m.group(1), int(m.group(2))
    return full_path, 1


def parse_gomod(go_mod_path: str, allowed_prefixes: tuple):
    """Yield (module_path, version) for every direct dep matching allowed_prefixes.

    Indirect deps (lines marked `// indirect`) are skipped — they're transitive and will
    be reconciled by `go mod tidy` after the direct deps are bumped.
    """
    text = open(go_mod_path).read()
    for raw in text.splitlines():
        line = raw.strip()
        if "// indirect" in line:
            continue
        if "//" in line:
            line = line[: line.index("//")].strip()
        m = re.match(r"^([^\s]+)\s+(v[0-9][^\s]*)", line)
        if not m:
            continue
        mod_path, ver = m.group(1), m.group(2)
        if any(mod_path.startswith(p) for p in allowed_prefixes):
            yield mod_path, ver


def probe_one(full_path: str, current_ver: str, include_beta: bool):
    """Probe for the highest available major above the current one."""
    base, current_major = parse_path(full_path)

    stable_highest = None
    beta_highest = None
    for n in range(current_major + 1, current_major + 1 + PROBE_MAJOR_RANGE):
        candidate = f"{base}/v{n}"
        latest_any, latest_stbl = probe_path(candidate)
        if latest_any is None:
            # Sequential majors: first 404 means no further majors exist.
            break
        if latest_stbl:
            stable_highest = (n, latest_stbl)
        elif not is_stable(latest_any):
            beta_highest = (n, latest_any)

    if stable_highest:
        n, v = stable_highest
        return ("UP", full_path, current_ver, f"{base}/v{n}", v)
    if include_beta and beta_highest:
        n, v = beta_highest
        return ("UP", full_path, current_ver, f"{base}/v{n}", v)
    if beta_highest:
        n, v = beta_highest
        return ("BETA", full_path, current_ver, f"{base}/v{n}", v)

    # Same major: report latest patch/minor.
    _, latest_patch = probe_path(full_path)
    if latest_patch and latest_patch != current_ver:
        return ("UP", full_path, current_ver, full_path, latest_patch)
    return ("OK", full_path, current_ver, "", "")


def format_row(row):
    status, cur_path, cur_ver, new_path, new_ver = row
    if status == "UP":
        return f"UP   {cur_path}@{cur_ver} -> {new_path}@{new_ver}"
    if status == "BETA":
        return f"BETA {cur_path}@{cur_ver}  (new major only as {new_ver}; staying)"
    return f"OK   {cur_path}@{cur_ver}"


def collect_upgrades(deps, include_beta: bool, quiet: bool = False):
    upgrades = []
    print(f"# probing {len(deps)} deps...", file=sys.stderr, flush=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(probe_one, p, v, include_beta): (p, v) for p, v in deps}
        for f in as_completed(futs):
            row = f.result()
            if not quiet:
                print(format_row(row), flush=True)
            upgrades.append(row)
    return upgrades


def rewrite_imports(module_dir: str, old_path: str, new_path: str):
    """Rewrite import path in every .go file under module_dir. Returns count of files touched."""
    if old_path == new_path:
        return 0
    touched = 0
    # Match the path inside double-quoted import strings (Go imports are always quoted).
    # Anchor with a quote on both sides so 'foo/bar' doesn't accidentally match 'foo/barbaz'.
    pattern = re.compile(r'"' + re.escape(old_path) + r'(?P<sub>(/[^"]*)?)"')
    replacement = lambda m: f'"{new_path}{m.group("sub")}"'

    for root, dirs, files in os.walk(module_dir):
        # Skip vendor/ and hidden directories.
        dirs[:] = [d for d in dirs if d != "vendor" and not d.startswith(".")]
        for name in files:
            if not name.endswith(".go"):
                continue
            full = os.path.join(root, name)
            try:
                with open(full, "r", encoding="utf-8") as f:
                    src = f.read()
            except (OSError, UnicodeDecodeError):
                continue
            new_src, n = pattern.subn(replacement, src)
            if n > 0:
                with open(full, "w", encoding="utf-8") as f:
                    f.write(new_src)
                touched += 1
    return touched


def edit_gomod(go_mod_path: str, old_path: str, old_ver: str, new_path: str, new_ver: str):
    """Replace `old_path old_ver` with `new_path new_ver` in go.mod, preserving any trailing
    comment (e.g. `// indirect`)."""
    with open(go_mod_path, "r") as f:
        text = f.read()
    # Match the dep line, capture leading whitespace and trailing comment.
    pat = re.compile(
        r"^(?P<indent>\s*)" + re.escape(old_path) + r"\s+" + re.escape(old_ver) + r"(?P<tail>\s*(//.*)?)$",
        re.MULTILINE,
    )
    new_text, n = pat.subn(lambda m: f"{m.group('indent')}{new_path} {new_ver}{m.group('tail')}", text)
    if n == 0:
        # Fallback: line might have unusual spacing. Do a looser, line-based match.
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(old_path + " "):
                tokens = stripped.split(None, 2)
                if len(tokens) >= 2 and tokens[0] == old_path and tokens[1] == old_ver:
                    indent = line[: len(line) - len(line.lstrip())]
                    rest = "" if len(tokens) < 3 else " " + tokens[2]
                    lines[i] = f"{indent}{new_path} {new_ver}{rest}\n"
                    n = 1
                    break
        new_text = "".join(lines)
    if n == 0:
        raise RuntimeError(f"could not find {old_path} {old_ver} in {go_mod_path}")
    with open(go_mod_path, "w") as f:
        f.write(new_text)


def apply_upgrades(go_mod_path: str, upgrades):
    module_dir = os.path.dirname(os.path.abspath(go_mod_path))
    applied = []
    for status, cur_path, cur_ver, new_path, new_ver in upgrades:
        if status != "UP":
            continue
        major_change = cur_path != new_path
        if major_change:
            files = rewrite_imports(module_dir, cur_path, new_path)
            print(f"  rewrote imports in {files} file(s): {cur_path} -> {new_path}", flush=True)
        edit_gomod(go_mod_path, cur_path, cur_ver, new_path, new_ver)
        applied.append((cur_path, cur_ver, new_path, new_ver, major_change))

    if not applied:
        print("nothing to apply.", flush=True)
        return

    print("\nrunning `go mod tidy`...", flush=True)
    subprocess.run(["go", "mod", "tidy"], cwd=module_dir, check=True)
    print("running `go build ./...`...", flush=True)
    result = subprocess.run(["go", "build", "./..."], cwd=module_dir)
    if result.returncode != 0:
        print(
            "\nbuild failed. Likely a breaking change in one of the new majors — review CHANGELOGs and patch call sites.",
            file=sys.stderr,
        )
        sys.exit(result.returncode)
    print("\nsummary:", flush=True)
    for cur_path, cur_ver, new_path, new_ver, major in applied:
        tag = "[major]" if major else "[minor]"
        print(f"  {tag} {cur_path}@{cur_ver} -> {new_path}@{new_ver}", flush=True)


def process_gomod(go_mod_path: str, prefixes: tuple, include_beta: bool, apply: bool, rows: list = None):
    """Probe (and optionally apply) upgrades for one go.mod, scanning only `prefixes`.

    `rows` collects structured results for --json; pass None to skip collection.
    """
    deps = list(parse_gomod(go_mod_path, prefixes))
    if not deps:
        print(f"no matching deps found in {go_mod_path}", file=sys.stderr)
        return

    upgrades = collect_upgrades(deps, include_beta, quiet=rows is not None)

    if rows is not None:
        for status, cur_path, cur_ver, new_path, new_ver in upgrades:
            rows.append(
                {
                    "goMod": go_mod_path,
                    "status": status,
                    "path": cur_path,
                    "version": cur_ver,
                    "newPath": new_path or None,
                    "newVersion": new_ver or None,
                    # A major change means the module path moves, so every import
                    # of it has to be rewritten. That is the expensive kind.
                    "majorChange": bool(new_path) and new_path != cur_path,
                }
            )

    if not apply:
        ups = [u for u in upgrades if u[0] == "UP"]
        betas = [u for u in upgrades if u[0] == "BETA"]
        if rows is None:
            print(f"# {len(ups)} upgradeable, {len(betas)} beta-only. Re-run with --apply to upgrade.", flush=True)
        return

    apply_upgrades(go_mod_path, upgrades)


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "go_mod",
        nargs="?",
        help="path to a single go.mod file. Omit to scan every requested provider's "
        "go.mod under <root>/providers/<name>/go.mod.",
    )
    p.add_argument("--apply", action="store_true", help="actually upgrade (default: probe only)")
    p.add_argument("--include-beta", action="store_true", help="upgrade to beta/pre-release majors too")
    p.add_argument("--list", action="store_true", help="list every known provider with its module prefixes, then exit")
    p.add_argument("--json", action="store_true", help="emit structured rows on stdout instead of the text legend")
    p.add_argument(
        "--max-majors",
        type=int,
        default=PROBE_MAJOR_RANGE,
        help=f"how many majors above the current one to probe (default: {PROBE_MAJOR_RANGE})",
    )
    p.add_argument(
        "--root",
        default=".",
        help="mql project root used to locate providers/<name>/go.mod when go_mod is omitted (default: .)",
    )
    p.add_argument(
        "--provider",
        "--cloud",  # kept so older invocations and muscle memory still work
        dest="provider",
        default=",".join(PROVIDER_PREFIXES),
        help=f"comma-separated subset of providers to update (default: all {len(PROVIDER_PREFIXES)}; see --list)",
    )
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    if args.list:
        width = max(len(c) for c in PROVIDER_PREFIXES)
        for name, prefixes in PROVIDER_PREFIXES.items():
            print(f"{name:<{width}}  {', '.join(prefixes)}")
        return

    global PROBE_MAJOR_RANGE
    PROBE_MAJOR_RANGE = args.max_majors

    requested = [c.strip() for c in args.provider.split(",") if c.strip()]

    # Naming an excluded provider is almost always someone assuming the omission
    # was an oversight, so answer with the reason rather than "unknown provider"
    # and let them go look for the escape hatch.
    for name in requested:
        if name in HELD_BACK:
            print(f"{name} is deliberately excluded: {HELD_BACK[name]}", file=sys.stderr)
            sys.exit(2)

    unknown = [c for c in requested if c not in PROVIDER_PREFIXES]
    if unknown:
        print(
            f"unknown provider(s): {unknown}. Valid: {list(PROVIDER_PREFIXES)}\n"
            "For a provider that is not in the table, pass its go.mod path directly.",
            file=sys.stderr,
        )
        sys.exit(2)

    rows = [] if args.json else None

    # Single-file mode: explicit go.mod, scanned for every requested provider's prefixes.
    if args.go_mod:
        if not os.path.isfile(args.go_mod):
            print(f"not a file: {args.go_mod}", file=sys.stderr)
            sys.exit(2)
        prefixes = tuple(p for c in requested for p in PROVIDER_PREFIXES[c])
        process_gomod(args.go_mod, prefixes, args.include_beta, args.apply, rows)
        if rows is not None:
            json.dump(rows, sys.stdout, indent=2)
            print()
        return

    # Discovery mode: each provider maps to providers/<name>/go.mod under the project root.
    missing = []
    for name in requested:
        go_mod = os.path.join(args.root, "providers", name, "go.mod")
        if not os.path.isfile(go_mod):
            missing.append(name)
            continue
        if rows is None:
            print(f"\n===== {name} ({go_mod}) =====", flush=True)
        before = len(rows) if rows is not None else 0
        process_gomod(go_mod, PROVIDER_PREFIXES[name], args.include_beta, args.apply, rows)
        if rows is not None:
            for r in rows[before:]:
                r["provider"] = name

    if rows is not None:
        json.dump(rows, sys.stdout, indent=2)
        print()

    if missing:
        providers_dir = os.path.join(args.root, "providers")
        print(f"\n# no provider go.mod found for: {missing} (looked under {providers_dir})", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
