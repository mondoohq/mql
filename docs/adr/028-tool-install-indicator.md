# ADR 028: Install Indicator for Tools via a Package Reference

## Status

Accepted

## Context

The `os` provider now models a growing family of developer tools as first-class
resources. The AI/LLM coding tools are the first large cohort — 26 of them today,
all `@maturity("preview")`:

`claude.code`, `openai.codex`, `cursor`, `github.copilot`, `goose`, `gemini`,
`windsurf`, `zed`, `roo`, `cline`, `kiro`, `continuedev`, `trae`, `opencode`, `pi`,
`mistral.vibe`, `antigravity`, `ibm.bob`, `openclaw`, `snowflake.cortex`, `junie`,
`augment`, `warp`, `kilocode`, `openhands`, `qwen.code`.

Each is keyed on a `configPath` that a shared init helper resolves from the target
user's home directory (`initConfigPath` / `targetHomeDir` in
`providers/os/resources/ai_coding_tools.go`). The resource is instantiated whether or
not the tool is actually present: init just computes a default `~/.<tool>` path.
Presence is only *implied* — by whether sub-resources such as `skills()` or
`mcpServers()` happen to come back non-empty.

**There is no signal that tells an audit whether a tool is installed.** A policy that
wants "is Cursor installed on this host?" has nothing to assert against.

The naive fix is a boolean (`installed bool`) on each tool. That answers the yes/no
question but throws away everything else a reader wants to know: which version,
where it came from, whether it is outdated, its CPEs for vulnerability correlation.
All of that already exists — on the `package` resource
(`providers/os/resources/os.lr:875`), which carries `name`, `version`, `installed`,
`available`, `outdated()`, `purl`, `cpes`, `vendor`, `installDate`, `files()`, and
more, and which already supports lookup by name via `initPackage`
(`providers/os/resources/packages.go:42`).

So the better indicator is not a boolean but a **reference to the package behind the
tool**: `tool.package.installed` answers the yes/no question, and `tool.package.*`
delivers the rest for free, through a resource users and policies already understand.

The complication is that a tool is not always installed by a system package manager.
It may be a standalone binary dropped in `~/.local/bin`, an editor application, an npm
global, a `curl | sh` install, or a vendored bundle. In those cases there is no
`deb`/`rpm`/`brew`/`msi` entry to point at — yet the tool is unmistakably present. We
still want `tool.package` to return *something* that says "this tool belongs to some
package; we just cannot identify its source," ideally with a version we infer per
tool.

This model is intended for **tools in general**. AI tools are simply where it starts.

## Decision

Expose the install indicator as a `package()` accessor on each tool resource, returning
the standard `package` resource. When the install can be traced to a system package
manager, return that real, manager-tracked package. When it cannot, return an
**abstract package** — a `package` instance that reuses the same resource and is marked
as not manager-tracked using existing fields only.

### Install indicator: `tool.package`

Every tool resource gains one field:

```
// Package that installed this tool
//
// Resolves to the system-package-manager entry that installed the tool when
// one can be identified; otherwise an abstract package (see below) that
// records the tool's presence and, where possible, an inferred version.
package() package
```

The install signal is then `tool.package.installed`, and the full package surface is
available:

```mql
claude.code.package.installed        // true
cursor.package.installed             // false
cursor.package { name version origin format }
openai.codex.package.version         // inferred per tool
```

No separate `installed bool` is added to the tool resource — the package *is* the
indicator.

### Real package resolution

`package()` attributes the tool to a real package through two signals, strongest first.
Whichever wins, the returned package is resolved by name through `initPackage`, so it is
the *same* cached instance that `packages.list()` built — `cursor.package` and
`packages.where(name == "cursor")[0]` are one and the same object, with a real `format`,
`origin`, `version`, `purl`, and `cpes`. `package()` never synthesizes its own package
when the system owns the tool.

1. **Binary ownership (primary).** Resolve the tool's binary on the target's `PATH` (via
   `command -v`, following symlinks) and ask the active package manager which package owns
   that path. This is a capability on the package-manager layer —
   `PkgFileOwnershipResolver.FindFileOwner` in `providers/os/resources/packages`, the
   inverse of the existing `Files()` — implemented for pacman (`pacman -Qo`), dpkg
   (`dpkg -S`), rpm (`rpm -qf`), and apk (`apk info --who-owns`). Because it matches on the
   *file*, it attributes a tool correctly no matter what its package is named. The owning
   package name is then resolved to its real `packages` entry.

2. **Candidate names (fallback).** When binary ownership finds no owner (the binary is not
   on `PATH`, or no manager owns it — e.g. an npm-global install), fall back to the
   name-based `initPackage` lookup against one or more per-tool candidate package names.
   This is conservative: it only attributes a tool whose package is *named like the tool*.

A tool's `binaryNames` are omitted when the binary name is ambiguous (bare `goose`
collides with the pressly/goose DB-migration tool; `gemini` is not distinctive), so it is
not mis-attributed to an unrelated package; such tools rely on candidate names only.
Tools that match neither signal fall back to an abstract package.

### The abstract package

When no manager candidate matches but the tool is detected present, `package()`
synthesizes an **abstract package**:

> An **abstract package** is a `package` resource that represents a tool we detected on
> the asset but cannot attribute to any system package manager. It asserts only that
> *some* package installed the tool; the exact source is unknown. It reuses the standard
> `package` resource, so `tool.package` exposes the familiar surface (`name`,
> `installed`, `version`, `purl`, `cpes`, `vendor`). It is distinguished from a
> manager-tracked package by three facts:
>
> 1. **`origin == "unknown"`** — the source is not known. Had it been known, the tool
>    would already resolve to a regular, manager-tracked package. This is the primary
>    discriminator.
> 2. **`format == ""`** — there is no package-manager format (a real package always
>    carries `deb`, `rpm`, `snap`, `msi`, and so on). This is the robust programmatic
>    corollary check.
> 3. **Absence from the `packages` collection** — abstract packages are minted only on
>    demand through `tool.package()` and are never enumerated by the package managers,
>    so they never appear in `packages`.
>
> `version` may be inferred on a tool-by-tool basis and is null when it cannot be
> determined. `vendor` may carry the producing tool or vendor identity when known.

When the tool is not detected at all, `package()` returns a package with
`installed == false` — the same shape as today's `initPackage` "not found" stub.

Deciding to reuse `package` rather than mark it with a new field is deliberate: the
"unknown origin + empty format + not in the list" facts already express everything a
new `managed`/`source` field would, without broadening the core resource's field set.

### Version inference

Version inference is **per tool and optional**. The default is no version (`version`
null). Tools that can determine a version do so with a strategy that fits how they
install:

- Read a version file in the config directory. Precedent:
  `openai.codex.version()` reads `version.json` (`providers/os/resources/openai_codex.go:55`).
- Parse `<binary> --version` — always through the **`command` resource**, never
  `os/exec` (see CLAUDE.md).
- Read a manifest or lockfile the tool writes.
- Read the `package.json` of the tool's npm package under a global npm prefix
  (`npmPackage` in its spec), for CLIs installed with `npm install -g`. It runs
  nothing, so it is tried before `--version`.

The same detection that produces the version doubles as the presence check that decides
`installed` for the abstract package.

### Field conventions for an abstract package

| Field       | Value                                         |
|-------------|-----------------------------------------------|
| `name`      | canonical tool/package name (e.g. `cursor`)   |
| `installed` | `true` if detected present, else `false`      |
| `origin`    | `"unknown"` (primary discriminator)           |
| `format`    | `""` (no package-manager format)              |
| `version`   | inferred per tool, or null                    |
| `vendor`    | producing tool/vendor when known, else null   |
| `purl`      | optional `pkg:generic/<name>@<version>`       |
| `cpes`      | empty unless a mapping is known               |
| in `packages` | never                                       |

## Alternatives Considered

### A new `managed bool` (or `source` enum) field on `package`

Add an explicit discriminator to `package`. Rejected: it adds surface to a core,
heavily-consumed resource for a fact already expressible through `origin == "unknown"`,
an empty `format`, and absence from the `packages` list. A string sentinel on an
existing field keeps the core resource's shape stable.

### A separate `os.tool.package` resource for abstract installs

Keep `package` strictly manager-tracked and model abstract installs as their own
resource. Rejected: `tool.package` would then not be a `package`, breaking the reuse
that makes this valuable — the same policies, decoders, and vulnerability correlation
that operate on `package` would not apply, and users would face two nearly-identical
types.

### A bare `installed bool` on each tool

Simple, but it answers only yes/no and discards the version, origin, PURL, CPEs, and
outdated-ness that the `package` reference delivers at no extra cost.

## Consequences

### Positive

- One uniform, discoverable indicator: `tool.package.installed`, with the full
  `package` surface behind it (version, purl, cpes, vendor, outdated, install date).
- Manager-tracked installs deduplicate against the real `packages` entry — no parallel
  representation of the same fact.
- No new field on the core `package` resource; the abstract case is expressed entirely
  through existing fields and a structural invariant.
- The mechanism is tool-agnostic and reusable beyond AI tools.
- Vulnerability correlation keeps working for manager-tracked tools, and abstract
  packages can still carry a `pkg:generic` PURL.

### Negative

- `package` semantics broaden to include entries that are not from a package manager.
  Mitigated by documenting the `origin == "unknown"` / empty-`format` / not-in-`packages`
  conventions on the resource itself.
- `origin == "unknown"` is a string sentinel, not a type-enforced flag; consumers must
  know the convention (documented on the field).
- Per-tool presence and version detectors are bespoke and add maintenance as the tool
  roster grows.
- A `pkg:generic` PURL on an abstract package will not match NVD, so those entries do
  not contribute to vulnerability findings until a real source is identified.

## Follow-Ups

- Roll the `package()` accessor out across the 26 AI tools with a shared resolver and a
  per-tool spec table. The step-by-step rollout lives in
  `docs/plans/2026-07-01-tool-install-indicator.md`.
- **Extend binary-ownership to more package managers.** The `PkgFileOwnershipResolver`
  capability is implemented for pacman, dpkg, rpm, and apk. Homebrew, snap, flatpak, and
  the Windows managers do not yet implement it and fall back to candidate names / abstract
  packages; add `FindFileOwner` for them as needed. apk's owner-name parsing strips the
  `-<version>-r<rel>` suffix heuristically; revisit if a package name is ever mangled.
- **Attribute npm-global / `curl | sh` installs.** Binary ownership covers OS-managed
  installs; tools installed via npm-global or a vendored script still resolve to an
  abstract package. A richer, still-not-manager `origin` for these could be added without
  regressing the "unknown means unknown" contract.
- Extend the same pattern to non-AI tools as they are modeled.
- Revisit whether commonly-seen abstract packages (e.g. npm-global installs) deserve a
  richer, still-not-manager `origin` once patterns emerge — without regressing the
  "unknown means unknown" contract.
