# ADR 047: Terraform module and configuration inventory

**Status:** Accepted
**Date:** 2026-09-25

Extends [ADR 011](011-cnspec-sbom-terraform.md), which added the
`.terraform.lock.hcl` provider cataloger.

---

## Context

In September 2026 DPRK-linked actors published malicious Terraform providers to
the public HashiCorp registry: `kreuzwenker/docker`, a one-character typosquat
of `kreuzwerker/docker` (57M downloads), and `gocommunity-io/dockerd`. The
payload sat in the provider's own Go source and executed during plan and apply.
Both were still downloadable from registry.terraform.io a day after disclosure.

That attack is the reason this work exists, so it is worth being precise about
what it says — and it is not that we were exposed. No repository in this
organization references any of the malicious packages; we do use the correctly
spelled `kreuzwerker/docker`, the legitimate provider being impersonated, which
is the population a typosquat targets but is not the attack.

The point is about detection. Had a scanned workspace pinned the malicious
provider, it would **already have appeared in the SBOM this cataloger generates
for it**, at an exact version, read from the lock file. Wider module coverage
would not have caught it. What was missing is a verdict on the coordinate — and
that verdict is produced by vulnerability intelligence, not here.

What this ADR fixes is the inventory the verdict is applied to. Four gaps:

1. **No modules at all.** A module's source is fetched and its code runs during
   plan and apply. It is a dependency in exactly the sense an SBOM records, and
   nothing inventoried it.
2. **No providers without a lock file.** `.terraform.lock.hcl` is frequently not
   committed. Such a repository produced *zero* Terraform packages, so there was
   nothing for any matcher to match.
3. **The lock file was read imprecisely.** Constraints and hashes were parsed
   past; the registry host was discarded, collapsing OpenTofu and private
   registries onto the HashiCorp coordinate; a four-segment private address
   produced a junk purl; a single-line `provider` block was swallowed along with
   the one after it; and only a lock file at the search root was ever found.
4. **Fabricated CPEs.** `cpe.NewPackage2Cpe(namespace, type, version)` claimed
   `cpe:2.3:a:hashicorp:vault:5.12.0` for the Terraform *provider*, while NVD
   carries 443 `cpe:2.3:a:hashicorp:vault` entries for Vault the *server*. The
   same collision exists for consul, nomad and boundary. No NVD CPE exists for a
   Terraform provider, so every one of these could only ever match the wrong
   product.

---

## Decision

### Three sources, merged

| Source | States | Present when |
| --- | --- | --- |
| `.terraform.lock.hcl` | provider versions init resolved | init has run and the file is committed |
| `*.tf` | modules called, providers required | always |
| `.terraform/modules/modules.json` | modules init installed, including nested ones | init has run |

`*.tf` is primary: it is authored intent and is present in every repository.
The manifest is secondary but contributes what the configuration cannot — the
modules that *this project's modules* call, and a reliable direct/transitive
split (an unqualified key such as `vpc` is direct, a dotted one such as
`vpc.subnets` is transitive).

### Parsing `*.tf` with hcl/v2

`*.tf` is real HCL with arbitrary expressions. A hand-rolled scanner of the kind
the lock file uses would be wrong in ways nobody notices, so `hcl/v2` is added
as a direct dependency of the root module. A `source` built from a variable
evaluates to nothing without a full Terraform evaluation context and is skipped
rather than guessed at; a file that does not parse contributes what it can
instead of failing the walk that reached it.

### Coordinates

| Artifact | purl |
| --- | --- |
| Terraform provider | `pkg:terraform/<ns>/<name>@<version>` |
| OpenTofu provider | `pkg:opentofu/<ns>/<name>@<version>` |
| Registry module | `pkg:terraform-module/<ns>/<name>@<version>?target_system=<system>` |
| Git / hg module | `pkg:generic/<host>/<owner>/<repo>@<ref>?vcs_url=…` |
| HTTP archive module | `pkg:generic/<host>/<path>?download_url=…` |
| Local path (`./x`, `../x`) | *not emitted* |
| `s3::`, `gcs::` | *not emitted* |

Three choices worth recording:

- **Modules get their own type**, not a fourth segment on `pkg:terraform`.
  `pkg:terraform/hashicorp/consul/aws` does not survive a round trip —
  packageurl reads it back as namespace `hashicorp/consul`, name `aws`. A
  provider and a module may also share a namespace and name while being
  different artifacts from different registry endpoints.
- **Git modules are `pkg:generic`, not `pkg:github`.** `pkg:github` is already
  read as a GitHub Action downstream, so a module filed under it would be
  reported as one.
- **A local path is not a dependency.** `./modules/vpc` is this repository's own
  code. Inventorying it would state a third-party dependency that does not
  exist, which is worse than the gap it closes. Likewise `s3::`/`gcs::`, which
  name no stable public artifact — a wrong coordinate is worse than none.

purl-spec registers no `terraform` type at all, so all four are de-facto
extensions. They are the vocabulary vulnerability intelligence must key on, and
changing one later is a breaking change for stored SBOMs.

### Versions, constraints and the collapse

`required_providers` states a **constraint** (`~> 5.0`); the lock file states
the **resolved version** (`5.31.0`). Declared providers are therefore recorded
with an empty version, never the constraint: a constraint in a version field
cannot be matched by anything, and anything that does not check reads it as an
exact version.

`terraform.Collapse` then drops a version-less record when the same coordinate
is present at a resolved version, and keeps it when it is not. Keeping it is the
point — in a repository with no committed lock file, that record is the only
statement of the provider. Duplicates fold into one component and keep every
file as evidence, so a repository with one workspace per environment reports one
component with three pieces of evidence rather than three components.

Constraints are captured but deliberately **not** used to infer directness:
Terraform omits the line when `required_providers` declares a source with no
version, so absent means "not recorded", not "transitive".

### Hashes

Only `zh:` entries become checksums, as `SHA-256`, one per platform zip. `h1:`
is retained in the parsed entry but not reported: it is base64 over a manifest
of the extracted files rather than over the zip, so filing both under one
algorithm would state two incomparable digests for one component and produce an
invalid CycloneDX document.

### Registry hosts

OpenTofu gets its own purl type. A **private** registry keeps the `terraform`
type — minting a type per customer helps nobody — and so still shares a
coordinate with the public registry. The source address is preserved on the
package (`terraform.package.source`) so the two remain distinguishable
downstream. This is a known, accepted residual.

### Where this lives

The OS cataloger owns Terraform inventory. The dedicated Terraform IaC provider
gets no SBOM surface: it already owns `terraform.module` and
`terraform.settings.requiredProvider` for configuration analysis, and
duplicating parsers there would create two code paths that must agree on what
`pkg:terraform/…` means, while deepening the existing `terraform.*` namespace
overlap. IaC code reaches the OS cataloger through a filesystem connection.

---

## Schema

`terraform.packages` now searches for all three file kinds under `path`
(default: the connection root). `terraform.package` gains:

- `type` — `"provider"` or `"module"`
- `source` — the address as written, the only place a private registry host
  survives

---

## Walk safety

The walk skips `.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `proc`, `sys`,
`dev` and `.terraform`, stops eight levels below the root, and visits at most
50,000 directories.

Both bounds are needed, and the second was found by measuring rather than by
reasoning. A depth cap bounds depth and nothing else: `/usr` walks in 0.18s and
3,900 directories, which made depth alone look sufficient, while a depth-8 walk
of a Go source tree on the same machine visits **3.6 million** directories and
takes over a minute. The resource walks whatever the connection is rooted at,
and for an OS or container connection that is `/`.

50,000 is far more than any repository holds and costs about a second.
Exceeding it means the root is not a project tree, so the walk stops and logs a
warning naming the path rather than reporting a partial inventory as though it
were complete.

`.terraform` is the one that matters for correctness: it holds downloaded module
*source*, each with its own `*.tf` declaring its own modules and providers.
Reading those would report a dependency's dependencies as this project's own.
The manifest at `.terraform/modules/modules.json` is read on the way past, and
then the directory is skipped.

---

## Consequences

- A repository with no committed lock file goes from zero Terraform packages to
  every provider it declares and every module it calls.
- OpenTofu providers stop masquerading as HashiCorp ones. Providers served by
  the default registry keep the coordinate they had, so nothing already matched
  moves.
- Terraform packages no longer carry CPEs. Nothing is lost that was correct:
  matching is purl-based, and the CPEs were fabricated.
- `hcl/v2` and `go-cty` become direct dependencies of the root module.

---

## Verification

```
go test ./providers/os/resources/languages/terraform/...
go test ./providers/os/resources/ -run TestCollectTerraform

mql run os -c "terraform.packages(path: '.') { list { name version type source purl } }"
```

Against a workspace holding a lock file, a `*.tf` declaring a registry module
and a git module, and a populated `.terraform/modules/`: every provider and
module appears once; a module declared and installed is one component, not two;
`./modules/...` appears not at all; and no provider or module belonging to a
downloaded module is reported.

---

## Not in scope

- A verdict on whether a coordinate is malicious. That is vulnerability
  intelligence's job; this ADR only makes the inventory it reads complete and
  correct, and fixes the vocabulary it must key on.
- Disambiguating private-registry providers from public ones by purl.
- `.tf.json`, `s3::`/`gcs::` module sources, and the `h1:` dirhash.
- An SBOM from `cnspec scan terraform ./infra`. That connection exposes no
  filesystem, so the OS cataloger cannot run on it; a filesystem scan of the
  same directory works today.
