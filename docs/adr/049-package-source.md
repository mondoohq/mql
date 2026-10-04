# ADR 049: Reporting Where an Installed Package Came From

## Status

Proposed

Deciders: @tas50, @chris-rock

## Context

A software inventory mixes three kinds of software that a security team
treats differently:

- software that **came with the operating system**: Calculator on macOS, the
  inbox apps on Windows, the packages a Linux image was built from;
- software installed later **from the distribution's own repositories**;
- **third-party** software: a vendor's repository (`download.docker.com`,
  `packages.microsoft.com`), an app store, or a file downloaded from the vendor
  and installed by hand.

A user who wants to focus on third-party software has to filter the first two
out. A user who audits a Linux fleet wants to see which hosts take packages
from outside the distribution, because those packages get no distribution
security updates.

`mql` cannot tell these apart today. The `package` resource reports what is
installed, not how it arrived. Some of the evidence is already collected, but
it is spread over fields whose meaning changes per backend:

| Evidence | Where it is today |
|---|---|
| macOS Gatekeeper classification (`obtained_from`) | `package.origin` on macOS (`providers/os/resources/os.lr:1392-1412`) |
| macOS signing chain (`signed_by`) | parsed (`providers/os/resources/packages/macos_packages.go:46`), not exposed |
| rpm `%{VENDOR}` | `package.vendor` (`rpm_packages.go:404`) |
| deb source package name | `package.origin` on deb |
| apt repository of the installed version | not read |
| dnf repository of the installed package | not read |
| rpm signing key | not read |
| AppX signature kind | not read: the query selects `Name, PackageFullName, Architecture, Version, Publisher, InstallLocation` (`windows_packages.go:225`) |

`package.origin` cannot carry the answer. Its meaning is already per-backend
by design (`os.lr:1392-1412`): the source package on deb, the ports origin on
FreeBSD, the remote on flatpak, the Gatekeeper class on macOS. A check that
compares it across platforms breaks today, and a fifth meaning would make
that worse.

The PURL namespace looks like an answer and is not one.
`pkg:deb/debian/curl` names **the host's distribution**, not where the
package came from. A `docker-ce-cli` installed from Docker's repository on a
Debian host is `pkg:deb/debian/docker-ce-cli` as well.

## Decision

Add a `source` field to `package`. It reports the **evidence** of how the
installed build reached the system. It does not judge that evidence.

```
package {
  // How this build of the package reached the system
  source() package.source
}

package.source @defaults("kind name") {
  // How the build arrived: "repository", "store", "file", or "unknown"
  kind string
  // The repository, store or channel, as the system names it
  name string
  // Where the repository is, with credentials removed
  url string
  // Who signed the build, when the system records it
  signer string
  // Whether the package is part of the operating system as installed
  system bool
  // Which record decided the answer
  method string
}
```

### The scanner reports evidence. The platform decides "third-party"

"Is this third-party?" needs a curated list of which repositories belong to
which distribution: `Origin: Debian`, `baseos`, `appstream`, the Ubuntu and
SUSE archives, and so on. That list changes, and it belongs to the platform
that also curates the software catalog. If `mql` baked it in, every agent
would carry a frozen copy, and fixing a wrong entry would need an agent
upgrade.

So `kind` names a **mechanism**, never a judgment:

| `kind` | Meaning |
|---|---|
| `repository` | Installed from a package repository. `name` and `url` say which. |
| `store` | Installed from an app store: Mac App Store, Microsoft Store, Snap Store, a flatpak remote. |
| `file` | Installed from a local file, with no repository or store behind it. |
| `unknown` | The system keeps no record that answers the question. |

`unknown` is a real answer, not an error. On a container image with empty
apt lists there is nothing to read, and the field says so. This follows the
rule from ADR 044: a value must mean "this is the case", never "this was not
checked".

`system` is nullable, like `kernel.parameter.active` in ADR 048. It is `true`
or `false` only when a record answers the question. It is null otherwise.

`method` names the record that produced the answer, for example `apt-lists`,
`dnf-history` or `gatekeeper`. A consumer can then give a direct record more
weight than an inference.

### Per backend

Each row below says how the answer is read. The **Verified** column says on
what. "Docs" means the behavior comes from vendor documentation and was not
checked on a host for this ADR.

| Backend | `kind` / `name` / `url` | `signer` | `system` | Verified |
|---|---|---|---|---|
| dpkg | Match the installed `(name, version, arch)` against `/var/lib/apt/lists/*_Packages`. The match gives the list file, and the sibling `InRelease` or `Release` gives `Origin`, which becomes `name`. The list's URI becomes `url`. No match while lists exist: `file`. No lists: `unknown`. | empty: Debian signs repository metadata, not packages | null (see open questions) | `debian:12` |
| dnf4 | The latest install item for the package in `/var/lib/dnf/history.sqlite` gives the repo id: `name`. `@commandline` means `file`. `url` comes from the repo's `baseurl` or `metalink` in `/etc/yum.repos.d/*.repo`, when that file still exists. | `%{SIGPGP:pgpsig}` / `%{RSAHEADER:pgpsig}` key ID | true when it was installed in the earliest transaction | `almalinux:9` |
| dnf5 | The same, from `/usr/lib/sysimage/libdnf5/transaction_history.sqlite` | same | same | `fedora:44` (file locations) |
| macOS | `obtained_from` = `mac_app_store` or `ios_app_store`: `store`. `identified_developer` or `unknown`: `file`. `apple`: see `system`. `name` is the raw `obtained_from` value. | leaf of `signed_by` | true when the bundle path is under `/System/` | macOS 27.0 |
| AppX | Add `SignatureKind` to the `Get-AppxPackage` query. `Store`: `store`, name `microsoft-store`. `Developer` or `Enterprise`: `file`. | `Publisher` | true when `SignatureKind` is `System` | Docs |
| snap | `store`, name from the snap's channel | publisher | null | not verified |
| flatpak | `store`, `name` from the remote that `package.origin` already reports | null | null | not verified |

What the checks showed:

**dpkg.** On `debian:12`, after `apt-get update`:

- `curl` matched `deb.debian.org` with `Origin: Debian`;
- `docker-ce-cli` matched only `download.docker.com`, with `Origin: Docker`
  and `Label: Docker CE`;
- a locally built `.deb` installed with `dpkg -i` matched nothing.

`apt-cache policy` agreed in all three cases.

**dnf4.** On `almalinux:9`:

- `bash` and `tree` recorded `baseos`;
- `docker-ce-cli` recorded `docker-ce-stable`;
- a local RPM installed with `dnf install ./nano-….rpm` recorded
  `@commandline`;
- a local RPM installed with `rpm -i` has no history entry at all.

The signing key separates the last case from a vendor build. The `rpm -i`
package still carries AlmaLinux's key ID (`d36cb86cb86b3716`), so it is a
distribution build installed from a file.

**dnf transaction history.** The history records the image build itself as
transaction 1: `install --installroot /mnt/sys-root … almalinux-release bash
…`, which installed 158 of the image's 159 packages. Later installs are later
transactions. That is how `system` is answered for rpm. The repo id alone
cannot answer it: the image's own packages report `baseos`, which is the same
value a later `dnf install` from the distribution writes.

**dnf5.** On `fedora:44`, the image's packages record two 32-hex-digit repo
ids, `4b3429950e3844b28ffdbe8ec843ae60` (75 packages) and
`f6ae26d2709140ec8807dba8ce4e3091` (71). These are the repositories of the
image build. A package installed afterwards records `fedora`.

**macOS.** On macOS 27.0, `system_profiler SPApplicationsDataType` reported
520 applications:

| `obtained_from` | Count |
|---|---|
| `apple` | 310 |
| `unknown` | 136 |
| `identified_developer` | 54 |
| `mac_app_store` | 19 |
| `ios_app_store` | 1 |

None of the 136 `unknown` entries has a `signed_by` chain. So `unknown`
means "no valid signature reported", not "unclassified".

### `apple` is not "shipped with the OS"

The comment on `ObtainedFrom` (`macos_packages.go:34`) says `"apple"` means
"shipped with the OS". On the host checked, 7 of the 310 `apple`
applications were outside `/System`. Among them:

- XProtect and MRT under `/Library/Apple/`, which macOS updates on its own;
- the Python bundled with the Command Line Tools, which the user installs
  separately.

The sealed system volume is the precise signal. Everything under `/System/`
ships with the OS and cannot be modified. So `system` is read from the path,
not from `obtained_from`. This ADR corrects that comment.

### Files, not commands

As in ADR 044, every answer is read from files the package manager keeps:

- the apt lists;
- the dnf history databases;
- the dnf `.repo` files;
- the bundle path and the `system_profiler` output that `mql` already reads.

`mql` scans images, mounted filesystems and snapshots, where no command can
run. A reader built on `apt-cache policy` or `dnf repoquery` would report
`unknown` there for every package. The exception is AppX: Windows exposes
`SignatureKind` only through the package manager API. The filesystem
fallback for AppX (`getFsAppxPackages`, `windows_packages.go:1216`) cannot read it, so it reports a null
`system` and `kind: unknown`.

### Credentials never leave the host

Private repositories often embed credentials in their URL. Examples are
`https://user:token@repo.example/…` in a `sources.list` entry, or a token in
a yum `baseurl` query string. `url` keeps only scheme, host and path. It
drops userinfo, the query string and the fragment. A test asserts this for
both backends.

### Reaching the platform

`mql_sbom.proto`'s `Package` gains a `PackageSource source` message with the
same fields, so `cnspec` reports the evidence to the platform. The platform's
classification (distribution vs vendor repository vs bundled) is defined in
a separate server-side ADR. This one only defines what the scanner reports.

## Security implications

- **Threat model:** unchanged in kind. Every value comes from files on the
  scanned system, like the rest of `packages`. A local administrator can
  forge any of them: an apt list, a `Release` file, a dnf history row. So
  `source` is evidence, not an attestation. `signer` is the hardest field to
  forge, because it is the key ID of a signature over the package itself.
- **Data handling:** `url` can contain secrets in its raw form. Userinfo and
  query strings are removed before the value leaves the provider (see
  above). Repository host names of private mirrors still reach the platform.
  They are infrastructure names, and similar to the `InstallSource` paths
  that Windows packages already report.
- **Authentication and authorization:** no change. No new connection, no new
  privilege. The apt lists, the dnf history and the `.repo` files are
  world-readable on the distributions checked.
- **Supply chain:** no new dependency. dnf history is sqlite, which
  `rpm_packages.go` already reads with `github.com/glebarez/go-sqlite`.
- **Residual risk:** a policy that trusts `kind: repository` with an
  allow-listed `name` as proof of a safe install can be fooled by a host
  that lies. Policies that need proof should check `signer`.

## Performance implications

- **Expected impact:** `source` is computed lazily, but SBOM generation asks
  for it on every package, so assume it runs on every scan.
- **dpkg is the expensive backend.** Matching needs the package indexes. On
  `debian:12` arm64 after `apt-get update`, the bookworm `main` index is 49 MB
  uncompressed (62,666 stanzas), stored as an 18.6 MB `.lz4` file. Security
  and updates add 2.3 MB. The host had 90 packages installed. Decompressing
  and filtering the main index locally took 23 ms. Over an SSH connection,
  those bytes cross the network on every scan.
- **Mitigations, in order:**
  1. Stream the index and keep only the stanzas whose package name is
     installed.
  2. Read each list once per `packages` call, not once per package.
  3. Read `InRelease` headers only up to the first blank line.
  4. If the transfer still shows up in SSH scan timings, let a connection
     that can run commands read `apt-cache policy <installed names>` instead.
     That output is small. Files stay the only path for images.
- **dnf** reads one small sqlite database: 135 KB plus a 4.1 MB write-ahead
  log on `almalinux:9`. Its write-ahead log must be copied with it. The
  existing rpmdb reader copies the database file alone to a temp directory
  (`rpm_packages.go:484-536`). Copying only the main file can lose rows that
  are still in the write-ahead log. I inferred this from the file sizes and
  did not test it.
- **macOS and AppX** add no I/O. `signed_by` and the bundle path are already
  parsed, and `SignatureKind` is one more column in an existing query.
- **Regression budget:** measure scan time on a Debian host over SSH before
  and after. The dpkg reader must not add more than the time `packages`
  already spends parsing `/var/lib/dpkg/status`.

## Consequences

- A platform can filter an inventory to third-party software, and can show
  which hosts install from outside their distribution, with no curated name
  list on the agent.
- `package.origin` keeps its per-backend meaning. Nothing that reads it
  changes.
- **Most container images answer `unknown` on dpkg.** Stock images ship with
  empty apt lists (`debian:12` does; `checkAptIndexes` at `dpkg_packages.go:618`
  documents the same for cloud images). The platform needs a fallback for
  them, for example the distribution suffix in the version (`+deb12u15`
  against `~debian.12~bookworm`), or the `Maintainer` field (`Docker
  <support@docker.com>` against a Debian maintainer). Those are inferences.
  They belong to the platform, not to this field.
- **An outdated dpkg package can look like a local install.** A distribution
  index lists only current versions. A package that missed an update matches
  the name but not the installed version. The reader then reports
  `repository` with the index that lists the name, and `method:
  apt-lists-name`, so a consumer can weight it lower.
- Backends this ADR does not cover keep reporting `unknown`. Each one can be
  added later as one more reader.

## Alternatives Considered

### Classify in the scanner

A `thirdParty bool`, or a `provenance` enum with values like `os-bundled`,
`distro` and `vendor-repo`. Rejected. Telling `distro` from `vendor-repo`
needs a curated list of distribution repositories, and that list changes. In
the agent it would be frozen per release. The software taxonomy is owned by
the platform. The scanner owns the facts.

### Running the package manager

`apt-cache policy`, `dnf repoquery --qf '%{from_repo}'`. Rejected as the
primary path for the reason in ADR 044: it answers nothing on images,
mounted filesystems and snapshots. It remains a possible optimization for
dpkg over SSH (see Performance).

### Reusing `package.origin`

Rejected. It already has a different meaning on each backend (the source package on deb, the parent package on Alpine, the ports origin, the flatpak remote, the Gatekeeper class), and checks compare it
against backend-specific values. Another meaning would break them on deb and rpm,
where `origin` is the source package name.

### A PURL qualifier

The PURL spec has a `repository_url` qualifier. Rejected as the carrier. The
PURL is the package's identity, and consumers key on it: vulnerability
matching, catalog lookups, deduplication (`collapsePackages` at
`windows_packages.go:2589`). A qualifier that differs per repository would split
one product into one identity per mirror.

### Using `obtained_from: apple` as "shipped with macOS"

Rejected after checking a host (see "`apple` is not shipped with the OS").
The system-volume path is exact. `obtained_from` is not.

### Using `Priority: required` or `important` as "base system" on Debian

Rejected. Priority describes the Debian base system, not what an image
contains. In `debian:12`, 51 of the 88 installed packages are `optional`.

## Not covered

- yum (Amazon Linux 2, RHEL 7) `yumdb`, zypper's `/var/log/zypp/history`,
  apk, pacman and opkg. Each keeps a different record, or none. None was
  checked for this ADR.
- Win32 programs from the Uninstall registry. Windows keeps no install
  channel for them. `SystemComponent=1` hides an entry from Add/Remove
  Programs. It does not mean the program came with Windows (the .NET
  runtime's MSI entries set it, see `collapsePackages`). Preinstalled Win32
  software has to be curated on the platform.
- Language packages (npm, PyPI, Maven and others). Their registry is implied
  by the ecosystem.
- Container image layers. "Came from the base image layer" is a strong
  `system` signal for images, but it comes from the image, not the package
  manager. It belongs to a separate change.

## Open Questions

1. **Debian and Ubuntu `system`.** dpkg keeps no install-time record. The
   installers keep a copy of the status file from install time
   (`/var/log/installer/status` on Debian, `initial-status.gz` on Ubuntu).
   I did not check either. Images have neither.
2. **anaconda installs.** The first dnf transaction on an image is the image
   build. On a host installed with anaconda I expect it to be the installer
   transaction, but I did not check this.
3. **dpkg `url` for `file:` and `cdrom:` sources.** Should `kind` be
   `repository` or `file` when the matching list comes from local media?
4. **Several matching repositories.** One version can be in two indexes,
   for example a mirror and the origin, or `bookworm` and
   `bookworm-security`. Report the one apt would install from (highest pin
   priority), or all of them?

## References

- ADR 044: Reporting Packages Held at Their Current Version
- ADR 048: Kernel Parameters, Live and Configured
- `providers/os/resources/os.lr`: `package`, `package.origin`
- `providers/os/resources/packages/dpkg_packages.go`,
  `rpm_packages.go`, `macos_packages.go`, `windows_packages.go`
- `sbom/mql_sbom.proto`: `Package`
- [Debian repository format](https://wiki.debian.org/DebianRepository/Format):
  `Release` / `InRelease` fields
- [PackageSignatureKind enumeration](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.packagesignaturekind)
