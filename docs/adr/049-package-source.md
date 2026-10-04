# ADR 049: Telling Operating-System Packages From Third-Party Software

## Status

Proposed

Deciders: @tas50, @chris-rock

## Context

A software inventory mixes two kinds of software that a security team treats
differently:

- software the **operating system vendor provides**: Calculator on macOS, the
  Windows inbox apps, and every package from the distribution's own
  repositories, whether it came with the image or was installed later;
- **third-party** software: anything from a vendor's repository
  (`nginx.org`, `download.docker.com`, `packages.microsoft.com`), from an app
  store, or from a file downloaded and installed by hand.

The user's question is a filter: "show me only the third-party software". The
case it must get right is a Debian host where an administrator added
nginx.org's repository. Debian's `nginx` and nginx.org's `nginx` have the same
package name and the same PURL, `pkg:deb/debian/nginx`. One is OS software. The
other is third-party.

`mql` cannot answer this today. The `package` resource reports what is
installed, not who provided it. The PURL namespace looks like an answer and is
not one: `pkg:deb/debian/…` names the host's distribution, not where the
package came from. `package.origin` cannot carry it either. Its meaning is
per-backend by design (`providers/os/resources/os.lr:1392-1412`): the source
package on deb, the parent package on Alpine, the ports origin on FreeBSD, the
remote on flatpak, the Gatekeeper class on macOS.

## Decision

Add two fields to `package`:

```
package {
  // Whether the operating system vendor provides this package
  osProvided() bool
  // Where the installed build came from
  source() package.source
}

package.source @defaults("channel name") {
  // How the build reached the system, e.g. "app-store", "homebrew", "direct"
  channel string
  // The repository, store or cask, as the system names it, e.g. "nginx", "Docker"
  name string
  // Where the repository is, with credentials removed
  url string
}
```

`osProvided` is the filter. `true` means the OS vendor provides the package.
`false` means third-party. It is null only when no record on the host answers,
and each backend below says when that happens. "Third-party only" is
`osProvided == false`.

`source.channel` answers the next question for third-party software: where did
it come from? It is a second filter ("everything installed from a dmg", "every
vendor repository") and drives display ("installed from nginx.org"). It does
not decide `osProvided`.

### The rule: the OS vendor's own signing keys

Every operating system ships the keys it signs its software with, inside one
of its own packages. A package manager installs only what those keys, or keys
the administrator added, have signed. So the scanner asks one question per
package: **was it signed with a key that the operating system itself
installed?**

- Yes: `osProvided: true`.
- No, it was signed with a key someone added later, or it is unsigned:
  `osProvided: false`.

This needs no curated list of repositories or vendors. It uses the trust
anchors the OS already relies on. The only code-owned knowledge is, per OS
family, which package ships those keys. That is one or two package names per
distribution, and they do not change between releases.

| OS family | Package that ships the OS keys |
|---|---|
| Debian | `debian-archive-keyring` |
| Ubuntu | `ubuntu-keyring` |
| RHEL and rebuilds | the package that provides `system-release`, and the `*-gpg-keys` package it requires (`almalinux-gpg-keys` on AlmaLinux) |
| Fedora | `fedora-gpg-keys` |
| macOS | Apple's OS signing identity, `macOS Software Signing` |
| Windows (AppX) | `SignatureKind: System` |

### Per backend

| Backend | `osProvided` | null when | Verified |
|---|---|---|---|
| rpm | The package's signature key ID (`%{RSAHEADER:pgpsig}`, `%{SIGPGP:pgpsig}`) is a key in a file owned by the OS key package. | never: an unsigned package is `false` | `almalinux:9` |
| dpkg | Debian signs repositories, not packages. The installed `(name, version, arch)` is matched against the apt indexes in `/var/lib/apt/lists`. The match is `true` when that index's `InRelease` is signed by a key in the OS keyring. See the next section for the rest of the cases. | no indexes on the host, or the case below | `debian:12` |
| macOS | The bundle's leaf signing certificate (`signed_by[0]`) is `macOS Software Signing`. | never | macOS 27.0 |
| AppX | `SignatureKind` is `System`. | the filesystem fallback (`getFsAppxPackages`, `windows_packages.go:1216`), which cannot read it | Docs |
| Win32 (registry) | Windows records no channel for these programs. | always | — |

#### dpkg cases

dpkg is the one backend where the answer depends on the apt indexes, so it
spells out every case:

| Installed `(name, version)` | `osProvided` |
|---|---|
| in an index signed by the OS keyring | `true` |
| only in indexes signed by other keys | `false` |
| name in no index at all | `false`: installed from a local `.deb` |
| version in no index, name only in OS-signed indexes | `true`: an OS package that missed an update. The Debian archive lists only current versions. |
| version in no index, name also in a third-party index | null |
| no indexes on the host | null |

The last two rows are null on purpose. A rule that matched on the name alone
would send an outdated Debian `nginx` to nginx.org's index and call a Debian
build third-party: the wrong answer for exactly the case this field exists
for.

### What the checks showed

**dpkg.** Three `debian:12` containers, each after `apt-get update`:

| | Debian `nginx` | nginx.org `nginx` | Docker `docker-ce-cli` |
|---|---|---|---|
| Installed version | `1.22.1-9+deb12u10` | `1.30.5-1~bookworm` | `5:29.8.2-1~debian.12~bookworm` |
| Index listing that version | `deb.debian.org …bookworm-security` | `nginx.org/packages/debian` | `download.docker.com/linux/debian` |
| That index's key | `/usr/share/keyrings/debian-archive-keyring.gpg`, owned by `debian-archive-keyring` | `/usr/share/keyrings/nginx-archive-keyring.gpg`, owned by no package | added by the administrator |
| `osProvided` | `true` | `false` | `false` |
| `source.name` (`Origin:`) | `Debian` | `nginx` | `Docker` |

nginx.org's `InRelease` verified against nginx's key and not against the
Debian keyring. Debian's indexes verified against the Debian keyring.
`apt-cache policy` agreed with the index match in every case. A locally built
`.deb` installed with `dpkg -i` matched no index.

Both vendor repositories keep old versions in their index. nginx.org still
listed `1.30.4-1~bookworm` next to the installed `1.30.5`. Docker listed
`29.8.1`, `29.8.0` and `29.7.2` next to `29.8.2`. So a host that skipped vendor
updates still matches its vendor repository exactly.

**rpm.** On `almalinux:9` with Docker's repository added:

| | `tree` (AlmaLinux) | `docker-ce-cli` (Docker) |
|---|---|---|
| Signature key ID | `d36cb86cb86b3716` | `c52feb6b621e9f35` |
| Key file | `/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9`, owned by `almalinux-gpg-keys` | fetched from `https://download.docker.com/linux/rhel/gpg`, owned by no package |
| `osProvided` | `true` | `false` |
| `source.name` (dnf history) | `baseos` | `docker-ce-stable` |

The rule also covers a package installed from a file. `jq`, downloaded and
installed with `rpm -i`, has no dnf history, but it carries AlmaLinux's key.
So it is OS software, which is correct.

**macOS.** On macOS 27.0, `system_profiler SPApplicationsDataType` reported 520
applications. 307 carry the `macOS Software Signing` leaf:

- 303 are under `/System/`;
- the other 4 are OS components under `/Library/Apple/` and
  `/Library/Image Capture/`.

All 304 applications under `/System/` carry that leaf, except one unsigned
helper. Apple's optional App Store apps (Pages, Keynote, Numbers) carry
`Apple Mac OS Application Signing` and `obtained_from: mac_app_store`. They are
`false`: the OS does not include them.

The leaf is a better rule than `obtained_from: apple`. The current comment on
`ObtainedFrom` (`macos_packages.go:34`) says `"apple"` means "shipped with the
OS". On the host checked, it also covered the Python bundled with the Command
Line Tools, which the user installs separately. This ADR corrects that
comment.

### `source.channel`

One value per way software reaches a system. `os` is the channel of every
`osProvided: true` package. The rest are third-party channels.

| `channel` | Meaning | `name` |
|---|---|---|
| `os` | provided by the operating system vendor | the OS repository or store, e.g. `Debian`, `baseos` |
| `vendor-repository` | a vendor's apt or dnf repository the administrator added | its `Origin` or repo id, e.g. `nginx`, `docker-ce-stable` |
| `app-store` | the Mac App Store or the Microsoft Store | `mac-app-store`, `ios-app-store`, `microsoft-store` |
| `homebrew` | a Homebrew formula or cask | the formula or cask token |
| `installer` | a vendor installer package: macOS `.pkg`, Windows MSI or EXE setup | the package identifier |
| `direct` | copied in by hand: an app dragged from a `.dmg` or `.zip`, a `.deb` or `.rpm` installed from a file | empty |
| `snap`, `flatpak`, `chocolatey` | that package manager | the snap, the flatpak remote, the package |
| `unknown` | no record answers | empty |

`url` is set for the repository channels. It keeps only scheme, host and path,
and drops userinfo, the query string and the fragment, because private
repositories embed tokens there.

#### How each platform resolves it

**Linux.** dpkg: an exact index match signed by the OS keyring is `os`, by
another key `vendor-repository`. A name in no index is `direct`. dnf: the repo
id in the transaction history (`/var/lib/dnf/history.sqlite`,
`/usr/lib/sysimage/libdnf5/transaction_history.sqlite`), with the signing key
deciding `os` against `vendor-repository`. `@commandline`, or no history entry
with a non-OS key, is `direct`. snap and flatpak packages are already their
own formats.

**macOS.** An application bundle can be claimed by several records. The first
that matches wins:

1. `macOS Software Signing` leaf: `os`.
2. `obtained_from` `mac_app_store` or `ios_app_store`: `app-store`.
3. A Homebrew cask whose version directory symlinks to the bundle
   (`/opt/homebrew/Caskroom/<token>/<version>/<App>.app`), also listed in the
   cask's `.metadata/INSTALL_RECEIPT.json` under `uninstall_artifacts`:
   `homebrew`.
4. An installer receipt in `/var/db/receipts/<id>.plist` with
   `InstallProcessName` `installer` that installed the bundle: `installer`.
5. Otherwise `direct`: the bundle was copied in, usually from a `.dmg`.

The order matters, and the host checked shows why. Bitwarden had a cask
symlink to `/Applications/Bitwarden.app` dated Sep 17. The bundle at that path
reported `obtained_from: mac_app_store`, with an App Store receipt
(`InstallProcessName: appstored`) dated Oct 2. The App Store install replaced
the cask's copy and left the symlink behind. The bundle's own signature is
current. A cask link can be stale.

On the host checked:

- all 30 casks had an `INSTALL_RECEIPT.json`;
- every cask that installs an app had the symlink;
- the 41 receipts split into 27 `installer`/`Installer` and 14
  `appstoreagent`/`appstored`.

Matching a `.pkg` receipt to the bundle it installed needs the receipt's bill
of materials (`/var/db/receipts/<id>.bom`). I did not check how reliably the
paths in it match the bundle path. Homebrew formulae are already reported as
`brew` packages (`homebrew_packages.go`) and are `homebrew` by definition.

**Windows.** AppX: `SignatureKind` `System` is `os`, `Store` is `app-store`,
`Developer` or `Enterprise` is `direct`. Win32: an Uninstall entry exists
only because an installer ran, so it is `installer`. `WindowsInstaller=1`,
already collected (`windows_packages.go:185`), marks an MSI. Chocolatey
packages are already their own format. winget leaves no per-package record
that was checked for this ADR, so a winget install reads as `installer`.

### Files, not commands

As in ADR 044, every answer is read from files:

- the OS key files;
- the apt indexes and their `InRelease`;
- the rpm signature tags;
- the dnf history;
- the `system_profiler` output that `mql` already reads.

The scanner runs no package-manager command. This works on images and mounted
filesystems. On rpm it also means `osProvided` answers on every image, because
the signature is in the rpm database. AppX is the exception:
`SignatureKind` is available only through the package manager API.

### Reaching the platform

`mql_sbom.proto`'s `Package` gains `os_provided` (an optional bool) and a
`PackageSource source` message, so `cnspec` reports both. The platform stores
them per install. Installs of the same product can differ: nginx is OS software
on one host and third-party on the next.

## Security implications

- **Threat model:** unchanged in kind. The answer comes from the same trust
  decision the package manager made: which keys it accepts. An administrator
  who controls the host can forge any of it, for example by placing a key in
  the OS keyring. So `osProvided` is evidence, not an attestation.
- **Data handling:** `url` can contain secrets in raw form. They are removed
  before the value leaves the provider. Private mirror host names still reach
  the platform. These are infrastructure names, similar to the
  `InstallSource` paths that Windows packages already report.
- **Authentication and authorization:** no change. No new connection, no new
  privilege. The key files, apt indexes and dnf history are world-readable on
  the distributions checked.
- **Supply chain:** reading an `InRelease` signature's issuer needs an
  OpenPGP parser. `github.com/ProtonMail/go-crypto` is already a dependency of
  the `mql` module (`go.mod:16`). The os provider adds it, so no new code
  enters the build.
- **Residual risk:** an OS that ships a vendor's key in its own keyring
  package would make that vendor's packages `osProvided: true`. None of the
  keyrings checked do.

## Performance implications

- **rpm, macOS, AppX:** no new I/O beyond small key files.
  - rpm: the signature is two more tags in the existing query
    (`rpm_packages.go:404`).
  - macOS: `signed_by` is already parsed (`macos_packages.go:46`).
  - AppX: `SignatureKind` is one more column in an existing query
    (`windows_packages.go:225`).
- **dpkg is the expensive backend.** On `debian:12` arm64, the bookworm `main`
  index is 49 MB uncompressed (62,666 stanzas), stored as an 18.6 MB `.lz4`
  file. Decompressing and filtering it locally took 23 ms. Over SSH those bytes
  cross the network on every scan.
- **Mitigations, in order:**
  1. Stream each index once per `packages` call, keeping only stanzas whose
     name is installed.
  2. Read each `InRelease` only for its header and its signature issuer.
  3. If SSH scan timings show the transfer, use `apt-cache policy <installed
     names>` on connections that can run commands. Files stay the only path
     for images.
- **dnf history** must be copied together with its write-ahead log (4.1 MB on
  `almalinux:9`, next to a 135 KB main file). The rpmdb reader copies only the
  database file (`rpm_packages.go:484-536`). I inferred from the sizes that
  rows can sit in the log, and did not test it.
- **Regression budget:** measure scan time on a Debian host over SSH before and
  after. The dpkg reader must not add more than `packages` already spends
  parsing `/var/lib/dpkg/status`.

## Consequences

- The platform can filter any inventory to third-party software with one
  field, and it is right for the nginx.org and Docker cases on both package
  families.
- rpm, macOS and AppX answer everywhere, including images.
- **dpkg images answer null.** Stock images ship with empty apt indexes
  (`debian:12` does; `checkAptIndexes` at `dpkg_packages.go:618` documents the
  same for cloud images). The platform fills these in by checking the exact
  `(release, name, version)` against the distribution's archive, which it can
  index once for all hosts. That check belongs to the platform. The scanner
  reports null rather than guessing.
- **Preinstalled Win32 programs** (Edge, OneDrive) are null. The platform
  curates them.
- `package.origin` keeps its per-backend meaning. Nothing that reads it
  changes.

## Alternatives Considered

### Report evidence only, and classify on the platform

The first draft of this ADR did this: repository name, signer and packager
fields, with a platform-side list of which repositories belong to which
distribution. Rejected. It gives no field to filter on, it needs a curated
repository list, and the list would be wrong the day a distribution adds a
repository. The OS's own keys answer the question without a list.

### Classify by the package's `Maintainer` or `Packager`

`Debian Nginx Maintainers` against `NGINX Packaging <…@f5.com>`. Rejected. It
is a heuristic: some Debian maintainers use personal addresses, and Ubuntu
rewrites the field. It cannot be the filter.

### Classify by the version string

`+deb12u10` is a Debian build, `~bookworm` is not. Rejected for the same
reason. Many Debian packages carry no suffix at all.

### Running the package manager

`apt-cache policy`, `dnf repoquery`. Rejected as the primary path for the
reason in ADR 044: it answers nothing on images, mounted filesystems and
snapshots.

### A PURL qualifier

The PURL spec has a `repository_url` qualifier. Rejected. The PURL is the
package's identity, and vulnerability matching, catalog lookups and
deduplication (`collapsePackages` at `windows_packages.go:2589`) key on it. A
qualifier per repository would split one product into one identity per
mirror.

### `obtained_from: apple` as "part of macOS"

Rejected after checking a host: it includes Apple software the user installs
separately. The OS signing identity is exact.

## Not covered

- yum on Amazon Linux 2 and RHEL 7, zypper, apk, pacman and opkg. Each keeps
  its keys differently. None was checked for this ADR. They report null until
  a reader is added.
- winget as a channel of its own.
- Language packages (npm, PyPI, Maven). They are third-party by construction.
- Whether an OS package came with the image or was installed later. The
  filter does not need it, so it is left for later.

## Open Questions

1. **Ubuntu Pro / ESM.** ESM repositories are signed with keys from
   `ubuntu-pro-client`, not `ubuntu-keyring`. They are OS software, so the key
   package list probably needs both. Not checked.
2. **Fedora and SUSE key packages.** Taken from the distributions' layout. Not
   checked on a host.
3. **Safari and other Apple apps outside `/System`.** The host checked did not
   list Safari, so whether it carries `macOS Software Signing` is unverified.

## References

- ADR 044: Reporting Packages Held at Their Current Version
- ADR 048: Kernel Parameters, Live and Configured
- `providers/os/resources/os.lr`: `package`, `package.origin`
- `providers/os/resources/packages/dpkg_packages.go`, `rpm_packages.go`,
  `macos_packages.go`, `windows_packages.go`
- `sbom/mql_sbom.proto`: `Package`
- [Debian repository format](https://wiki.debian.org/DebianRepository/Format)
- [PackageSignatureKind enumeration](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.packagesignaturekind)
