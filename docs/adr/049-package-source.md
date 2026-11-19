# ADR 049: Telling Operating-System Packages From Third-Party Software

## Status

Accepted. Implemented in the os provider; the sections below were corrected
on 2026-10-05 where the implementation, run against real systems, disproved
what this ADR first said. Each correction says what it replaces.

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
anchors the OS already relies on. The only code-owned knowledge is, per
platform, which package ships those keys. That is one to three package names
per distribution, and they do not change between releases.

The list is explicit, keyed by mql's platform name, and every entry was read
off the distribution's own image: the package that owns the key files whose
keys sign that image's packages.

| Platform | Package that ships the OS keys |
|---|---|
| `debian` | `debian-archive-keyring`, `debian-ports-archive-keyring` |
| `ubuntu` | `ubuntu-keyring`, and `ubuntu-pro-client` (formerly `ubuntu-advantage-tools`) for the ESM repositories Ubuntu Pro enables |
| `kali` | `kali-archive-keyring` |
| `linuxmint` | `linuxmint-keyring`, plus `ubuntu-keyring` (Mint) or `debian-archive-keyring` (LMDE) |
| `raspbian` | `raspberrypi-archive-keyring`, `raspbian-archive-keyring`, `debian-archive-keyring` (from the packages' published file lists; not run on a host) |
| `redhat` | `redhat-release` |
| `centos`, `centos-stream` | `centos-gpg-keys` (and `centos-release` on CentOS 7 and 8) |
| `almalinux` | `almalinux-gpg-keys` (9), `almalinux-release` (8) |
| `rockylinux` | `rocky-gpg-keys`, `rocky-release` |
| `oraclelinux` | `oraclelinux-release` |
| `fedora` | `fedora-gpg-keys` |
| `amazonlinux` | `system-release` |
| `opensuse`, `opensuse-leap`, `opensuse-tumbleweed` | `openSUSE-build-key` |
| `sles` | `suse-build-key` |
| `photon` | `photon-repos` |
| `azurelinux` | `azurelinux-repos-shared` |
| macOS | Apple's OS signing identity, `macOS Software Signing`, or the sealed system volume |
| Windows | see "How each platform resolves it" |

*Corrected 2026-10-05.* This table first said the RHEL key package is "the
package that provides `system-release`, and the `*-gpg-keys` package it
requires". That holds on none of the families checked in a uniform way: RHEL,
Oracle Linux and Amazon Linux keep the keys in the release package itself,
Fedora, Photon and Azure Linux in a package from another source package. The
explicit list replaces the rule.

Counting every key file an operating-system package owns would be wrong. On
AlmaLinux, Rocky, CentOS and Amazon Linux 2, `epel-release` is signed by the
distribution and installs the EPEL key next to the distribution's own. On
Debian and Ubuntu, `postgresql-common` installs the key of the PostgreSQL
project's repository. Both keys sign third-party software. Oracle Linux is the
one case where this rule calls an EPEL package the operating system's: Oracle
re-signs its EPEL mirror (`ol9_developer_EPEL`) with its release key.

### Per backend

| Backend | `osProvided` | null when | Verified |
|---|---|---|---|
| rpm | The package's signature key ID (`RSAHEADER`, `DSAHEADER`, `SIGPGP` or `SIGGPG`) is a key, or a subkey, in a file owned by the OS key package. SUSE signs with version 3 signature packets, which the OpenPGP library skips, so those are read directly. | the platform has no entry in the key package list | almalinux:9 (container, image, EC2), amazonlinux:2023 (EC2); the matrix below |
| dpkg | Debian signs repositories, not packages. The installed `(name, version, arch)` is matched against the apt indexes in `/var/lib/apt/lists`. The match is `true` when that index's `InRelease` (or `Release` with `Release.gpg`) is signed by a key in the OS keyring. See the next section for the rest of the cases. | see the next section | debian:12 (container, image, EC2), Ubuntu 22.04 and 24.04 Pro (EC2) |
| macOS | The bundle's leaf signing certificate (`signed_by[0]`) is `macOS Software Signing`, or the bundle is under `/System/`. The second covers Safari, which lives on the App cryptex under `/System/Cryptexes` and which mql lists without a signer, and the applications mql finds by listing the folders. | never | macOS 27.0 |
| AppX | See "How each platform resolves it". | the package was found on disk without PowerShell and is not under `SystemApps` | Windows 11 24H2 |
| Win32 (registry) | `true` only for Edge, WebView2 and Edge Update when Edge Update records Windows as their install source, and for the .NET Framework 4.x runtime. | every other program: Windows records nothing that says it came with Windows | Windows 11 24H2 |

#### dpkg cases

dpkg is the one backend where the answer depends on the apt indexes, so it
spells out every case:

| Installed `(name, version)` | `osProvided` |
|---|---|
| in an index signed by the OS keyring | `true` |
| only in indexes signed by other keys | `false` |
| name in no index at all, and every component the sources enable has an index | `false`: installed from a local `.deb` |
| name in no index at all, and some enabled component has no index | null |
| version in no index, name only in OS-signed indexes | `true`: an OS package that missed an update. The Debian archive lists only current versions. |
| version in no index, name also in a third-party index | null |
| no indexes on the host | null |

The null rows are null on purpose. An Ubuntu cloud image ships the main and
restricted indexes and none for universe until the first `apt-get update`, so
a universe package from the image build is in no index; calling it a local
install would be a confident wrong answer. *Added 2026-10-05.*

The last two rows of the table are also null on purpose. A rule that matched on the name alone
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

**Windows.** *Corrected 2026-10-05.* This section first said AppX
`SignatureKind` decides: `System` is `os`, `Store` is `app-store`,
`Developer` or `Enterprise` is `direct`. On a Windows 11 24H2 host that calls
most of Windows third-party. The signature kind says how a package is signed,
not whether it came with Windows. Only the 49 shell components are `System`.
The inbox apps (Calculator, Photos, Paint, Notepad, Terminal, the Store) are
`Store`-signed, and Edge, Teams and Outlook are `Developer`-signed, exactly
like the package Notepad++'s installer registers.

What does mark an inbox app is that the Windows image provisions it for every
new user: it is listed under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`,
by bundle name (`<Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>`), which
reduces to the package family. An app a user installs from the Store is not
listed. So an AppX package is `os` when:

1. its signature kind is `System`;
2. its family is provisioned;
3. it is a framework package Microsoft publishes (VCLibs, UI.Xaml), which the
   inbox apps depend on; or
4. it is published by `CN=Microsoft Windows` (Windows' own web experience and
   cross-device components ship that way, `Store`-signed).

Otherwise a `Store`-signed package is `app-store`, and any other is `direct`.
Two packages Windows installs through the Store after the first logon
(StartExperiencesApp, WidgetsPlatformRuntime) read as `app-store`: nothing on
the system tells them apart from a user's Store install.

Win32: an Uninstall entry exists only because an installer ran, so it is
`installer`, named by the MSI ProductCode for an MSI (the purl's
`product_code` qualifier). Edge, WebView2 and Edge Update are the exception:
Edge Update records `InstallSource=windows` (and `brand=INBX`) for the copies
that came with Windows, and the Uninstall entry is matched by its install
location. The .NET Framework 4.x runtime, which the backend synthesizes from
its setup key, is `os`. OneDrive installs per user from a setup program the
image ships and carries no such marker; it is `installer` with a null
`osProvided`.

These facts are read with one PowerShell query, only when a query asks for
`osProvided` or `source`; the package list's own AppX query is unchanged.

### Files, not commands

As in ADR 044, every answer is read from files:

- the OS key files;
- the apt indexes and their `InRelease`;
- the rpm signature tags;
- the dnf history;
- the `system_profiler` output that `mql` already reads.

The scanner runs no package-manager command for these on local, container and
image connections. This works on images and mounted filesystems. On rpm it
also means `osProvided` answers on every image, because the signature is in
the rpm database.

*Added 2026-10-05.* SSH is the exception, in the other direction: there every
file read is a network round trip, and running one command is cheaper than
copying the files. Over SSH the reader filters the apt indexes on the host
(`apt-helper cat-file` plus `awk`, printing only the lines of installed
package names), asks `rpm -qa` for each package's signature instead of
copying the rpm database, queries dnf's history with the Python dnf itself
runs on instead of copying the database and its write-ahead log, and fetches
release files, key files and sources lists in one batched command. Each falls
back to reading the files when its command fails.

Windows is the other exception: the provisioned AppX list and the Edge Update
install sources are read with PowerShell. Both are file-readable in principle
(the registry hive, `StateRepository-Machine.srd`), which a reader for offline
Windows disks can use later.

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
- **Signatures are checked where it is cheap.** *Added 2026-10-05.* A dpkg
  release counts as the operating system's only when its signature verifies
  against an OS key, not because it names an OS key ID: anyone who can write a
  file in the lists directory could name Debian's key. Expiry is not checked,
  so a host whose indexes predate a key rotation still matches. An rpm
  package's header signature is matched by key ID and not re-verified: rpm
  verified it when it installed the package into a database only root can
  write, and verifying it again means rebuilding the signed header region from
  the database copy. Whoever can rewrite that database can rewrite the
  keyring too.
- **Mirror lists** named by a `mirror+file:` source are read only under
  `/etc/apt`, so a sources entry cannot point the scan at an arbitrary file.
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
- **Untrusted input:** the readers parse files a host's owner controls: rpm
  headers, keyrings, release files, sqlite databases. Counts taken from a
  header are checked against the bytes that remain before anything is
  allocated, so a crafted header cannot force a large allocation.
  *Added 2026-10-05.*
- **Commands over SSH:** the commands are fixed strings. The only values put
  into them are file paths read from the package manager's own records, and
  those are single-quoted. They read; they change nothing on the host.
- **Names:** when a release file names no origin, the repository's address is
  reported as its name. It is decoded from the list file name, which apt
  writes without user information but with the query string, so the query
  string and anything before an `@` are removed first.
- **Residual risk:** an OS that ships a vendor's key in its own keyring
  package would make that vendor's packages `osProvided: true`. None of the
  keyrings checked do, which is why the list names keyring packages rather
  than trusting every package the OS signed.

## Performance implications

*Replaced 2026-10-05 with measurements.* The first version estimated the cost
and named `apt-cache policy` as the SSH mitigation.

- **Nothing is read unless a query asks.** Sources are resolved once per
  package manager, the first time a package reads `osProvided` or `source`.
  A plain `packages` inventory does no new work.
- **Local and container scans.** On a `debian:12` container with nginx.org's
  and Docker's repositories, adding `osProvided` and `source` to a 157-package
  query took it from 1.0 s to 2.4 s: reading the 18.6 MB `.lz4` index and
  the release files.
- **SSH scans, measured from a laptop against t3.small EC2 instances.** The
  extra time over the same query without the two fields:

  | Host | Packages | First implementation | Final |
  |---|---|---|---|
  | Debian 12 | 370 | +11 s | +4 s |
  | Ubuntu 24.04 Pro | 671 | +26 s | +2 s |
  | Ubuntu 22.04 | 626 | +22 s | +6 s |
  | AlmaLinux 9 | 488 | +16 s | +3 to +7 s |
  | Amazon Linux 2023 | 506 | | +2 to +4 s |

  The first implementation read every file over SFTP: about twenty key files
  per Debian host, every release file, the rpm database and dnf's history with
  its 4 MB write-ahead log. Copying the apt indexes alone would have been 60 to
  210 MB per scan, 10 to 40 s. The final one runs the filtering on the host
  (see "Files, not commands"); the filtered apt indexes are 50 to 110 KB.
- **dnf history** copied for a local scan includes its write-ahead log. Twelve
  databases read without it lost no rows, but a scan during a transaction
  could.

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
- **Preinstalled Win32 programs** other than Edge, WebView2, Edge Update and
  the .NET Framework runtime are null. The platform curates them; OneDrive is
  the one seen on a stock image.
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
snapshots. Over SSH, commands do run, but they filter and query the same
files the reader reads elsewhere (see "Files, not commands"), so a host and
its image give the same answer.

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

- apk, pacman, opkg, xbps and the BSDs. They report null until a reader is
  added. (*Corrected 2026-10-05:* yum on Amazon Linux 2 and zypper are
  covered: their signatures decide `osProvided` like dnf's, and their history,
  `yumdb` and `/var/log/zypp/history`, names the repository.)
- winget as a channel of its own. winget does keep a record: an `installed.db`
  per user and one for SYSTEM, mapping its package IDs to Uninstall keys. A
  winget install reads as `installer` until a reader uses it.
- Chocolatey installs that run an installer also appear in the Uninstall
  registry, as `installer`; `C:\ProgramData\chocolatey\.chocolatey\<pkg>\.registry`
  names the key and could mark them `chocolatey`.
- Language packages (npm, PyPI, Maven). They are third-party by construction.
- Whether an OS package came with the image or was installed later. The
  filter does not need it, so it is left for later.

## Answered Questions

Answered 2026-10-05.

1. **Ubuntu Pro / ESM.** The ESM repositories are signed with keys in
   `/usr/share/keyrings/ubuntu-pro-esm-{apps,infra}.gpg`, owned by
   `ubuntu-pro-client`. On an Ubuntu 24.04 Pro EC2 instance, ESM packages
   resolve to `os` with the source name `UbuntuESMApps` only with that package
   on the list.
2. **Fedora and SUSE key packages.** `fedora-gpg-keys`, `openSUSE-build-key`
   and `suse-build-key`, read off their images.
3. **Safari.** It lives on the App cryptex
   (`/System/Cryptexes/App/System/Applications/Safari.app`), and mql lists it
   without a signer; the `/System/` rule covers it.

## References

- ADR 044: Reporting Packages Held at Their Current Version
- ADR 048: Kernel Parameters, Live and Configured
- `providers/os/resources/os.lr`: `package`, `package.origin`
- `providers/os/resources/packages/dpkg_packages.go`, `rpm_packages.go`,
  `macos_packages.go`, `windows_packages.go`
- `sbom/mql_sbom.proto`: `Package`
- [Debian repository format](https://wiki.debian.org/DebianRepository/Format)
- [PackageSignatureKind enumeration](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.packagesignaturekind)
