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
| `winget` | a program winget installed or took over | the winget package identifier, e.g. `7zip.7zip` |
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

**Amendment 2026-11-27: winget.** A program winget installed reads
`channel: "winget"`, `name: <winget package id>` (`7zip.7zip`),
`osProvided: false`, instead of `installer`. winget keeps a tracking catalog,
one SQLite `installed.db` per source directory and per account that ran
winget: for the packaged winget (App Installer) under
`<profile>\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\<source>\`,
for the unpackaged one (SYSTEM, Intune) under
`<profile>\AppData\Local\Microsoft\WinGet\State\defaultState\<source>\`.
SYSTEM's profile is `C:\Windows\System32\config\systemprofile`. A
machine-scope install is tracked in the catalog of the account that ran
winget, so the reader opens the catalogs of SYSTEM and of every profile under
`C:\Users`. `productcodes_map` holds the Uninstall subkey name of each tracked
manifest, lower-cased, and that is the join: the key name of the entry (a GUID,
`7-Zip`, an Inno Setup AppId with `_is1`, or `<id>_<source identifier>` for a
portable) matched case-insensitively. Old manifests stay after an upgrade;
when several name one key, the manifest whose version equals the installed
version wins, then the most recently tracked one (`manifest_metadata` 7). A
catalog can hold an older version than the registry and still names the
installer. The Edge/WebView2 and .NET Framework rules keep precedence. A
catalog of the `StoreEdgeFD` source directory (msstore) reads `app-store`,
`microsoft-store`; another source directory reads `winget` with the id.

Measured on Windows 11 Enterprise 23H2 (22631), App Installer 1.29.380.0: 7-Zip,
Chrome, Acrobat Reader, Notepad++ (SYSTEM's catalog), Visual Studio Code (a
user's packaged catalog) and the portable jq (SYSTEM) all join; Zoom, the
AdoptOpenJDK JRE, Mondoo, the VC++ runtimes and the Intune Management Extension
are in no catalog and stay `installer`. The reader runs only when a query asks
for `osProvided` or `source` and the list holds an Uninstall entry. It copies
each `installed.db` (and a `-wal` file beside it) through the connection's file
system to a temporary file, at most 64 files of at most 16 MiB, and skips any it
cannot read. SYSTEM's catalogs are read first, so the bound never drops them.
Catalogs an older winget created have no `manifest_metadata` table; they are
read without the tracking time. Over SSH that is a directory listing per state
directory plus one read per catalog: on the host above (8 catalogs of about
220 KB) a query for `source` took 16.6 s instead of 15.0 s (median of three),
and the plain inventory stayed byte-identical. SYSTEM staying first matters
there: the catalog the Intune and remediation installs went into was SYSTEM's.
No host showed an msstore Win32 install, so that mapping follows what AppX
Store installs report.

**Amendment 2026-11-27: Chocolatey.** A program a Chocolatey package's
installer created reads `channel: "chocolatey"`, `name: <Chocolatey package
id>` (`git.install`), `url: <feed>`, `osProvided: false`, instead of
`installer`. Chocolatey's own packages stay in `chocolatey.packages`, not in
`packages`. Chocolatey keeps one record folder per installed package version,
`<root>\.chocolatey\<id>.<version>\`, with the root from `ChocolateyInstall`
(read in the same PowerShell query as the other facts) or
`C:\ProgramData\chocolatey`. `.registry` is XML and lists the Uninstall keys
the installer created (`KeyPath`, `displayVersion`, and the `user` that ran
choco); a meta package, a portable package or an extension has none.
`.sourceInstalledFrom` holds the feed, with a UTF-8 byte order mark and padding
spaces, and is missing from the record of an upgraded package; the `url` is
then empty and is not borrowed from another record. The join is the last
segment of `KeyPath`, matched case-insensitively to the entry's key name, and
the hive of `KeyPath` has to fit the entry's scope: `HKEY_LOCAL_MACHINE` only a
machine-scope entry, `HKEY_CURRENT_USER` and `HKEY_USERS\<sid>` only a user's
(SYSTEM's own hive is machine scope, as in the package listing). The package id
is the record folder name without its version suffix. The 32-bit and 64-bit
registry views are not told apart: the package does not keep which view it was
read from, so a key name used in both views joins to the same record.

Upgrades leave the old versions' folders behind. When several records name one
key, the one whose `displayVersion` equals the entry's version wins, then the
newest version in the folder name, then the most recently written record. winget
and Chocolatey can claim one key (a program one installed and the other
upgraded), and the same rule decides between them: the manager whose record is
for the installed version wins; when both or neither are, the record written
last wins (winget: `manifest_metadata` 7; Chocolatey: the `.registry` file's
modification time). The Edge/WebView2 and .NET Framework rules keep precedence.

Measured on Windows 11 Enterprise 23H2 (22631), Chocolatey 2.7.5 installed as
SYSTEM: `git.install` 2.56.1 (Inno Setup, key `Git_is1`), `putty.install` 0.85.0
(MSI, a ProductCode), `vlc.install` 3.0.24 (key `VLC media player`) and
`7zip.install` (key `7-Zip`) join; `vlc` (the meta package), `Wget` (portable)
and the extensions have no `.registry`. 7-Zip was installed by winget (26.03 in
its catalog), then by Chocolatey as 25.01 and upgraded to 26.06; both record
folders name `7-Zip`, the entry says 26.06, so the 26.6.0 record wins over the
25.1.0 one and over winget's 26.03 manifest, with an empty `url`. Notepad++,
Chrome and Acrobat Reader stay `winget`; "Chocolatey (Install Only)", the MSI of
the Chocolatey installer, is in winget's catalog (`Chocolatey.Chocolatey`)
because it was installed with winget; Zoom, the JRE, Mondoo and the VC++
runtimes stay `installer`. The reader runs only when a query asks for
`osProvided` or `source` and the list holds an Uninstall entry, through the
connection's file system, over at most 4096 record folders and at most 1 MiB per
`.registry`; a file it cannot read or parse is skipped. Over SSH on the host
above (9 record folders) a query for `source` took 17.9 s instead of 17.0 s
without the Chocolatey reader (median of three), and the plain inventory of all
185 packages stayed byte-identical; every Uninstall entry read as listed here.

**Amendment 2026-11-27: apk and pacman.** Both package managers record
nothing about the repository an installed package came from, so both follow
the dpkg rule: match the installed package against the indexes the package
manager downloaded, and let the index's signing key decide.

*apk.* The installed database (`/lib/apk/db/installed`, `/usr/lib/apk/db/installed`
on Wolfi, `/var/lib/apk/db/installed` with apk-tools 3) holds, per package, a
checksum `C:` (`Q1` and the base64 SHA-1 of the package's control segment) and
no repository, tag or signer. The same `C:` is in the repository's index
(`APKINDEX.tar.gz`) for the same build. apk keeps a downloaded index as
`APKINDEX.<hash>.tar.gz` in `/var/cache/apk` (or `/etc/apk/cache`), where
`<hash>` is the first four bytes, in hex, of the SHA-1 of
`<repository>/<arch>/APKINDEX.tar.gz`. A repository that is a directory is
read in place. The index is two gzip streams: a tar with one
`.SIGN.RSA.<key file>` (RSA with SHA-1) or `.SIGN.RSA256.<key file>` (SHA-256)
file per signature, then a tar with `DESCRIPTION` and `APKINDEX`. The
signature covers the second stream as it is stored. The reader verifies it with
the public key of that name in `/etc/apk/keys`, so a file that merely names an
OS key does not count. An OS key is a file in `/etc/apk/keys` that an
installed key package owns, read from the `F:` and `R:` lines of that package's
record in the installed database:

| Platform | Key package |
|---|---|
| `alpine` | `alpine-keys` |
| `alpaquita` | `distro-keys` |
| `wolfi`, `chainguard` | `wolfi-keys`, and the `chainguard-<64 hex>.rsa.pub` files, see below |

The rules, in order: the installed `(name, version, checksum)` in an index
signed by an OS key is `os`, `name` the repository's tag (`@testing`) or its
address without scheme, as `apk policy` prints it. Listed only by indexes
signed by other keys, or by an index with no signature, it is
`vendor-repository`. A name in no index, with an index for every line of
`/etc/apk/repositories`, is `direct`: `apk add ./file.apk`. A version in no
index with the name only in OS-signed indexes is `os` (an index lists only the
current version). Everything else is null: the version listed but with another
checksum (a rebuild), a third-party index that lists the name as well, a
repository without an index, an index apk-tools 3 wrote in its own format, a
platform with no entry. An index apk downloaded for a repository that
`/etc/apk/repositories` no longer names is not read.

Measured on 2026-11-27, aarch64 containers:

- `alpine:3.21` (apk-tools 2.14.13): five keys in `/etc/apk/keys`, all owned by
  `alpine-keys-2.5-r0`; no index until `apk update`, which wrote
  `APKINDEX.3983ad5a.tar.gz` (main), `APKINDEX.76499195.tar.gz` (community) and
  `APKINDEX.9b60f87e.tar.gz` (`@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing`),
  signed `.SIGN.RSA.alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub`.
  `alpine:edge` (apk-tools 3.0.7) and `bellsoft/alpaquita-linux-base:glibc`
  (3.0.9) name their cached indexes by the same hash and still write
  `APKINDEX.tar.gz`. The hash was computed for eight repositories and matched
  the file name each time.
- With nginx.org's repository added (`https://nginx.org/packages/alpine/v3.21/main`,
  `.SIGN.RSA256.nginx_signing.rsa.pub`, a key no package owns) and nginx,
  neofetch (from `@testing`), jq and a locally built package installed: of 78
  packages 74 are `os` from main, `neofetch` is `os` named `testing`,
  `nginx` is `vendor-repository`, `hello-direct`
  (`apk add --allow-untrusted ./hello-direct-2.0-r0.apk`) is `direct`, and
  `zlib` is `os` as a package that missed an update. nginx.org's index, like
  nginx.org's apt index, lists older versions next to the current one
  (1.26.2-r1 to 1.30.8-r1); the installed `C:` equals the index's `C:` for
  1.30.8-r1.
- `cgr.dev/chainguard/wolfi-base`: the index of `https://apk.cgr.dev/chainguard`
  is signed with three RSA-SHA256 signatures by
  `chainguard-<hex>.rsa.pub` keys. No package owns those files (`apk info -W`
  finds no owner); `wolfi-keys` owns `wolfi-signing.rsa.pub`, which does not
  sign this index. apko writes the keys into `/etc/apk/keys` when it builds the
  image. Ownership cannot decide here, so on `wolfi` and `chainguard` a
  key file named `chainguard-<64 hex>.rsa.pub` counts too. That is a
  weaker rule than ownership: whoever can write `/etc/apk/keys` can use such a
  name, and could equally place a key in an owned file. After `apk update` all
  19 packages are `os`.
- `alpine:3.21`, `wolfi-base`, `alpaquita` and `cgr.dev/chainguard/static` ship
  with no index, so every package reads null (`unknown`, `osProvided` null), as
  on a stock Debian image.

*pacman.* The local database (`/var/lib/pacman/local/<name>-<version>/desc`)
holds `%VALIDATION%` (how pacman checked the package when it installed it) and
no repository. The sync databases `pacman -Sy` downloads
(`/var/lib/pacman/sync/<repo>.db`, a tar of `<name>-<version>/desc`, gzip on
the images checked) list each repository's packages with `%PGPSIG%`, the
base64 detached signature of the package file. The package file is not on the
system, so the signature is matched by its issuer and not verified again,
exactly as for rpm. The OS keys are the keys in the keyring files that the
distribution's keyring package owns (the `usr/share/pacman/keyrings/*.gpg`
entries of the package's `files` record):

| Platform | Keyring packages |
|---|---|
| `arch` | `archlinux-keyring` |
| `manjaro` | `manjaro-keyring`, `archlinux-keyring` |

The repositories and their `Server` addresses come from `/etc/pacman.conf` and
the mirror list it includes (read only from `/etc`); `$repo` and `$arch` are
replaced. The rules mirror apk's: the installed `(name, version, architecture)`
in a database whose package signature is from an OS key is `os`, `name` the
repository (`core`, `extra`). Listed only with another key or no signature it
is `vendor-repository`. A name in no database, with a database for every
repository `pacman.conf` names, is `direct`: the `pacman -Qm` case, a package
built locally, from the AUR or installed with `pacman -U`. A version in no
database with the name only in OS-signed packages is `os` (Arch lists only the
current version). A package an OS database lists whose `%VALIDATION%` is not
`pgp` was not checked against that signature, so it is null; so is every case
the apk rules call null.

Measured on 2026-11-27, `archlinux:latest` (pacman 7.1.0, linux/amd64, under
emulation) and `manjarolinux/base`:

- Arch ships no sync database until `pacman -Sy`; before it the answer is null.
  After it, `core.db` (130 KB) and `extra.db` (9 MB) are gzip tars. For a
  repository with `DatabaseOptional` (the default) no `.db.sig` is kept
  (`core.db.sig` is absent), so the database signature cannot be used; for a
  `DatabaseRequired` repository it is kept. The signature of `acl` 2.4.0-1 is
  by subkey `6D42BDD116E0068F`, a key in `archlinux.gpg` (1.8 MB, armored,
  owned by `archlinux-keyring 20260909-1`).
- All 137 local records of the image read `%VALIDATION%` `pgp`. A package
  installed with `pacman -U` from an unsigned file reads `none`; one installed
  from a local repository with `SigLevel = Required`, a signed database and a
  signed package read `sha256`.
- With a signed local repository (`vendor`, its key added with
  `pacman-key --lsign-key`), nano from `core`, and `hello-direct` installed
  with `pacman -U`: of 179 packages 170 are `os` (156 `core`, 14 `extra`), 7
  are `os` as packages that missed an update, `hello-vendor` is
  `vendor-repository` named `vendor`, and `hello-direct` is `direct`
  (`pacman -Qm` lists exactly it).
- `manjarolinux/base`: the sync databases are on the image. Of the 320 packages
  in `core.db`, 254 are signed with a key from `archlinux.gpg` and 66 with one
  from `manjaro.gpg`: Manjaro copies many Arch builds and signs the rest itself.
  Both keyring packages are installed, so both keyrings are the operating
  system's, and all 182 packages are `os`. The residual risk is an Arch
  repository an administrator adds to a Manjaro host: its packages read as the
  operating system's.

Other Arch derivatives (EndeavourOS, Garuda, Arch Linux ARM's own repository)
and Alpine derivatives (postmarketOS) have no entry, because no image of them
was read; they report null, as an rpm platform without a key package does.

Like dpkg, both readers read files and run no command, so a container, an image
and a mounted disk give the same answer. Over SSH they read the same files
through the connection's file system. The bytes are the cost there: the indexes
apk reads are the configured repositories' only (alpine:3.21 with four
repositories 3.2 MB, Wolfi 7.7 MB), and pacman reads `extra.db` (9 MB) and the
keyring (1.8 MB). Measured on one machine against a container through a
loopback SSH connection, apk's query for `source` took 0.33 s instead of 0.26 s
without it; on a local container 0.70 s instead of 0.54 s (apk) and 1.88 s
instead of 1.22 s (pacman, under emulation); the plain inventory stayed
byte-identical. A transfer over a real network was not measured: at the sizes
above it is a few seconds on a 20 Mbit link, which is the cost the dpkg
section avoided by filtering on the host; a command that filters the indexes
on the host is the next step if this proves slow.

Guards both readers apply, so that a read that went wrong never becomes
`direct`. An index or database that is cut short, damaged, larger than its cap
or in a format the reader does not know counts as not read, and every answer
that needed it stays null. The list of repositories is complete only when every
line was placed: apk also reads `*.list` files in `/etc/apk/repositories.d` and
`/lib/apk/repositories.d` (apk-tools 3 has those paths; the 2.14 binary on
`alpine:3.21` has none), and a line that is neither `<url>` nor `@<tag> <url>`,
or more repositories than the cap of 64, makes the list incomplete. An
`APKINDEX.*` file in the cache that no configured repository explains (the
index of `apk add -X <url>`, or of a repository since removed) makes it
incomplete too: its address is unknown, so it is not read, and a package may
have come from it. pacman is incomplete for an `Include` outside a repository
section (the file may define repositories), for more repositories than the cap,
and for a `sync/*.db` file no repository of `pacman.conf` names (the stale
`community.db` of `manjarolinux/base` is one). A pacman package whose
`%BUILDDATE%` differs from the sync entry of the same name, version and
architecture is a rebuild by another repository and reads null, as an apk
checksum mismatch does. `%VALIDATION%` can list several methods; `pgp` among
them counts as a checked signature. Keys listed in the keyring package's
`*-revoked` file (fingerprints, one per line) are not the operating system's.
For apk, only the second gzip stream of an index is read when a signature
stream precedes it: an `APKINDEX` entry in the first stream is outside the
signature and is ignored, and an index of a single stream is unsigned and never
`os`. The signature stream is read through a 1 MB cap and at most 16
signatures.

Two behaviours are kept as they are. A package that missed an update reads `os`
when the name is only in OS-signed indexes, whether or not every repository has
an index, as for dpkg. And pacman's signature match is by the issuer in the
sync database's `%PGPSIG%`, which is not tied to the installed file, the same
trade-off as for rpm: pacman verified the file when it installed it, and the
database is what names the repository.

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

- opkg, xbps and the BSDs. They report null until a reader is added.
  (*Amended 2026-11-27:* apk and pacman are covered, see the amendment under
  "How each platform resolves it".) (*Corrected 2026-10-05:* yum on Amazon Linux 2 and zypper are
  covered: their signatures decide `osProvided` like dnf's, and their history,
  `yumdb` and `/var/log/zypp/history`, names the repository.)
- ~~winget as a channel of its own.~~ Done 2026-11-27, see the amendment under
  "How each platform resolves it".
- ~~Chocolatey installs that run an installer.~~ Done 2026-11-27, see the
  "Chocolatey" amendment under "How each platform resolves it".
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
