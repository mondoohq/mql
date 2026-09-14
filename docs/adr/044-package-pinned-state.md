# ADR 044: Reporting Packages Held at Their Current Version

## Status

Accepted

## Context

An audit that finds an outdated package cannot currently tell two very
different situations apart:

- nobody has applied the update yet, or
- this host is **configured** never to apply it.

Only the second needs a human. An administrator who runs `apt-mark hold nginx`
or `dnf versionlock add kernel` has made a deliberate decision, usually to keep
a working system working. That decision is invisible to `mql` today, so a report
lists the package as outdated with no indication that the update is blocked, and
a remediation ticket goes to someone who will discover the hold only after
trying to patch.

The `package` resource already carries `outdated`, `available` and `status`. It
does not carry the fact that upgrading is switched off.

## Decision

Add a `pinned bool` field to `package`.

`pinned` is true when the package manager is configured not to upgrade the
package: a dpkg or opkg hold, a dnf or yum versionlock, or a zypper lock.

### It is read from files, not from the tools

Every mechanism has a file behind it, and the commands are wrappers over those
files:

| manager | source | verified against |
|---|---|---|
| dpkg | `/var/lib/dpkg/status`, `Status: hold ok installed` | `debian:12` |
| opkg | `/usr/lib/opkg/status`, `Status: install hold installed` | fixture in-repo |
| dnf4 | `/etc/dnf/plugins/versionlock.list` | `almalinux:9` |
| yum | `/etc/yum/pluginconf.d/versionlock.list` | `amazonlinux:2` |
| dnf5 | `/etc/dnf/versionlock.toml` | `fedora:latest` |
| zypper | `/etc/zypp/locks` | `opensuse/leap:15` |

This is the decision with the longest reach, and it is made for coverage rather
than for speed. `mql` scans container images, mounted filesystems and disk
snapshots, and on those targets **no command can run at all**. A reader built on
`apt-mark showhold` or `dnf versionlock list` reports "nothing is pinned" there,
which is indistinguishable from a host that genuinely holds nothing — a check
that passes precisely where it has the least information.

Reading files also matches how the resource already works: `packages` parses the
dpkg database and the rpmdb directly rather than shelling out to `dpkg-query` or
`rpm -qa` when it can avoid it.

The behaviour is verified on both connection types. The same locked host is
scanned as a running container and as a committed image, and both report
`pinned: true`.

### Locations are probed, not derived from the platform version

`RpmPkgManager` serves RHEL, AlmaLinux, Rocky, Oracle Linux, Amazon Linux,
Photon, azurelinux, bottlerocket and wrlinux, each on its own dnf/yum/tdnf
timeline. A version gate would encode a guess about every one of them.

The three versionlock stores are therefore probed in order, newest first, and
the first that exists wins. This mirrors how the same file already locates the
rpm database across three eras (`rpmdb.sqlite`, `Packages`, `Packages.db`), and
it stays correct on a distribution nobody anticipated. On RHEL 9 the yum path is
a symlink onto the dnf one, so probing resolves both with a single read.

### A manager with no mechanism reports false

apk has no lock concept. Photon's tdnf has no versionlock plugin, none is
available in its repositories, and `tdnf versionlock` is not a command
(`No such command: versionlock`, tdnf 3.6.5).

On those platforms `pinned` is always false, and that is stated in the field
documentation. The distinction matters: false has to mean "there is no such
thing here", not "this was not checked".

### Debian's apt preferences are out of scope

In Debian terminology "pinning" usually means `/etc/apt/preferences`, which
assigns priorities that bias which candidate apt selects. That is not a hold: a
pinned-by-priority package can still be upgraded. Treating it as `pinned: true`
would report a host as frozen when it is not, so the field covers holds and
version locks only, and its documentation says so to head off the obvious
misreading.

## Consequences

- A policy can distinguish "not yet patched" from "patching is switched off",
  and can flag the second for review rather than for remediation.
- The field answers identically on a live host, an image and a mounted
  filesystem, so a fleet report does not change shape with the connection type.
- Two managers cost nothing to support: the hold is already in the status the
  resource parses, so dpkg and opkg required no new I/O.
- New lock mechanisms are additive: a new store is one more probed path.

## Alternatives Considered

### Running the tools

`apt-mark showhold`, `dnf versionlock list`, `zypper locks`. Rejected: it
answers nothing on an image, a mounted filesystem or a snapshot, and those are a
large share of what gets scanned. It also spawns a process per manager per scan
to read data already present on disk.

### A `pinnedReason` string, or an enum of mechanisms

Rejected. The question a check asks is yes/no, and the mechanism is already
implied by the platform: a `deb` package is held by dpkg, an `rpm` by
versionlock or zypper. A string invites checks that match on the wording of a
mechanism name, which is the kind of assertion that breaks when a distribution
changes tooling.

### Reusing `status` alone

`status` already exposes the dpkg triple, so a check *could* match `hold` in it.
Rejected: it answers only for dpkg and opkg, is empty on rpm-based systems, and
pushes string parsing into every policy that wants the answer. It also could not
express a versionlock, which lives outside the package database entirely.

### Covering pacman's `IgnorePkg`

Arch records held packages in `/etc/pacman.conf`. It is a real equivalent and
was left out only to keep this change to the managers in the original request.
It is additive under the same design: one more source, one more `lockedNames`.
