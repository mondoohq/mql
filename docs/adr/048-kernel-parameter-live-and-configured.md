# ADR 048: Kernel Parameters, Live and Configured

## Status

Proposed

## Context

A kernel parameter has two values that a security check cares about:

- the **live** value the running kernel uses now, and
- the **configured** value the system will apply at the next boot.

`kernel.parameters` reports only the first. It is a `map[string]string` read
from `sysctl -a`, or from `/proc/sys` when no command can run. The second
value is spread over a set of configuration files, and there is no resource
for it.

Hardening benchmarks require both: the running kernel must have the
setting, and it must survive a reboot. Today a policy builds the configured
value in MQL, per check, from `files.find` and line regexes:

```
sysctlDirs = ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d"].where(file(_).exists)
sysctlFiles = sysctlDirs.map(files.find(from: _, type: "file").list.map(path)).flat.where(_ == /\.conf$/) + ["/etc/sysctl.conf"].where(file(_).exists)
settings = sysctlFiles.map(file(_).content.lines).flat.where(_ == /^\s*fs[.\/]protected_hardlinks\s*=/)
settings.any(_ == /=\s*1\s*$/)
```

That is four lines of plumbing for one assertion, and it answers a different
question from the one asked. `.any()` passes when any file assigns the value,
but the system applies the **last** assignment, so a file that sets `1`
followed by a file that sets `0` passes. Expressing the real rules in MQL is
not practical, because they are not a filter over lines:

- A file in `/etc/sysctl.d` hides a file of the same name in a lower-priority
  directory, which is then never read.
- The surviving files are applied in file name order, across directories.
- A key may be a glob (`net.ipv4.conf.*.rp_filter = 1`). An explicit
  assignment of a key excludes it from every glob, regardless of which comes
  first, and `-key` on its own line excludes a key from globs without setting
  it. RHEL 9 ships both forms in `/usr/lib/sysctl.d/50-redhat.conf`.
- `/` and `.` are interchangeable separators, decided by the first one used.
- A leading `-` on an assignment means "ignore errors", not a different key.

The live and configured values also disagree for reasons that are not
misconfiguration. A parameter that belongs to an unloaded module
(`net.bridge.*` without `br_netfilter`), a disabled feature (`net.ipv6.*`
under `ipv6.disable=1`), an absent interface or a removed knob is configured
but not live. And on a container image or a mounted filesystem there is no
running kernel at all, so nothing is live and everything that is configured
is all there is to report.

## Decision

Add a `kernel.parameter` resource that carries both values for one name,
with the assignments behind the configured one, and a `kernel.sysctls` list
of every parameter known from either source.

```
kernel {
  // unchanged
  parameters() map[string]string
  // Every kernel parameter that is live, configured, or both
  sysctls() []kernel.parameter
}

kernel.parameter @defaults("name value configured") {
  init(name string)
  name string
  active() bool
  value() string
  configured() string
  settings() []kernel.parameter.setting
}

kernel.parameter.setting @defaults("key value file.path line") {
  key string
  value string
  file file
  line int
  effective bool
  ignoreErrors bool
}
```

A check that today needs the four lines above becomes:

```
kernel.parameter("fs.protected_hardlinks") {
  value == "1"
  configured == "1"
}
```

### Live and configured are separate fields, never merged

`value` is what the kernel reports. `configured` is what the files say after
precedence. Neither is derived from the other, and neither falls back to the
other when it is missing. A merged "effective" value would answer the
question most checks do not ask, and it would hide the most useful finding
this resource makes visible: the two disagree.

| `active` | `value` | `configured` | meaning |
|---|---|---|---|
| true | `"1"` | null | kernel default, nothing persisted |
| true | `"1"` | `"1"` | persisted and applied |
| true | `"1"` | `"0"` | drift: the next boot or reload changes it |
| false | null | `"1"` | configured, the kernel does not expose it |
| null | null | `"1"` | no running kernel observable, configuration only |

### `active` is null when there is no running kernel to observe

A container image, a mounted disk or a tar archive has no `/proc/sys`.
Reporting `active: false` there would claim the kernel lacks every parameter,
a measurement that was never taken. `active` is null in that case, the same
convention `kernel.aslr.enabled` uses for a missing `/proc`.

The live set is treated as unobservable when it is empty, or when reading it
fails on a connection that cannot run commands. A running Linux, macOS or BSD
kernel exposes hundreds of parameters, so an empty set means "no kernel was
read", not "a kernel with no parameters". Scanned as an image, both test
images in the verification below report `active` null for every entry.

### `kernel.sysctls` is the union of both sources

Iterating only the live parameters would drop exactly the entries that need
attention: a configured parameter the kernel does not have. Every name from
either source appears once. A configured-only name has `active: false` (or
null), and the list answers questions the map cannot:

```
// persisted settings the running kernel is not applying
kernel.sysctls.where(active == false && configured != empty)

// drift between running and persisted
kernel.sysctls.where(active && configured != empty && value != configured)
```

### Every assignment is kept, with the file and line

`configured` alone says what will be applied, not where it comes from or what
it overrode. `settings` lists every assignment that matches the parameter, in
the order it is applied, with its file and line. Exactly one has
`effective: true`; `configured` is that setting's value. This is what a
reviewer needs to fix a finding, and it supports audits that ignore
precedence on purpose (`settings.none(value == "0")`).

A file hidden by a same-named file in a higher-priority directory is not
listed. It is never read, so it takes no part in precedence.

### The precedence follows what applies the files at boot

Measured on Debian 12 (systemd 252, procps-ng 4.0.2) and AlmaLinux 9.8
(systemd 252 with `systemd-udev`, procps-ng 3.3.17), with test files in
`/usr/lib/sysctl.d`, `/etc/sysctl.d` and `/etc/sysctl.conf`:

| | `systemd-sysctl` (boot) | `sysctl --system` (procps) |
|---|---|---|
| directories, highest first | `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/lib` `sysctl.d` | same |
| same file name in two directories | higher directory wins | higher directory wins |
| order | file name, across directories | file name, across directories |
| `/etc/sysctl.conf` | only via the `/etc/sysctl.d/99-sysctl.conf` symlink both distributions ship | applied again after every other file |

The two disagree when a file sorts after `99-sysctl.conf`: at boot that file
wins, after `sysctl --system` `/etc/sysctl.conf` does. `configured` reports the
boot result, because a hardening check asks what survives a reboot. On a host
with a `systemd-sysctl` binary (`/usr/lib/systemd/systemd-sysctl` or
`/lib/systemd/systemd-sysctl`) the systemd order is used; otherwise the procps
order, which is what non-systemd init systems invoke. Both are read from the
files, never by running either tool, so the result is the same on a running
host and on its image.

`/lib/sysctl.d` is read after `/usr/lib/sysctl.d`. Both binaries name it
(procps-ng 4.0.4; Debian's `systemd-sysctl` 252, built for split `/usr`); the
`sysctl.d(5)` page lists only the first four, because newer systemd builds drop
it. On a merged-`/usr` system it is the same directory as `/usr/lib/sysctl.d`
and every file in it is deduplicated by name, so reading it is harmless there
and correct on an older split-`/usr` system.

On FreeBSD the files are `/etc/sysctl.conf` then `/etc/sysctl.conf.local`; on
OpenBSD and NetBSD `/etc/sysctl.conf`; on macOS `/etc/sysctl.conf`, which
`sysctl.conf(5)` documents and `/sbin/launchd` references. The BSD and macOS
behaviour follows from their documentation and has not been observed at
runtime.

### Globs follow systemd and procps, which agree

Measured with procps-ng 3.3.17, 4.0.2 and 4.0.4 and `systemd-sysctl` 252: a
glob assigns to every matching key except keys with an explicit assignment
anywhere in the configuration, in either order, and except keys named by a
`-key` exclusion line.

`kernel.parameter(name)` matches the name against every glob directly, so a
lookup gets the right answer on an image scan too. `kernel.sysctls` expands a
glob only against live names, because there is no other list of names to
expand it against. A glob that matches no live name is listed as its own entry
under the pattern, with `active` false or null, so a configured setting never
disappears from the list. `setting.key` keeps the key as written.

### `kernel.parameters` does not change

Changing it from a map to a list would break every `kernel.parameters["x"]`
query in existing policies. It stays the live-only map, and `kernel.parameter`
reads the same data.

### Verification

Two test images carry the same files: `10-a.conf` in `/usr/lib/sysctl.d`, a
`50-shadow.conf` in both `/usr/lib` and `/etc`, a `zz-after.conf` with a
slash-separated key, a glob, an exclusion, an explicit override and a removed
knob, and an assignment appended to `/etc/sysctl.conf`. Scanned as a running
container and as an image:

| image | `fs.protected_hardlinks` configured | from |
|---|---|---|
| AlmaLinux 9.8, `systemd-udev` | `4` | `/etc/sysctl.d/zz-after.conf`, after `99-sysctl.conf` |
| Debian 12, procps only | `5` | `/etc/sysctl.conf`, after every sysctl.d file |

Both match what `systemd-sysctl --cat-config` and `sysctl --system` apply on
those images. `net.ipv4.conf.all.rp_filter` (excluded) has no configured
value, `lo` (explicit) is `0`, `eth0` takes the last glob, and
`net.ipv4.tcp_tw_recycle` is configured with `active: false` in the
containers and `active: null` in the images.

## Security implications

The files read are root-owned and world-readable on every distribution
checked, so no new privilege is needed, and no command is run beyond the
`sysctl -a` that `kernel.parameters` already runs. The parser reads only the
fixed directories listed above, one level deep, through the target's own
filesystem, and skips hidden files and anything that is not `*.conf`, matching
both tools. A line longer than 1 MiB ends the parse with an error, the same
limit `ParseSysctl` applies to `sysctl -a` output.

The risk is a false pass: precedence modelled wrongly would report a hardening
setting as persisted when it is not. That is the failure mode of the MQL the
resource replaces, which accepts a value a later file overrides. Fixture tests
cover each rule in the tables above, and the rules were measured on running
systems rather than taken from documentation, except where noted for BSD and
macOS.

BusyBox `sysctl` (Alpine without procps) rejects glob keys and does not apply
them. On such a host a glob is reported as configured although it is not
applied. That is a known false pass, limited to globs on BusyBox systems.

## Performance implications

The live side is the existing `sysctl -a` or `/proc/sys` read. The
configured side lists at most five directories and reads the files in them,
typically under twenty files of a few hundred bytes each. Both are read once
per `kernel` resource and cached, so a policy with seventy sysctl checks reads
the configuration once, where the MQL it replaces ran `files.find` and read
every file seventy times. A lookup by name is a map read plus a match against
the glob settings.

## Consequences

**Positive**

- A sysctl check is two assertions instead of four lines of file plumbing, and
  it is correct under precedence.
- Drift between running and persisted values is queryable across the fleet.
- A finding points at the file and line that set the value.

**Negative**

- A policy using `kernel.parameter` needs a provider release that includes it.
- Check authors must decide per check how to treat `active == false` (module
  not loaded) and `active == null` (image scan). A check that requires
  `value == "1"` fails on every image scan, as it does today.
- The boot order is the systemd order. A host where an administrator applied
  changes with `sysctl --system` and a file sorts after `99-sysctl.conf` shows
  drift between `value` and `configured` until reboot. That is correct, but it
  may surprise.

## Alternatives Considered

### A top-level `sysctl` resource, like osquery's `system_controls`

It would put two resources in front of the same live data, `kernel.parameters`
and `sysctl`, and the kernel already owns parameters, modules and their
configuration (`kernel.module.blacklisted` is the same pattern for modprobe).

### Changing `kernel.parameters` to carry both values

Its type is part of the query language contract. A map of objects or a list
would break every existing `kernel.parameters["name"] == "1"` check.

### A `configured` string without `settings`

Cheaper, but it cannot say which file set the value or what it overrode, which
is the first thing anyone fixing a finding needs. Keeping every assignment
costs a slice per parameter.

### Running `systemd-sysctl --cat-config` or `sysctl --system`

`--cat-config` prints the files in order but not the outcome of glob and
exclusion rules, and neither tool runs on an image or a mounted filesystem,
where the configured value is the only one available. `sysctl --system` also
writes to the kernel.

### Reporting the procps order

It matches what an administrator sees after `sysctl --system`, but not what a
reboot produces, and a hardening control is about the reboot.
