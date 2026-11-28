# ADR 065: Effective sshd Configuration Without a Privilege Separation Directory

## Status

Proposed

## Context

`sshd.config.effectiveCiphers`, `effectiveMacs` and `effectiveKexs` report
what the OpenSSH server would accept. They come from one `sshd -T` run
(`effectiveParams` in `providers/os/resources/sshd.go`), which prints the
configuration after defaults, `Include` files, Match blocks and command-line
options are applied. Checks for weak ciphers, MACs and key exchange
algorithms read these fields because `ciphers`, `macs` and `kexs` only show
what the files say, not the compiled-in defaults that apply when a file says
nothing.

Before it prints anything, `sshd -T` checks that its privilege separation
directory exists. On Debian and Ubuntu that is `/run/sshd`. `/run` is a tmpfs
that is empty after every boot, and the directory is created by the service
unit (`RuntimeDirectory=sshd`) when `ssh.service` starts.

Since Ubuntu 22.10, openssh is socket-activated: `ssh.socket` listens on port
22 and starts `ssh.service` on the first connection. Ubuntu 24.04 does this by
default. On a host that nobody has connected to over SSH since it booted,
for example a server managed through an agent, `ssh.service` has not run
and `/run/sshd` does not exist:

```
$ sudo sshd -T
Missing privilege separation directory: /run/sshd
$ echo $?
255
```

The three effective fields then fail with
`sshd -T failed (exit 255): Missing privilege separation directory: /run/sshd`,
so every check that reads them is reported as an error instead of a pass or
a fail. The first SSH login creates the directory, the checks start to work,
and a host that looked unscored now shows failures, which reads as a
regression even though nothing on the host changed. The state is easy to
reproduce on Ubuntu 24.04:

```
sudo systemctl stop ssh.service
sudo rm -rf /run/sshd
mql run local -c 'sshd.config.effectiveMacs'
```

The directory is only a precondition of the daemon. `sshd -T` does not use
it, and the configuration it would print does not depend on it.

## Decision

When `sshd -T` on Linux fails with `Missing privilege separation directory:
<dir>`, and `<dir>` is a direct child of `/run` or `/var/run`, the provider
runs the same command a second time in a private mount namespace that has an
empty tmpfs at the directory's parent:

```
unshare --mount --propagation private sh -c \
  'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -m 0755 /run/sshd && exec sshd -T …'
```

The command after `exec` is the one the provider would have run anyway, with
the `-f` path, any `-C` connection specification and the `-o` options of the
running daemon. Once a run needed the namespace, the provider's later
`sshd -T` runs for the same resource (the `-C` retry for OpenSSH 7.9, the run
with the daemon's options) go straight to the namespace instead of failing
first.

### Nothing on the host changes

The tmpfs and the directory exist only in the new mount namespace, which ends
when `sshd -T` exits. `--propagation private` is passed explicitly so the
mount cannot propagate to the host's mount namespace, even with an `unshare`
whose default differs. The host's `/run` and everything under it stays as it
was: no directory is created, no service is started, no unit changes state.

### Only that error, only on Linux, only under `/run`

The retry happens only for the one stderr line above. Any other `sshd -T`
failure (a bad option, missing host keys, a Match block that needs `-C`)
behaves as before. The directory path is taken from the error and must be
`/run/<name>` or `/var/run/<name>` with a plain name; any other path, such as
`/var/empty` on distributions that use it, is left alone, because mounting a
tmpfs over `/var` would hide files `sshd -T` may need. Other platforms are
unchanged.

### When the namespace is not available

`unshare` is part of util-linux and is installed on every mainstream
distribution; BusyBox also ships it. Creating a mount namespace and mounting
a tmpfs needs `CAP_SYS_ADMIN`, so it fails for a scan that runs as an
unprivileged user and in a container without that capability. In those cases
the wrapper exits with its own status (1 from `unshare` or `mkdir`, 32 from
`mount`, 127 when `unshare` is missing), never with the 255 `sshd` uses for a
fatal error. The provider then reports the original failure with the reason
it could not work around it:

```
sshd -T failed (exit 255): Missing privilege separation directory: /run/sshd
(sshd creates this directory when the ssh service starts; running sshd -T in
a private mount namespace with a temporary /run failed too: unshare: unshare
failed: Operation not permitted)
```

A failure with status 255 inside the namespace is `sshd` itself and is
treated as any other `sshd -T` result, so the `-C` retry still applies.

### Remote scans

When the scanner reaches the host over SSH, `ssh.service` is running and the
directory exists, so the first run succeeds and the new path is never taken.
If the connection elevates with sudo, the wrapper runs under sudo like any
other command.

### Verification

Unit tests in `providers/os/resources/sshd_privsep_test.go` cover the retry
that succeeds, the retry that is unavailable (the original error is kept and
explained), a path outside `/run` (no retry), a non-Linux platform (no
retry), and the `-C` retry after the namespace was needed.

The change was checked on an Ubuntu 24.04 virtual machine (OpenSSH 9.6p1)
after `systemctl stop ssh.service` and `rm -rf /run/sshd`, with `sshd -T`
failing as above: `effectiveMacs`, `effectiveCiphers` and `effectiveKexs`
return their lists, `/run/sshd` still does not exist afterwards, `ssh.service`
stays inactive and the host's `/run` mount is unchanged. The same query under
`capsh --drop=cap_sys_admin` returns the explained error shown above.

## Security implications

The provider runs one more command, only on a host where `sshd -T` already
ran with the same privileges. The command creates a mount namespace, which
needs privileges the scan already has when the namespace works at all, and
runs the same `sshd -T`. The inner script is built from fixed text, a
directory path that matched a strict pattern, and the `sshd -T` command line
that is already shell-escaped; the whole script is shell-quoted again for
`sh -c`.

## Performance implications

None on the common path. On a host in the state described above, the scan
runs `sshd -T` twice instead of once (the failing run, then the one in the
namespace), and later runs for the same resource go straight to the
namespace.

## Consequences

- CIS-style checks on ciphers, MACs and key exchange algorithms report a
  result on socket-activated hosts whether or not anyone has connected
  over SSH since boot, and the result does not change on the first login.
- A scan without the privileges for a mount namespace still errors, but the
  error says why and what would make it work.

## Alternatives Considered

### Creating `/run/sshd` on the host

`mkdir -p /run/sshd` before `sshd -T` is what the service unit does, and it
would work everywhere the scan runs as root. It writes to the system being
scanned. A scanner reports state; it must not change it, and the os provider
does not create files or directories on the host in order to read something.
Rejected.

### Starting the service, or `systemd-run` with `RuntimeDirectory=`

`systemctl start ssh.service` changes the host's state and starts a network
daemon the operator chose to run only on demand. `systemd-run
-p RuntimeDirectory=sshd sshd -T` runs a transient unit that creates the
real `/run/sshd` on the host for its lifetime, removes it afterwards, and
leaves a unit in the journal. It also needs systemd and its D-Bus, which a
container or a minimal host may not have. Both write to the host. Rejected.

### Falling back to the configuration files

The files only list what was set explicitly. When `MACs` is not set, the
effective list is the compiled-in default, which differs between OpenSSH
releases and distribution patches. Reporting the files' view, or an empty
list, as the effective value would make a check against weak algorithms pass
on a host that accepts them. The fields exist to avoid that. Rejected.

### Pointing sshd at another directory

The privilege separation directory is compiled into sshd
(`_PATH_PRIVSEP_CHROOT_DIR`); there is no option or environment variable to
change it.

### Running as an unprivileged user

`sshd -T` as an unprivileged user fails because it cannot read the host
keys, so it is not a way around the directory check. Rejected.

### Only a clearer error

Explaining the error without working around it leaves the checks unscored on
the hosts where they matter. The clearer error is kept for the cases where
the namespace is not available.
