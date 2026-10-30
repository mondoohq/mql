# OS Provider

This provider makes the operating system accessible, including Linux, macOS, Windows, and many more.

It provides connectors for Local OS, SSH, WinRM, and Docker.

## Usage

```shell
mql shell os
```

## Examples

<!-- TODO: add example queries -->

## Native file searches

Native and archive searches default to a two-minute elapsed budget, at most
1,000,000 visited entries, and at most 100,000 matches. An exhausted budget is
an error. Narrow `from`, `depth`, or `type` to reduce the search scope.

A native search reports an error when its root cannot be read, or when a strict
mount-boundary search cannot read a directory's device metadata. These failures
cannot establish a complete inventory. A root that does not exist still has no
matches.

Cancellation and budget checks run between filesystem operations. A single
kernel-blocked `Stat` or `ReadDir` cannot be interrupted through `io/fs`; a
directory backend can also allocate its listing before the entry budget is
checked.

## SSH connection timeout

SSH banner probing, TCP connection establishment, the handshake and authentication
share a 30-second timeout. Set the `ssh_connect_timeout` inventory connection option
or `MONDOO_SSH_CONNECT_TIMEOUT` environment variable to a positive Go duration such
as `60s` to allow slower connections. The inventory option takes precedence. The
banner probe also has a five-second limit. The startup deadline is cleared after
authentication so it does not expire a healthy scan connection.

## Command limits

Local, SSH, WinRM and running-container commands have a five-minute budget,
including queueing and output collection. Set `MONDOO_COMMAND_TIMEOUT` to a
positive Go duration, for example `2m`. A caller’s earlier context deadline or
cancellation takes precedence. Existing `RunCommand` callers receive the same
finite limit; `RunCommandContext` additionally accepts caller cancellation.

Combined stdout and stderr are limited to 128 MiB per command. Set
`MONDOO_COMMAND_OUTPUT_LIMIT` to a positive byte count to change the limit.
Exceeding it stops capture, cancels execution and returns an error; a captured
prefix is never returned as a successful complete result. Persistent PowerShell
sessions include their small framing records in this budget. WinRM additionally
limits encoded response traffic to twice the output limit plus 64 KiB, bounding
SOAP/base64 allocation before the SDK can decode it.

Local cancellation terminates the command’s process group on Unix and job object
on Windows, and bounds output-pipe draining. SSH closes the command’s channel;
if channel closure stalls, it closes the connection. WinRM commands own a
transport so cancellation also interrupts shell creation and HTTP body reads.
Docker cancellation closes the hijacked attachment. Closing SSH or Docker
streams cannot guarantee that the remote server terminates every descendant;
Docker has no per-exec kill API, and the scanner does not stop the container.
