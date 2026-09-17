# secboot fixtures

Test data for `secboot.go`, which reads the configuration of the
[secboot](https://github.com/dadevel/secboot) utility and the unified kernel
images it installs.

`host/files/` keeps the absolute layout, so a test can root a filesystem at it
and exercise path resolution rather than only parsing.

## The images

The four `.efi` files under `host/files/boot/efi/EFI/Linux/` were built on
2026-09-17 by systemd's own `ukify`, in a `fedora:42` container on aarch64.
Nothing here is hand-made: the section table, the padding and the headers are
what `ukify` emits.

```bash
ukify build --stub=/usr/lib/systemd/boot/efi/addonaa64.efi.stub \
  --cmdline="rd.luks.name=8d0b7f2c-1111-2222-3333-444455556666=vault root=LABEL=root rw quiet audit=1" \
  --uname="6.19.14-108.fc42.aarch64" --output=linux-9f8e7d6c.efi
```

| file | command line | signature |
|---|---|---|
| `linux-9f8e7d6c.efi` | `… root=LABEL=root rw quiet audit=1` | none |
| `signed-9f8e7d6c.efi` | identical to the above | `sbsign`, self-signed fixture certificate |
| `stale-9f8e7d6c.efi` | `… root=LABEL=root rw quiet`, no `audit=1` | none |
| `fwupdaa64.efi` | none | none |

**They are built on the addon stub rather than the kernel stub, and carry no
kernel.** `secboot.go` reads the headers, the certificate table, `.cmdline` and
`.uname`, and nothing else. Building on the 76 KB kernel stub with a kernel
inside would add roughly 320 KB across the four files, none of which any test
reads. Every section that is read is produced by the same tool in the same way.

The parser was also run against a full unified kernel image built the ordinary
way, on the kernel stub around `kernel-core` 6.19.14, 16 MB with all 11
sections. It reported the same command line and kernel release. That image is
not committed, for the reason above.

`signed-9f8e7d6c.efi` is `linux-9f8e7d6c.efi` put through `sbsign` with a
throwaway self-signed certificate, so the pair differs only in the certificate
table. That is what lets a test state that signing does not change what the
image says it boots.

`fwupdaa64.efi` is a copy of systemd's `addonaa64.efi.stub`. It stands in for
the files that share the directory without being images: secboot copies a
firmware updater in beside them, and the boot loader lives on the same
partition. It is a valid PE executable with no `.cmdline` section, so it is not
an image and is not reported as one.

The LUKS UUID in the command lines is invented. It is there because secboot
builds `rd.luks.name=<uuid>=vault` into every image from the LUKS header at
build time, and no configuration file ever states it.

## The configuration

`host/files/etc/secboot/config.json` sets 8 of the tool's 16 keys, so the same
fixture exercises both halves of the decode: the values read from the file, and
the 8 that have to come from the defaults in `main.py`. `machine-id` and
`tpm-device` are the ones checked for the second case.

## What is not here

No fixture was produced by running secboot itself. The tool builds through
`dracut --uefi-stub` on a host with LUKS and an EFI system partition, and none
was available. What that leaves unverified is written up in
https://github.com/mondoohq/mql/issues/10929.
