# Boot loader configuration fixtures

Boot loader configuration copied verbatim from real hosts on 2026-09-17, for
testing `grub.go` against the layouts the os provider actually meets. Nothing
here is hand-written: every file under a host's `files/` directory is a byte
copy of that path on the host it is named for.

Each host directory holds:

- `files/` — the configuration, keeping its absolute layout, so a test can root
  an afero filesystem at `files/` and exercise path resolution, not just line
  parsing.
- `oracle/` — what that host actually did, for assertions to be checked
  against rather than derived from the same parser under test:
  - `proc-cmdline.txt` — the command line the running kernel booted with.
  - `grubby-info-all.txt` — RHEL-family. `grubby` expands `$kernelopts` the
    same way the boot loader does, so it is the reference for entries that use
    it.
  - `bootctl-list.txt`, `bootctl-status.txt`, `efibootmgr.txt`.
  - `blscfg.txt` — whether each `grub.cfg` delegates to Boot Loader
    Specification entries.
  - `boot-tree.txt` — the shape of `/boot`, with kernels, initramfs images,
    device trees, modules and fonts filtered out.
  - `firmware.txt`, `arch.txt`, `os-release.txt`, `kernel-release.txt`,
    `tools.txt`, `mount-boot.txt`, `mount-boot-efi.txt`.

## Provenance

EC2 hosts were launched from the AMIs below in us-west-2, collected from, and
terminated the same day. `proxmox-nas` is a physical Proxmox VE host.

| Fixture | Distribution | Arch | Firmware | Layout | BLS entries | AMI |
|---|---|---|---|---|---|---|
| `al1` | Amazon Linux AMI 2018.03 | x86_64 | bios | GRUB legacy menu | 0 | ami-03a3cd72255745584 |
| `al2` | Amazon Linux 2 | x86_64 | bios | grub.cfg | 0 | ami-0d4f0921b6c18b937 |
| `al2023` | Amazon Linux 2023.12.20260914 | x86_64 | uefi | BLS inline | 1 | ami-0d21970fc031a9d81 |
| `arm-al2023` | Amazon Linux 2023.12.20260914 | aarch64 | uefi | BLS inline | 1 | ami-0016b4a92b3d1a1e4 |
| `arm-debian12` | Debian GNU/Linux 12 (bookworm) | aarch64 | uefi | grub.cfg | 0 | ami-0b398d23ef3774293 |
| `arm-rhel9` | Red Hat Enterprise Linux 9.6 (Plow) | aarch64 | uefi | BLS inline | 1 | ami-07cbe1ffd7a16533f |
| `arm-sles15sp7` | SUSE Linux Enterprise Server 15 SP7 | aarch64 | uefi | grub.cfg | 0 | ami-06818f021b47f3109 |
| `arm-ubuntu2404` | Ubuntu 24.04.4 LTS | aarch64 | uefi | grub.cfg | 0 | ami-05c117a6593f02954 |
| `centos-stream10` | CentOS Stream 10 (Coughlan) | x86_64 | bios | BLS inline | 1 | ami-0498cdaf150a46fd1 |
| `centos-stream9` | CentOS Stream 9 | x86_64 | bios | BLS inline | 1 | ami-063f5805ab0c5d8a9 |
| `debian12` | Debian GNU/Linux 12 (bookworm) | x86_64 | bios | grub.cfg | 0 | ami-0651ef0db87bc8ced |
| `debian13` | Debian GNU/Linux 13 (trixie) | x86_64 | bios | grub.cfg | 0 | ami-0c605b75e3a75e872 |
| `nixos2605` | NixOS 26.05 (Yarara) | x86_64 | bios | grub.cfg | 0 | ami-0448897c4da7b6fd8 |
| `opensuse-leap16` | openSUSE Leap 16.0 | x86_64 | uefi | grub.cfg | 0 | ami-01e8f34bf515f1207 |
| `proxmox-nas` | Proxmox VE on Debian 13 (trixie) | x86_64 | uefi | grub.cfg | 0 | physical host |
| `rhel10` | Red Hat Enterprise Linux 10.0 (Coughlan) | x86_64 | uefi | BLS inline | 1 | ami-04ba39e500d39656f |
| `rhel8` | Red Hat Enterprise Linux 8.10 (Ootpa) | x86_64 | uefi | BLS + $kernelopts | 2 | ami-0e864a6ed291e7e7f |
| `rhel9` | Red Hat Enterprise Linux 9.6 (Plow) | x86_64 | uefi | BLS inline | 1 | ami-099ccdd264601d646 |
| `rocky8` | Rocky Linux 8.10 (Green Obsidian) | x86_64 | uefi | BLS + $kernelopts | 2 | ami-002d02e441c88be78 |
| `rocky9` | Rocky Linux 9.8 (Blue Onyx) | x86_64 | uefi | BLS inline | 2 | ami-00c356e7c787b9fc0 |
| `sles15sp7` | SUSE Linux Enterprise Server 15 SP7 | x86_64 | uefi | grub.cfg | 0 | ami-0150c541f790e233b |
| `ubuntu2204` | Ubuntu 22.04.5 LTS | x86_64 | uefi | grub.cfg | 0 | ami-07b3d2f97d89e29a4 |
| `ubuntu2404` | Ubuntu 24.04.4 LTS | x86_64 | uefi | grub.cfg | 0 | ami-04678417fc39d7171 |

## What the collection showed

These are the behaviors the fixtures exist to pin.

**A grub.cfg on the EFI system partition is usually a stub.** On every
RHEL-family host there are two files named `grub.cfg`: the real one at
`/boot/grub2/grub.cfg`, and a four-line stub at
`/boot/efi/EFI/<vendor>/grub.cfg` that does `configfile $prefix/grub.cfg`. The
stub holds no entries. `rocky8` is the exception, carrying a full configuration
in both places, and a second `grubenv` beside the ESP copy.

**The RHEL family keeps no kernel command line in grub.cfg at all.** On
`rhel8`, `rhel9`, `rhel10`, `centos-stream9`, `centos-stream10`, `al2023`,
`arm-al2023`, `arm-rhel9`, `rocky8` and `rocky9` the authoritative `grub.cfg`
has zero `linux` lines. It calls `blscfg`, which reads
`/boot/loader/entries/*.conf`. Any reading of `grub.cfg` alone finds nothing to
audit on these hosts. `rocky9` and `al2023` still contain a `menuentry`, for
UEFI firmware settings, which boots no kernel.

**`$kernelopts` is RHEL 8 only.** `rhel8` and `rocky8` entries read
`options $kernelopts`, resolved from the `kernelopts=` line in
`/boot/grub2/grubenv`. RHEL 9 and later write the arguments inline. The
`grubenv` file is a fixed 1024 bytes, padded to the end with `#`.

**`$kernelopts` is not the only variable.** RHEL 8 and 9 entries also carry
`$tuned_params` and `$tuned_initrd`, which `grubby` leaves unexpanded, and
NixOS writes its kernel path as `($drive2)/nix/store/...`. A parser has to
tolerate variables it cannot resolve rather than treat them as values.

**Firmware does not follow architecture, and an ESP can be present either
way.** Most x86_64 AMIs here boot UEFI, while `centos-stream9`,
`centos-stream10`, `debian12`, `debian13` and `al2` boot BIOS. All of them have
`/boot/efi` populated regardless, so the presence of an ESP says nothing about
how the host booted.

**Recovery entries differ from normal ones in their arguments, and are marked
several ways.** Debian and Ubuntu mark them with a `recovery` flag and a
`(recovery mode)` title, SUSE with `single`, and the RHEL family with a
`0-rescue` entry file. `ubuntu2404` carries six `linux` lines for one kernel:
top-level and submenu copies, plus recovery variants that drop the console
arguments the normal entries carry.

**Memory test entries boot no kernel.** `proxmox-nas` carries eight, marked
`--class memtest`, loading `/boot/memtest86+*.efi` rather than a kernel.

**`/etc/kernel/cmdline` is present but is not the boot arguments.** It exists
on `al2023`, `rhel9`, `rhel10`, `centos-stream9` and `centos-stream10`, and on
`rhel9` it lacks the `crashkernel` argument that the BLS entry and
`/proc/cmdline` both carry.

**GRUB legacy names its menu twice, and only one of the names is a file.**
`al1` is the one host here that boots GRUB 0.97. Its menu is
`/boot/grub/menu.lst`; `/boot/grub/grub.conf` is a symlink to it and
`/etc/grub.conf` is a second symlink to the same file. A scan that does not
resolve links sees whichever name it looks for, so all of them are candidates.
The host has no `/etc/default/grub`, no `grubby` and no configuration
generator: the menu is the only statement of what it boots, and it is edited by
hand. `al1` also carries two installed kernels with different arguments, so its
two entries are not copies of each other.

The AMI is the ECS-optimized build. The stock `amzn-ami-hvm-2018.03` images
have been deregistered, and `amzn-ami-2018.03.*-amazon-ecs-optimized` is the
remaining published Amazon Linux 1 AMI.

**No host here boots with systemd-boot.** The `/boot/loader/entries` files
above are GRUB's, read through `blscfg`. `proxmox-nas` uses GRUB, not
`proxmox-boot-tool` with systemd-boot. A systemd-boot fixture still has to come
from somewhere else.

## Re-collecting

`collect.sh`, kept with the collection scripts rather than in the repository,
gathers the paths above and the oracles into a tarball. It is best-effort by
design: a missing file records its absence, because absence is fixture data
too. A host with no `/boot/loader/entries` is the case that must not be
mistaken for a host with an empty entry list.
