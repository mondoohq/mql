# MikroTik Provider Testing

## Overview

This document covers standing up a MikroTik RouterOS device in AWS for provider
development and validation, and the traps that cost time the first time. All of
it is verified against **CloudEOS-equivalent MikroTik CHR 7.23.2** launched from
the AWS Marketplace.

A full run — launch, configure, sweep every resource, tear down — takes about
20 minutes and costs a few cents.

---

## Prerequisites

- An AWS account subscribed to [MikroTik Cloud Hosted Router](https://aws.amazon.com/marketplace/pp/prodview-sf5gn6js6av54)
- `terraform`, `aws` CLI, and a built provider (`make providers/build/mikrotik && make providers/install/mikrotik`)

### Licensing

CHR is **BYOL on Marketplace, with no software charge**, and its free licence
level runs indefinitely: 1 Mbps per interface, every other feature unrestricted.
That cap is irrelevant for provider work, since the provider only reads
configuration over the RouterOS API and never passes traffic. You pay for EC2
and nothing else.

### Finding the AMI

Unlike some network-appliance listings, the CHR image **is** publicly
discoverable:

```bash
aws ec2 describe-images --owners aws-marketplace \
  --filters "Name=name,Values=*CHR*" --region us-west-2 \
  --query 'Images[].[ImageId,Name,ProductCodes[0].ProductCodeId]' --output text
# ami-01af9289831640581  CHR RouterOS 7.23.2-...  blez4ywfw64kidgmc4v6vyjoa
```

Confirm the account can actually launch it before writing any Terraform — a
subscription can take a few minutes to propagate, and until it does the error
is `OptInRequired`:

```bash
aws ec2 run-instances --dry-run --region us-west-2 \
  --image-id <ami-id> --instance-type t3.small --subnet-id <subnet>
# want: DryRunOperation ("Request would have succeeded")
```

To check what an account holds:

```bash
aws license-manager list-received-licenses --region us-west-2 \
  --query 'Licenses[].ProductName' --output text | tr '\t' '\n' | grep -i "cloud hosted"
```

**If you cannot subscribe**, MikroTik publishes the CHR raw disk image and
there is an official guide for [importing it as your own AMI](https://manual.mikrotik.com/docs/getting-started/installation-and-upgrade/install/chr-installation/aws/)
via S3 and VM Import/Export. That needs a `vmimport` IAM role and takes longer,
but requires no Marketplace subscription at all.

---

## Instance and security group

`t3.small` is plenty — CHR needs 256 MB RAM minimum, 1 GB recommended, 128 MB
disk. At the time of writing that is **$0.0208/hr** in `us-west-2`.

The provider speaks the **RouterOS API**, not SSH or REST, so the security
group opens different ports than you might expect:

| Port | Purpose |
|---|---|
| 8728 | RouterOS API, **plaintext** |
| 8729 | RouterOS API over TLS (`api-ssl`) |
| 22 | SSH, only needed to bootstrap the device |

Restrict all three to your own address. Both API ports are **enabled by default**
on the CHR image, so the device is reachable as soon as it boots — there is no
service to turn on first.

CHR boots fast: the API answers roughly 10 seconds after `terraform apply`
returns.

---

## Bootstrapping

MikroTik does **not** document EC2 user-data support for CHR (cloud-init is
documented for Hetzner and Vultr, not AWS), so do not bake configuration into
user-data and hope. Launch with an EC2 key pair and configure over SSH.

The default account is `admin` with **no password**:

```bash
ssh -i <key> admin@<ip> "/system/resource/print"
```

Set a password so the provider can authenticate:

```bash
ssh -n -i <key> admin@<ip> "/user set admin password=<password>"
```

### Applying a lab config

Two things will bite when scripting this:

**`ssh` eats stdin inside a read loop.** Applying a config file line by line
with `while read cmd; do ssh ... "$cmd"; done < file` silently runs only the
first line, because `ssh` consumes the rest of the loop's input. Use `ssh -n`.

**`/import` needs the file on the device**, and `scp` does not put it where
RouterOS looks by default. Running the commands directly over SSH is simpler
and gives you a per-command pass/fail, which is what you want when some
commands are version-dependent.

A few commands that a current CHR rejects, worth knowing before you debug them:

| Command | Result on CHR 7.23.2 |
|---|---|
| `/system logging action add name=lab-remote ...` | action names accept **letters and numbers only** — no hyphens |
| `/interface ovpn-server server set enabled=yes` | syntax error unless a certificate is also given |
| `/container`, `/ip/firewall/connection-tracking`, `/system/routerboard` | `no such command prefix` — absent on CHR |

`sflow`, physical-hardware menus, and anything RouterBOARD-specific do not
exist on a virtual router. `mikrotik.system.routerboard` correctly reports
`false` there.

---

## Pointing mql at it

```bash
export PROVIDERS_PATH="$HOME/.config/mondoo/providers"
mql run mikrotik "admin@<ip>" --password "<password>" --auto-update=false \
  -c 'mikrotik { system { version boardName } }'
```

`--auto-update=false` matters: without it mql can replace your locally-built
provider with the released one mid-run, and you end up validating code you did
not build.

### Query private resources through their parent

Most of this provider's resources are `private`, and reaching one by its dotted
path returns a husk — every field null, with
`provider returned no data and no error for a field`:

```bash
mql run mikrotik ... -c 'mikrotik.system.version'          # null
mql run mikrotik ... -c 'mikrotik { system { version } }'  # "7.23.2 (stable)"
```

Always go through the parent accessor when validating, or you will chase a
provider bug that is not there.

### TLS

`--tls` selects port 8729 and does a real TLS handshake. On a stock CHR that
**fails**, because `api-ssl` has no certificate bound by default:

```
failed to connect ... :8729: could not connect to router os: remote error: tls: handshake failure
```

Generate and bind a self-signed certificate on the device first if you need to
exercise the TLS path. `/certificate sign` without a CA fails with `CA not
found`, so sign a CA first and then the service certificate with `ca=<name>`,
as two separate commands; a batch that signs both runs the second before the
first has finished.

---

## Running CHR locally under qemu

The same CHR runs on a laptop with no cloud account. Verified with the
`chr-7.25.1-arm64.img` image on an Apple silicon Mac with Homebrew qemu.

```bash
qemu-system-aarch64 -M virt -cpu cortex-a72 -accel tcg,thread=single -icount shift=auto -m 1024 -smp 1 \
  -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -drive file=chr.img,if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:18728-:8728,hostfwd=tcp:127.0.0.1:18729-:8729,hostfwd=tcp:127.0.0.1:12222-:22 \
  -device virtio-net-pci,netdev=n0 -display none -serial file:serial.log -daemonize
```

Each setting avoids a failure that was observed:

| Setting | Without it |
|---|---|
| `-cpu cortex-a72 -accel tcg` | `-accel hvf -cpu host` boots the kernel, which then panics with `No working init found`; `pauth=off` and `highmem=off` do not change that |
| `-icount shift=auto` | The kernel panics with `soft lockup - CPU#0 stuck for 440s` every 5 to 20 minutes and the router reboots, with one emulated CPU or two |

`-icount` advances guest time with the instructions executed rather than with
the host clock, so emulation being slow no longer looks like a stuck CPU to the
kernel watchdog. It needs `thread=single`. With it, the device completed a full policy
validation run of over a hundred scenarios without a reboot, where without it
the same run was cut short by a panic. Guest uptime then counts emulated time and
runs slow against the wall clock.

A reboot clears the update check, so `mikrotik.packageUpdate.checked` is false
again afterwards. The serial log shows any panic; check it when a scan suddenly
returns nothing.

Configuration survives a restart because it lives on the disk image. qemu's
user-mode DNS forwarder at 10.0.2.3 can time out from inside the guest, which
breaks `check-for-updates`; `/ip dns set servers=1.1.1.1` avoids it. The API
and SSH reach the device from 10.0.2.2, which is the address to use in
`available-from`, `/user address`, and firewall accept rules.

### Driving it over SSH

Password logins over SSH fail intermittently on the emulated CPU, and a burst
of short sessions ends in `too many concurrent logins`. Import a key and reuse
one connection:

```bash
/file add name=lab.pub contents="<public key>"
/user ssh-keys import public-key-file=lab.pub user=<user>
```

```bash
ssh -o IdentitiesOnly=yes -i lab -o ControlMaster=auto \
    -o ControlPath=/tmp/chr-%r -o ControlPersist=30m -p 12222 <user>@127.0.0.1 '<command>'
```

`IdentitiesOnly` matters when an agent holds other keys: RouterOS rejects the
login after the agent's keys are offered first. The control socket path must
be under 104 bytes, so keep it short. Importing a key also disables password
login for that user over SSH, because `password-authentication` defaults to
`yes-if-no-key`.

Two RouterOS behaviours make a scripted change look applied when it was not:

- `set [find ...]` on an empty selection is silently a no-op, so a selector
  that stops matching after the change it reverts (such as finding a rule by
  `action=drop` after setting it to `reject`) leaves the change in place.
- An out-of-range value can be rejected with a message while `ssh` still
  exits 0: `/user set <name> inactivity-timeout=59s` did, where the range is
  1m to 1d. Match the output for errors rather than trusting the exit status.

Comparing `/export terse` before a change and after reverting it catches both.

---

## Capturing fixtures for unit tests

The provider's unit tests are driven by rows captured from a real device, in
`resources/testdata/live/`. They are the exact `map[string]string` the RouterOS
API hands to an args builder, so a builder that mishandles a real row's shape
fails in a unit test rather than in a scan.

To refresh them, dump every menu the provider reads through the same client the
provider uses:

```bash
# the menus, straight from the source
grep -rhoE 'Print(One)?(Optional)?\("([^"]+)"' resources/*.go \
  | grep -oE '"/[^"]+"' | tr -d '"' | sort -u
```

Then connect with `github.com/go-routeros/routeros/v3`, run `<menu>/print` for
each, and write `reply.Re[i].Map` out as JSON. Capturing through the CLI instead
would be wrong: `/system/resource/print` pretty-prints `1766.6MiB`, while the
API returns the raw `2113929216` that the provider actually parses.

---

## Tear down, and verify per service

Tag everything through Terraform `default_tags` so a crashed run is still
findable, then confirm deletion against the owning service. The Resource Groups
Tagging API lags by hours and will keep listing resources that are already gone:

```bash
aws ec2 describe-instances --region us-west-2 \
  --filters "Name=tag:mondoo-run-id,Values=$RUN_ID" \
            "Name=instance-state-name,Values=running,pending,stopping,stopped" \
  --query 'length(Reservations[].Instances[])' --output text
```

If you took the VM Import route, remember the `vmimport` IAM role and the S3
staging bucket are not in Terraform state and must be removed separately.
