# Arista EOS Provider Testing

## Overview

This document covers how to set up a vEOS lab device for mql provider development and validation. All commands are verified against vEOS. Some features are not available on vEOS — see [vEOS Limitations](#veos-limitations).

## Prerequisites

- Access to a CloudEOS/vEOS instance — see [Spinning up a test device in AWS](#spinning-up-a-test-device-in-aws)
- SSH or console access

---

## Spinning up a test device in AWS

A full run — launch, configure, sweep every resource, tear down — takes about
40 minutes and costs well under a dollar. The traps below are all ones that
have actually bitten; read them before starting rather than after.

### 1. Subscribe, and get the AMI id from the console

Arista publishes CloudEOS under **two separate Marketplace listings** with
different product codes:

| Listing | Product code | Notes |
|---|---|---|
| CloudEOS Router (BYOL) | `3gruvlcso4s66wfg2mdzxg8z6` | needs a licence from Arista sales; the AMI *is* publicly listed |
| CloudEOS Router (PAYG) | `8xzz74jx7agumduhohu7zful3` | hourly software charge, no licence needed |

**The PAYG AMI is not discoverable from the CLI.** `describe-images` returns
only the BYOL image, in every region, even when you are subscribed to PAYG:

```bash
aws ec2 describe-images --owners aws-marketplace \
  --filters "Name=name,Values=*CloudEOS*" --region us-west-2 \
  --query 'Images[].[ImageId,Name,ProductCodes[0].ProductCodeId]' --output text
```

Launching the BYOL image while subscribed to PAYG fails with `OptInRequired`,
which reads like "you are not subscribed" but actually means "not to *that*
listing". Get the PAYG AMI id from the console instead:

> Marketplace → Manage subscriptions → *Arista CloudEOS Router (PAYG)* →
> **Launch new instance** → the AMI id is shown per region.

Confirm it is launchable before writing any Terraform:

```bash
aws ec2 run-instances --dry-run --region us-west-2 \
  --image-id <ami-id> --instance-type c5.xlarge --subnet-id <subnet>
# want: DryRunOperation ("Request would have succeeded")
```

To check which listing an account holds:

```bash
aws license-manager list-received-licenses --region us-west-2 \
  --query 'Licenses[].ProductName' --output text | tr '\t' '\n' | grep -i arista
```

### 2. Launch with a *minimal* startup-config

CloudEOS reads a startup-config from EC2 user-data, wrapped in markers:

```
%EOS-STARTUP-CONFIG-START%
...config...
%EOS-STARTUP-CONFIG-END%
```

**Do not paste a complete lab config here.** What you supply *replaces* the
image's AWS bootstrap config, which is what puts the management interface on
DHCP. Omit that stanza and EOS comes up with no management address: the
instance passes both EC2 status checks, the console shows a healthy EOS with
your hostname and banner, and **both 22 and 443 are closed** with no
indication why.

Keep the bootstrap minimal, and always include the management interface:

```
%EOS-STARTUP-CONFIG-START%
hostname arista-test-lab
!
interface Management1
   ip address dhcp
   no shutdown
!
interface Ethernet1
   no switchport
   ip address dhcp
   no shutdown
!
username netadmin privilege 15 role network-admin secret 0 <password>
!
management api http-commands
   protocol https
   no shutdown
!
management ssh
   no shutdown
!
end
%EOS-STARTUP-CONFIG-END%
```

Both interface names are listed on purpose: a single-ENI CloudEOS presents
eth0 as `Management1`, but configuring `Ethernet1` too costs nothing and
removes the guess.

eAPI takes roughly **2.5 minutes** to come up after `terraform apply` returns.

### 3. Push the lab config over eAPI

Apply everything else afterwards, over eAPI, where a mistake cannot lock you
out and you can iterate:

```bash
curl -sk -u "netadmin:$PW" "https://$IP/command-api" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,
       "cmds":["enable","configure","hostname lab"],"format":"json"},"id":1}'
```

Points that cost time:

- **`enable` must be the first command**, or every config command fails with
  `Invalid input (privileged mode required)`.
- **eAPI aborts the whole batch on the first bad command** and tells you which
  one: `CLI command N of M '<cmd>' failed`. Parse that, drop the command, and
  retry in a loop — otherwise you fix them one round trip at a time.
- **Banners need the `input` field**, not a plain command string:
  `{"cmd": "banner login", "input": "line one\nline two\nEOF\n"}`.
- **Never bind a deny-all ACL to the management interface.** An
  `ip access-group ... in` whose list ends in `deny ip any any` will lock you
  out exactly like the missing DHCP stanza does. Bind interface ACLs to a
  Port-Channel or a non-management interface instead.
- Setting `enable secret` can change what eAPI needs to authenticate — apply
  it last, after everything else is verified.

### 4. Point mql at it

```bash
export PROVIDERS_PATH="$HOME/.config/mondoo/providers"
mql run arista "netadmin@$IP" --password "$PW" --auto-update=false \
  -c 'arista.eos { hostname version }'
```

`--auto-update=false` matters: without it mql can replace your locally-built
provider with the released one mid-run, and you end up validating code you did
not build.

### 5. Unreleased fields are hidden until the version bumps

Fields carry a `.lr.versions` entry, and one newer than `config/config.go`'s
`Version` is invisible — queries fail with `cannot find field`, not with
anything that points at the version gate. Check before concluding a field is
broken:

```bash
grep -n 'Version:' providers/arista/config/config.go
grep '13.3.16' providers/arista/resources/arista.lr.versions | wc -l
```

Bump `config.go` **locally and uncommitted** to validate them, and revert
before committing — the release flow owns that bump.

### 6. Query private resources through their parent

Most of this provider's resources are `private`, and reaching one by its
dotted path returns a husk — every field null, with
`provider returned no data and no error for a field`:

```bash
mql run arista ... -c 'arista.eos.aaa { rootAccountEnabled }'      # null
mql run arista ... -c 'arista.eos { aaa { rootAccountEnabled } }'  # true
```

Always go through the parent accessor when validating.

### 7. Tear down, and verify per service

Tag everything through Terraform `default_tags` so a crashed run is still
findable, then confirm deletion against the owning service — the Resource
Groups Tagging API lags by hours and will keep listing resources that are
already gone:

```bash
aws ec2 describe-instances --region us-west-2 \
  --filters "Name=tag:mondoo-run-id,Values=$RUN_ID" \
            "Name=instance-state-name,Values=running,pending,stopping,stopped" \
  --query 'length(Reservations[].Instances[])' --output text
```

---

## CloudEOS limitations and EOS 4.34 syntax changes

Captured from CloudEOS 4.34.2F. Commands in this document that a current
device rejects:

| Command | Result on CloudEOS 4.34.2F |
|---|---|
| `ip domain-name <name>` | deprecated — use `dns domain <name>` |
| `sflow ...` (all forms) | not supported on this hardware platform |
| `monitor session X destination Cpu` | not supported on this hardware platform |
| `show system environment power` | fails — no emulated PSUs, so `arista.eos.hardware.powerSupplies` cannot be exercised on a virtual device |
| `logging host ... protocol tls` | incomplete command; `tcp` and `udp` work |
| `snmp-server community <c> ro ipv6 <acl>` | the ACL must be a **standard** IPv6 list |
| `neighbor <x> password 7 <string>` | rejected unless the string is genuinely type-7 encrypted; use `password 0 <plaintext>` |
| `username <u> ssh-key ssh-rsa AAAA...` | rejected unless the key is real and well-formed |

Two shapes a real device will not produce, so they can only be tested by unit
test rather than against hardware:

- **Two SNMP destinations to the same collector at different security levels**,
  and **the same community declared per address family** — EOS replaces rather
  than stacks these.
- **One syslog collector on one port over two transports** — same reason.
- **A secret written with no encoding selector** (`aaa root secret <plaintext>`)
  — EOS hashes on load and always renders a selector.

---

## System Basics

```
enable
configure terminal

! Hostname and domain
hostname arista-test-lab
! 4.34+ deprecates `ip domain-name` in favor of `dns domain`
dns domain lab.mondoo.com

! DNS
ip name-server 8.8.8.8
ip name-server 8.8.4.4

! Banners
banner motd
  ******************************************
  *   Mondoo mql Provider Test Lab         *
  *   Unauthorized access is prohibited    *
  ******************************************
EOF

banner login
  Authorized users only. All activity is monitored.
EOF

! Local users
username netadmin privilege 15 role network-admin secret netadmin123
username netops privilege 5 role network-operator secret netops123
username auditor privilege 1 secret auditor123

! SSH
management ssh
   idle-timeout 60
   authentication mode password
   no shutdown
!

! eAPI (used by mql HTTPS transport)
management api http-commands
   protocol https
   no shutdown
!

end
```

---

## Management Interface

```
configure terminal

interface Management1
   description MGMT
   ip address 192.168.100.10/24
!

ip route 0.0.0.0/0 192.168.100.1

end
```

---

## VRFs

```
configure terminal

vrf instance PROD
   description Production VRF
!
vrf instance DEV
   description Development VRF
!
vrf instance MGMT
   description Management VRF
!

end
```

---

## VLANs

```
configure terminal

! VLAN 101 - Basic, just a name
vlan 101
   name TEST-BASIC
!
! VLAN 102 - Suspended state
vlan 102
   name TEST-SUSPENDED
   state suspended
!
! VLAN 103 - Trunk group membership
vlan 103
   name TEST-TRUNK-GROUP
   trunk group CORE-PEERS
!
! VLAN 104 - Multiple trunk groups
vlan 104
   name TEST-MULTI-TRUNK
   trunk group CORE-PEERS
   trunk group MLAG-PEER
!
! VLAN 105 - PVLAN primary
vlan 105
   name TEST-PVLAN-PRIMARY
   private-vlan primary
!
! VLAN 106 - PVLAN community (associated to 105)
vlan 106
   name TEST-PVLAN-COMMUNITY
   private-vlan community
!
! VLAN 107 - PVLAN isolated (associated to 105)
vlan 107
   name TEST-PVLAN-ISOLATED
   private-vlan isolated
!
! VLAN 108 - No name (tests nil/default name handling)
vlan 108
!
! VLAN 109 - Name with underscores and hyphens
vlan 109
   name TEST_UNDERSCORE-AND-HYPHEN_99
!
! VLAN 110 - Suspended and in a trunk group (combined edge case)
vlan 110
   name TEST-SUSPENDED-TRUNK
   state suspended
   trunk group MLAG-PEER
!

end
```

| VLAN | Test case |
|------|-----------|
| 101  | Minimal config, name only |
| 102  | Suspended state |
| 103  | Single trunk group |
| 104  | Multiple trunk groups |
| 105  | PVLAN primary |
| 106  | PVLAN community |
| 107  | PVLAN isolated |
| 108  | No name (default/nil handling) |
| 109  | Name with special characters |
| 110  | Suspended + trunk group combined |

---

## Interfaces

### Loopbacks

```
configure terminal

interface Loopback0
   description ROUTER-ID
   ip address 10.0.0.1/32
!
interface Loopback1
   description BGP-ANYCAST
   ip address 10.0.0.2/32
!
interface Loopback100
   description VRF-PROD-LOOPBACK
   vrf PROD
   ip address 10.100.0.1/32
!

end
```

### SVIs

```
configure terminal

interface Vlan101
   description SVI-TEST-BASIC
   ip address 10.101.0.1/24
!
interface Vlan103
   description SVI-TRUNK-GROUP
   ip address 10.103.0.1/24
!
interface Vlan110
   description SVI-SUSPENDED-TRUNK
   ip address 10.110.0.1/24
   shutdown
!

end
```

---

## Routing

### Static Routes

```
configure terminal

ip route 192.168.0.0/16 10.1.1.2
ip route 172.16.0.0/12 10.1.1.2 name PRIVATE-RANGE
ip route 10.99.0.0/24 Null0 254 name BLACKHOLE

! VRF static route
ip route vrf PROD 0.0.0.0/0 10.100.1.2

end
```

### OSPF

```
configure terminal

router ospf 1
   router-id 10.0.0.1
   network 10.1.1.0/30 area 0.0.0.0
   network 10.0.0.0/32 area 0.0.0.0
   passive-interface default
   no passive-interface Ethernet1
!

end
```

### BGP

```
configure terminal

router bgp 65001
   router-id 10.0.0.1
   bgp log-neighbor-changes
   timers bgp 30 90

   ! eBGP peer
   neighbor 10.1.1.2 remote-as 65002
   neighbor 10.1.1.2 description EBGP-PEER-CORE
   neighbor 10.1.1.2 send-community

   ! iBGP peer
   neighbor 10.0.0.2 remote-as 65001
   neighbor 10.0.0.2 description IBGP-PEER-LOOPBACK
   neighbor 10.0.0.2 update-source Loopback0

   ! Shutdown peer (tests disabled neighbor fetching)
   neighbor 10.1.1.6 remote-as 65003
   neighbor 10.1.1.6 description EBGP-PEER-SHUTDOWN
   neighbor 10.1.1.6 shutdown

   ! Address family
   address-family ipv4
      neighbor 10.1.1.2 activate
      neighbor 10.0.0.2 activate
      network 10.0.0.1/32
      network 10.0.0.2/32
!

   ! VRF BGP
   vrf PROD
      router-id 10.100.0.1
      neighbor 10.100.1.2 remote-as 65099
      neighbor 10.100.1.2 description PROD-VRF-PEER
      address-family ipv4
         neighbor 10.100.1.2 activate
         network 10.100.0.1/32
!

end
```

---

## ACLs

```
configure terminal

! Standard ACL
ip access-list standard MGMT-ACCESS
   10 permit 192.168.100.0/24
   20 deny any log
!

! Extended ACL
ip access-list extended UPLINK-IN
   10 permit tcp 10.0.0.0/8 any eq 443
   20 permit tcp 10.0.0.0/8 any eq 22
   30 permit icmp any any
   40 deny ip any any log
!

! IPv6 ACL
ipv6 access-list V6-MGMT
   10 permit ipv6 fc00::/7 any
   20 deny ipv6 any any log
!

end
```

---

## AAA / TACACS+

```
configure terminal

! TACACS+ server (unreachable in lab, config present for fetch testing)
tacacs-server host 192.168.100.200 key lab-tacacs-key
tacacs-server timeout 5

! AAA
aaa group server tacacs+ TACACS-GROUP
   server 192.168.100.200
!
aaa authentication login default group TACACS-GROUP local
aaa authentication enable default group TACACS-GROUP local
aaa authorization exec default group TACACS-GROUP local
aaa accounting exec default start-stop group TACACS-GROUP

end
```

---

## Monitoring

### NTP

```
configure terminal

ntp server 0.pool.ntp.org prefer
ntp server 1.pool.ntp.org
ntp server 192.168.100.1 local-interface Management1

end
```

### Syslog

```
configure terminal

logging on
logging host 192.168.100.201
logging host 192.168.100.202 514
logging trap informational
logging source-interface Management1
logging facility local6

end
```

### SNMP

```
configure terminal

snmp-server community public ro
snmp-server community private rw
snmp-server location "Mondoo Lab - vEOS Test Instance"
snmp-server contact "lab@mondoo.com"
snmp-server host 192.168.100.203 version 2c public
snmp-server enable traps

end
```

---

## Verify

```
show running-config
show vlan brief
show interfaces status
show ip route summary
show bgp summary
show ip ospf neighbor
show ip access-lists
show ntp status
show snmp
show users
```

---

## Teardown

```
configure terminal

no vlan 101-110
no router bgp 65001
no router ospf 1
no ip access-list standard MGMT-ACCESS
no ip access-list extended UPLINK-IN
no ipv6 access-list V6-MGMT
no vrf instance PROD
no vrf instance DEV
no vrf instance MGMT
no username netops
no username auditor
no ntp server 0.pool.ntp.org
no ntp server 1.pool.ntp.org
no logging host 192.168.100.201
no logging host 192.168.100.202
no snmp-server community public
no snmp-server community private

end
```

---

## vEOS Limitations

The following are supported on physical EOS hardware but unavailable on vEOS:

| Feature | Command | Workaround |
|---------|---------|------------|
| Per-VLAN STP priority | `spanning-tree vlan X priority Y` | Not applicable |
| IGMP snooping | `ip igmp snooping vlan X` | Not applicable |
| Per-VLAN MAC aging | `mac address-table aging-time X vlan Y` | Not applicable |
