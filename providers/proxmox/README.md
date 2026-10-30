# Proxmox VE Provider

Query and scan Proxmox VE clusters with cnspec/cnquery.

## Prerequisites

- Proxmox VE 7.x or 8.x
- API token with at least `PVEAuditor` role
- QEMU Guest Agent installed in VMs (for update queries)

## Usage

```bash
# Scan a Proxmox VE cluster
cnspec scan proxmox --host https://192.168.1.10:8006 \
  --token 'PVEAPIToken=user@realm!tokenid=secret'

# Skip TLS verification (self-signed certificates)
cnspec scan proxmox --host https://pve.example.com:8006 \
  --token 'PVEAPIToken=user@realm!tokenid=secret' --insecure

# Interactive shell
mql shell proxmox --host https://192.168.1.10:8006 \
  --token 'PVEAPIToken=user@realm!tokenid=secret'
```

## Examples

```mql
# Cluster overview
proxmox.cluster { name quorate nodeCount }

# List all nodes with hardware info
proxmox.nodes { name cpuModel cpuCores memTotal kernelVersion pveVersion }

# Check node services
proxmox.nodes { name services.where(state == "running") { name } }

# List VMs with their config
proxmox.vms { id name status bios agent tags networks { model bridge } }

# Find VMs with pending security updates
proxmox.vms.where(status == "running") {
  name
  updates.where(severity == "security" && upgradable == true) { name newVersion }
}

# Storage capacity overview
proxmox.storages { id type usagePercent total }

# Audit API tokens
proxmox.users { id tokens { id expire privsep } }

# Check firewall rules
proxmox.vms { name firewallRules { pos action proto dest dport } }

# Ceph health and any active health checks
proxmox.ceph { available healthStatus healthChecks }

# Find Ceph pools that accept writes with only one copy of the data
proxmox.ceph.pools.where(type == "replicated" && minSize < 2) { name size minSize }

# OSDs that are down or have been marked out
proxmox.ceph.osds.where(status != "up" || inCluster == false) { id host status deviceClass }

# Confirm Ceph authentication has not been turned off
proxmox.ceph.config.where(name == /^auth_.*_required$/) { section name value }

# Guests that have never been backed up
proxmox.vms.where(backups.length == 0) { id name }

# When each guest was last actually captured
proxmox.vms { name lastBackupAt }

# Backups that are not protected from pruning
proxmox.storages { backups.where(protected == false) { volid createdAt } }

# Proxmox Backup Server archives that failed or skipped verification
proxmox.storages { backups.where(verification['state'] != "ok") { volid createdAt } }
```

```mql
# Notification targets posting over plain HTTP
proxmox.webhookEndpoints.where(url != /^https:/) { name url }

# Where cluster metrics are being shipped
proxmox.metricServers.where(disabled == false) { id type server port }

# Cluster members with no redundant corosync link
proxmox.corosync.nodes.where(ring1Address == "") { name ring0Address }
```

On clusters without Ceph, `proxmox.ceph.available` is `false` and every Ceph
list is empty. Reading these fields needs `Sys.Audit` or `Datastore.Audit` on
`/`, both of which `PVEAuditor` grants.

## Token privileges

Most of the provider works with `PVEAuditor`. Three groups of resources need
more, and return an **empty list** rather than failing when the token lacks it:

| Resources | Required privilege |
|---|---|
| `proxmox.notification.*` | `Mapping.Audit` on `/mapping/notifications` |
| `proxmox.mapping.pci`, `proxmox.mapping.usb` | `Mapping.Audit` on `/mapping/pci`, `/mapping/usb` |
| `proxmox.acme.plugin` | `Sys.Modify` — no audit role carries this, so plugins are normally not visible to a read-only token |

Grant the `Mapping.Audit` privileges to the scanning token if you want the
notification and device-mapping checks to evaluate. Permission failures are
logged at debug level, so run with `--log-level debug` to confirm whether an
empty list means "nothing configured" or "not visible to this token".

## Resources

| Resource                    | Description                                         |
|-----------------------------|-----------------------------------------------------|
| `proxmox`                   | Root resource — cluster overview                    |
| `proxmox.cluster`           | Cluster status, quorum, HA                          |
| `proxmox.cluster.haResource`| High-availability managed resource                  |
| `proxmox.node`              | Cluster node with full hardware/system details      |
| `proxmox.node.update`       | Pending package update on a node                    |
| `proxmox.vm`                | QEMU virtual machine with config and metrics        |
| `proxmox.vm.network`        | Network interface attached to a VM                  |
| `proxmox.vm.virtualDisk`    | Virtual disk attached to a VM                       |
| `proxmox.vm.snapshot`       | VM snapshot                                         |
| `proxmox.vm.update`         | Pending software update inside a VM (via QGA)       |
| `proxmox.storage`           | Storage pool with capacity information              |
| `proxmox.pool`              | Resource pool                                       |
| `proxmox.network`           | Node network interface (bridge, bond, VLAN)         |
| `proxmox.dns`               | DNS configuration on a node                         |
| `proxmox.service`           | systemd service on a node                           |
| `proxmox.certificate`       | TLS/SSL certificate on a node                       |
| `proxmox.subscription`      | Proxmox subscription status                         |
| `proxmox.repository`        | APT repository configured on a node                 |
| `proxmox.firewall.rule`     | Firewall rule (cluster, node, or VM level)          |
| `proxmox.user`              | User account                                        |
| `proxmox.token`             | API token for a user                                |
| `proxmox.role`              | Access control role                                 |
| `proxmox.ceph`              | Ceph cluster health, daemons, and data layout       |
| `proxmox.ceph.monitor`      | Ceph monitor daemon and its quorum membership       |
| `proxmox.ceph.manager`      | Ceph manager daemon                                 |
| `proxmox.ceph.metadataServer`| Ceph metadata server backing a CephFS              |
| `proxmox.ceph.osd`          | Ceph object storage daemon                          |
| `proxmox.ceph.pool`         | Ceph pool and its replication settings              |
| `proxmox.ceph.filesystem`   | CephFS file system                                  |
| `proxmox.ceph.configEntry`  | Entry in the Ceph configuration database            |
| `proxmox.storage.volume`    | Volume on a storage: backup, ISO, template, or disk |
| `proxmox.notification.target`| Notification destination of any transport          |
| `proxmox.notification.matcher`| Rule routing notifications to targets             |
| `proxmox.notification.smtpEndpoint` | SMTP notification target                    |
| `proxmox.notification.sendmailEndpoint` | Sendmail notification target            |
| `proxmox.notification.gotifyEndpoint` | Gotify notification target                |
| `proxmox.notification.webhookEndpoint` | Webhook notification target              |
| `proxmox.metricServer`      | External InfluxDB or Graphite metrics target        |
| `proxmox.acme.account`      | ACME account for certificate issuance               |
| `proxmox.acme.plugin`       | ACME DNS challenge plugin                           |
| `proxmox.corosync`          | Corosync membership and transport configuration     |
| `proxmox.corosync.node`     | Cluster member with its corosync links              |
| `proxmox.mapping.pci`       | Cluster-wide PCI device mapping                     |
| `proxmox.mapping.usb`       | Cluster-wide USB device mapping                     |
| `proxmox.sdn.controller`    | SDN controller (EVPN, BGP, IS-IS)                   |
| `proxmox.sdn.ipam`          | SDN IP address management backend                   |
| `proxmox.sdn.dns`           | SDN DNS backend                                     |

## Features

- **Cluster**: Cluster status, quorum, HA resources, options
- **Nodes**: Hardware info, services, DNS, timezone, certificates, subscription, repositories, updates, firewall rules
- **VMs**: Configuration, resource metrics, network interfaces, disks, snapshots, tags, firewall rules
- **Updates**: Package update checks via QEMU Guest Agent (apt, dnf, Windows) and node APT
- **Storage**: Storage pools with capacity monitoring
- **Ceph**: Cluster health, monitors, managers, metadata servers, OSDs, pools, CephFS, and the Ceph config database
- **Backups**: Backup archives actually present on each storage, with creation time, encryption, protection, and PBS verification state
- **Notifications**: Targets and matchers, with SMTP, sendmail, Gotify, and webhook endpoint settings
- **Telemetry**: External metric servers the cluster ships to
- **Certificates**: ACME accounts and DNS challenge plugins
- **Cluster membership**: Corosync nodes, ring addresses, quorum votes, and QDevice
- **Device mappings**: Cluster-wide PCI and USB passthrough aliases
- **SDN**: Zones, VNets, subnets, controllers, IPAM, and DNS backends
- **Access Control**: Users, API tokens, roles and privileges
- **Firewall**: Rules at cluster, node, and VM level

## Security policies

Policies and checks live in cnspec, not here. The shipped Proxmox policy is
`mondoo-proxmox-security` in the cnspec content repository. This provider is
responsible for gathering the data those checks query.
