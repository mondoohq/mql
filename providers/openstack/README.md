# OpenStack Provider

Query OpenStack projects with mql and cnspec. Built on `gophercloud/v2`.

## Prerequisites

- A reachable Keystone v3 endpoint
- Project-scoped credentials (username/password, application credential, or `clouds.yaml` entry)
- Network access to the service catalog endpoints for each subsystem you want to query

Permissions:

- Tenant tokens see their own project's data across all services.
- Listing all `users`, `roles`, or admin-only Keystone endpoints requires admin scope.
- Calls to services that aren't deployed (e.g. Octavia or Barbican on smaller clouds) return empty rather than failing the query, so policies can be portable across clouds with different service catalogs.

## Usage

```bash
# clouds.yaml entry
mql shell openstack --cloud my-cloud

# environment variables
export OS_AUTH_URL=https://keystone.example.com/v3
export OS_USERNAME=admin
export OS_PASSWORD=secret
export OS_PROJECT_NAME=demo
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
mql shell openstack

# explicit flags
mql shell openstack \
  --auth-url https://keystone.example.com/v3 \
  --username admin --password secret \
  --project-name demo \
  --user-domain-name Default --project-domain-name Default \
  --region RegionOne

# Keystone v3 application credentials
mql shell openstack \
  --auth-url https://keystone.example.com/v3 \
  --application-credential-id <id> \
  --application-credential-secret <secret>
```

Auth precedence (highest first): CLI flags → `--cloud` (resolves a `clouds.yaml` entry) → `OS_*` environment variables.

## Coverage

Seven OpenStack services across 34 resources:

- **Identity (Keystone v3)** — projects, users, roles, domains
- **Compute (Nova v2)** — servers, flavors, keypairs, server groups
- **Image (Glance v2)** — images
- **Networking (Neutron v2)** — networks, subnets, routers, ports, floating IPs, security groups (with rules), subnet pools, QoS policies, trunks, FWaaS v2 (groups, policies, rules)
- **Block Storage (Cinder v3)** — volumes, snapshots
- **Key Manager (Barbican v1)** — secrets, containers, orders
- **Load Balancer (Octavia v2)** — load balancers, listeners, pools, members, health monitors, L7 policies, L7 rules

## Asset URL

Assets are placed under `technology=openstack` with the project ID as the discriminant:

```
technology=openstack/project=<project-uuid>
```

Each connection produces exactly one asset (the Keystone-scoped project). The asset's platform is `openstack-project`; family is `["openstack"]`.
