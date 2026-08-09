# MQL

![mql light-mode logo](.github/images/mql-light.svg#gh-light-mode-only)
![mql dark-mode logo](.github/images/mql-dark.svg#gh-dark-mode-only)

**Open source, cloud-native asset inventory and discovery**

MQL is a cloud-native tool for querying your entire infrastructure. Built upon Mondoo's security data fabric, it answers thousands of questions about your infrastructure and integrates with over 1,300 resources across cloud accounts, Kubernetes, containers, services, VMs, APIs, and more.

![MQL run example](.github/images/mql-run.gif)

Here are a few more examples:

```bash
# run a query and print the output
mql run -c "ports.listening { port process }"

# open an interactive shell to an aws account
mql shell aws
> aws.ec2.instances{*}
```

[:books: To learn more, read the MQL docs.](https://mondoo.com/docs/mql)

## Installation

Install `mql` with our installation script:

**Linux and macOS**

```bash
bash -c "$(curl -sSL https://install.mondoo.com/sh)"
```

**Windows**

```powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iex ((New-Object System.Net.WebClient).DownloadString('https://install.mondoo.com/ps1'));
Install-Mondoo;
```

If you prefer manual installation, you can find the `mql` packages in our [GitHub releases](https://github.com/mondoohq/mql/releases).

## Interactive shell

The easiest way to explore MQL is to use our interactive shell, which has auto-complete to guide you:

```bash
mql shell
```

Once inside the shell, you can enter MQL queries like this:

```coffeescript
> asset { name title }
```

To learn more, use the `help` command.

To exit, either press CTRL + D or type `exit`.

You can run the shell against local and remote targets like `k8s`, `aws`, `docker`, and many more. Run `--help` to see a full list of supported providers.

## Run simple queries

To run standalone queries in your shell, use the `run` command:

```bash
mql run <TARGET> -c <QUERY>
```

For example, this runs a query against your local system:

```bash
mql run -c "services { name running }"
```

For automation, it is often helpful to convert the output to JSON. Use `-j` or `--json`:

```bash
mql run local -c "services { * }" -j
```

You can then pipe the output to [jq](https://jqlang.org/) or other applications.

## Explore your infrastructure in Mondoo Platform​

To more easily explore your infrastructure, sign up for a Mondoo Platform account. Mondoo's web-based console allows you to navigate, search, and arrange all of your assets.

To get started, [contact us](https://mondoo.com/contact).

To learn about Mondoo Platform, read the [Mondoo Platform docs](https://mondoo.com/docs) or visit [mondoo.com](https://mondoo.com).

## Supported targets

| Target                        | Provider                   | Example                                                                                                                                         |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Active Directory              | `activedirectory`          | `mql shell activedirectory --dc DC_HOST --user admin@corp.local --password PASSWORD`                                                            |
| AI/MCP servers                | `mcp`                      | `mql shell mcp http http://localhost:8080/mcp`                                                                                                  |
| Alibaba Cloud accounts        | `alicloud`                 | `mql shell alicloud --access-key-id ID --access-key-secret SECRET`                                                                              |
| Claude AI platform            | `claude`                   | `mql shell claude --token YOUR_API_KEY`                                                                                                         |
| Ansible playbooks             | `ansible`                  | `mql shell ansible YOUR_PLAYBOOK.yml`                                                                                                           |
| Apache Cassandra cluster      | `cassandra`                | `mql shell cassandra localhost --user cassandra --ask-pass`                                                                                     |
| Arista network devices        | `arista`                   | `mql shell arista DEVICE_PUBLIC_IP --ask-pass`                                                                                                  |
| Artifactory instances         | `artifactory`              | `mql shell artifactory --url https://example.jfrog.io --token YOUR_TOKEN`                                                                       |
| Atlassian organizations       | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| Auth0 tenants                 | `auth0`                    | `mql shell auth0 --domain YOUR_TENANT.auth0.com --client-id CLIENT_ID --client-secret CLIENT_SECRET`                                            |
| AWS accounts                  | `aws`                      | `mql shell aws`                                                                                                                                 |
| AWS CloudFormation templates  | `cloudformation`           | `mql shell cloudformation cloudformation_file.json`                                                                                             |
| AWS EC2 EBS snapshot          | `aws ec2 ebs snapshot`     | `mql shell aws ec2 ebs snapshot SNAPSHOTID`                                                                                                     |
| AWS EC2 EBS volume            | `aws ec2 ebs volume`       | `mql shell aws ec2 ebs volume VOLUMEID`                                                                                                         |
| AWS EC2 Instance Connect      | `aws ec2 instance-connect` | `mql shell aws ec2 instance-connect ec2-user@INSTANCEID`                                                                                        |
| AWS EC2 instances             | `ssh`                      | `mql shell ssh user@host`                                                                                                                       |
| Bitbucket workspaces          | `bitbucket`                | `mql shell bitbucket --workspace WORKSPACE --token TOKEN`                                                                                       |
| Bitwarden organizations       | `bitwarden`                | `mql shell bitwarden --client-id CLIENT_ID --client-secret CLIENT_SECRET`                                                                       |
| Cisco network devices         | `nd-ssh`                   | `mql shell nd-ssh admin@DEVICE_IP --password PASSWORD`                                                                                          |
| Cisco Catalyst Center         | `ciscocatalyst`            | `mql shell ciscocatalyst --host HOST --user USER --password PASSWORD`                                                                           |
| ClickHouse Cloud organization | `clickhousecloud`          | `mql shell clickhousecloud --organization-id ORG_ID --api-key KEY_ID --ask-secret`                                                              |
| ClickHouse server             | `clickhousedb`             | `mql shell clickhousedb db.contoso.com --user default --ask-pass`                                                                               |
| Cloudflare accounts           | `cloudflare`               | `mql shell cloudflare --token ACCESS_TOKEN`                                                                                                     |
| Confluence users              | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| Container images              | `container`, `docker`      | `mql shell container ubuntu:latest`                                                                                                             |
| Container registries          | `container registry`       | `mql shell container registry index.docker.io/library/rockylinux:8`                                                                             |
| Databricks account            | `databricks`               | `mql shell databricks --account-id ACCOUNT_ID --client-id CLIENT_ID --client-secret CLIENT_SECRET`                                              |
| Datadog organization          | `datadog`                  | `mql shell datadog --api-key API_KEY --app-key APP_KEY`                                                                                         |
| Dockerfiles                   | `docker`                   | `mql shell docker file FILENAME`                                                                                                                |
| DNS records                   | `host`                     | `mql shell host mondoo.com`                                                                                                                     |
| Dropbox Business teams        | `dropbox`                  | `mql shell dropbox --token TEAM_TOKEN`                                                                                                          |
| Elasticsearch cluster         | `elasticsearch`            | `mql shell elasticsearch localhost --user elastic --ask-pass`                                                                                   |
| F5 BIG-IP load balancers      | `bigip`                    | `mql shell bigip --hostname HOST --user USER --password PASSWORD`                                                                               |
| Fortinet FortiOS devices      | `fortios`                  | `mql shell fortios --hostname HOSTNAME --token TOKEN`                                                                                           |
| GitHub organizations          | `github org`               | `mql shell github org mondoohq`                                                                                                                 |
| GitHub repositories           | `github repo`              | `mql shell github repo mondoohq/mql`                                                                                                            |
| GitLab groups                 | `gitlab`                   | `mql shell gitlab --group mondoohq`                                                                                                             |
| Google Cloud projects         | `gcp`                      | `mql shell gcp`                                                                                                                                 |
| Google Workspace              | `google-workspace`         | `mql shell google-workspace --customer-id CUSTOMER_ID --impersonated-user-email EMAIL --credentials-path JSON_FILE`                             |
| Grafana organizations         | `grafana`                  | `mql shell grafana --url https://myorg.grafana.net --token TOKEN`                                                                               |
| HashiCorp Cloud Platform      | `hcp`                      | `mql shell hcp --client-id CLIENT_ID --client-secret CLIENT_SECRET`                                                                             |
| Hetzner Cloud projects        | `hetzner`                  | `mql shell hetzner --token API_TOKEN`                                                                                                           |
| Hugging Face                  | `huggingface`              | `mql shell huggingface --token HF_TOKEN`                                                                                                        |
| IBM Db2 database              | `db2`                      | `mql shell db2 db.contoso.com --database TESTDB --user auditor --ask-pass`                                                                      |
| OPC UA IoT devices            | `opcua`                    | `mql shell opcua`                                                                                                                               |
| IP address information        | `ipinfo`                   | `mql shell ipinfo`                                                                                                                              |
| IPMI-enabled devices          | `ipmi`                     | `mql shell ipmi user@HOST`                                                                                                                      |
| Iru (formerly Kandji) tenants | `iru`                      | `mql shell iru --subdomain SUBDOMAIN --token API_TOKEN`                                                                                         |
| Jira projects                 | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| JumpCloud organizations       | `jumpcloud`                | `mql shell jumpcloud --api-key API_KEY`                                                                                                         |
| Juniper Junos devices         | `junos`                    | `mql shell junos --hostname DEVICE_IP --username admin --password PASSWORD`                                                                     |
| Keycloak realms               | `keycloak`                 | `mql shell keycloak --url URL --username admin --password PASSWORD`                                                                             |
| Kubernetes cluster nodes      | `local`, `ssh`             | `mql shell ssh user@host`                                                                                                                       |
| Kubernetes clusters           | `k8s`                      | `mql shell k8s`                                                                                                                                 |
| Kubernetes manifests          | `k8s`                      | `mql shell k8s manifest.yaml`                                                                                                                   |
| Kubernetes workloads          | `k8s`                      | `mql shell k8s --discover pods,deployments`                                                                                                     |
| Linux hosts                   | `local`, `ssh`             | `mql shell local` or<br></br>`mql shell ssh user@host`                                                                                          |
| macOS hosts                   | `local`, `ssh`             | `mql shell local` or<br></br>`mql shell ssh user@IP_ADDRESS`                                                                                    |
| MikroTik RouterOS devices     | `mikrotik`                 | `mql shell mikrotik admin@192.168.88.1 --password SECRET`                                                                                       |
| Mistral AI accounts           | `mistral`                  | `mql shell mistral --token API_KEY`                                                                                                             |
| Microsoft 365 tenants         | `ms365`                    | `mql shell ms365 --tenant-id TENANT_ID --client-id CLIENT_ID --certificate-path PFX_FILE`                                                       |
| Microsoft Azure instances     | `ssh`                      | `mql shell ssh user@host`                                                                                                                       |
| Microsoft Azure subscriptions | `azure`                    | `mql shell azure --subscription SUBSCRIPTION_ID`                                                                                                |
| Microsoft SQL Server          | `mssql`                    | `mql shell mssql sql.contoso.com --user sa --ask-pass`                                                                                          |
| MySQL or MariaDB server       | `mysqldb`                  | `mql shell mysqldb db.contoso.com --user root --ask-pass`                                                                                       |
| MongoDB Atlas organization    | `mongodbatlas`             | `mql shell mongodbatlas --org-id ORG_ID --public-key PUBLIC_KEY --private-key PRIVATE_KEY`                                                       |
| MongoDB server (self-hosted)  | `mongo`                    | `mql shell mongo db.contoso.com --user admin --ask-pass`                                                                                        |
| Neon organization             | `neon`                     | `mql shell neon --token TOKEN`                                                                                                                  |
| Netlify account               | `netlify`                  | `mql shell netlify --token TOKEN`                                                                                                               |
| Network scanning              | `nmap`                     | `mql shell nmap --networks 192.168.1.0/24`                                                                                                      |
| NextDNS accounts              | `nextdns`                  | `mql shell nextdns --api-key API_KEY`                                                                                                           |
| Nutanix cluster               | `nutanix`                  | `mql shell nutanix --endpoint ENDPOINT --user USER --password PASSWORD`                                                                         |
| Okta org                      | `okta`                     | `mql shell okta --token TOKEN --organization ORGANIZATION`                                                                                      |
| Ollama instance               | `ollama`                   | `mql shell ollama` or `mql shell ollama --host HOST --token TOKEN`                                                                              |
| OpenAI account                | `openai`                   | `mql shell openai --token TOKEN`                                                                                                                |
| OpenSearch cluster            | `opensearch`               | `mql shell opensearch localhost --user admin --ask-pass --tls-insecure`                                                                        |
| OpenStack project             | `openstack`                | `mql shell openstack --cloud CLOUD_NAME` or<br></br>`mql shell openstack --auth-url AUTH_URL --username USER --password PASSWORD --project-name PROJECT` |
| Oracle Cloud Interface (OCI)  | `oci`                      | `mql shell oci`                                                                                                                                 |
| Oracle Database               | `oracledb`                 | `mql shell oracledb db.contoso.com --service FREEPDB1 --user auditor --ask-pass`                                                                |
| Portainer server              | `portainer`                | `mql shell portainer HOST --access-token TOKEN`                                                                                                 |
| PostgreSQL server             | `postgresdb`               | `mql shell postgresdb --host db.contoso.com --user postgres --ask-pass`                                                                        |
| Proxmox VE                    | `proxmox`                  | `mql shell proxmox --host HOST --token TOKEN`                                                                                                   |
| Palo Alto Networks PAN-OS     | `panos`                    | `mql shell panos --hostname DEVICE_IP --username admin --password PASSWORD`                                                                     |
| Running containers            | `docker`                   | `mql shell docker CONTAINER_ID`                                                                                                                 |
| Redfish controller (BMC)      | `redfish`                  | `mql shell redfish USER@HOST --ask-pass --insecure`                                                                                            |
| Redis or Valkey server        | `redisdb`                  | `mql shell redisdb localhost --ask-pass`                                                                                                        |
| Shodan organization           | `shodan`                   | `mql shell shodan`                                                                                                                              |
| Slack team                    | `slack`                    | `mql shell slack --token TOKEN`                                                                                                                 |
| Snowflake account             | `snowflake`                | `mql shell snowflake --account ACCOUNT_ID --region REGION --user USER --role ROLE --ask-pass`                                                   |
| SSL certificates on websites  | `host`                     | `mql shell host mondoo.com`                                                                                                                     |
| STACKIT projects              | `stackit`                  | `mql shell stackit --project-id PROJECT_ID --service-account-key-path KEY_FILE`                                                                |
| Tailscale organization        | `tailscale`                | `mql shell tailscale --token ACCESS_TOKEN`                                                                                                      |
| Terraform HCL                 | `terraform`                | `mql shell terraform HCL_FILE_OR_PATH`                                                                                                          |
| Terraform plan                | `terraform plan`           | `mql shell terraform plan plan.json`                                                                                                            |
| Terraform state               | `terraform state`          | `mql shell terraform state state.json`                                                                                                          |
| Together AI                   | `together`                 | `mql shell together --token TOKEN`                                                                                                              |
| UniFi network controllers     | `unifi`                    | `mql shell unifi --hostname HOST --api-key YOUR_API_KEY`                                                                                        |
| Vagrant virtual machines      | `vagrant`                  | `mql shell vagrant HOST`                                                                                                                        |
| Vercel teams and projects     | `vercel`                   | `mql shell vercel --token TOKEN`                                                                                                                |
| vLLM inference servers        | `vllm`                     | `mql shell vllm http://localhost:8000`                                                                                                          |
| VMware Cloud Director         | `vcd`                      | `mql shell vcd user@domain@host --ask-pass`                                                                                                     |
| VMware vSphere                | `vsphere`                  | `mql shell vsphere user@domain@host --ask-pass`                                                                                                 |
| Weaviate vector database      | `weaviate`                 | `mql shell weaviate localhost --api-key API_KEY`                                                                                                |
| Windows hosts                 | `local`, `ssh`, `winrm`    | `mql shell local`,<br></br>`mql shell ssh Administrator@IP_ADDRESS --ask-pass` or<br></br>`mql shell winrm Administrator@IP_ADDRESS --ask-pass` |
| Zoom accounts                 | `zoom`                     | `mql shell zoom --account-id ACCOUNT_ID --client-id CLIENT_ID --client-secret CLIENT_SECRET`                                                    |
| YARA rule scanning            | `yara`                     | `mql run local -c "yara.scan('/path/to/rules.yar').result"`                                                                                     |

## What's next?

There are so many things MQL can do! Gather information about your infrastructure, find tool-sprawl across systems, run incident response, and share data with auditors… MQL is nearly limitless in capabilities.

Explore:

- [MQL docs](https://mondoo.com/docs/mql)
- [MQL introduction](https://mondoohq.github.io/mql-intro/index.html)
- [MQL language reference](https://mondoo.com/docs/mql/resources)
- [cnspec](https://github.com/mondoohq/cnspec), our open source, cloud-native security scanner

## Join the community!

Our goal is to become the API for your entire infrastructure. Join our [community](https://github.com/orgs/mondoohq/discussions) today and let's grow it together!

## Development

See our [development documentation](DEVELOPMENT.md) for information on building and contributing to MQL.

## Legal

- **Copyright:** 2018-2026, Mondoo, Inc.
- **License:** BUSL 1.1
- **Authors:** Christoph Hartmann, Dominik Richter
