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

[:books: To learn more, read the MQL docs.](https://mondoo.com/docs/mql/home/)

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

To learn about Mondoo Platform, read the [Mondoo Platform docs](https://mondoo.com/docs/platform/home/) or visit [mondoo.com](https://mondoo.com).

## Supported targets

| Target                        | Provider                   | Example                                                                                                                                         |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| AI/MCP servers                | `mcp`                      | `mql shell mcp http http://localhost:8080/mcp`                                                                                                  |
| Ansible playbooks             | `ansible`                  | `mql shell ansible YOUR_PLAYBOOK.yml`                                                                                                           |
| Arista network devices        | `arista`                   | `mql shell arista DEVICE_PUBLIC_IP --ask-pass`                                                                                                  |
| Atlassian organizations       | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| AWS accounts                  | `aws`                      | `mql shell aws`                                                                                                                                 |
| AWS CloudFormation templates  | `cloudformation`           | `mql shell cloudformation cloudformation_file.json`                                                                                             |
| AWS EC2 EBS snapshot          | `aws ec2 ebs snapshot`     | `mql shell aws ec2 ebs snapshot SNAPSHOTID`                                                                                                     |
| AWS EC2 EBS volume            | `aws ec2 ebs volume`       | `mql shell aws ec2 ebs volume VOLUMEID`                                                                                                         |
| AWS EC2 Instance Connect      | `aws ec2 instance-connect` | `mql shell aws ec2 instance-connect ec2-user@INSTANCEID`                                                                                        |
| AWS EC2 instances             | `ssh`                      | `mql shell ssh user@host`                                                                                                                       |
| Cisco network devices         | `nd-ssh`                   | `mql shell nd-ssh admin@DEVICE_IP --password PASSWORD`                                                                                          |
| Cisco Catalyst Center         | `ciscocatalyst`            | `mql shell ciscocatalyst --host HOST --user USER --password PASSWORD`                                                                           |
| Cloudflare accounts           | `cloudflare`               | `mql shell cloudflare --token ACCESS_TOKEN`                                                                                                     |
| Confluence users              | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| Container images              | `container`, `docker`      | `mql shell container ubuntu:latest`                                                                                                             |
| Container registries          | `container registry`       | `mql shell container registry index.docker.io/library/rockylinux:8`                                                                             |
| Dockerfiles                   | `docker`                   | `mql shell docker file FILENAME`                                                                                                                |
| DNS records                   | `host`                     | `mql shell host mondoo.com`                                                                                                                     |
| Fortinet FortiOS devices      | `fortios`                  | `mql shell fortios --hostname HOSTNAME --token TOKEN`                                                                                           |
| GitHub organizations          | `github org`               | `mql shell github org mondoohq`                                                                                                                 |
| GitHub repositories           | `github repo`              | `mql shell github repo mondoohq/mql`                                                                                                            |
| GitLab groups                 | `gitlab`                   | `mql shell gitlab --group mondoohq`                                                                                                             |
| Google Cloud projects         | `gcp`                      | `mql shell gcp`                                                                                                                                 |
| Google Workspace              | `google-workspace`         | `mql shell google-workspace --customer-id CUSTOMER_ID --impersonated-user-email EMAIL --credentials-path JSON_FILE`                             |
| OPC UA IoT devices            | `opcua`                    | `mql shell opcua`                                                                                                                               |
| IP address information        | `ipinfo`                   | `mql shell ipinfo`                                                                                                                              |
| IPMI-enabled devices          | `ipmi`                     | `mql shell ipmi user@HOST`                                                                                                                      |
| Jira projects                 | `atlassian`                | `mql shell atlassian --host YOUR_HOST_URL --admin-token YOUR_TOKEN`                                                                             |
| Juniper Junos devices         | `junos`                    | `mql shell junos --hostname DEVICE_IP --username admin --password PASSWORD`                                                                     |
| Kubernetes cluster nodes      | `local`, `ssh`             | `mql shell ssh user@host`                                                                                                                       |
| Kubernetes clusters           | `k8s`                      | `mql shell k8s`                                                                                                                                 |
| Kubernetes manifests          | `k8s`                      | `mql shell k8s manifest.yaml`                                                                                                                   |
| Kubernetes workloads          | `k8s`                      | `mql shell k8s --discover pods,deployments`                                                                                                     |
| Linux hosts                   | `local`, `ssh`             | `mql shell local` or<br></br>`mql shell ssh user@host`                                                                                          |
| macOS hosts                   | `local`, `ssh`             | `mql shell local` or<br></br>`mql shell ssh user@IP_ADDRESS`                                                                                    |
| Microsoft 365 tenants         | `ms365`                    | `mql shell ms365 --tenant-id TENANT_ID --client-id CLIENT_ID --certificate-path PFX_FILE`                                                       |
| Microsoft Azure instances     | `ssh`                      | `mql shell ssh user@host`                                                                                                                       |
| Microsoft Azure subscriptions | `azure`                    | `mql shell azure --subscription SUBSCRIPTION_ID`                                                                                                |
| Network scanning              | `nmap`                     | `mql shell nmap --networks 192.168.1.0/24`                                                                                                      |
| Okta org                      | `okta`                     | `mql shell okta --token TOKEN --organization ORGANIZATION`                                                                                      |
| Oracle Cloud Interface (OCI)  | `oci`                      | `mql shell oci`                                                                                                                                 |
| Palo Alto Networks PAN-OS     | `panos`                    | `mql shell panos --hostname DEVICE_IP --username admin --password PASSWORD`                                                                     |
| Running containers            | `docker`                   | `mql shell docker CONTAINER_ID`                                                                                                                 |
| Shodan search engine          | `shodan`                   | `mql shell shodan`                                                                                                                              |
| Slack team                    | `slack`                    | `mql shell slack --token TOKEN`                                                                                                                 |
| Snowflake data warehouse      | `snowflake`                | `mql shell snowflake --account ACCOUNT_ID --region REGION --user USER --role ROLE --ask-pass`                                                   |
| SSL certificates on websites  | `host`                     | `mql shell host mondoo.com`                                                                                                                     |
| Tailscale network             | `tailscale`                | `mql shell tailscale --token ACCESS_TOKEN`                                                                                                      |
| Terraform HCL                 | `terraform`                | `mql shell terraform HCL_FILE_OR_PATH`                                                                                                          |
| Terraform plan                | `terraform plan`           | `mql shell terraform plan plan.json`                                                                                                            |
| Terraform state               | `terraform state`          | `mql shell terraform state state.json`                                                                                                          |
| UniFi network controllers     | `unifi`                    | `mql shell unifi --hostname HOST --api-key YOUR_API_KEY`                                                                                        |
| Vagrant virtual machines      | `vagrant`                  | `mql shell vagrant HOST`                                                                                                                        |
| VMware Cloud Director         | `vcd`                      | `mql shell vcd user@domain@host --ask-pass`                                                                                                     |
| VMware vSphere                | `vsphere`                  | `mql shell vsphere user@domain@host --ask-pass`                                                                                                 |
| Windows hosts                 | `local`, `ssh`, `winrm`    | `mql shell local`,<br></br>`mql shell ssh Administrator@IP_ADDRESS --ask-pass` or<br></br>`mql shell winrm Administrator@IP_ADDRESS --ask-pass` |
| YARA rule scanning            | `yara`                     | `mql run local -c "yara.scan('/path/to/rules.yar').result"`                                                                                     |

## What's next?

There are so many things MQL can do! Gather information about your infrastructure, find tool-sprawl across systems, run incident response, and share data with auditors… MQL is nearly limitless in capabilities.

Explore:

- [MQL docs](https://mondoo.com/docs/mql/home/)
- [MQL introduction](https://mondoohq.github.io/mql-intro/index.html)
- [MQL language reference](https://mondoo.com/docs/mql/resources/)
- [cnspec](https://github.com/mondoohq/cnspec), our open source, cloud-native security scanner

## Join the community!

Our goal is to become the API for your entire infrastructure. Join our [community](https://github.com/orgs/mondoohq/discussions) today and let's grow it together!

## Development

See our [development documentation](docs/development.md) for information on building and contributing to MQL.

## Legal

- **Copyright:** 2018-2026, Mondoo, Inc.
- **License:** BUSL 1.1
- **Authors:** Christoph Hartmann, Dominik Richter
