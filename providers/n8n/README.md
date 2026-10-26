# n8n Provider

The `n8n` provider connects to an n8n instance through its [Public API](https://docs.n8n.io/api/) and inventories it with read-only calls. It exposes workflows with their nodes, execution settings, and the credentials they use, stored credentials (never their secret data), users with their role and MFA state, tags, installed community node packages, and the instance's built-in security audit, so you can audit an n8n instance for unauthenticated webhooks, unused credentials, risky nodes, and accounts without MFA.

## Prerequisites

The Public API must be enabled on the instance (it is unless `N8N_PUBLIC_API_DISABLED` is set).

The provider reads what the API key's scopes allow:

| Reads | Scope |
| --- | --- |
| `n8n.workflows` | `workflow:list` |
| `n8n.credentials` | `credential:list` |
| `n8n.users` | `user:list` |
| `n8n.tags` | `tag:list` |
| `n8n.communityPackages` | `communityPackage:list` |
| `n8n.securityAudit` | `securityAudit:generate` |

A field the key may not read reports an access-denied error naming the scope, never an empty answer.

## Authentication

Arguments:

- `[url]` or `--url` - the instance URL, for example `https://n8n.example.com`.
- `--api-key` - an n8n API key.

> Create an API key in n8n under **Settings > n8n API > Create an API key**, and select the scopes above.

```shell
mql shell n8n https://n8n.example.com --api-key API_KEY
```

The `N8N_URL` and `N8N_API_KEY` environment variables can replace the URL and the flag:

```shell
export N8N_URL=https://n8n.example.com
export N8N_API_KEY=API_KEY
mql shell n8n
```

## Usage

```shell
mql shell n8n https://n8n.example.com --api-key API_KEY
cnspec scan n8n https://n8n.example.com --api-key API_KEY
```

Each instance is one asset, identified by its host.

## Examples

**Workflows with a webhook that requires no authentication**

```shell
mql> n8n.workflows.where(nodes.any(type == "n8n-nodes-base.webhook" && authentication == "none")) { name active isArchived }
workflows.where: [
  0: {
    name: "mql-verify-open-webhook"
    active: false
    isArchived: true
  }
]
```

**Credentials no workflow uses**

```shell
mql> n8n.credentials.where(workflows.length == 0) { name type }
credentials.where: [
  0: {
    name: "mql-verify-unused"
    type: "httpHeaderAuth"
  }
]
```

**Active users without multi-factor authentication**

```shell
mql> n8n.users.where(isPending == false && mfaEnabled == false) { email role }
users.where: [
  0: {
    email: "owner@example.com"
    role: "global:owner"
  }
]
```

**Installed community node packages**

```shell
mql> n8n.communityPackages { name installedVersion nodeTypes }
communityPackages: [
  0: {
    nodeTypes: [
      0: "n8n-nodes-text-manipulation.textManipulation"
    ]
    name: "n8n-nodes-text-manipulation"
    installedVersion: "1.4.0"
  }
]
```

**Findings of the built-in security audit**

```shell
mql> n8n.securityAudit.reports { risk sections { title } }
securityAudit.reports: [
  0: {
    sections: [
      0: {
        title: "Credentials not used in any workflow"
      }
      1: {
        title: "Credentials not used in any active workflow"
      }
      2: {
        title: "Credentials not used in recently executed workflows"
      }
    ]
    risk: "credentials"
  }
  1: {
    sections: [
      0: {
        title: "Security settings"
      }
    ]
    risk: "instance"
  }
  2: {
    sections: [
      0: {
        title: "Official risky nodes"
      }
      1: {
        title: "Community nodes"
      }
    ]
    risk: "nodes"
  }
]
```

## Verification

`n8n.apiKeyScopes` lists the scopes of the key in use. Compare it with the table above to see which fields the key can read.

## Secrets

Credentials are listed by name and type only: the Public API never returns their data. Of a node's parameters, the provider reads only `authentication`. The rest are free-form per node type and can hold secrets typed in directly, such as header values or code, so they are not exposed.
