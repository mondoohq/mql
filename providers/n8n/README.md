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
| `n8n.securityAudit`, `n8n.instanceSettings` | `securityAudit:generate` |

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

A webhook left on its default authentication counts too: the n8n editor does not store default settings, and the provider reports the default.

```shell
mql> n8n.workflows.where(nodes.any(type == "n8n-nodes-base.webhook" && authentication == "none")) { name }
workflows.where: [
  0: {
    name: "mql-verify-node-security"
  }
  1: {
    name: "mql-verify-open-webhook"
  }
]
```

**Workflows with a public chat anyone can use**

```shell
mql> n8n.workflows.where(nodes.any(public == true && authentication == "none")) { name }
workflows.where: [
  0: {
    name: "mql-verify-node-security"
  }
]
```

**HTTP requests that skip TLS certificate verification**

`requestHost` is null when the URL is built from an expression.

```shell
mql> n8n.workflows { name nodes.where(allowUnauthorizedCerts == true) { name requestHost } }
workflows: [
  0: {
    nodes.where: [
      0: {
        name: "HTTP insecure"
        requestHost: null
      }
      1: {
        name: "HTTP v1 insecure"
        requestHost: "legacy.example.com"
      }
    ]
    name: "mql-verify-node-security"
  }
  1: {
    nodes.where: []
    name: "mql-verify-open-webhook"
  }
  2: {
    nodes.where: []
    name: "mql-verify-http"
  }
]
```

**Instance settings**

Setting `NODES_EXCLUDE` replaces n8n's default exclusions rather than adding to them, so check the list itself.

```shell
mql> n8n.instanceSettings { communityPackagesEnabled excludedNodes }
instanceSettings: {
  excludedNodes: [
    0: "n8n-nodes-base.executeCommand"
    1: "n8n-nodes-base.localFileTrigger"
    2: "n8n-nodes-base.e2eTest"
    3: "n8n-nodes-base.dynamicCredentialCheck"
  ]
  communityPackagesEnabled: true
}
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

Credentials are listed by name and type only: the Public API never returns their data. Node parameters are free-form per node type and can hold secrets typed in directly, such as header values or code, so the provider does not expose them. It reads only named security settings (authentication, webhook path and IP allowlist, chat visibility and origins, TLS verification) and, for HTTP Request nodes, the host of the URL, never its path or query.
