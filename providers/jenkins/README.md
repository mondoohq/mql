# Jenkins Provider

The `jenkins` provider connects to a Jenkins controller and inventories its
security configuration, installed plugins, jobs, build agents, and stored
credential metadata through read-only queries. It's built to audit the
controller's access-control posture (authentication, CSRF protection, agent
ports), plugin currency, and the credential and job surface a pipeline can
reach.

Credential secret material (passwords, private keys, tokens) is never
fetched or exposed. Only identifying metadata is read.

## Prerequisites

A Jenkins user with **Overall/Read** permission on the controller, plus a
per-user API token. Reading agent and credential metadata additionally
needs **Agent/Read** and **Credentials/View**; without them those
collections come back empty rather than failing the scan.

## Authentication

Authentication uses a Jenkins username paired with a per-user API token
over HTTP Basic auth.

Arguments:

- `--url` - the Jenkins base URL.
- `--user` - the user to authenticate as.
- `--token` - that user's Jenkins API token.

```shell
mql shell jenkins --url https://jenkins.example.com --user USER --token TOKEN
```

> Create an API token from Jenkins under **Your user page > Configure >
> API Token > Add new Token**. Use a token rather than the account
> password; Jenkins rejects passwords for API requests when security
> realms such as SSO are in use.

You can also use the environment variables `JENKINS_URL`, `JENKINS_USER`,
and `JENKINS_TOKEN` to provide your connection details.

## Usage

Open an interactive shell:

```shell
mql shell jenkins
```

## Discovery

The provider models a single asset per controller; there are no
`--discover` child-asset targets in this initial release.

## Examples

**Controller version and operating mode**

```shell
mql> jenkins { url version mode quietingDown }
```

**Controllers running with access control turned off**

With security disabled, anyone who can reach the controller has
administrative rights on it.

```shell
mql> jenkins.security { securityEnabled csrfProtectionEnabled allowsAnonymousAdmin }
```

**Plugins with an available update**

An outdated plugin is the most common route to a controller compromise, so
this is the list that matters most for patching.

```shell
mql> jenkins.plugins.where( hasUpdate == true ) { shortName version }
```

**Jobs that are buildable but undocumented**

```shell
mql> jenkins.jobs.where( buildable == true && description == "" ) { fullName class }
```

**Stored credentials outside the global domain**

Folder-scoped and non-default-domain credentials are easy to lose track
of, since they don't appear in the controller's main credentials view.

```shell
mql> jenkins.credentials.where( domain != "_" ) { id typeName domain }
```

**Agents that are offline for an unexplained reason**

```shell
mql> jenkins.nodes.where( offline == true && temporarilyOffline == false ) { name offlineCauseReason }
```

## Resources

See `resources/jenkins.lr` for the full schema. Top-level resources:
`jenkins`, `jenkins.security`, `jenkins.plugin`, `jenkins.job`,
`jenkins.node`, and `jenkins.credential`.

## Verification

`jenkins { version }` confirms the connection authenticates and the
controller answers. `jenkins.credentials` confirms the account can read
credential metadata; an empty result with no error usually means the
account lacks **Credentials/View** rather than that no credentials exist.
The same applies to an empty `jenkins.nodes` and **Agent/Read**.

## Troubleshooting

- **"a Jenkins base URL is required"** - pass `--url` or set
  `JENKINS_URL`.
- **"a Jenkins username and API token are required"** - pass
  `--user`/`--token` or set `JENKINS_USER`/`JENKINS_TOKEN`.
- **401 or 403 from every query** - the token was rejected, or the account
  lacks **Overall/Read**. Regenerate the token from the user's configure
  page and confirm the account can load the Jenkins dashboard.
