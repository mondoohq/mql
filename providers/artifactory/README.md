# Artifactory Provider

Query the configuration of a JFrog Artifactory instance: which repositories
exist and what a remote one proxies, which principals hold which actions on
which repository patterns, who is an administrator, which access tokens never
expire, and whether an unauthenticated caller can read or publish.

Artifactory is often the only registry a platform installs from, so a
permission mistake there reaches every consumer of the artifacts it serves.

## Prerequisites

An access token, or the legacy API key. Create an access token in the JFrog
platform under **User Menu > Edit Profile > Generate an Identity Token**, or
with `jf` (`jf atc`).

Most of what this provider reads is administrator-only:

| Resource                        | Rights needed |
| ------------------------------- | ------------- |
| `repositories`, `system`        | any account   |
| `permissionTargets`             | administrator |
| `users`, `groups`               | administrator |
| `accessTokens`                  | administrator to see every token, otherwise only the caller's own |
| `security` and its integrations | administrator |
| `backups`                       | administrator |
| `cleanupPolicies`               | administrator, and a product version that serves the endpoint |
| `projects` and their members    | administrator, or a project administrator for their own projects |
| `xray` and its watches, policies, and ignore rules | a reachable Xray, and the Manage Watches role |

A token without those rights reports the field as an error rather than as an
empty result, so an audit does not pass on data that was never read.

## Authentication

Arguments:

- `--url` - the JFrog platform base URL. Also accepted as a bare argument.
- `--token` - an Artifactory access token.
- `--api-key` - a legacy API key, an alternative to the token.

```shell
# flags
mql shell artifactory --url https://example.jfrog.io --token TOKEN

# bare argument
mql shell artifactory https://example.jfrog.io --token TOKEN

# environment variables (ARTIFACTORY_URL or JFROG_URL, ARTIFACTORY_TOKEN or
# JFROG_ACCESS_TOKEN, ARTIFACTORY_API_KEY)
export ARTIFACTORY_URL=https://example.jfrog.io
export ARTIFACTORY_TOKEN=TOKEN
mql shell artifactory
```

### URL shapes

Both deployment shapes are accepted, and so is the URL the web interface shows:

| What you pass                              | What is used                     |
| ------------------------------------------ | -------------------------------- |
| `https://example.jfrog.io`                 | `https://example.jfrog.io`       |
| `https://artifactory.example.com`          | `https://artifactory.example.com`|
| `https://artifactory.example.com/artifactory` | `https://artifactory.example.com` |
| `artifactory.example.com`                  | `https://artifactory.example.com`|

The provider appends the service prefix itself, so a trailing `/artifactory` is
removed rather than doubled. A bare host is assumed to be HTTPS, so the
credential is never sent in the clear.

## Usage

Open an interactive shell:

```shell
mql shell artifactory --url https://example.jfrog.io --token TOKEN
```

The connection produces one asset, the instance. It is identified by the
instance's service identifier, which survives a URL change.

## Examples

**Docker repositories that still accept unsigned schema 1 manifests**

A schema 1 manifest is not content addressable, so a tag can be moved to
different content without the digest changing.

```shell
mql> artifactory.repositories.where(packageType == "docker" && blockPushingSchema1 != true) { key type }
```

**Remote repositories that hold a credential and may leak it on a redirect**

```shell
mql> artifactory.repositories.where(hasUpstreamCredential == true && allowAnyHostAuth == true) { key url }
```

**Identity integrations that create an account on first sign-in**

Auto-creation makes every principal the directory or identity provider accepts
a principal here, so what it may do is whatever the auto-join groups and the
anonymous grants give it.

```shell
mql> artifactory.security.ldapSettings.where(enabled && autoCreateUser) { key ldapUrl }
mql> artifactory.security { saml { enabled noAutoUserCreation } oauth { enabled persistUsers } }
```

**Header-based sign-in, which a caller can set itself**

HTTP single sign-on trusts a request header. A deployment that also accepts
requests that did not pass through the proxy lets a caller choose any account.

```shell
mql> artifactory.security.httpSso { httpSsoProxied remoteUserRequestVariable noAutoUserCreation }
```

**LDAP servers reached without transport encryption**

```shell
mql> artifactory.security.ldapSettings.where(enabled && usesEncryptedTransport == false) { key ldapUrl }
```

**Build info readable without a permission target**

```shell
mql> artifactory.security { buildGlobalBasicReadAllowed buildGlobalBasicReadForAnonymous }
```

**Backups that leave new repositories out, or are kept forever**

```shell
mql> artifactory.backups.where(enabled && excludeNewRepositories) { key cronExpression }
mql> artifactory.backups.where(enabled && retentionPeriodHours == null) { key }
```

**Anonymous access, and whether it can publish**

The highest-value check. Both halves must hold: anonymous access is on
instance-wide, and a permission target gives the anonymous user a publishing
action.

```shell
mql> artifactory.security { anonymousAccessEnabled anonymousCanRead anonymousCanDeploy }
```

**Which permission targets would let an unauthenticated caller publish**

Listed whether or not anonymous access is on, so that turning it on shows what
would immediately apply.

```shell
mql> artifactory.security.anonymousDeployTargets { name repo { repositories includePatterns } }
```

**What an unauthenticated caller can do to one repository**

```shell
mql> artifactory.repositories.where(key == "example-docker") { key anonymousActions }
```

**Permission targets that cover every repository through a wildcard**

Such a target reaches repositories that did not exist when it was written.

```shell
mql> artifactory.permissionTargets.where(repo.appliesToAllRepositories) { name repo { repositories } }
```

**Grants that are not narrowed to a path**

```shell
mql> artifactory.permissionTargets.where(repo.appliesToAllPaths) { name principals.where(canDeploy) { name type actions } }
```

**Who can publish to the repositories a platform installs from**

```shell
mql> artifactory.repositories.where(key == "example-docker") {
       key
       permissionTargets { name principals.where(canDeploy) { name type actions } }
     }
```

**Principals that can widen their own access**

```shell
mql> artifactory.permissionTargets { name principals.where(canManage) { name type } }
```

**Remote repositories and the upstream they proxy**

An upstream that is not the expected registry places untrusted content behind a
trusted repository name.

```shell
mql> artifactory.repositories.where(type == "remote") { key packageType url }
```

**Remote repositories that may resolve from other hosts, or leak credentials on a redirect**

```shell
mql> artifactory.repositories.where(type == "remote" && (allowAnyHostAuth || externalDependenciesEnabled)) { key url }
```

**Where the registry's contents are copied to**

A push replication sends every artifact of a repository to another instance. An
unexpected URL there is an export of the registry.

```shell
mql> artifactory.repositories { key replications.where(enabled) { url syncDeletes hasCredential } }
```

**Replications that send artifacts and a credential in the clear**

```shell
mql> artifactory.repositories { key replications.where(enabled && usesEncryptedTransport == false) { url hasCredential } }
```

**Repositories that are scanned but not protected**

Being indexed is not the same as being covered. A repository is only acted on
when an active watch names it and that watch carries a policy that blocks.

```shell
mql> artifactory.repositories.where(xrayIndex == true && xrayBlocksDownload == false) { key xrayWatches { name } }
mql> artifactory.repositories.where(xrayWatches.length == 0) { key type packageType }
```

**Watches that cover every repository through a wildcard**

Such a watch also reaches repositories created after it was written.

```shell
mql> artifactory.xray.watches.where(active && coversAllRepositories) { name policyNames }
```

**Watches that are configured but not enforced**

```shell
mql> artifactory.xray.watches.where(active == false) { name policyNames }
```

**Policies that record a violation without stopping anything**

```shell
mql> artifactory.xray.policies.where(blocksDownload == false && failsBuild == false) { name type }
mql> artifactory.xray.policies.where(blocksUnscanned == false) { name }
```

**Policies no watch enforces**

```shell
mql> artifactory.xray.policies.where(watches.length == 0) { name type }
```

**Rules that only count a finding with a fix available**

A vulnerability with no released fix is then not a violation, so it blocks
nothing.

```shell
mql> artifactory.xray.policies { name rules.where(fixVersionDependant) { name minSeverity } }
```

**Suppressions that never expire**

The suppression list is paged and the provider walks every page, so this counts
all of them rather than the first page.

```shell
mql> artifactory.xray.ignoreRules.where(expires == false) { id notes vulnerabilities repositories }
```

**Projects that delegate access decisions to their own administrators**

A project administrator with `manageMembers` decides who reaches the project's
repositories, and one with `manageResources` decides which repositories the
project holds. Neither decision appears in the instance's permission targets.

```shell
mql> artifactory.projects.where(manageMembers) { key members.where(isAdmin) { name roles } }
mql> artifactory.projects.where(manageResources) { key repositories { key type } }
```

**Repositories Xray does not index**

An unindexed repository is never scanned, so a finding on an artifact stored
there is never raised.

```shell
mql> artifactory.repositories.where(xrayIndex != true) { key type packageType }
```

Use `!= true` rather than `== false`. The setting is null on repository types
that do not carry it, and `== false` would skip those.

**Administrators, and accounts that are local to the instance**

A local account keeps working after the identity provider disables the person.

```shell
mql> artifactory.users.where(admin) { name realm email }
mql> artifactory.users.where(internal) { name lastLoggedIn }
```

**Groups that carry administrative rights, or that everyone joins**

```shell
mql> artifactory.groups.where(adminPrivileges) { name realm users { name } }
mql> artifactory.groups.where(autoJoin) { name permissionTargets { name } }
```

**Access tokens that never expire**

Such a token stays usable until somebody revokes it by hand.

```shell
mql> artifactory.accessTokens.where(expires == false) { id subject issuedAt }
```

**Access tokens that carry administrative rights**

```shell
mql> artifactory.accessTokens.where(grantsAdmin) { id subject expiry }
```

**Cleanup policies and what they delete from**

```shell
mql> artifactory.cleanupPolicies.where(enabled) { key cronExpression repositories keepLastNVersions }
```

**Cross-resource traversal**

Repositories, permission targets, users, and groups reference each other, so a
query can start from any of them:

```shell
mql> artifactory.users.where(admin) { name permissionTargets { name } }
mql> artifactory.permissionTargets { name principals { name group { adminPrivileges } } }
mql> artifactory.repositories.where(type == "virtual") { key memberRepositoryRefs { key type } }
```

## Verification

Confirm the credential works and see what it reaches:

```shell
mql> artifactory.system { version serviceId }
mql> artifactory.repositories { key type packageType }
```

An error on `permissionTargets` while `repositories` answers means the
credential is valid but not an administrator.

## Notes

**Repository, user, and group detail is read in bulk when the instance allows
it.** Repository configurations come from one call to
`/api/repositories/configurations`, which needs an administrator and a recent
product version. The user and group lists are used directly when they already
carry the full record. When neither applies, the detail is read on demand, one
call per record, so a query that asks only for `key`, `name`, `type`, and
`packageType` stays cheap either way.

A list entry is only taken as complete when it carries both of its markers, the
administrative flag and the group or member list. An entry carrying one of them
is treated as short and read in full, because taking a stale `false` would
report an administrator as an ordinary account, and taking an absent list would
report an account as belonging to no group.

**`anonymousActions` is taken at repository level.** It unions what every
permission target gives the anonymous user over a repository and does not
evaluate the targets' path patterns, so an action it lists may be limited to
part of the repository. Read `permissionTargets` on the repository for the
patterns.

**Replication is read per repository.** The instance serves no instance-wide
list, so `replications` is one call for each repository it is asked about.
Query it on the repositories that matter rather than across the whole instance.
A repository that replicates nothing reports an empty list, because not
replicating is a normal state.

**The replication password is never decoded.** The instance returns it with the
configuration. It is not read into a struct field at all, so it cannot reach a
resource field, a log line, or a recording. `hasCredential` reports whether one
exists.

**Xray reports null when the platform has no reachable Xray.** That is a
different answer from an Xray with no watch: the first means nothing scans, the
second means nothing is enforced. Query `artifactory.xray == null` to tell them
apart.

**A denied Xray read is an error, not a null.** Only a platform that serves no
Xray at all reports null. A token that may not read Xray fails the field and
names the rights it needs, because reporting null there would say the platform
does not scan, and a policy asking whether a repository is protected would pass
on an answer that was never read.

**A policy acts only through a watch.** `artifactory.xray.policies` lists what
is configured, and `artifactory.repositories { xrayPolicies }` lists what is
enforced on a repository. A policy no watch names is enforced nowhere, whatever
its rules say.

**A project is a second path to access.** The instance's permission targets do
not show what a project administrator granted inside a project. Read
`artifactory.projects { members }` together with
`artifactory.permissionTargets` to see both.

**Project membership is read per project.** The instance serves the roster per
project, so `members` is one call for each project it is asked about.

**An integration the instance never configured reports null, not disabled.**
`saml`, `oauth`, `httpSso`, and `crowd` are null when the instance descriptor
carries no block for them. An instance that configured an integration and
turned it off reports the resource with `enabled` false, which is a different
answer.

**Settings that do not apply to a repository type stay null.** A local
repository carries no upstream settings, and a package format carries only its
own controls, so `allowAnyHostAuth`, `blockPushingSchema1`, and their peers are
null rather than false there. Test them with `!= true`.

**A permission target that cannot be read fails the field.** The list reports
names only, and each grant is read separately. A target that is denied fails
`permissionTargets` rather than being dropped, because a permission review that
silently skips a target is worse than one that reports it could not read it.

**Cleanup policies need a recent product version.** An instance that does not
serve the endpoint reports an error naming it, rather than an empty list that
would read as "no policies configured".
