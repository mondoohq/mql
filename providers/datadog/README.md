# Datadog Provider

Query and assess your Datadog account configuration, including organization single sign-on settings, users, roles and permissions, monitors, dashboards, security rules, and more.

## Prerequisites

You need a Datadog **API key** and **Application key**:

1. **API Key**: Go to **Datadog > Organization Settings > API Keys** and create (or copy) a key.
2. **Application Key**: Go to **Datadog > Organization Settings > Application Keys** and create a key with the required scopes (see below).

## Authentication

### Environment Variables (recommended)

```bash
export DD_API_KEY="<your-api-key>"
export DD_APP_KEY="<your-application-key>"

# Optional: set for non-US Datadog sites
export DD_SITE="datadoghq.eu"          # EU
# export DD_SITE="us3.datadoghq.com"   # US3
# export DD_SITE="us5.datadoghq.com"   # US5
# export DD_SITE="ap1.datadoghq.com"   # AP1
```

### CLI Flags

```bash
mql shell datadog --api-key <key> --app-key <key>
mql shell datadog --api-key <key> --app-key <key> --site datadoghq.eu
```

## Examples

**Check that single sign-on is enforced**

```shell
mql> datadog.org { samlEnabled samlStrictModeEnabled privateWidgetShare }
```

**Find who holds a privileged permission**

```shell
mql> datadog.roles.where(permissions.any(name == "org_management")) { name users { email } }
```

**Find dashboards shared publicly**

```shell
mql> datadog.dashboards { title sharedDashboards.where(shareType == "open") { publicUrl status expiration } }
```

**Find who can open a remote shell on a host through Datadog**

```shell
mql> datadog.executionPolicies.where(effect == "allow" && integration == "INTEGRATION_REMOTE_ACTION") { name targets { agentTags } scope { scopeType remoteShellRules { access targetPaths } } createdBy { email } }
```

**Review where logs are forwarded outside Datadog**

```shell
mql> datadog.logsCustomDestinations { name enabled destinationType endpoint query }
```

**Check which identity provider attributes grant a role**

```shell
mql> datadog.authnMappings { attributeKey attributeValue role { name } team { name } }
```

**Find application keys that are unscoped or unused**

```shell
mql> datadog.applicationKeys { name lastUsedAt scopes owner { email } }
```

**List all users**

```shell
mql> datadog.users
datadog.users: [
  0: datadog.user id="abc-123" email="alice@example.com" status="Active"
  1: datadog.user id="def-456" email="bob@example.com" status="Active"
]
```

**Check for disabled monitors**

```shell
mql> datadog.monitors { name type overallState }
```

**List dashboards**

```shell
mql> datadog.dashboards { title authorHandle createdAt }
```

**Inspect SLO targets**

```shell
mql> datadog.slos { name type targetThreshold timeframe }
```

**List security monitoring rules**

```shell
mql> datadog.securityRules { name type isEnabled isDefault }
```

**Check synthetics tests**

```shell
mql> datadog.syntheticsTests { name type status locations }
```

**Review API key metadata**

```shell
mql> datadog.apiKeys { name last4 createdAt }
```

**List AWS integrations**

```shell
mql> datadog.integrationAwsAccounts { accountId metricsEnabled logsEnabled resourceCollectionEnabled }
```

**List teams**

```shell
mql> datadog.teams { name handle userCount }
```

**Review logs archive configuration**

```shell
mql> datadog.logsArchives { name query state destinationType }
```

## Required Permissions

By default, an unscoped Application Key inherits all permissions of the user who created it. For production use, Datadog supports [scoped Application Keys](https://docs.datadoghq.com/account_management/api-app-keys/) that restrict access to specific RBAC permissions.

The table below lists the Datadog RBAC permission each resource requires. These are the same permission names shown in **Datadog > Organization Settings > Roles**.

| Resource | Required RBAC Permission |
|---|---|
| `datadog.org` | `org_management` |
| `datadog.org.domainAllowlistEnabled` / `domainAllowlistDomains` | `org_management` |
| `datadog.users` | `user_access_invite` |
| `datadog.user.roles` | `user_access_read` |
| `datadog.user.teams` | `teams_read` |
| `datadog.roles` | `user_access_invite` |
| `datadog.role.permissions` / `datadog.role.users` | `user_access_read` |
| `datadog.permissions` | `user_access_read` |
| `datadog.serviceAccounts` | `user_access_invite` |
| `datadog.monitors` | `monitors_read` |
| `datadog.dashboards` | `dashboards_read` |
| `datadog.slos` | `slos_read` |
| `datadog.downtimes` | `monitors_downtime` |
| `datadog.syntheticsTests` | `synthetics_read` |
| `datadog.syntheticsGlobalVariables` | `synthetics_read` |
| `datadog.syntheticsPrivateLocations` | `synthetics_read` |
| `datadog.logIndexes` | `logs_read_index_data` |
| `datadog.logsArchives` | `logs_read_archives` |
| `datadog.securityRules` | `security_monitoring_rules_read` |
| `datadog.securityFilters` | `security_monitoring_filters_read` |
| `datadog.securitySuppressions` | `security_monitoring_suppressions_read` |
| `datadog.sensitiveDataScannerGroups` | `data_scanner_read` |
| `datadog.apiKeys` | `api_keys_read` |
| `datadog.applicationKeys` | `user_app_keys` |
| `datadog.ipAllowlistEntries` / `ipAllowlistEnabled` | `org_management` |
| `datadog.integrationAwsAccounts` | `aws_configuration_read` |
| `datadog.teams` / `datadog.team.members` | `teams_read` |
| `datadog.authnMappings` | `user_access_read` |
| `datadog.logsPipelines` | `logs_read_config` |
| `datadog.logsCustomDestinations` | `logs_read_config` |
| `datadog.logsRestrictionQueries` | `logs_read_config` |
| `datadog.dashboard.sharedDashboards` | `dashboards_public_share` |
| `*.restrictionPolicy` | the read permission of the resource it is attached to |
| `datadog.rumApplications` | `rum_apps_read` |

> **Tip**: For full access to all resources, use an unscoped Application Key (it inherits all permissions from its creator). Scoped keys are recommended for production use to follow least-privilege principles.

> **Note**: Some resources require your Datadog plan to include the corresponding product. If the feature is not enabled, the API returns 403 Forbidden regardless of your key's permissions. The provider handles this gracefully by returning an empty list and logging a warning.

### Plan-Gated Resources

The following resources require specific Datadog products to be enabled in your organization:

| Resource | Required Product |
|---|---|
| `datadog.securityRules` | Cloud SIEM |
| `datadog.securityFilters` | Cloud SIEM |
| `datadog.securitySuppressions` | Cloud SIEM |
| `datadog.sensitiveDataScannerGroups` | Sensitive Data Scanner |

> **Note**: `datadog.executionPolicies` reads `/api/v2/actions/execution-policies`, which Datadog marks as a preview operation. The provider enables it explicitly, because the API client refuses preview operations by default. The RBAC permission and the product that gates it are not published in the API client, so they are absent from the tables above; a 403 is handled the same way as for the plan-gated resources, returning an empty list and logging a warning.

To check which products are enabled, go to **Datadog > Organization Settings > Subscription** or contact your Datadog account representative.
