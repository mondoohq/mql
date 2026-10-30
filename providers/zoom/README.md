# Zoom Provider

The `zoom` provider connects to a Zoom account through Server-to-Server OAuth
and inventories its account-level security posture: meeting-security
defaults, cloud-recording encryption, single sign-on, users, roles, and
groups, through read-only queries.

> The API client in `connection/` is a minimal, hand-written implementation
> covering exactly the endpoints this provider's resources need. The
> production intent per [ADR-033](../../docs/adr/033-zoom-provider.md) is a
> client generated from Zoom's published OpenAPI spec.

## Prerequisites

A Zoom Server-to-Server OAuth app (Account ID, Client ID, Client Secret)
with read scopes for accounts, users, roles, and groups.

## Authentication

Arguments:

- `--account-id` - the Zoom account ID (or `ZOOM_ACCOUNT_ID`).
- `--client-id` - the Server-to-Server OAuth app client ID (or `ZOOM_CLIENT_ID`).
- `--client-secret` - the Server-to-Server OAuth app client secret (or `ZOOM_CLIENT_SECRET`).

```shell
mql shell zoom --account-id <id> --client-id <id> --client-secret <secret>
```

> Create a Server-to-Server OAuth app in the Zoom App Marketplace to obtain
> these credentials.

## Usage

Open an interactive shell:

```shell
mql shell zoom
```

## Examples

**Meeting security defaults**

```shell
mql> zoom.account { meetingWaitingRoomEnabled meetingPasscodeRequired meetingE2eeAvailable meetingEncryptionType }
```

**Sign-in enforcement**

```shell
mql> zoom.account { meetingSignedInUsersOnly meetingAuthenticationRequired signInSessionTimeoutWebMinutes signInSessionTimeoutClientMinutes }
```

**Users who do not sign in through SSO**

```shell
mql> zoom.users.where(ssoLinked == false) { email loginTypes }
```

**Users and their roles**

```shell
mql> zoom.users { email type status ssoLinked role { name } }
```

**Admin-equivalent role membership**

```shell
mql> zoom.roles { name totalMembers members { email } }
```

**Group-level meeting-security overrides**

```shell
mql> zoom.groups { name settingsWaitingRoomEnabled settingsMeetingPasscodeRequired }
```

## Resources

See the [MQL resource docs](https://mondoo.com/docs/mql/resources) for the
full `zoom.*` resource reference, generated from `resources/zoom.lr`.

## Verification

```shell
mql> zoom.account { id accountName }
```

An error at connect time usually means the Server-to-Server OAuth app is
missing a required scope (accounts, users, roles, or groups read access).
