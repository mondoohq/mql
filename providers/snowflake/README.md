# Snowflake Provider

```shell
mql shell snowflake
```

## Authentication

Required arguments:

- `--account` - The Snowflake account name.
- `--region` - The Snowflake region.
- `--user` - The Snowflake username.
- `--role` - The Snowflake role.

> The easiest way to get the account name and region is to look at the URL when you log in to the Snowflake web interface. When clicking on the account icon you can copy the account URL that included the account name and region.

**Programmatic Access Token (PAT) — recommended**

A programmatic access token (PAT) is Snowflake's recommended method for tools and automation. It replaces password sign-ins, which Snowflake is phasing out, and can be scoped to a role and governed by a network policy.

Arguments:

- `--token` - The programmatic access token.

```shell
mql shell snowflake --account zi12345 --region us-central1.gcp --user CHRIS --role ACCOUNTADMIN --token <your PAT>
```

> To generate a PAT, use [Snowsight](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens) and assign it to your user. Prefer a token scoped to the least-privileged role that still allows the scan.

**Key-Pair Authentication**

Arguments:

- `--identity-file` (`-i`) - The path to the private key file.

```shell
mql shell snowflake --account zi12345 --region us-central1.gcp --user CHRIS --role ACCOUNTADMIN --identity-file ~/.ssh/id_rsa
```

> You need to generate a RSA key pair and assign the public key to your user via [Snowsight](https://docs.snowflake.com/en/user-guide/key-pair-auth).

**Password Authentication (legacy)**

Password sign-ins are being deprecated by Snowflake and require MFA for interactive users. Prefer a PAT or key-pair for new setups.

Arguments:

- `--password` - The Snowflake password.
- `--ask-pass` - Prompt for the Snowflake password.

```shell
mql shell snowflake --account zi12345 --region us-central1.gcp --user CHRIS --role ACCOUNTADMIN --ask-pass
```

> To create a username and password, use [Snowsight](https://docs.snowflake.com/en/user-guide/admin-user-management#using-snowsight) or using [SQL](https://docs.snowflake.com/en/user-guide/admin-user-management#using-sql).

## Discovery

A scan surfaces the Snowflake account as its own asset and, in addition, one asset per database in the account:

- The **account asset** (`snowflake`) carries the account-wide security posture: users, roles, integrations, network/password/session/authentication policies, and resource monitors.
- Each **database asset** (`snowflake-database`) carries that database's data-governance posture: its schemas, database roles, masking policies, row-access policies, tags, and secrets.

This split lets account-wide checks target the account asset while per-database checks target each database asset independently.

The account asset is always the root of the scan; the `--discover` targets only control which additional child assets are emitted alongside it:

- `auto` (default) - also emit one asset per database. Same as `all`.
- `all` - also emit one asset per database.
- `databases` - also emit one asset per database.
- `none` - account only, without emitting per-database assets.

```shell
# Scan the account and every database
cnspec scan snowflake --account zi12345 --region us-central1.gcp --user CHRIS --role ACCOUNTADMIN --identity-file ~/.ssh/id_rsa

# Scan the account only
cnspec scan snowflake --account zi12345 --region us-central1.gcp --user CHRIS --role ACCOUNTADMIN --identity-file ~/.ssh/id_rsa --discover none
```

## Examples

**Retrieve all users**

```shell
mql> snowflake.account.users
snowflake.account.users: [
  0: snowflake.user name="CHRIS"
  1: snowflake.user name="DATAUSER"
  2: snowflake.user name="SNOWFLAKE"
]
```

**Retrieve all users that have no MFA**

```shell
mql> snowflake.account.users.where(extAuthnDuo == false)
snowflake.account.users.where: [
  0: snowflake.user name="CHRIS"
  1: snowflake.user name="DATAUSER"
  2: snowflake.user name="SNOWFLAKE"
]
```

**Retrieve all users that have password authentication**

```shell
mql> snowflake.account.users.where(hasPassword)
snowflake.account.users.where: [
  0: snowflake.user name="CHRIS"
  1: snowflake.user name="DATAUSER"
  2: snowflake.user name="SNOWFLAKE"
]

```

**Retrieve all users that have certificate authentication**

```shell
mql> snowflake.account.users.where(hasRsaPublicKey)
snowflake.account.users.where: [
  0: snowflake.user name="CHRIS"
]
```

**Retrieve users that have not logged in for 30 days**

```shell
mql> snowflake.account.users.where(time.now - lastSuccessLogin > time.day * 30) { lastSuccessLogin }
snowflake.account.users.where: [
  0: {
    lastSuccessLogin: 366 days 
  }
]
```

**Check that SCIM is enabled**

```shell
mql> snowflake.account.securityIntegrations.where(type == /SCIM/).any(enabled == true)
[failed] [].any()
  actual:   []
```

**Check the retention time is greater 90 days**

```shell
mql> snowflake.account.parameters.one(key == "DATA_RETENTION_TIME_IN_DAYS" && value >= 90)
```

**Retrieve all databases**

```shell
mql> snowflake.account.databases
snowflake.account.databases: [
  0: snowflake.database name="CNQUERY"
  1: snowflake.database name="SNOWFLAKE"
  2: snowflake.database name="SNOWFLAKE_SAMPLE_DATA"
]
```


