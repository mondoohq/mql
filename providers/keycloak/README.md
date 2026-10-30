# Keycloak Provider

The `keycloak` provider reads a Keycloak server through its admin REST API. It
inventories realms, clients, roles, groups, users, federated identity providers,
authentication flows and user federation components, so the authentication
posture of a realm can be audited without reading the server's database.

## Prerequisites

- A reachable Keycloak server, version 20 or newer.
- Credentials that hold the realm-management view roles of every realm you read.

The provider only issues GET requests. It never changes a realm.

## Authentication

There are two ways to authenticate.

**Admin user.** The password grant signs in against the built-in `admin-cli`
client. It is the quickest way to try the provider, and it inherits every
privilege of the account.

```shell
mql shell keycloak --url https://keycloak.example.com --username admin --password PASSWORD
```

**Service account.** A confidential client with service accounts enabled uses
the client credentials grant. It holds only the roles it was granted, so it can
be limited to read-only access to one realm.

```shell
mql shell keycloak --url https://keycloak.example.com --realm production \
  --client-id mondoo-scanner --client-secret SECRET
```

> To create the service account, add a client in the realm, disable the standard
> flow, enable **Client authentication** and **Service accounts roles**, then
> assign the `realm-management` roles `view-realm`, `view-users`,
> `view-clients`, `view-identity-providers` and `view-authorization` to its
> service account.

Arguments:

- `--url` - base URL of the server, for example `https://keycloak.example.com`.
  A server installed under a context path keeps that path, for example
  `https://keycloak.example.com/auth`.
- `--realm` - scope the scan to one realm. Without it, every realm the
  credentials can read is in scope.
- `--auth-realm` - realm the token is requested from. It defaults to `master`
  for a user, and to the scanned realm for a service account.
- `--client-id` - client the token is requested for. It defaults to `admin-cli`
  for a user.
- `--client-secret` - secret of a confidential client, which selects service
  account authentication.
- `--username` and `--password` - admin user, which selects password
  authentication.
- `--ca-cert` - certificate authority to trust for the server certificate,
  either the PEM itself or a path to it. A Keycloak server is commonly
  published under a private authority. Trusting that authority keeps the
  certificate verified, which skipping verification would not. It applies to
  the token endpoint as well as the admin API.

`KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_AUTH_REALM`, `KEYCLOAK_CLIENT_ID`,
`KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_CA_CERT`, `KEYCLOAK_USERNAME` and `KEYCLOAK_PASSWORD` supply the
same values as the flags.

Keycloak access tokens are short lived, one minute on a stock install. The
provider renews the token with its refresh token during a scan, and falls back
to the configured credentials when the refresh is rejected.

## Usage

Open an interactive shell:

```shell
mql shell keycloak --url https://keycloak.example.com --username admin --password PASSWORD
```

## Discovery

Connecting without `--realm` makes the connection a discovery root. It emits one
asset per realm the credentials can read:

- **`keycloak-realm`** - a realm, identified by the server host and the realm
  name, since a realm name is only unique within one server.

```shell
mql scan keycloak --url https://keycloak.example.com --username admin --password PASSWORD --discover realms
```

Passing `--realm` scans that realm as a single asset and emits no child assets.

Assets land under `technology=saas/provider=keycloak/host=<host>/realm=<realm>`.

## Examples

**Select one realm or client directly**

A realm is selected by name and a client by its client id, so a policy does not
have to filter the whole list.

```shell
mql> keycloak.realm(name: "production") { sslRequired bruteForceProtected }
mql> keycloak.client(clientId: "kubernetes") { publicClient redirectUris }
```

A client id is only unique within a realm. When the same id exists in more than
one realm, the lookup reports the realms it found rather than picking one, so
scope the connection with `--realm`.

**Find a full authentication bypass**

A public client accepts an authorization code without proving who it is, and a
wildcard redirect URI lets whoever controls a matching URL collect that code.
Together they are a full authentication bypass for every user of the realm.

```shell
mql> keycloak.clients.where(enabled && publicClient && hasWildcardRedirectUri) { clientId realm.name wildcardRedirectUris }
```

**Find every wildcard redirect URI**

```shell
mql> keycloak.clients.where(hasWildcardRedirectUri) { clientId wildcardRedirectUris publicClient }
```

**Find clients that skip PKCE**

Without a proof key, an intercepted authorization code can be redeemed by
whoever holds it.

```shell
mql> keycloak.clients.where(publicClient && standardFlowEnabled && pkceCodeChallengeMethod != "S256") { clientId }
```

**Find realms that do not require TLS**

```shell
mql> keycloak.realms.where(sslRequired != "all") { name sslRequired }
```

**Find realms without brute force detection**

```shell
mql> keycloak.realms.where(bruteForceProtected == false) { name passwordPolicy }
```

**Assert one password policy rule**

The policy string is parsed into its named rules, so a rule can be asserted on
without parsing the string.

```shell
mql> keycloak.realms { name passwordPolicyRules["length"] passwordPolicyRules["digits"] }
```

**Find realms that allow self-registration**

```shell
mql> keycloak.realms.where(registrationAllowed) { name verifyEmail defaultGroups }
```

**Find long-lived sessions**

A revoked user keeps a working session until the maximum lifespan closes.

```shell
mql> keycloak.realms.where(ssoSessionMaxLifespan > 36000) { name ssoSessionMaxLifespan accessTokenLifespan }
```

**Find a missing second factor**

A browser flow whose only credential step is a password, with no required or
conditional one-time password step, accepts a single factor.

```shell
mql> keycloak.realms { name browserFlowRef { alias executions { displayName requirement providerId } } }
```

**Find a realm that offers a second factor without requiring it**

```shell
mql> keycloak.realms { name requiredActions.where(alias == "CONFIGURE_TOTP") { enabled defaultAction } }
```

**Find groups that make every member an administrator**

A client role is as capable as a realm role, and the realm-management ones
administer the realm.

```shell
mql> keycloak.realms.first.groups { path clientRoleMappings.where(name == "realm-admin") { name } }
```

**Find service accounts that administer a realm**

A service account authenticates with the client's secret, and no second factor
applies to it. One that holds an administration role turns a leaked secret into
full control of the realm.

```shell
mql> keycloak.clients.where(serviceAccountsEnabled) { clientId serviceAccountUser { username hasAdminRole } }
```

**Find identity providers that trust an unverified assertion**

```shell
mql> keycloak.realms { name identityProviders.where(enabled && validateSignature == false) { alias providerId } }
```

**Find an unencrypted LDAP federation**

An unencrypted federation sends the bind credentials and every validated
password in the clear.

```shell
mql> keycloak.realms { name components.where(isUserFederation && connectionEncrypted == false) { name connectionUrl startTls } }
```

**Find a mapper that widens a token's audience**

An audience mapper lets a token issued for one client be accepted by another,
so it moves trust between applications.

```shell
mql> keycloak.clientScopes.where(protocolMappers.any(mapperType == "oidc-audience-mapper")) { name protocolMappers { name includedClientAudience } }
```

**Find scopes attached to every client**

A mapper added to a realm default scope reaches every client, including ones
that never asked for it.

```shell
mql> keycloak.realms.first.clientScopes.where(isRealmDefault) { name protocolMappers { name claimName addToAccessToken } }
```

**Find mappers that copy a user attribute into a token**

```shell
mql> keycloak.clientScopes { name protocolMappers.where(userAttribute != "") { name userAttribute claimName addToAccessToken } }
```

**Find the roles a client's token may carry**

With the full scope off, the scope mappings are what bound a compromised
client.

```shell
mql> keycloak.clients.where(fullScopeAllowed == false) { clientId scopeMappings { name clientRole } }
```

**Find clients that carry every role of the user**

```shell
mql> keycloak.clients.where(enabled && fullScopeAllowed) { clientId }
```

**Find a realm that signs tokens with a shared secret**

An HS256 signing key is shared with every client that validates it, so any one
of them can forge a token for the rest.

```shell
mql> keycloak.realms { name keys.where(isActive && use == "SIG" && algorithm == "HS256") { kid algorithm } }
```

**Find realms that record no administrative changes**

Without admin events, a change to a client's redirect URIs leaves no trace an
audit can read back.

```shell
mql> keycloak.realms.where(eventsConfig.adminEventsEnabled == false) { name }
```

**Find realms that drop login failures**

A realm that records LOGIN but not LOGIN_ERROR keeps no trace of a password
guessing run.

```shell
mql> keycloak.realms { name eventsConfig { eventsEnabled enabledEventTypes.contains("LOGIN_ERROR") eventsListeners } }
```

**Find client policies that enforce nothing**

A policy that is disabled, or that names no profile, is inert.

```shell
mql> keycloak.realms.first.clientPolicies.where(enabled == false || profiles.length == 0) { name enabled profiles }
```

**Find a permissive authorization server**

With PERMISSIVE, a request for a resource that no policy covers is allowed, so
adding a resource without a policy grants it to everyone.

```shell
mql> keycloak.clients.where(authorizationServicesEnabled) { clientId authorizationSettings { policyEnforcementMode decisionStrategy } }
```

**Find a conditional second factor set to skip**

A step set to skip demands no second factor, which the requirement alone does
not reveal.

```shell
mql> keycloak.realms.first.browserFlowRef.executions.where(authenticationConfig != "") { displayName requirement config }
```

**Follow a composite role**

A role named after a team commonly carries `realm-admin` without saying so.

```shell
mql> keycloak.realms.first.roles.where(composite) { name composites { name clientRole client.clientId } }
```

## Resources

The root resource is `keycloak`. It carries `realms`, and `clients` flattens
every client across the realms in scope. A realm carries its `clients`, `roles`,
`groups`, `users`, `identityProviders`, `authenticationFlows`, `components`,
`clientScopes`, `keys`, `eventsConfig`, `clientProfiles`, `clientPolicies` and
`requiredActions`. A client scope carries its
`protocolMappers`, which is where a token's claims come from. The full field reference is generated from the schema
comments in `resources/keycloak.lr`.

## Verification

Confirm the connection and the permissions:

```shell
mql> keycloak.realms { name enabled }
mql> keycloak.realms.first.clients.length
```

An empty realm list means the credentials cannot enumerate realms. Scope the
scan with `--realm` when the account only holds the view roles of one realm.

## Troubleshooting

**`keycloak API /admin/realms: 403`** - the account is authenticated but holds
no view role for the resource. Grant the `realm-management` view roles, or scope
the scan to the realm the account can read.

**`keycloak token request: 401 (Invalid client credentials)`** - the client
secret is wrong, or the client is public and therefore has none. Enable **Client
authentication** on the client.

**`keycloak token request: 401 (Invalid user credentials)`** - the user lives in
another realm than the one the token is requested from. Pass `--auth-realm` with
the realm the account belongs to.

**An empty `users` list on a large realm** - the account holds `view-realm` but
not `view-users`.
