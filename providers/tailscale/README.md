# Tailscale Provider

Use the tailscale provider to query devices, users, DNS namespaces, and more information about a Tailscale network,
known as a `tailnet`.

## Authentication

To authenticate using an API access token:

```
mql shell tailscale --token <access-token>
```

To authenticate using an OAuth client:

```
mql shell tailscale --client-id <id> --client-secret <secret>
```

You can also use the default environment variables `TAILSCALE_OAUTH_CLIENT_ID`, `TAILSCALE_OAUTH_CLIENT_SECRET`,
and `TAILSCALE_TAILNET` to provide your credentials.

If you are using an API access token instead of an OAuth client, use the `TAILSCALE_API_KEY` variable instead.

## Examples

**List all devices in a tailnet**

```shell
mql> tailscale.devices()
```

**Get information on a single device**

```shell
mql> tailscale.device(id: "55161288425123456") {*}
tailscale.device: {
  id: "55161288425123456"
  isExternal: false
  os: "linux"
  created: 2021-06-25 12:34:34 -0700 PDT
  updateAvailable: true
  nodeKey: "nodekey:abc123"
  lastSeen: 2024-03-25 08:01:04 -0700 PDT
  user: "afiune@mondoo.com"
  hostname: "raspberrypi"
  clientVersion: "1.10.0-t766ae6c10-g3e6822772"
  authorized: true
  blocksIncomingConnections: false
  addresses: [
    0: "100.71.181.41"
    1: "abc1:abc1:a1e0:ab12:abc1:cd96:abc1:bf33"
  ]
  keyExpiryDisabled: true
  expires: 2022-08-02 18:55:39 -0700 PDT
  name: "raspberrypi.tail1a4a6.ts.net"
  machineKey: "mkey:abc123"
  tailnetLockKey: ""
  tailnetLockError: ""
}
```

**List all users in a tailnet**

```shell
mql> tailscale.users()
```

**Get information on a single user**

```shell
mql> tailscale.user(id: "uiR4AD141DAA") {*}
tailscale.user: {
  id: "uiR4AD141DAA"
  type: "member"
  deviceCount: 64
  createdAt: 2021-06-24 11:17:02.151878675 -0700 PDT
  loginName: "afiune@mondoo.com"
  status: "active"
  lastSeenAt: 2025-02-18 13:56:23.715800061 -0800 PST
  tailnetId: "12345678900012344"
  profilePicUrl: "https://lh3.googleusercontent.com/a/ACg8ocKPxpFdO4al-Si9YXhJz_iN9qnZ-8h5UorbQrKWxrS-uPutP6E=s96-c"
  role: "owner"
  displayName: "Salim Afiune Maya"
}
```

## Advanced Usage

**Discover all devices (any computer or mobile device) that join the tailnet `example.com`**

```shell
mql shell tailscale example.com --discover devices
```
