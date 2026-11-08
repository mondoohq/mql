# Talos Linux Provider

The `talos` provider connects to a Talos Linux node through the Talos API, as `talosctl` does, and inventories it through read-only calls. It exposes the Talos version, the kernel parameters, the machine configuration with its secrets removed, and any resource the Talos API serves (security state, time servers, admission control, volumes, firewall chains and more), so you can audit a node that has no shell or SSH.

## Prerequisites

The provider talks to the Talos API (port 50000) of the node, directly or through an endpoint such as a control plane node.

The role of the talosconfig decides what the provider can report:

| Reads | Needs |
| --- | --- |
| version, kernel parameters Talos manages, non-sensitive resources | `os:reader` |
| kernel parameters Talos doesn't manage (read from `/proc/sys`) | `os:admin` |
| the machine configuration and other sensitive resources | `os:admin` |

A read-only talosconfig, created with an admin one:

```shell
talosctl config new --roles os:reader reader.talosconfig
```

A field the role may not read reports an error naming `os:admin`, never an empty answer. The machine configuration is returned with Talos's own secret redaction applied: every key, certificate key and token is empty.

## Authentication

Arguments:

- `[node]` or `--node` - the node to query (default the context's first node).
- `--talosconfig` - the talosconfig file (default `TALOSCONFIG`, else `~/.talos/config`).
- `--context` - the talosconfig context to use instead of the current one.
- `--endpoints` - comma-separated endpoints that replace the context's endpoints.

```shell
mql shell talos 10.5.0.2 --talosconfig reader.talosconfig
```

Through an endpoint, with a named context:

```shell
mql shell talos --context prod --endpoints 192.0.2.10 --node 192.0.2.21
```

## Usage

```shell
mql shell talos 10.5.0.2 --talosconfig reader.talosconfig
cnspec scan talos 10.5.0.2 --talosconfig reader.talosconfig
```

Each node is one asset, identified by its Talos node identity, which survives reboots. The asset's platform is `talos` with the runtime `talos`. The os provider also names a Talos image or disk `talos`, with a different runtime, so a policy for the Talos API selects `asset.platform == "talos" && asset.runtime == "talos"`.

## Examples

**Talos version**

```shell
mql> talos.version { tag arch }
version: {
  tag: "v1.14.5"
  arch: "arm64"
}
```

**Kernel parameters Talos manages**, with their current and kernel default values:

```shell
mql> talos.kernelParameters.where(key == /redirects/) { key current default }
kernelParameters.where: [
  0: {
    default: "1"
    current: "0"
    key: "net.ipv4.conf.all.send_redirects"
  }
  1: {
    default: "1"
    current: "0"
    key: "net.ipv4.conf.default.send_redirects"
  }
]
```

**Any kernel parameter.** One Talos doesn't manage is read from `/proc/sys`, which needs `os:admin`:

```shell
mql> talos.kernelParameter(key: "net.ipv4.tcp_syncookies") { current source }
talos.kernelParameter: {
  current: "1"
  source: "proc"
}
```

**Any Talos API resource**, by its type or alias as `talosctl get` accepts it:

```shell
mql> talos.resources(type: "timeserverstatus").list { spec }
talos.resources.list: [
  0: {
    spec: {
      timeServers: [
        0: "time.cloudflare.com"
      ]
      useNTS: true
    }
  }
]
```

**The Pod Security Standards level the API server enforces by default:**

```shell
mql> talos.resources(type: "admissioncontrolconfig").list[0].spec["config"][0]["configuration"]["defaults"]["enforce"]
talos.resources.list[0].spec.config[0].configuration.defaults.enforce: "baseline"
```

**The machine configuration documents** (`os:admin`):

```shell
mql> talos.machineConfig.where(_["kind"] == "KubeAPIServerConfig").length
machineConfig.where.length: 1
```

## Verification

`talos.version` confirms the connection. `talos.machineConfig` tells the role apart: it returns the documents with `os:admin`, and with `os:reader` the error `the Talos API serves this only to the os:admin role`.

## Testing

The integration tests run against a live node, such as a local cluster:

```shell
talosctl cluster create docker --name talos-test --workers 0 --talosconfig-destination ./talosconfig
talosctl --talosconfig ./talosconfig -n 10.5.0.2 config new --roles os:reader ./reader.talosconfig
TALOS_TEST_NODE=10.5.0.2 TALOS_TEST_TALOSCONFIG=$PWD/talosconfig TALOS_TEST_READER_TALOSCONFIG=$PWD/reader.talosconfig \
  go test ./resources/ -run Integration
talosctl cluster destroy --name talos-test
```

## Troubleshooting

- `the Talos API serves this only to the os:admin role` - the talosconfig has a role without access to that call: the machine configuration, a sensitive resource, or a kernel parameter Talos doesn't manage.
- `no node to connect to` - pass the node, or set `nodes` or `endpoints` in the talosconfig context.
