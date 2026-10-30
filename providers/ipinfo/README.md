# IPinfo Provider

## Authentication

For authentication, you can use the `IPINFO_TOKEN` environment variable.

```shell
export IPINFO_TOKEN="<token>"
```

## Usage

```shell
mql shell ipinfo
```

## Examples

**Query IP information**

Query information for a specific IP address.

```shell
mql> ipinfo(ip("8.8.8.8")) { * }
ipinfo: {
  requested_ip: "8.8.8.8"
  returned_ip: "8.8.8.8"
  hostname: "dns.google"
  bogon: false
}
```

**Query your public IP**

Query information for your machine's public IP address.

```shell
mql> ipinfo() { * }
ipinfo: {
  requested_ip: null
  returned_ip: "<your-public-ip>"
  hostname: "<hostname>"
  bogon: false
}
```

**Query IP information from network interfaces**

Query IP information for all IPs from network interfaces.

```shell
mql run -c "network.interfaces.map(ips.map(_.ip)).flat.map(ipinfo(_){*})"
network.interfaces.map.flat.map: [
  0: {
    returned_ip: 127.0.0.1
    hostname: ""
    bogon: true
    requested_ip: 127.0.0.1
  }
  ......

```
