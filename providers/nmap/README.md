# Nmap Provider

Nmap, short for Network Mapper, is a powerful and versatile open-source tool used for network discovery and security auditing. This tool is widely utilized by network administrators, security professionals, and penetration testers to map out network structures, discover hosts, identify services, and detect vulnerabilities.

The nmap provider maps primary objects and attributes that nmap uses to store and manage information about scanned targets, discovered hosts, and their associated ports and services.

## Prerequisites

This provider requires the Nmap tool to be installed on your system. You can download and install Nmap from the official [website](https://nmap.org/download.html).

## Usage

```shell
mql shell nmap
```

## Examples

*Scan active IP address in network*

```shell
nmap.network("192.168.178.0/24").hosts { name ports { * }  }
nmap.network.hosts: [
  0: {
    ports: [
      0: {
        service: "http"
        version: ""
        method: "probed"
        state: "open"
        protocol: "tcp"
        port: 443
        product: "FRITZ!Box http config"
      }
      1: {
        service: "sip"
        version: ""
        method: "probed"
        state: "open"
        protocol: "tcp"
        port: 5060
        product: "AVM FRITZ!OS SIP"
      }
    ]
    name: "192.168.178.1"
  }
  1: {
    ports: [
      0: {
        service: "rtsp"
        version: "770.8.1"
        method: "probed"
        state: "open"
        protocol: "tcp"
        port: 5000
        product: "AirTunes rtspd"
      }
      1: {
        service: "rtsp"
        version: "770.8.1"
        method: "probed"
        state: "open"
        protocol: "tcp"
        port: 7000
        product: "AirTunes rtspd"
      }
    ]
    name: "192.168.178.25"
  }
]
```

*Host scan with specific ip*

```shell
nmap.network(target: "192.168.178.25").hosts { ports }
nmap.network.hosts: [
  0: {
    ports: [
      0: nmap.port port=5000 service="rtsp"
      1: nmap.port port=7000 service="rtsp"
    ]
  }
]
```

## Advanced Usage

Discover all exposed hosts on a network.

```shell
mql shell nmap --networks "192.168.0.0/20" --discover hosts
```

Connect to a specific IP address and display all open ports.

```shell
mql shell nmap host 8.8.8.8
```

## Verification

To verify the installation of nmap, run the following command:

```shell
mql run nmap -c "nmap.version { * }"
nmap.version: {
  compiledWithout: []
  nsockEngines: [
    0: "kqueue"
    1: "poll"
    2: "select"
  ]
  version: "7.95"
  platform: "arm-apple-darwin23.4.0"
  compiledWith: [
    0: "liblua-5.4.6"
    1: "openssl-3.3.1"
    2: "libssh2-1.11.0"
    3: "libz-1.2.12"
    4: "libpcre2-10.44"
    5: "nmap-libpcap-1.10.4"
    6: "nmap-libdnet-1.12"
    7: "ipv6"
  ]
}
```

## Inventory Yaml

```yaml
spec:
  assets:
    - name: "Web Server Scan"
      connections:
        - type: nmap
          host: 192.168.1.1
          options:
            ports: "22,80,443"
```