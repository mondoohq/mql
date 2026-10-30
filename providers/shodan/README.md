# Shodan Provider

## Authentication

For authentication, you can use the `SHODAN_TOKEN` environment variable.

```shell
export SHODAN_TOKEN="<token>"
```

## Usage

```shell
mql shell shodan
```

## Examples

**Host information**

Query the base information for a host by IP address.

```shell
mql> shodan.host("8.8.8.8") { * }
shodan.host: {
  tags: []
  hostnames: [
    0: "dns.google"
  ]
  org: "Google LLC"
  asn: "AS15169"
  ip: "8.8.8.8"
  isp: "Google LLC"
  vulnerabilities: null
  os: null
  ports: [
    0: 443
    1: 53
  ]
}
```

**Display the hostname for a host**

Query the hostname for a host.

```shell
mql> shodan.host("8.8.8.8").hostnames
shodan.host.hostnames: [
  0: "dns.google"
]
```

**Open ports for a host**

Display all open ports for a host.

```shell
mql> shodan.host("8.8.8.8").ports
shodan.host.ports: [
  0: 443
  1: 53
]
```

**DNS Lookup**

Query the DNS information for a domain.

```shell
mql> shodan.domain("example.com") { * }
shodan.domain: {
  name: "example.com"
  nsrecords: [
    0: shodan.nsrecord domain="example.com" subdomain="" type="A"
    1: shodan.nsrecord domain="example.com" subdomain="" type="AAAA"
    2: shodan.nsrecord domain="example.com" subdomain="" type="MX"
    3: shodan.nsrecord domain="example.com" subdomain="" type="NS"
    4: shodan.nsrecord domain="example.com" subdomain="" type="NS"
    5: shodan.nsrecord domain="example.com" subdomain="" type="SOA"
    6: shodan.nsrecord domain="example.com" subdomain="" type="TXT"
    7: shodan.nsrecord domain="example.com" subdomain="" type="TXT"
    8: shodan.nsrecord domain="example.com" subdomain="www" type="A"
    9: shodan.nsrecord domain="example.com" subdomain="www" type="AAAA"
    10: shodan.nsrecord domain="example.com" subdomain="www" type="TXT"
    11: shodan.nsrecord domain="example.com" subdomain="www" type="TXT"
  ]
  tags: [
    0: "ipv6"
    1: "spf"
  ]
  subdomains: [
    0: "www"
  ]
}
```

**Get all DNS NS records**

Query the DNS NS records for a domain.

```shell
mql> shodan.domain("example.com").nsrecords.where(type == "NS") { subdomain  type value }
shodan.domain.nsrecords.where: [
  0: {
    type: "NS"
    subdomain: ""
    value: "a.iana-servers.net"
  }
  1: {
    type: "NS"
    subdomain: ""
    value: "b.iana-servers.net"
  }
]
```

**Find all AAAA records for a subdomain**

Query the DNS AAAA records for  the "www" subdomain.

```shell
mql> shodan.domain("example.com").nsrecords.where(type == "AAAA").where(subdomain == "www") { subdomain  type value }
shodan.domain.nsrecords.where.where: [
  0: {
    subdomain: "www"
    value: "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
    type: "AAAA"
  }
]
```

## Advanced Usage

Discover all exposed hosts on a network.

```shell
mql shell shodan --networks "192.168.0.0/20" --discover hosts
```

Connect to a specific IP address and display all open ports.

```shell
mql shell shodan host 8.8.8.8
```

Connect to a domain and display subdomains.

```shell
mql shell shodan domain example.com
```