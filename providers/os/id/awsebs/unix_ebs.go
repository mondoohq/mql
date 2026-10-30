// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsebs

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/id/hostname"
)

// Compiled once: applied to every line of the metadata and lsblk output.
var (
	ipv4PublicRE = regexp.MustCompile(`meta-data/network/interfaces/macs/([0-9a-f:]+)/ipv4-associations/([0-9.]+)`)
	ipRegex      = regexp.MustCompile(`\|\s+(\w+)\s+\|\s+True\s+\|\s+([^\s]+)\s+\|\s+([^\s]+)\s+\|[^\|]+\|\s+([^\s]+)\s+\|`)
)

func (m *ebsMetadata) unixMetadata() (any, error) {
	mdata := map[string]any{}

	instanceID, ok := m.getInstanceID()
	if ok {
		mdata["instance-id"] = instanceID
	}

	region, ok := m.getRegion()
	if ok {
		mdata["region"] = region
	}

	if privateHostname, ok := hostname.Hostname(m.conn, m.platform); ok {
		mdata["hostname"] = privateHostname
	} else {
		// we are looking for something similar to:
		//
		// {
		// "fqdn": "ip-172-31-22-246.ec2.internal",
		// "hostname": "ip-172-31-22-246"
		// }
		setHostnameData, err := afero.ReadFile(m.conn.FileSystem(), "/var/lib/cloud/data/set-hostname")
		if err == nil {
			var setHostname struct {
				FQDN     string `json:"fqdn"`
				Hostname string `json:"hostname"`
			}
			if err := json.Unmarshal(setHostnameData, &setHostname); err == nil {
				mdata["hostname"] = setHostname.FQDN
			}
		}
	}

	if interfaces, ok := m.getUnixNetworkInterfaces(); ok {
		mdata["network"] = map[string]any{"interfaces": interfaces}
	}

	return mdata, nil
}

func (m *ebsMetadata) getUnixNetworkInterfaces() (any, bool) {
	macs := map[string]*macDetails{}
	detected := false

	cloudInitLog, err := afero.ReadFile(m.conn.FileSystem(), "/var/log/cloud-init.log")
	if err != nil {
		log.Debug().Err(err).Msg("unable to read cloud-init log")
	} else {
		// Detect public IP from the cloud-init.log file - we are searching for something similar to this line:
		//
		// 'http://169.254.169.254:80/2021-03-23/meta-data/network/interfaces/macs/0a:ff:ed:34:f3:6d/ipv4-associations/54.146.163.122'
		//
		for line := range strings.SplitSeq(string(cloudInitLog), "\n") {
			if matches := ipv4PublicRE.FindStringSubmatch(line); len(matches) == 3 {
				// check if we have already detected that MAC address
				if md, exist := macs[matches[1]]; !exist {
					detected = true
					macs[matches[1]] = &macDetails{
						PublicIPv4s: matches[2],
						MAC:         matches[1],
					}
				} else {
					log.Debug().Msg("updating public ipv4")
					md.PublicIPv4s = matches[2]
				}
			}
		}
	}

	cloudInitOutputLog, err := afero.ReadFile(m.conn.FileSystem(), "/var/log/cloud-init-output.log")
	if err != nil {
		log.Debug().Err(err).Msg("unable to read cloud-init log")
	} else {
		// [root@ip-172-31-17-10 ~]# cat /tmp/cnspec-scan869474293/var/log/cloud-init-output.log
		// Cloud-init v. 22.2.2 running 'init' at Tue, 17 Sep 2024 18:59:35 +0000. Up 7.11 seconds.
		// ci-info: ++++++++++++++++++++++++++++++++++++++Net device info++++++++++++++++++++++++++++++++++++++
		// ci-info: +--------+------+----------------------------+---------------+--------+-------------------+
		// ci-info: | Device |  Up  |          Address           |      Mask     | Scope  |     Hw-Address    |
		// ci-info: +--------+------+----------------------------+---------------+--------+-------------------+
		// ci-info: |  enX0  | True |       172.31.35.121        | 255.255.240.0 | global | 0e:65:05:67:e6:01 |
		// ci-info: |  enX0  | True | fe80::c65:5ff:fe67:e601/64 |       .       |  link  | 0e:65:05:67:e6:01 |
		// ci-info: |   lo   | True |         127.0.0.1          |   255.0.0.0   |  host  |         .         |
		// ci-info: |   lo   | True |          ::1/128           |       .       |  host  |         .         |
		// ci-info: +--------+------+----------------------------+---------------+--------+-------------------+
		// ci-info: ++++++++++++++++++++++++++++++Route IPv4 info++++++++++++++++++++++++++++++
		// ci-info: +-------+-------------+-------------+-----------------+-----------+-------+
		// ci-info: | Route | Destination |   Gateway   |     Genmask     | Interface | Flags |
		// ci-info: +-------+-------------+-------------+-----------------+-----------+-------+
		// ci-info: |   0   |   0.0.0.0   | 172.31.32.1 |     0.0.0.0     |    enX0   |   UG  |
		// ci-info: |   1   |  172.31.0.2 | 172.31.32.1 | 255.255.255.255 |    enX0   |  UGH  |
		// ci-info: |   2   | 172.31.32.0 |   0.0.0.0   |  255.255.240.0  |    enX0   |   U   |
		// ci-info: |   3   | 172.31.32.1 |   0.0.0.0   | 255.255.255.255 |    enX0   |   UH  |
		// ci-info: +-------+-------------+-------------+-----------------+-----------+-------+
		// ci-info: +++++++++++++++++++Route IPv6 info+++++++++++++++++++
		// ci-info: +-------+-------------+---------+-----------+-------+
		// ci-info: | Route | Destination | Gateway | Interface | Flags |
		// ci-info: +-------+-------------+---------+-----------+-------+
		// ci-info: |   0   |  fe80::/64  |    ::   |    enX0   |   U   |
		// ci-info: |   2   |    local    |    ::   |    enX0   |   U   |
		// ci-info: |   3   |  multicast  |    ::   |    enX0   |   U   |
		// ci-info: +-------+-------------+---------+-----------+-------+
		for line := range strings.SplitSeq(string(cloudInitOutputLog), "\n") {
			matches := ipRegex.FindStringSubmatch(line)
			if len(matches) == 5 {
				// match[3] is the mask, we don't use it at the moment
				iface, ip, _, mac := matches[1], matches[2], matches[3], matches[4]
				if mac == "." {
					continue
				}
				ip = strings.Split(ip, "/")[0] // remove CIDR if present
				netIP := net.ParseIP(ip)
				if netIP == nil || netIP.To4() == nil {
					continue // not an ipv4
				}

				detected = true
				if md, exists := macs[mac]; !exists {
					macs[mac] = &macDetails{InterfaceID: iface, MAC: mac, LocalIPv4s: ip}
				} else {
					log.Debug().Str("old", md.LocalIPv4s).Str("new", ip).Msg("updating local ipv4")
					md.InterfaceID = iface
					md.LocalIPv4s = ip
				}
			}
		}
	}

	return map[string]any{"macs": macs}, detected
}
