// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"slices"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// detectAixInterfaces detects network interfaces on AIX. ifconfig -a lists
// the addresses in the BSD layout but no MTU and no MAC address, which the
// link rows of netstat -in carry; the default gateways come from
// netstat -rn as on BSD.
func (n *neti) detectAixInterfaces() ([]Interface, error) {
	detectors := []func() ([]Interface, error){
		n.getBSDIfconfigInterfaces,
		n.getAixNetstatLinks,
		n.getBSDGatewayDetails,
	}

	var errs []error
	interfaces := []Interface{}
	for _, detectFn := range detectors {
		detected, err := detectFn()
		if err != nil {
			log.Debug().Err(err).Msg("os.network.interface> unable to detect network interfaces")
			errs = append(errs, err)
			continue
		}
		interfaces = AddOrUpdateInterfaces(interfaces, detected)
	}

	// AIX ifconfig has no status line; an interface is up and has its
	// resources when it is RUNNING.
	for i := range interfaces {
		if interfaces[i].Active == nil && interfaces[i].Flags != nil {
			interfaces[i].Active = convert.ToPtr(slices.Contains(interfaces[i].Flags, "RUNNING"))
		}
	}

	if len(interfaces) == 0 {
		return interfaces, errors.Join(errs...)
	}
	return interfaces, nil
}

func (n *neti) getAixNetstatLinks() ([]Interface, error) {
	output, err := n.RunCommand("netstat -in")
	if err != nil {
		return nil, err
	}
	return parseAixNetstatLinks(output), nil
}

// parseAixNetstatLinks reads the link rows of AIX `netstat -in`:
//
//	Name   Mtu   Network     Address                 Ipkts     Ierrs ...
//	en0    1450  link#2      fa.16.3e.5b.8a.c5             7558     0 ...
//	en0    1450  192.168.234 192.168.234.35               7558     0 ...
//	lo0    16896 link#1                                    245     0 ...
//
// The MAC address is dot-separated and drops leading zeros (82.de.e.65.c.1a);
// the link row of the loopback has none.
func parseAixNetstatLinks(output string) []Interface {
	var interfaces []Interface
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !strings.HasPrefix(fields[2], "link#") {
			continue
		}
		mtu, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		iface := Interface{Name: fields[0], MTU: mtu}
		iface.SetMAC(parseAixMAC(fields[3]))
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

// parseAixMAC turns a dot-separated MAC address whose octets drop their
// leading zero into the colon form. Anything else, such as the packet
// counter in the address column of a loopback row, is no address.
func parseAixMAC(s string) string {
	octets := strings.Split(s, ".")
	if len(octets) != 6 {
		return ""
	}
	for i, o := range octets {
		if len(o) == 0 || len(o) > 2 {
			return ""
		}
		if _, err := strconv.ParseUint(o, 16, 8); err != nil {
			return ""
		}
		if len(o) == 1 {
			octets[i] = "0" + o
		}
	}
	return strings.ToLower(strings.Join(octets, ":"))
}
