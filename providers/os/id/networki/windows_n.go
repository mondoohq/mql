// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// Compiled once: the header pattern is matched against every line of ipconfig
// output, and the suffix pattern against every address it reports.
var (
	interfaceHeaderRegex = regexp.MustCompile(`^(Ethernet|Wireless|Bluetooth|VPN|Local Area Connection|Wi-Fi|Cellular|Tunnel) adapter (.+):$`)
	ipSuffixRegex        = regexp.MustCompile(`\(.*?\)$`)
)

// detectWindowsInterfaces detects network interfaces on Windows.
func (n *neti) detectWindowsInterfaces() ([]Interface, error) {
	var errs []error
	interfaces := []Interface{}

	// List of detectors that collect network interfaces, we stop executing them as
	// soon as one of them succeeds collecting all the information
	detectors := []func() ([]Interface, error){
		n.getWindowsGetNetIPInterfaceCmdInterfaces,
		n.getWindowsIpconfigCmdInterfaces,
	}

	for _, detectFn := range detectors {
		detectedInterfaces, err := detectFn()
		if err == nil && len(detectedInterfaces) != 0 {
			interfaces = AddOrUpdateInterfaces(interfaces, detectedInterfaces)
			break
		}
		log.Debug().Err(err).
			Msg("os.network.interface> unable to detect network interfaces")
		errs = append(errs, err)
	}

	if len(interfaces) == 0 {
		return interfaces, errors.Join(errs...)
	}

	return interfaces, nil
}

func (n *neti) getWindowsGetNetIPInterfaceCmdInterfaces() (interfaces []Interface, err error) {
	cmd := `
  Get-NetIPInterface | 
    Select-Object InterfaceIndex, InterfaceAlias, NlMtu, ConnectionState, AddressFamily,
    @{ Name='MacAddress'; Expression={ (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).MacAddress } },
    @{ Name='IPAddresses'; Expression={
      (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex) |
      Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength |
      ConvertTo-Json
    } },
    @{ Name='DefaultGateway'; Expression={
      (Get-NetRoute -InterfaceIndex $_.InterfaceIndex | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' }) |
      Select-Object -ExpandProperty NextHop -ErrorAction SilentlyContinue
    } },
    @{ Name='Virtual'; Expression={ (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).Virtual } } |
    ConvertTo-Json
	`
	output, err := n.RunCommand(cmd)
	if err != nil {
		return nil, err
	}

	netInterfaces, err := unmarshalPowershellObjects(output)
	if err != nil {
		return nil, err
	}

	log.Trace().Interface("output", netInterfaces).Msg("os.network.interface> net interface cmd")

	for _, adapter := range netInterfaces {
		name, ok := adapter["InterfaceAlias"].(string)
		if !ok {
			// The alias is the only key we have for an adapter, so one without
			// it cannot be represented. Log the skip so a shorter list is
			// attributable instead of silent.
			log.Warn().
				Interface("interface_index", adapter["InterfaceIndex"]).
				Str("detector", "cmd.Get-NetIPInterface").
				Msg("os.network.interface> skipping adapter without an interface alias")
			continue
		}
		iinterface := Interface{
			Name: name,
		}

		// Get MAC address
		if value, ok := adapter["MacAddress"].(string); ok {
			iinterface.SetMAC(value)
		}

		// Get MTU
		if value, ok := adapter["NlMtu"].(float64); ok {
			iinterface.MTU = int(value)
		}

		// Get Status
		if state, ok := adapter["ConnectionState"].(float64); ok {
			active := true
			if state == 0 {
				active = false
			}
			iinterface.Active = &active
		}

		// Detect virtual interface
		if virtual, ok := adapter["Virtual"].(bool); ok {
			iinterface.Virtual = &virtual
		}

		// Get default gateway
		if value, ok := adapter["DefaultGateway"].(string); ok {
			iinterface.enrichments = func(in *Interface) {
				// IPv4 (default)
				gatewayVersion := IPv4
				if strings.Contains(value, ":") {
					// IPv6
					gatewayVersion = IPv6
				}
				for i := range in.IPAddresses {
					if version, ok := in.IPAddresses[i].Version(); ok && version == gatewayVersion {
						in.IPAddresses[i].Gateway = value
					}
				}
			}
		}

		// Get IP Addresses (v4 or v6) in JSON format
		if data, ok := adapter["IPAddresses"].(string); ok {
			// This error stays local: one undecodable address list must not
			// discard every adapter the detector already parsed.
			ipaddresses, ipErr := unmarshalPowershellObjects(data)
			if ipErr != nil {
				log.Debug().Err(ipErr).
					Str("data", data).
					Str("detector", "cmd.Get-NetIPInterface").
					Msg("os.network.interface> unable to detect IPAddresses")
			}

			var (
				ipaddress IPAddress
				valid     bool
			)
			for _, ipMap := range ipaddresses {
				if ip, ok := ipMap["IPAddress"].(string); ok {
					ip = cleanIPString(ip)
					// Get the prefix length
					if prefixLength, ok := ipMap["PrefixLength"].(float64); ok {
						ipaddress, valid = NewIPWithPrefixLength(ip, int(prefixLength))
					} else {
						// No prefix, plain ip address
						ipaddress, valid = NewIPAddress(ip)
					}

					if valid {
						iinterface.AddOrUpdateIP(ipaddress)
					}
				}
			}
		}

		interfaces = append(interfaces, iinterface)
	}

	return
}

func (n *neti) getWindowsIpconfigCmdInterfaces() (interfaces []Interface, err error) {
	output, err := n.RunCommand("ipconfig /all")
	if err != nil {
		return nil, err
	}

	var (
		ips              []IPAddress
		gateways         []string
		currentInterface *Interface
	)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// We are looking for an output like this one to identify a new interface
		//
		// Ethernet adapter Ethernet0:
		if matches := interfaceHeaderRegex.FindStringSubmatch(line); matches != nil {
			if currentInterface != nil {
				updateWindowsNetInterface(currentInterface, ips, gateways)
				interfaces = append(interfaces, *currentInterface)
			}

			// New interface initialization
			currentInterface = &Interface{Name: matches[2]}
			ips = make([]IPAddress, 0)
			gateways = make([]string, 0)
		}

		if currentInterface != nil {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch {
			case strings.HasPrefix(line, "Physical Address"):
				currentInterface.SetMAC(lastField(fields))
			case strings.HasPrefix(line, "IPv4 Address"):
				fallthrough
			case strings.HasPrefix(line, "IPv6 Address"):
				ip, ok := NewIPAddress(cleanIPString(lastField(fields)))
				if ok {
					ips = append(ips, ip)
				}
			case strings.HasPrefix(line, "Subnet Mask"):
				// Subnet mask are only valid for IPv4
				subnet := lastField(fields)
				for i := range ips {
					if version, ok := ips[i].Version(); ok && version == IPv4 {
						ips[i] = NewIPv4WithMask(ips[i].IP.String(), subnet)
					}
				}
			case strings.HasPrefix(line, "Default Gateway"):
				// collect the gateways found to inject them as part of the enrichments
				gateways = append(gateways, lastField(fields))
			}
		}
	}

	if currentInterface != nil {
		updateWindowsNetInterface(currentInterface, ips, gateways)
		interfaces = append(interfaces, *currentInterface)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "cmd.ipconfig_/all").
		Msg("os.network.interfaces> discovered")
	return
}

func lastField(fields []string) string {
	if len(fields) > 2 {
		return fields[len(fields)-1]
	}
	return ""
}

// cleanIPString strips the annotations Windows appends to an address: the
// `(Preferred)` suffix `ipconfig` prints, and the `%N` zone index
// `Get-NetIPAddress` reports on link-local addresses. Neither belongs to the
// address and `net.ParseIP` rejects both, which is why the BSD and Darwin
// detectors strip the zone the same way.
func cleanIPString(ip string) string {
	ip = strings.TrimSpace(ipSuffixRegex.ReplaceAllString(ip, ""))
	if pct := strings.Index(ip, "%"); pct != -1 {
		ip = ip[:pct]
	}
	return ip
}

// unmarshalPowershellObjects decodes a `ConvertTo-Json` payload into a list of
// objects. PowerShell emits a bare object rather than a single-element array
// whenever the pipeline produced exactly one item, so both shapes have to be
// accepted: a host with one network interface, or an interface with one IP
// address, otherwise decodes as nothing at all.
func unmarshalPowershellObjects(data string) ([]map[string]any, error) {
	var list []map[string]any
	listErr := json.Unmarshal([]byte(data), &list)
	if listErr == nil {
		return list, nil
	}

	var single map[string]any
	if err := json.Unmarshal([]byte(data), &single); err == nil {
		return []map[string]any{single}, nil
	}

	// Report the list error, it describes the shape we expect.
	return nil, listErr
}

func updateWindowsNetInterface(currentInterface *Interface, ips []IPAddress, gateways []string) {
	currentInterface.AddOrUpdateIP(ips...)
	if len(gateways) == 0 {
		// no enrichments needed
		return
	}
	currentInterface.enrichments = func(in *Interface) {
		for g := range gateways {
			// IPv4 (default)
			gateway := gateways[g]
			gatewayVersion := IPv4
			if strings.Contains(gateway, ":") {
				// IPv6
				gatewayVersion = IPv6
			}
			for i := range in.IPAddresses {
				if version, ok := in.IPAddresses[i].Version(); ok && version == gatewayVersion {
					in.IPAddresses[i].Gateway = gateway
				}
			}
		}
	}
}
