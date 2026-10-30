// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/gce"
)

const GCP Provider = "GCP"

// gcp implements the OSCloud interface for Google Cloud
type gcp struct {
	conn shared.Connection
}

func (g *gcp) Provider() Provider {
	return GCP
}

func (g *gcp) Instance() (*InstanceMetadata, error) {
	mdsvc, err := gce.Resolve(g.conn, g.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.gcp> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.gcp> failed to get raw metadata")
		return nil, err
	}
	if metadata == nil {
		log.Debug().Msg("os.cloud.gcp> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := InstanceMetadata{Metadata: metadata}

	m, ok := metadata.(map[string]any)
	if !ok {
		return &instanceMd, errors.New("unexpected raw metadata")
	}

	if value, ok := m["hostname"]; ok {
		instanceMd.PrivateHostname = value.(string)
	}

	if value, ok := m["network-interfaces"]; ok {
		byteData, err := json.Marshal(value)
		if err != nil {
			return &instanceMd, err
		}

		var interfaces GCPInterfaces
		if err := json.Unmarshal(byteData, &interfaces); err != nil {
			return &instanceMd, err
		}

		// all network interfaces
		instanceMd.PublicIpv4 = make([]Ipv4Address, 0)
		instanceMd.PrivateIpv4 = make([]Ipv4Address, 0)
		for identified, details := range interfaces {
			ignored := true

			if ip, ok := details.PublicIP(); ok {
				instanceMd.PublicIpv4 = append(instanceMd.PublicIpv4, ip)
				ignored = false
			}

			if ip, ok := details.PrivateIP(); ok {
				instanceMd.PrivateIpv4 = append(instanceMd.PrivateIpv4, ip)
				ignored = false
			}

			if ignored {
				log.Debug().
					Str("network_interface_identifier", identified).
					Interface("interface_details", details).
					Msg("os.cloud.gcp> no valid public or private ipaddress, skipping")
			}
		}
	}

	// GCP does not expose the public hostname (DNS) but we can try to
	// fetch it doing a lookup on the network if we have a public ip
	for _, address := range instanceMd.PublicIpv4 {
		names, err := net.LookupAddr(address.IP)
		if err == nil && len(names) != 0 {
			log.Debug().Str("name", names[0]).Msg("os.cloud.gcp> public hostname found")
			instanceMd.PublicHostname = strings.TrimSuffix(names[0], ".")
		}
	}

	return &instanceMd, nil
}

// GCPInterfaces structure for GCP
type GCPInterfaces map[string]NetworkDetails

// NetworkDetails structure
type NetworkDetails struct {
	AccessConfigs     map[int]AccessConfig `json:"access-configs"`
	DNSServers        string               `json:"dns-servers"`
	ForwardedIPs      string               `json:"forwarded-ips"`
	Gateway           string               `json:"gateway"`
	IP                string               `json:"ip"`
	IPAliases         string               `json:"ip-aliases"`
	MAC               string               `json:"mac"`
	MTU               float64              `json:"mtu"`
	Network           string               `json:"network"`
	SubnetMask        string               `json:"subnetmask"`
	TargetInstanceIPs string               `json:"target-instance-ips"`
}

// Nested struct for access-configs
type AccessConfig struct {
	ExternalIP string `json:"external-ip"`
	Type       string `json:"type"`
}

// PublicIP detects if the network interface has a public ip address,
// if so it initializes an Ipv4Address struct and return true.
func (d NetworkDetails) PublicIP() (Ipv4Address, bool) {
	for _, config := range d.AccessConfigs {
		log.Trace().
			Str("external-ip", config.ExternalIP).
			Str("type", config.Type).
			Msg("os.cloud.gcp> parsing access config")
		if config.ExternalIP != "" && config.Type == "ONE_TO_ONE_NAT" {
			// Where is this type coming from, you ask?
			//
			// https://developers.google.com/resources/api-libraries/documentation/compute/v1/python/latest/compute_v1.instances.html
			return Ipv4Address{IP: config.ExternalIP}, true
		}
	}
	return Ipv4Address{}, false
}

// PrivateIP detects if the network interface has a private ip address,
// if so it initializes an Ipv4Address structure and return true.
func (d NetworkDetails) PrivateIP() (Ipv4Address, bool) {
	ip := NewIpv4WithMask(d.IP, d.SubnetMask)
	ip.Gateway = d.Gateway
	return ip, d.IP != ""
}
