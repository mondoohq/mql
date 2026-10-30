// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/azcompute"
	"go.mondoo.com/mql/providers/os/id/hostname"
)

const AZURE Provider = "Azure"

// azure implements the OSCloud interface for Azure Cloud
type azure struct {
	conn shared.Connection
}

func (a *azure) Provider() Provider {
	return AZURE
}

func (a *azure) Instance() (*InstanceMetadata, error) {
	mdsvc, err := azcompute.Resolve(a.conn, a.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.azure> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.azure> failed to get raw metadata")
		return nil, err
	}
	if metadata == nil {
		log.Debug().Msg("os.cloud.azure> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := &InstanceMetadata{Metadata: metadata}

	m, ok := metadata.(map[string]any)
	if !ok {
		return instanceMd, errors.New("unexpected raw metadata")
	}

	// The public IP address may come from two different endpoints within the IMDS, either
	// the `instance/` or the `loadbalander/` metadata endpoint.
	//
	// Docs: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=windows#endpoint-categories
	//
	// We don't know where will it come from, so we check both places starting with the
	// `loadbalancer/` endpoint.
	if value, ok := m["loadbalancer"]; ok {
		byteData, err := json.Marshal(value)
		if err != nil {
			return instanceMd, err
		}
		var azLbMd AzureLoadbalancerMetadata
		if err := json.Unmarshal(byteData, &azLbMd); err != nil {
			return instanceMd, errors.Wrap(err, "unable to unmarshal loadbalancer information")
		}

		// look for ip addresses
		for _, details := range azLbMd.Loadbalancer.PublicIPAddresses {
			ignored := true

			if ip, ok := details.PublicIP(); ok {
				instanceMd.AddOrUpdatePublicIP(ip)
				ignored = false
			}

			if ip, ok := details.PrivateIP(); ok {
				instanceMd.AddOrUpdatePrivateIP(ip)
				ignored = false
			}

			if ignored {
				log.Debug().
					Interface("loadbalancer_details", details).
					Msg("no valid frontend or private ipaddress, skipping")
			}
		}
	}

	// Then we look into the `instance/` endpoint. If we find any IP address, we do an upsert
	// using the `InstanceMetadata.AddOrUpdate{Public|Private}IP()`.
	if value, ok := m["instance"]; ok {
		byteData, err := json.Marshal(value)
		if err != nil {
			return instanceMd, err
		}
		var azInstanceMd AzureInstanceMetadata
		if err := json.Unmarshal(byteData, &azInstanceMd); err != nil {
			return instanceMd, errors.Wrap(err, "unable to unmarshal 'instance' information")
		}

		// all network interfaces
		for _, details := range azInstanceMd.Network.Interface {
			ignored := true

			if ip, ok := details.Ipv4.PublicIPs(); ok {
				instanceMd.AddOrUpdatePublicIP(ip...)
				ignored = false
			}

			if ip, ok := details.Ipv4.PrivateIPs(); ok {
				instanceMd.AddOrUpdatePrivateIP(ip...)
				ignored = false
			}

			if ignored {
				log.Debug().
					Interface("interface_details", details).
					Msg("no valid public or private ipaddress, skipping")
			}
		}
	}

	// Azure does not expose the either the private nor the public hostnames,
	// here we try to detect them both.

	for _, address := range instanceMd.PublicIpv4 {
		// for the public hostname, try lookup on the network if we have a public ip
		names, err := net.LookupAddr(address.IP)
		if err == nil && len(names) != 0 {
			log.Debug().Str("name", names[0]).Msg("os.cloud.azure> public hostname found")
			instanceMd.PublicHostname = strings.TrimSuffix(names[0], ".")
		}
	}
	if hostname, ok := hostname.Hostname(a.conn, a.conn.Asset().GetPlatform()); ok {
		// for the private hostname, use the hostname detector
		log.Debug().
			Str("hostname", hostname).
			Msg("os.cloud.azure> private hostname detected")
		instanceMd.PrivateHostname = hostname
	}

	return instanceMd, nil
}

// https://learn.microsoft.com/en-us/azure/load-balancer/howto-load-balancer-imds?tabs=windows
type AzureLoadbalancerMetadata struct {
	Loadbalancer struct {
		PublicIPAddresses []AzureLoadbalancerIPAddressDetails `json:"publicIpAddresses"`
		InboundRules      []struct {
			FrontendIPAddress string `json:"frontendIpAddress"`
			Protocol          string `json:"protocol"`
			FrontendPort      int    `json:"frontendPort"`
			BackendPort       int    `json:"backendPort"`
			PrivateIPAddress  string `json:"privateIpAddress"`
		} `json:"inboundRules"`
		OutboundRules []struct {
			FrontendIPAddress string `json:"frontendIpAddress"`
			PrivateIPAddress  string `json:"privateIpAddress"`
		} `json:"outboundRules"`
	} `json:"loadbalancer"`
}

type AzureLoadbalancerIPAddressDetails struct {
	FrontendIPAddress string `json:"frontendIpAddress"`
	PrivateIPAddress  string `json:"privateIpAddress"`
}

func (i AzureLoadbalancerIPAddressDetails) PublicIP() (Ipv4Address, bool) {
	return Ipv4Address{IP: i.FrontendIPAddress}, i.FrontendIPAddress != ""
}

func (i AzureLoadbalancerIPAddressDetails) PrivateIP() (Ipv4Address, bool) {
	return Ipv4Address{IP: i.PrivateIPAddress}, i.PrivateIPAddress != ""
}

type AzureInstanceMetadata struct {
	Compute struct {
		AzEnvironment              string `json:"azEnvironment"`
		CustomData                 string `json:"customData"`
		EvictionPolicy             string `json:"evictionPolicy"`
		IsHostCompatibilityLayerVM string `json:"isHostCompatibilityLayerVm"`
		LicenseType                string `json:"licenseType"`
		Location                   string `json:"location"`
		Name                       string `json:"name"`
		Offer                      string `json:"offer"`
		OsProfile                  struct {
			AdminUsername                 string `json:"adminUsername"`
			ComputerName                  string `json:"computerName"`
			DisablePasswordAuthentication string `json:"disablePasswordAuthentication"`
		} `json:"osProfile"`
		OsType           string `json:"osType"`
		PlacementGroupID string `json:"placementGroupId"`
		Plan             struct {
			Name      string `json:"name"`
			Product   string `json:"product"`
			Publisher string `json:"publisher"`
		} `json:"plan"`
		PlatformFaultDomain  string `json:"platformFaultDomain"`
		PlatformUpdateDomain string `json:"platformUpdateDomain"`
		Priority             string `json:"priority"`
		Provider             string `json:"provider"`
		PublicKeys           []struct {
			KeyData string `json:"keyData"`
			Path    string `json:"path"`
		} `json:"publicKeys"`
		Publisher         string `json:"publisher"`
		ResourceGroupName string `json:"resourceGroupName"`
		ResourceID        string `json:"resourceId"`
		SecurityProfile   struct {
			SecureBootEnabled string `json:"secureBootEnabled"`
			VirtualTpmEnabled string `json:"virtualTpmEnabled"`
		} `json:"securityProfile"`
		Sku            string `json:"sku"`
		StorageProfile struct {
			DataDisks      []any `json:"dataDisks"`
			ImageReference struct {
				ID        string `json:"id"`
				Offer     string `json:"offer"`
				Publisher string `json:"publisher"`
				Sku       string `json:"sku"`
				Version   string `json:"version"`
			} `json:"imageReference"`
			OsDisk struct {
				Caching          string `json:"caching"`
				CreateOption     string `json:"createOption"`
				DiffDiskSettings struct {
					Option string `json:"option"`
				} `json:"diffDiskSettings"`
				DiskSizeGB         string `json:"diskSizeGB"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
				Image struct {
					URI string `json:"uri"`
				} `json:"image"`
				ManagedDisk struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name   string `json:"name"`
				OsType string `json:"osType"`
				Vhd    struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"osDisk"`
			ResourceDisk struct {
				Size string `json:"size"`
			} `json:"resourceDisk"`
		} `json:"storageProfile"`
		SubscriptionID string `json:"subscriptionId"`
		Tags           string `json:"tags"`
		TagsList       []any  `json:"tagsList"`
		UserData       string `json:"userData"`
		Version        string `json:"version"`
		VMID           string `json:"vmId"`
		VMScaleSetName string `json:"vmScaleSetName"`
		VMSize         string `json:"vmSize"`
		Zone           string `json:"zone"`
	} `json:"compute"`
	Network AzureNetwork `json:"network"`
}

type AzureNetwork struct {
	Interface []AzureNetworkInterface `json:"interface"`
}

type AzureNetworkInterface struct {
	MacAddress string                    `json:"macAddress"`
	Ipv4       AzureNetworkInterfaceIpv4 `json:"ipv4"`
	Ipv6       struct {
		// @afiune this might look different but, I didn't see any example, so
		// leaving it as an interface for now.
		//
		// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=windows
		IPAddress []any `json:"ipAddress"`
	} `json:"ipv6"`
}

type AzureNetworkInterfaceIpv4 struct {
	IPAddress []AzureIPAddress `json:"ipAddress"`
	Subnet    []AzureSubnet    `json:"subnet"`
}

type AzureSubnet struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

func (s AzureSubnet) CIDR() string {
	return fmt.Sprintf("%s/%s", s.Address, s.Prefix)
}

type AzureIPAddress struct {
	PrivateIPAddress string `json:"privateIpAddress"`
	PublicIPAddress  string `json:"publicIpAddress"`
}

// PublicIPs detects if the network interface has one or more public ip
// addresses, if so it initializes them as Ipv4Address structs and return true.
func (i AzureNetworkInterfaceIpv4) PublicIPs() ([]Ipv4Address, bool) {
	ips := make([]Ipv4Address, 0)

	for _, ip := range i.IPAddress {
		netIP := net.ParseIP(ip.PublicIPAddress)
		if netIP == nil {
			continue
		}

		// we have a public ip address, try to fetch subnet info
		pubIP := Ipv4Address{IP: netIP.String()}
		if subnet, ok := i.findMatchingSubnet(netIP); ok {
			// we found the subnet
			pubIP.Subnet = subnet.Address
			pubIP.CIDR = fmt.Sprintf("%s/%s", netIP.String(), subnet.Prefix)
		}

		// add the public ip
		ips = append(ips, pubIP)
	}

	return ips, len(ips) != 0
}

// PrivateIPs detects if the network interface has one or more private ip
// addresses, if so it initializes them as Ipv4Address structs and return true.
func (i AzureNetworkInterfaceIpv4) PrivateIPs() ([]Ipv4Address, bool) {
	ips := make([]Ipv4Address, 0)

	for _, ip := range i.IPAddress {
		netIP := net.ParseIP(ip.PrivateIPAddress)
		if netIP == nil {
			continue
		}

		// we have a private ip address, try to fetch subnet info
		pubIP := Ipv4Address{IP: netIP.String()}
		if subnet, ok := i.findMatchingSubnet(netIP); ok {
			// we found the subnet
			pubIP.Subnet = subnet.Address
			pubIP.CIDR = fmt.Sprintf("%s/%s", netIP.String(), subnet.Prefix)
		}

		// add the private ip
		ips = append(ips, pubIP)
	}

	return ips, len(ips) != 0
}

// findMatchingSubnet checks which subnet the provided IP belongs to.
func (i AzureNetworkInterfaceIpv4) findMatchingSubnet(ip net.IP) (AzureSubnet, bool) {
	for _, subnet := range i.Subnet {
		_, netSubnet, err := net.ParseCIDR(subnet.CIDR())
		if err == nil && netSubnet.Contains(ip) {
			// The ip address belongs to the subnet
			return subnet, true
		}
	}

	return AzureSubnet{}, false
}
