// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	vimtypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (v *mqlVsphereHost) bootInfo() (*mqlVsphereHostBootInfo, error) {
	if v.host == nil {
		v.BootInfo.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	var bootTime, releaseDate time.Time
	if v.host.Runtime.BootTime != nil {
		bootTime = *v.host.Runtime.BootTime
	}

	var (
		biosVersion                                        string
		biosMajor, biosMinor, firmwareMajor, firmwareMinor int64
	)
	if v.host.Hardware != nil {
		if bios := v.host.Hardware.BiosInfo; bios != nil {
			biosVersion = bios.BiosVersion
			biosMajor = int64(bios.MajorRelease)
			biosMinor = int64(bios.MinorRelease)
			firmwareMajor = int64(bios.FirmwareMajorRelease)
			firmwareMinor = int64(bios.FirmwareMinorRelease)
			if bios.ReleaseDate != nil {
				releaseDate = *bios.ReleaseDate
			}
		}
	}

	id := v.InventoryPath.Data + "/bootInfo"
	res, err := CreateResource(v.MqlRuntime, "vsphere.host.bootInfo", map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"bootTime":             llx.TimeData(bootTime),
		"biosVersion":          llx.StringData(biosVersion),
		"biosReleaseDate":      llx.TimeData(releaseDate),
		"biosMajorRelease":     llx.IntData(biosMajor),
		"biosMinorRelease":     llx.IntData(biosMinor),
		"firmwareMajorRelease": llx.IntData(firmwareMajor),
		"firmwareMinorRelease": llx.IntData(firmwareMinor),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereHostBootInfo), nil
}

func (v *mqlVsphereHost) systemInfo() (*mqlVsphereHostSystemInfo, error) {
	if v.host == nil || v.host.Hardware == nil {
		v.SystemInfo.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	si := v.host.Hardware.SystemInfo
	assetTag, serviceTag, installDate, oem := classifyIdentifyingInfo(si.OtherIdentifyingInfo)

	id := v.InventoryPath.Data + "/systemInfo"
	res, err := CreateResource(v.MqlRuntime, "vsphere.host.systemInfo", map[string]*llx.RawData{
		"__id":         llx.StringData(id),
		"vendor":       llx.StringData(si.Vendor),
		"model":        llx.StringData(si.Model),
		"uuid":         llx.StringData(si.Uuid),
		"serialNumber": llx.StringData(si.SerialNumber),
		"assetTag":     llx.StringData(assetTag),
		"serviceTag":   llx.StringData(serviceTag),
		"installDate":  llx.TimeData(installDate),
		"oemSpecific":  llx.MapData(oem, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereHostSystemInfo), nil
}

// classifyIdentifyingInfo splits HostSystemIdentificationInfo entries into
// the typed fields we promote (AssetTag, ServiceTag, HostInstallDate) and the
// rest (vendor-specific bag). HostInstallDate is reported as an ISO-8601
// string by ESXi 7+; older platforms omit it.
func classifyIdentifyingInfo(items []vimtypes.HostSystemIdentificationInfo) (assetTag, serviceTag string, installDate time.Time, oem map[string]any) {
	oem = map[string]any{}
	for _, item := range items {
		key := item.IdentifierType.GetElementDescription().Key
		val := item.IdentifierValue
		switch key {
		case "AssetTag":
			assetTag = val
		case "ServiceTag":
			serviceTag = val
		case "HostInstallDate":
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				installDate = t
			}
		default:
			if key != "" {
				oem[key] = val
			}
		}
	}
	return
}

func (v *mqlVsphereHost) dnsConfig() (*mqlVsphereHostDnsConfig, error) {
	if v.host == nil || v.host.Config == nil || v.host.Config.Network == nil || v.host.Config.Network.DnsConfig == nil {
		v.DnsConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	dns := v.host.Config.Network.DnsConfig.GetHostDnsConfig()
	if dns == nil {
		v.DnsConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	fqdn := dns.HostName
	if dns.HostName != "" && dns.DomainName != "" {
		fqdn = dns.HostName + "." + dns.DomainName
	}

	id := v.InventoryPath.Data + "/dnsConfig"
	res, err := CreateResource(v.MqlRuntime, "vsphere.host.dnsConfig", map[string]*llx.RawData{
		"__id":             llx.StringData(id),
		"dhcp":             llx.BoolData(dns.Dhcp),
		"hostName":         llx.StringData(dns.HostName),
		"domain":           llx.StringData(dns.DomainName),
		"fqdn":             llx.StringData(fqdn),
		"servers":          llx.ArrayData(stringsToAny(dns.Address), types.String),
		"searchDomains":    llx.ArrayData(stringsToAny(dns.SearchDomain), types.String),
		"virtualNicDevice": llx.StringData(dns.VirtualNicDevice),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereHostDnsConfig), nil
}

func (v *mqlVsphereHost) ipRouteConfig() (*mqlVsphereHostIpRouteConfig, error) {
	if v.host == nil || v.host.Config == nil || v.host.Config.Network == nil || v.host.Config.Network.IpRouteConfig == nil {
		v.IpRouteConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ipr := v.host.Config.Network.IpRouteConfig.GetHostIpRouteConfig()
	if ipr == nil {
		v.IpRouteConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	id := v.InventoryPath.Data + "/ipRouteConfig"
	res, err := CreateResource(v.MqlRuntime, "vsphere.host.ipRouteConfig", map[string]*llx.RawData{
		"__id":               llx.StringData(id),
		"defaultGateway":     llx.StringData(ipr.DefaultGateway),
		"ipv6DefaultGateway": llx.StringData(ipr.IpV6DefaultGateway),
		"gatewayDevice":      llx.StringData(ipr.GatewayDevice),
		"ipv6GatewayDevice":  llx.StringData(ipr.IpV6GatewayDevice),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereHostIpRouteConfig), nil
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
