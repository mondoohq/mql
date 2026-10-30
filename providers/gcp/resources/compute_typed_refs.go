// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// region/zone typed accessors. The raw self-link URLs are held on each
// resource's Internal struct (cacheRegionUrl/cacheZoneUrl) so the accessor can
// resolve the region or zone resource without exposing the URL as a field.

func (g *mqlGcpProjectComputeServiceAddress) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceSecurityPolicy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceSslPolicy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceSslCertificate) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceVpnGateway) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceInstanceGroup) zone() (*mqlGcpProjectComputeServiceZone, error) {
	z, err := getZoneByUrl(g.cacheZoneUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if z == nil {
		g.Zone.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return z, nil
}

func (g *mqlGcpProjectComputeServiceInstanceGroupManager) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceInstanceGroupManager) zone() (*mqlGcpProjectComputeServiceZone, error) {
	z, err := getZoneByUrl(g.cacheZoneUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if z == nil {
		g.Zone.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return z, nil
}

func (g *mqlGcpProjectComputeServiceFirewallPolicy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceHealthCheck) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceUrlMap) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceTargetHttpProxy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceTargetHttpsProxy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceServiceAttachment) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceNetworkEndpointGroup) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceNetworkEndpointGroup) zone() (*mqlGcpProjectComputeServiceZone, error) {
	z, err := getZoneByUrl(g.cacheZoneUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if z == nil {
		g.Zone.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return z, nil
}

func (g *mqlGcpProjectComputeServiceInterconnectAttachment) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceTargetTcpProxy) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServicePacketMirroring) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}

func (g *mqlGcpProjectComputeServiceTargetPool) region() (*mqlGcpProjectComputeServiceRegion, error) {
	r, err := getRegionByUrl(g.cacheRegionUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if r == nil {
		g.Region.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return r, nil
}
