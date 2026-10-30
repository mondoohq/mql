// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/globalloadbalancerv1"
	"github.com/IBM/networking-go-sdk/sslcertificateapiv1"
	"github.com/IBM/networking-go-sdk/zonessettingsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
)

// Cloud Internet Services clients are bound to one instance (by CRN) and,
// below the zone list, to one zone. All of them answer on the global CIS
// endpoint; each is built once per instance and zone.

// cisClient builds a CIS client once per key and gives it the timeout and
// retries every other client has.
func cisClient[T any](c *IbmConnection, key string, build func() (T, *core.BaseService, error)) (T, error) {
	v, err := c.Memo("cis/"+key, func() (any, error) {
		svc, base, err := build()
		if err != nil {
			return nil, err
		}
		configure(base)
		return svc, nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}

// CisZones returns the zones client of a CIS instance.
func (c *IbmConnection) CisZones(crn string) (*zonesv1.ZonesV1, error) {
	return cisClient(c, "zones/"+crn, func() (*zonesv1.ZonesV1, *core.BaseService, error) {
		svc, err := zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{Authenticator: c.auth, Crn: &crn})
		if err != nil {
			return nil, nil, err
		}
		return svc, svc.Service, nil
	})
}

// CisZoneSettings returns the settings client of a zone.
func (c *IbmConnection) CisZoneSettings(crn, zoneID string) (*zonessettingsv1.ZonesSettingsV1, error) {
	return cisClient(c, "settings/"+crn+"/"+zoneID, func() (*zonessettingsv1.ZonesSettingsV1, *core.BaseService, error) {
		svc, err := zonessettingsv1.NewZonesSettingsV1(&zonessettingsv1.ZonesSettingsV1Options{Authenticator: c.auth, Crn: &crn, ZoneIdentifier: &zoneID})
		if err != nil {
			return nil, nil, err
		}
		return svc, svc.Service, nil
	})
}

// CisSsl returns the SSL/TLS client of a zone, which reads the SSL mode and
// the TLS 1.3 setting.
func (c *IbmConnection) CisSsl(crn, zoneID string) (*sslcertificateapiv1.SslCertificateApiV1, error) {
	return cisClient(c, "ssl/"+crn+"/"+zoneID, func() (*sslcertificateapiv1.SslCertificateApiV1, *core.BaseService, error) {
		svc, err := sslcertificateapiv1.NewSslCertificateApiV1(&sslcertificateapiv1.SslCertificateApiV1Options{Authenticator: c.auth, Crn: &crn, ZoneIdentifier: &zoneID})
		if err != nil {
			return nil, nil, err
		}
		return svc, svc.Service, nil
	})
}

// CisDnsRecords returns the DNS records client of a zone.
func (c *IbmConnection) CisDnsRecords(crn, zoneID string) (*dnsrecordsv1.DnsRecordsV1, error) {
	return cisClient(c, "dnsrecords/"+crn+"/"+zoneID, func() (*dnsrecordsv1.DnsRecordsV1, *core.BaseService, error) {
		svc, err := dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{Authenticator: c.auth, Crn: &crn, ZoneIdentifier: &zoneID})
		if err != nil {
			return nil, nil, err
		}
		return svc, svc.Service, nil
	})
}

// CisGlobalLoadBalancers returns the global load balancer client of a zone.
func (c *IbmConnection) CisGlobalLoadBalancers(crn, zoneID string) (*globalloadbalancerv1.GlobalLoadBalancerV1, error) {
	return cisClient(c, "glb/"+crn+"/"+zoneID, func() (*globalloadbalancerv1.GlobalLoadBalancerV1, *core.BaseService, error) {
		svc, err := globalloadbalancerv1.NewGlobalLoadBalancerV1(&globalloadbalancerv1.GlobalLoadBalancerV1Options{Authenticator: c.auth, Crn: &crn, ZoneIdentifier: &zoneID})
		if err != nil {
			return nil, nil, err
		}
		return svc, svc.Service, nil
	})
}
