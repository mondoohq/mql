// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/globalloadbalancerv1"
	"github.com/IBM/networking-go-sdk/sslcertificateapiv1"
	"github.com/IBM/networking-go-sdk/zonessettingsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// cisService is the CRN service name of Cloud Internet Services.
const cisService = "internet-svcs"

// cisZonePageSize is the largest page of zones the API returns.
const cisZonePageSize = int64(50)

// cisRecordPageSize is the page size for DNS record listings.
const cisRecordPageSize = int64(100)

// ---- instances ----

type mqlIbmCisInstanceInternal struct {
	cacheResourceGroupID string
}

func (r *mqlIbm) cisInstances() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ri := range items {
		crn := derefStr(ri.CRN)
		if crnService(crn) != cisService {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.cis.instance", map[string]*llx.RawData{
			"__id":  llx.StringData("ibm.cis.instance/" + crn),
			"id":    llx.StringData(crn),
			"guid":  strData(ri.GUID),
			"name":  strData(ri.Name),
			"state": strData(ri.State),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmCisInstance)
		m.cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmCisInstance) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmCisInstance) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Id.Data) }
func (r *mqlIbmCisInstance) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Id.Data) }

// ---- zones ----

type mqlIbmCisZoneInternal struct {
	cacheInstanceCRN string
}

func (r *mqlIbmCisInstance) zones() ([]any, error) {
	crn := r.Id.Data
	svc, err := conn(r.MqlRuntime).CisZones(crn)
	if err != nil {
		return nil, err
	}
	zones, err := listCisZones(svc)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(zones))
	for _, z := range zones {
		res, err := CreateResource(r.MqlRuntime, "ibm.cis.zone", cisZoneArgs(crn, z))
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmCisZone).cacheInstanceCRN = crn
		out = append(out, res)
	}
	return out, nil
}

// listCisZones reads every zone of an instance, page by page. A refusal is
// returned as an error, not as an empty list.
func listCisZones(svc *zonesv1.ZonesV1) ([]zonesv1.ZoneDetails, error) {
	var all []zonesv1.ZoneDetails
	page, size := int64(1), cisZonePageSize
	for {
		res, resp, err := svc.ListZones(&zonesv1.ListZonesOptions{Page: &page, PerPage: &size})
		if err != nil {
			return nil, classifyError(withStatus(err, resp), "internet-svcs.zones.read")
		}
		all = append(all, res.Result...)
		var total *int64
		if res.ResultInfo != nil {
			total = res.ResultInfo.TotalCount
		}
		if !morePages(total, len(res.Result), len(all), size) {
			return all, nil
		}
		page++
	}
}

// morePages reports whether a paged CIS listing has another page: the last
// page was full and fewer items than the total were read. An empty page ends
// the walk, so an API that keeps answering cannot loop it forever.
func morePages(total *int64, got, read int, size int64) bool {
	if got == 0 || int64(got) < size {
		return false
	}
	return total == nil || int64(read) < *total
}

func cisZoneArgs(crn string, z zonesv1.ZoneDetails) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("ibm.cis.zone/" + crn + "/" + derefStr(z.ID)),
		"id":          strData(z.ID),
		"name":        strData(z.Name),
		"status":      strData(z.Status),
		"paused":      llx.BoolDataPtr(z.Paused),
		"nameServers": stringsData(z.NameServers),
		"createdAt":   rfc3339Data(z.CreatedOn),
		"modifiedAt":  rfc3339Data(z.ModifiedOn),
	}
}

// ---- zone settings ----

// Every setting is its own API call, made only when the field is queried.

func (r *mqlIbmCisZone) settings() (*zonessettingsv1.ZonesSettingsV1, error) {
	return conn(r.MqlRuntime).CisZoneSettings(r.cacheInstanceCRN, r.Id.Data)
}

// setting returns a zone setting's value; a setting the API answers without
// a value reads as null.
func setting(field *plugin.TValue[string], v string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if v == "" {
		nullResource(field)
	}
	return v, nil
}

func (r *mqlIbmCisZone) ssl() (string, error) {
	svc, err := conn(r.MqlRuntime).CisSsl(r.cacheInstanceCRN, r.Id.Data)
	if err != nil {
		return "", err
	}
	v, err := cisSslMode(svc)
	return setting(&r.Ssl, v, err)
}

func (r *mqlIbmCisZone) tls13() (string, error) {
	svc, err := conn(r.MqlRuntime).CisSsl(r.cacheInstanceCRN, r.Id.Data)
	if err != nil {
		return "", err
	}
	v, err := cisTls13(svc)
	return setting(&r.Tls13, v, err)
}

func (r *mqlIbmCisZone) minTlsVersion() (string, error) {
	svc, err := r.settings()
	if err != nil {
		return "", err
	}
	v, err := cisMinTlsVersion(svc)
	return setting(&r.MinTlsVersion, v, err)
}

func (r *mqlIbmCisZone) alwaysUseHttps() (string, error) {
	svc, err := r.settings()
	if err != nil {
		return "", err
	}
	v, err := cisAlwaysUseHttps(svc)
	return setting(&r.AlwaysUseHttps, v, err)
}

// wafEnabled is true when the zone's web application firewall setting is on.
func (r *mqlIbmCisZone) wafEnabled() (bool, error) {
	svc, err := r.settings()
	if err != nil {
		return false, err
	}
	v, err := cisWaf(svc)
	if err != nil {
		return false, err
	}
	if v == "" {
		nullResource(&r.WafEnabled)
		return false, nil
	}
	return v == "on", nil
}

func cisMinTlsVersion(svc *zonessettingsv1.ZonesSettingsV1) (string, error) {
	res, resp, err := svc.GetMinTlsVersion(&zonessettingsv1.GetMinTlsVersionOptions{})
	if err != nil {
		return "", classifyError(withStatus(err, resp), "internet-svcs.security.read")
	}
	if res.Result == nil {
		return "", nil
	}
	return derefStr(res.Result.Value), nil
}

func cisAlwaysUseHttps(svc *zonessettingsv1.ZonesSettingsV1) (string, error) {
	res, resp, err := svc.GetAlwaysUseHttps(&zonessettingsv1.GetAlwaysUseHttpsOptions{})
	if err != nil {
		return "", classifyError(withStatus(err, resp), "internet-svcs.security.read")
	}
	if res.Result == nil {
		return "", nil
	}
	return derefStr(res.Result.Value), nil
}

// cisWaf reads the zone's web application firewall setting: on or off.
func cisWaf(svc *zonessettingsv1.ZonesSettingsV1) (string, error) {
	res, resp, err := svc.GetWebApplicationFirewall(&zonessettingsv1.GetWebApplicationFirewallOptions{})
	if err != nil {
		return "", classifyError(withStatus(err, resp), "internet-svcs.security.read")
	}
	if res.Result == nil {
		return "", nil
	}
	return derefStr(res.Result.Value), nil
}

func cisSslMode(svc *sslcertificateapiv1.SslCertificateApiV1) (string, error) {
	res, resp, err := svc.GetSslSetting(&sslcertificateapiv1.GetSslSettingOptions{})
	if err != nil {
		return "", classifyError(withStatus(err, resp), "internet-svcs.security.read")
	}
	if res.Result == nil {
		return "", nil
	}
	return derefStr(res.Result.Value), nil
}

func cisTls13(svc *sslcertificateapiv1.SslCertificateApiV1) (string, error) {
	res, resp, err := svc.GetTls13Setting(&sslcertificateapiv1.GetTls13SettingOptions{})
	if err != nil {
		return "", classifyError(withStatus(err, resp), "internet-svcs.security.read")
	}
	if res.Result == nil {
		return "", nil
	}
	return derefStr(res.Result.Value), nil
}

// ---- DNS records ----

func (r *mqlIbmCisZone) dnsRecords() ([]any, error) {
	svc, err := conn(r.MqlRuntime).CisDnsRecords(r.cacheInstanceCRN, r.Id.Data)
	if err != nil {
		return nil, err
	}
	records, err := listCisDnsRecords(svc)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(r.MqlRuntime, "ibm.cis.dnsRecord", cisDnsRecordArgs(r.cacheInstanceCRN, r.Id.Data, rec))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listCisDnsRecords reads every DNS record of a zone, page by page.
func listCisDnsRecords(svc *dnsrecordsv1.DnsRecordsV1) ([]dnsrecordsv1.DnsrecordDetails, error) {
	var all []dnsrecordsv1.DnsrecordDetails
	page, size := int64(1), cisRecordPageSize
	for {
		res, resp, err := svc.ListAllDnsRecords(&dnsrecordsv1.ListAllDnsRecordsOptions{Page: &page, PerPage: &size})
		if err != nil {
			return nil, classifyError(withStatus(err, resp), "internet-svcs.dns-records.read")
		}
		all = append(all, res.Result...)
		var total *int64
		if res.ResultInfo != nil {
			total = res.ResultInfo.TotalCount
		}
		if !morePages(total, len(res.Result), len(all), size) {
			return all, nil
		}
		page++
	}
}

func cisDnsRecordArgs(crn, zoneID string, rec dnsrecordsv1.DnsrecordDetails) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData("ibm.cis.dnsRecord/" + crn + "/" + zoneID + "/" + derefStr(rec.ID)),
		"id":         strData(rec.ID),
		"name":       strData(rec.Name),
		"type":       strData(rec.Type),
		"content":    strData(rec.Content),
		"proxiable":  llx.BoolData(rec.Proxiable != nil && *rec.Proxiable),
		"proxied":    llx.BoolData(rec.Proxied != nil && *rec.Proxied),
		"ttl":        intPtrData(rec.TTL),
		"createdAt":  rfc3339Data(rec.CreatedOn),
		"modifiedAt": rfc3339Data(rec.ModifiedOn),
	}
}

// ---- global load balancers ----

func (r *mqlIbmCisZone) globalLoadBalancers() ([]any, error) {
	svc, err := conn(r.MqlRuntime).CisGlobalLoadBalancers(r.cacheInstanceCRN, r.Id.Data)
	if err != nil {
		return nil, err
	}
	lbs, err := listCisGlobalLoadBalancers(svc)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(lbs))
	for _, lb := range lbs {
		res, err := CreateResource(r.MqlRuntime, "ibm.cis.globalLoadBalancer", cisGlobalLoadBalancerArgs(r.cacheInstanceCRN, r.Id.Data, lb))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listCisGlobalLoadBalancers reads the global load balancers of a zone. The
// API returns them in one answer.
func listCisGlobalLoadBalancers(svc *globalloadbalancerv1.GlobalLoadBalancerV1) ([]globalloadbalancerv1.LoadBalancerPack, error) {
	res, resp, err := svc.ListAllLoadBalancers(&globalloadbalancerv1.ListAllLoadBalancersOptions{})
	if err != nil {
		return nil, classifyError(withStatus(err, resp), "internet-svcs.reliability.read")
	}
	return res.Result, nil
}

func cisGlobalLoadBalancerArgs(crn, zoneID string, lb globalloadbalancerv1.LoadBalancerPack) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":            llx.StringData("ibm.cis.globalLoadBalancer/" + crn + "/" + zoneID + "/" + derefStr(lb.ID)),
		"id":              strData(lb.ID),
		"name":            strData(lb.Name),
		"description":     strData(lb.Description),
		"enabled":         llx.BoolData(lb.Enabled != nil && *lb.Enabled),
		"proxied":         llx.BoolData(lb.Proxied != nil && *lb.Proxied),
		"ttl":             intPtrData(lb.TTL),
		"defaultPools":    stringsData(lb.DefaultPools),
		"fallbackPool":    strData(lb.FallbackPool),
		"steeringPolicy":  strData(lb.SteeringPolicy),
		"sessionAffinity": strData(lb.SessionAffinity),
		"createdAt":       rfc3339Data(lb.CreatedOn),
		"modifiedAt":      rfc3339Data(lb.ModifiedOn),
	}
}
