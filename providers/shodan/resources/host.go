// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shadowscatcher/shodan/models"
	"github.com/shadowscatcher/shodan/search"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/shodan/connection"
	"go.mondoo.com/mql/types"
)

// mqlShodanHostInternal caches state derived from the Shodan host fetch so we
// can populate computed flag fields (isCloud, isVpn, etc.) without re-deriving
// from the runtime tag list each time.
type mqlShodanHostInternal struct {
	cachedTags map[string]bool
}

func initShodanHost(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["ip"]; !ok {
		// try to get the ip from the connection
		conn := runtime.Connection.(*connection.ShodanConnection)
		if conn.Conf.Options != nil && conn.Conf.Options["search"] == "host" {
			args["ip"] = llx.StringData(conn.Conf.Host)
		}
	}

	if _, ok := args["ip"]; !ok {
		return nil, nil, errors.New("missing required argument 'ip'")
	}

	return args, nil, nil
}

func (r *mqlShodanHost) id() (string, error) {
	return "shodan.host/" + r.Ip.Data, nil
}

// Tag families that Shodan uses to label hosts. The host derives several
// boolean flags from these so callers can spot CDN/proxy obfuscation without
// hand-rolling tag matches.
var (
	shodanCloudTags = map[string]bool{
		"cloud": true, "hosting": true, "aws": true, "ec2": true,
		"azure": true, "gcp": true, "google-cloud": true, "digitalocean": true,
		"linode": true, "alibaba": true, "ovh": true, "hetzner": true,
		"vultr": true, "scaleway": true,
	}
	shodanCdnTags   = map[string]bool{"cdn": true, "cloudflare": true, "fastly": true, "akamai": true}
	shodanVpnTags   = map[string]bool{"vpn": true}
	shodanTorTags   = map[string]bool{"tor": true, "tor-exit": true}
	shodanProxyTags = map[string]bool{"proxy": true, "anonymous": true, "open-proxy": true}
)

func (r *mqlShodanHost) ensureTagSet() map[string]bool {
	if r.cachedTags != nil {
		return r.cachedTags
	}
	r.cachedTags = map[string]bool{}
	if !r.Tags.IsSet() || r.Tags.Data == nil {
		return r.cachedTags
	}
	for _, t := range r.Tags.Data {
		if s, ok := t.(string); ok {
			r.cachedTags[strings.ToLower(s)] = true
		}
	}
	return r.cachedTags
}

func (r *mqlShodanHost) hasTagFromSet(set map[string]bool) bool {
	tags := r.ensureTagSet()
	for tag := range tags {
		if set[tag] {
			return true
		}
	}
	return false
}

func (r *mqlShodanHost) fetchBaseInformation() error {
	conn := r.MqlRuntime.Connection.(*connection.ShodanConnection)
	client := conn.Client()
	if client == nil {
		return errors.New("cannot retrieve new data while using a mock connection")
	}

	// set default information
	r.Os = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Org = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Isp = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Asn = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Country = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.City = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.CountryCode = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.RegionCode = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.PostalCode = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Latitude = plugin.TValue[float64]{Data: 0, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Longitude = plugin.TValue[float64]{Data: 0, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.LastUpdate = plugin.TValue[*time.Time]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Tags = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Hostnames = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Ports = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Vulnerabilities = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Vulns = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Services = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	ctx := context.Background()
	host, err := client.Host(ctx, search.HostParams{
		IP: r.Ip.Data,
	})

	// ignore no information available error since it is not an error
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no information available") {
		return nil
	} else if err != nil {
		return err
	}

	if host.OS != nil {
		r.Os = plugin.TValue[string]{Data: *host.OS, Error: nil, State: plugin.StateIsSet}
	}

	if host.Org != nil {
		r.Org = plugin.TValue[string]{Data: *host.Org, Error: nil, State: plugin.StateIsSet}
	}

	if host.ISP != nil {
		r.Isp = plugin.TValue[string]{Data: *host.ISP, Error: nil, State: plugin.StateIsSet}
	}

	if host.ASN != nil {
		r.Asn = plugin.TValue[string]{Data: *host.ASN, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.City != nil {
		r.City = plugin.TValue[string]{Data: *host.Location.City, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.CountryName != nil {
		r.Country = plugin.TValue[string]{Data: *host.Location.CountryName, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.CountryCode != nil {
		r.CountryCode = plugin.TValue[string]{Data: *host.Location.CountryCode, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.RegionCode != nil {
		r.RegionCode = plugin.TValue[string]{Data: *host.Location.RegionCode, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.PostalCode != nil {
		r.PostalCode = plugin.TValue[string]{Data: *host.Location.PostalCode, Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.Latitude != nil {
		r.Latitude = plugin.TValue[float64]{Data: float64(*host.Location.Latitude), Error: nil, State: plugin.StateIsSet}
	}

	if host.Location.Longitude != nil {
		r.Longitude = plugin.TValue[float64]{Data: float64(*host.Location.Longitude), Error: nil, State: plugin.StateIsSet}
	}

	if host.LastUpdate != "" {
		// Shodan emits last_update without timezone (e.g. "2024-05-01T12:00:00.000000"),
		// so try a couple of formats before falling back to null.
		lastUpdate := parseShodanTime(host.LastUpdate)
		if lastUpdate != nil {
			r.LastUpdate = plugin.TValue[*time.Time]{Data: lastUpdate, Error: nil, State: plugin.StateIsSet}
		}
	}

	if host.Tags != nil {
		r.Tags = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(host.Tags), Error: nil, State: plugin.StateIsSet}
	}

	if host.Hostnames != nil {
		r.Hostnames = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(host.Hostnames), Error: nil, State: plugin.StateIsSet}
	}

	if host.Ports != nil {
		// we cannot use convert.SliceIntToInterface since the ports need to be int64
		ports := make([]any, len(host.Ports))
		for i := range host.Ports {
			ports[i] = int64(host.Ports[i])
		}
		r.Ports = plugin.TValue[[]any]{Data: ports, Error: nil, State: plugin.StateIsSet}
	}

	if host.Vulns != nil {
		r.Vulnerabilities = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(host.Vulns), Error: nil, State: plugin.StateIsSet}
	}

	// Build per-service and per-cve resources. Service.Vulns is the only place
	// the Shodan API returns CVSS values; host.Vulns is just a flat list of CVE
	// IDs without scoring metadata.
	services, hostVulns, err := r.buildServiceResources(host.Services)
	if err != nil {
		return err
	}
	r.Services = plugin.TValue[[]any]{Data: services, Error: nil, State: plugin.StateIsSet}
	r.Vulns = plugin.TValue[[]any]{Data: hostVulns, Error: nil, State: plugin.StateIsSet}

	return nil
}

// parseShodanTime accepts the timestamp formats Shodan emits for host and
// banner times (RFC3339, or a microsecond timestamp without a timezone).
func parseShodanTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		// Certificate validity dates arrive as X.509 ASN.1 GeneralizedTime
		// rather than the ISO-8601 form used for host, banner and DNS
		// timestamps, so they need their own layout.
		"20060102150405Z",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return &t
		}
	}
	return nil
}

func (r *mqlShodanHost) os() (string, error)             { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) org() (string, error)            { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) isp() (string, error)            { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) asn() (string, error)            { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) tags() ([]any, error)            { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) hostnames() ([]any, error)       { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) ports() ([]any, error)           { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) vulnerabilities() ([]any, error) { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) vulns() ([]any, error)           { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) city() (string, error)           { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) country() (string, error)        { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) countryCode() (string, error)    { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) regionCode() (string, error)     { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) postalCode() (string, error)     { return "", r.fetchBaseInformation() }
func (r *mqlShodanHost) latitude() (float64, error)      { return 0, r.fetchBaseInformation() }
func (r *mqlShodanHost) longitude() (float64, error)     { return 0, r.fetchBaseInformation() }
func (r *mqlShodanHost) lastUpdate() (*time.Time, error) { return nil, r.fetchBaseInformation() }
func (r *mqlShodanHost) services() ([]any, error)        { return nil, r.fetchBaseInformation() }

func (r *mqlShodanHost) isCloud() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanCloudTags), nil
}

func (r *mqlShodanHost) isCdn() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanCdnTags), nil
}

func (r *mqlShodanHost) isVpn() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanVpnTags), nil
}

func (r *mqlShodanHost) isTor() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanTorTags), nil
}

func (r *mqlShodanHost) isProxy() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanProxyTags), nil
}

func (r *mqlShodanHost) isInfrastructure() (bool, error) {
	if !r.Tags.IsSet() {
		if err := r.fetchBaseInformation(); err != nil {
			return false, err
		}
	}
	return r.hasTagFromSet(shodanCloudTags) ||
		r.hasTagFromSet(shodanCdnTags) ||
		r.hasTagFromSet(shodanVpnTags) ||
		r.hasTagFromSet(shodanProxyTags) ||
		r.hasTagFromSet(shodanTorTags), nil
}

// buildServiceResources walks the per-port banner array Shodan returns and
// produces typed `shodan.host.service` resources, lifting per-banner SSL/cert
// detail and CVE metadata into their own sub-resources. It also collects the
// host-wide deduplicated CVE list (with the highest CVSS we saw across the
// banners reporting it).
func (r *mqlShodanHost) buildServiceResources(svcs []*models.Service) ([]any, []any, error) {
	if len(svcs) == 0 {
		return []any{}, []any{}, nil
	}

	services := make([]any, 0, len(svcs))
	// CVE -> aggregated info; we want the best CVSS we saw because some Shodan
	// banners omit CVSS while others provide it for the same CVE.
	hostCves := map[string]*aggregatedCVE{}

	for _, svc := range svcs {
		if svc == nil {
			continue
		}
		// Build per-banner vulnerability resources first so we can attach them
		// to the service resource and merge into the host map.
		bannerVulnResources := make([]any, 0, len(svc.Vulns))
		bannerCveIds := make([]any, 0, len(svc.Vulns))
		// Sort CVEs alphabetically so that __id ordering is stable for
		// recordings/replays.
		cveKeys := make([]string, 0, len(svc.Vulns))
		for cve := range svc.Vulns {
			cveKeys = append(cveKeys, cve)
		}
		sort.Strings(cveKeys)
		// Use IPString() so the service IP is populated for both v4 and v6
		// banners (svc.IPstr is empty when the host is reached over IPv6).
		svcIP := svc.IPString()
		for _, cve := range cveKeys {
			vuln := svc.Vulns[cve]
			cvss, hasCvss := parseCVSS(vuln.CVSS)
			severity := classifyCVSS(cvss, hasCvss)
			vulnRes, err := CreateResource(r.MqlRuntime, "shodan.host.vulnerability", map[string]*llx.RawData{
				"__id":       llx.StringData(fmt.Sprintf("shodan.host.vulnerability/%s/%d/%s", svcIP, svc.Port, cve)),
				"cve":        llx.StringData(cve),
				"cvss":       llx.FloatData(cvss),
				"severity":   llx.StringData(severity),
				"verified":   llx.BoolData(vuln.Verified),
				"summary":    llx.StringData(vuln.Summary),
				"references": llx.ArrayData(convert.SliceAnyToInterface(vuln.References), types.String),
			})
			if err != nil {
				return nil, nil, err
			}
			bannerVulnResources = append(bannerVulnResources, vulnRes)
			bannerCveIds = append(bannerCveIds, cve)

			// merge into host-level map
			if existing, ok := hostCves[cve]; ok {
				if hasCvss && (!existing.hasCVSS || cvss > existing.cvss) {
					existing.cvss = cvss
					existing.severity = severity
					existing.hasCVSS = true
				}
				if vuln.Verified {
					existing.verified = true
				}
			} else {
				hostCves[cve] = &aggregatedCVE{
					cve:        cve,
					cvss:       cvss,
					hasCVSS:    hasCvss,
					severity:   severity,
					verified:   vuln.Verified,
					summary:    vuln.Summary,
					references: vuln.References,
				}
			}
		}

		// Build the SSL/TLS sub-resource if present.
		var tlsResource *mqlShodanHostTls
		if svc.SSL != nil {
			tlsRes, err := buildTlsResource(r.MqlRuntime, svcIP, svc.Port, svc.SSL)
			if err != nil {
				return nil, nil, err
			}
			tlsResource = tlsRes
		}

		// Construct the service resource.
		serviceArgs := map[string]*llx.RawData{
			"__id":            llx.StringData(fmt.Sprintf("shodan.host.service/%s/%d/%s", svcIP, svc.Port, svc.Transport)),
			"ip":              llx.StringData(svcIP),
			"port":            llx.IntData(int64(svc.Port)),
			"transport":       llx.StringData(svc.Transport),
			"product":         llx.StringData(svc.ProductString()),
			"version":         llx.StringData(svc.VersionString()),
			"cpe":             llx.ArrayData(convert.SliceAnyToInterface(svc.CpeList()), types.String),
			"data":            llx.StringData(svc.Data),
			"hash":            llx.IntData(int64(svc.Hash)),
			"hostnames":       llx.ArrayData(convert.SliceAnyToInterface(svc.HostInfo.Hostnames), types.String),
			"vulnerabilities": llx.ArrayData(bannerCveIds, types.String),
			"vulns":           llx.ArrayData(bannerVulnResources, types.Resource("shodan.host.vulnerability")),
			"module":          llx.StringData(svc.Shodan.Module),
		}

		// Optional scalar fields — only set when the API returned a value.
		serviceArgs["title"] = optionalStringPtr(svc.Title)
		serviceArgs["deviceType"] = optionalStringPtr(svc.DeviceType)
		serviceArgs["timestamp"] = optionalShodanTime(svc.Timestamp)
		serviceArgs["tlsBanner"] = optionalResource(tlsResource)

		serviceRes, err := CreateResource(r.MqlRuntime, "shodan.host.service", serviceArgs)
		if err != nil {
			return nil, nil, err
		}
		services = append(services, serviceRes)
	}

	// Build deduplicated host-level vulnerability resources keyed by CVE.
	hostCveKeys := make([]string, 0, len(hostCves))
	for k := range hostCves {
		hostCveKeys = append(hostCveKeys, k)
	}
	sort.Strings(hostCveKeys)
	hostVulnResources := make([]any, 0, len(hostCveKeys))
	for _, cve := range hostCveKeys {
		v := hostCves[cve]
		vulnRes, err := CreateResource(r.MqlRuntime, "shodan.host.vulnerability", map[string]*llx.RawData{
			"__id":       llx.StringData(fmt.Sprintf("shodan.host.vulnerability/%s/%s", r.Ip.Data, cve)),
			"cve":        llx.StringData(v.cve),
			"cvss":       llx.FloatData(v.cvss),
			"severity":   llx.StringData(v.severity),
			"verified":   llx.BoolData(v.verified),
			"summary":    llx.StringData(v.summary),
			"references": llx.ArrayData(convert.SliceAnyToInterface(v.references), types.String),
		})
		if err != nil {
			return nil, nil, err
		}
		hostVulnResources = append(hostVulnResources, vulnRes)
	}

	return services, hostVulnResources, nil
}

type aggregatedCVE struct {
	cve        string
	cvss       float64
	hasCVSS    bool
	severity   string
	verified   bool
	summary    string
	references []string
}

// parseCVSS unwraps the variant `cvss` field (Shodan returns a number, a
// string, or null depending on the banner). Returns -1 when no score is
// available so MQL queries can still distinguish missing scores from a true
// score of 0.
func parseCVSS(raw any) (float64, bool) {
	switch v := raw.(type) {
	case nil:
		return -1, false
	case float64:
		// JSON-unmarshalled numbers are always float64 — no need to handle
		// other numeric types here.
		return v, true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return -1, false
		}
		// Use ParseFloat (not fmt.Sscanf) so partial parses like "9.8 high"
		// are rejected rather than silently truncated.
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return -1, false
		}
		return f, true
	default:
		return -1, false
	}
}

func classifyCVSS(score float64, hasScore bool) string {
	if !hasScore {
		return "unknown"
	}
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func optionalStringPtr(p *string) *llx.RawData {
	if p == nil {
		return llx.NilData
	}
	return llx.StringData(*p)
}

func optionalShodanTime(raw string) *llx.RawData {
	return llx.TimeDataPtr(parseShodanTime(raw))
}

// optionalResource emits a Shodan resource ref, or NilData if the resource
// pointer is nil. Callers pass the resource as plugin.Resource; if the
// underlying pointer is nil we emit NilData.
func optionalResource(r plugin.Resource) *llx.RawData {
	if r == nil || isNilResource(r) {
		return llx.NilData
	}
	return llx.ResourceData(r, r.MqlName())
}

// isNilResource checks for the typed-nil case (e.g. a *mqlShodanHostTls that
// is nil) which a plain `r == nil` comparison can't catch.
func isNilResource(r plugin.Resource) bool {
	switch v := r.(type) {
	case *mqlShodanHostTls:
		return v == nil
	case *mqlShodanHostCert:
		return v == nil
	default:
		return false
	}
}
