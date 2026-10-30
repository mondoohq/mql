// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/globalloadbalancerv1"
	"github.com/IBM/networking-go-sdk/sslcertificateapiv1"
	"github.com/IBM/networking-go-sdk/zonessettingsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

const (
	testCisCRN  = "crn:v1:bluemix:public:internet-svcs:global:a/acc:cis-guid::"
	testCisZone = "zone-1"
)

// cisServer is a fake CIS endpoint. answer returns the status and JSON body
// for a request; every request URL is recorded.
func cisServer(t *testing.T, answer func(r *http.Request) (int, string), urls *[]*url.URL) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if urls != nil {
			*urls = append(*urls, r.URL)
		}
		status, body := answer(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// byPath answers each path with its body, and anything else with 404.
func byPath(t *testing.T, bodies map[string]string) func(r *http.Request) (int, string) {
	return func(r *http.Request) (int, string) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s", r.URL)
			return http.StatusNotFound, `{"success": false, "errors": [], "messages": [], "result": null}`
		}
		return http.StatusOK, body
	}
}

func refuseAll(*http.Request) (int, string) {
	return http.StatusForbidden, `{"success": false, "errors": [{"code": 10000, "message": "Authentication error"}], "messages": [], "result": null}`
}

func cisZonesClient(t *testing.T, u string) *zonesv1.ZonesV1 {
	crn := testCisCRN
	svc, err := zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{URL: u, Authenticator: &core.NoAuthAuthenticator{}, Crn: &crn})
	require.NoError(t, err)
	return svc
}

func cisSettingsClient(t *testing.T, u string) *zonessettingsv1.ZonesSettingsV1 {
	crn, zone := testCisCRN, testCisZone
	svc, err := zonessettingsv1.NewZonesSettingsV1(&zonessettingsv1.ZonesSettingsV1Options{URL: u, Authenticator: &core.NoAuthAuthenticator{}, Crn: &crn, ZoneIdentifier: &zone})
	require.NoError(t, err)
	return svc
}

func cisSslClient(t *testing.T, u string) *sslcertificateapiv1.SslCertificateApiV1 {
	crn, zone := testCisCRN, testCisZone
	svc, err := sslcertificateapiv1.NewSslCertificateApiV1(&sslcertificateapiv1.SslCertificateApiV1Options{URL: u, Authenticator: &core.NoAuthAuthenticator{}, Crn: &crn, ZoneIdentifier: &zone})
	require.NoError(t, err)
	return svc
}

func cisDnsClient(t *testing.T, u string) *dnsrecordsv1.DnsRecordsV1 {
	crn, zone := testCisCRN, testCisZone
	svc, err := dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{URL: u, Authenticator: &core.NoAuthAuthenticator{}, Crn: &crn, ZoneIdentifier: &zone})
	require.NoError(t, err)
	return svc
}

func cisGlbClient(t *testing.T, u string) *globalloadbalancerv1.GlobalLoadBalancerV1 {
	crn, zone := testCisCRN, testCisZone
	svc, err := globalloadbalancerv1.NewGlobalLoadBalancerV1(&globalloadbalancerv1.GlobalLoadBalancerV1Options{URL: u, Authenticator: &core.NoAuthAuthenticator{}, Crn: &crn, ZoneIdentifier: &zone})
	require.NoError(t, err)
	return svc
}

func TestListCisZonesPages(t *testing.T) {
	zone := func(id, name string) string {
		return `{"id": "` + id + `", "name": "` + name + `", "status": "active", "paused": false,
			"name_servers": ["ns1.example.net", "ns2.example.net"],
			"created_on": "2026-10-01T08:00:00.123456Z", "modified_on": "2026-10-02T08:00:00Z"}`
	}
	full := "["
	for i := range int(cisZonePageSize) {
		if i > 0 {
			full += ","
		}
		full += zone("z"+string(rune('a'+i%26))+string(rune('a'+i/26)), "example.com")
	}
	full += "]"
	var urls []*url.URL
	u := cisServer(t, func(r *http.Request) (int, string) {
		require.Equal(t, "/v1/"+testCisCRN+"/zones", r.URL.Path)
		if r.URL.Query().Get("page") == "1" {
			return http.StatusOK, `{"success": true, "errors": [], "messages": [], "result": ` + full + `,
				"result_info": {"page": 1, "per_page": 50, "count": 50, "total_count": 51}}`
		}
		return http.StatusOK, `{"success": true, "errors": [], "messages": [], "result": [` + zone("last", "example.org") + `],
			"result_info": {"page": 2, "per_page": 50, "count": 1, "total_count": 51}}`
	}, &urls)

	zones, err := listCisZones(cisZonesClient(t, u))
	require.NoError(t, err)
	require.Len(t, zones, 51)
	require.Len(t, urls, 2)
	assert.Equal(t, "1", urls[0].Query().Get("page"))
	assert.Equal(t, "50", urls[0].Query().Get("per_page"))
	assert.Equal(t, "2", urls[1].Query().Get("page"))

	args := cisZoneArgs(testCisCRN, zones[50])
	assert.Equal(t, "ibm.cis.zone/"+testCisCRN+"/last", args["__id"].Value)
	assert.Equal(t, "last", args["id"].Value)
	assert.Equal(t, "example.org", args["name"].Value)
	assert.Equal(t, "active", args["status"].Value)
	assert.Equal(t, false, args["paused"].Value)
	assert.Equal(t, []any{"ns1.example.net", "ns2.example.net"}, args["nameServers"].Value)
	assert.NotNil(t, args["createdAt"].Value, "fractional seconds parse")
	assert.NotNil(t, args["modifiedAt"].Value)
}

func TestListCisZonesSinglePage(t *testing.T) {
	var urls []*url.URL
	u := cisServer(t, byPath(t, map[string]string{
		"/v1/" + testCisCRN + "/zones": `{"success": true, "errors": [], "messages": [],
			"result": [{"id": "z1", "name": "example.com", "status": "pending", "paused": true}],
			"result_info": {"page": 1, "per_page": 50, "count": 1, "total_count": 1}}`,
	}), &urls)
	zones, err := listCisZones(cisZonesClient(t, u))
	require.NoError(t, err)
	require.Len(t, zones, 1)
	assert.Len(t, urls, 1, "a short page is the last one")
	args := cisZoneArgs(testCisCRN, zones[0])
	assert.Equal(t, true, args["paused"].Value)
	assert.Nil(t, args["createdAt"].Value, "an absent timestamp is null")
}

func TestMorePages(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	assert.True(t, morePages(n(120), 50, 50, 50))
	assert.False(t, morePages(n(100), 50, 100, 50), "every item read")
	assert.False(t, morePages(n(120), 20, 120, 50), "a short page is the last")
	assert.False(t, morePages(nil, 0, 0, 50), "an empty page ends the walk")
	assert.True(t, morePages(nil, 50, 50, 50), "without a total, a full page may have a successor")
}

func TestCisZoneSettings(t *testing.T) {
	base := "/v1/" + testCisCRN + "/zones/" + testCisZone + "/settings/"
	setting := func(id, value string) string {
		return `{"success": true, "errors": [], "messages": [],
			"result": {"id": "` + id + `", "value": "` + value + `", "editable": true, "modified_on": "2026-10-01T08:00:00Z"}}`
	}
	u := cisServer(t, byPath(t, map[string]string{
		base + "min_tls_version":  setting("min_tls_version", "1.2"),
		base + "always_use_https": setting("always_use_https", "on"),
		base + "waf":              setting("waf", "on"),
		base + "ssl":              setting("ssl", "strict"),
		base + "tls_1_3":          setting("tls_1_3", "zrt"),
	}), nil)

	settings := cisSettingsClient(t, u)
	v, err := cisMinTlsVersion(settings)
	require.NoError(t, err)
	assert.Equal(t, "1.2", v)
	v, err = cisAlwaysUseHttps(settings)
	require.NoError(t, err)
	assert.Equal(t, "on", v)
	v, err = cisWaf(settings)
	require.NoError(t, err)
	assert.Equal(t, "on", v)

	ssl := cisSslClient(t, u)
	v, err = cisSslMode(ssl)
	require.NoError(t, err)
	assert.Equal(t, "strict", v)
	v, err = cisTls13(ssl)
	require.NoError(t, err)
	assert.Equal(t, "zrt", v)
}

// The CIS SDK hides the HTTP problem of a failed call; the status is taken
// from the response so a refusal is an error on the field, not an empty
// answer.
func TestCisRefused(t *testing.T) {
	u := cisServer(t, refuseAll, nil)
	forbidden := llx.ErrorKind_ERROR_KIND_FORBIDDEN

	_, resp, err := cisZonesClient(t, u).ListZones(&zonesv1.ListZonesOptions{})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyError(err, "")), "the SDK error alone hides the status")
	assert.Equal(t, forbidden, llx.KindOf(classifyError(withStatus(err, resp), "")))

	_, err = listCisZones(cisZonesClient(t, u))
	assert.Equal(t, forbidden, llx.KindOf(err))

	settings := cisSettingsClient(t, u)
	_, err = cisMinTlsVersion(settings)
	assert.Equal(t, forbidden, llx.KindOf(err))
	_, err = cisAlwaysUseHttps(settings)
	assert.Equal(t, forbidden, llx.KindOf(err))
	_, err = cisWaf(settings)
	assert.Equal(t, forbidden, llx.KindOf(err))

	ssl := cisSslClient(t, u)
	_, err = cisSslMode(ssl)
	assert.Equal(t, forbidden, llx.KindOf(err))
	_, err = cisTls13(ssl)
	assert.Equal(t, forbidden, llx.KindOf(err))

	records, err := listCisDnsRecords(cisDnsClient(t, u))
	assert.Nil(t, records)
	assert.Equal(t, forbidden, llx.KindOf(err))

	lbs, err := listCisGlobalLoadBalancers(cisGlbClient(t, u))
	assert.Nil(t, lbs)
	assert.Equal(t, forbidden, llx.KindOf(err))
}

func TestListCisDnsRecords(t *testing.T) {
	record := func(id, name, typ string, proxiable, proxied bool) string {
		b := func(v bool) string {
			if v {
				return "true"
			}
			return "false"
		}
		return `{"id": "` + id + `", "name": "` + name + `", "type": "` + typ + `", "content": "192.0.2.1",
			"zone_id": "zone-1", "zone_name": "example.com", "proxiable": ` + b(proxiable) + `, "proxied": ` + b(proxied) + `,
			"ttl": 1, "created_on": "2026-10-01T08:00:00Z", "modified_on": "2026-10-01T08:00:00Z"}`
	}
	var urls []*url.URL
	u := cisServer(t, func(r *http.Request) (int, string) {
		require.Equal(t, "/v1/"+testCisCRN+"/zones/"+testCisZone+"/dns_records", r.URL.Path)
		if r.URL.Query().Get("page") == "1" {
			page := "["
			for i := range int(cisRecordPageSize) {
				if i > 0 {
					page += ","
				}
				page += record("r"+string(rune('a'+i%26))+string(rune('a'+i/26)), "www.example.com", "A", true, true)
			}
			page += "]"
			return http.StatusOK, `{"success": true, "errors": [], "messages": [], "result": ` + page + `,
				"result_info": {"page": 1, "per_page": 100, "count": 100, "total_count": 102}}`
		}
		return http.StatusOK, `{"success": true, "errors": [], "messages": [], "result": [` +
			record("origin", "origin.example.com", "A", true, false) + `,` +
			record("txt", "example.com", "TXT", false, false) + `],
			"result_info": {"page": 2, "per_page": 100, "count": 2, "total_count": 102}}`
	}, &urls)

	records, err := listCisDnsRecords(cisDnsClient(t, u))
	require.NoError(t, err)
	require.Len(t, records, 102)
	require.Len(t, urls, 2)
	assert.Equal(t, "100", urls[0].Query().Get("per_page"))
	assert.Equal(t, "2", urls[1].Query().Get("page"))

	exposed := cisDnsRecordArgs(testCisCRN, testCisZone, records[100])
	assert.Equal(t, "ibm.cis.dnsRecord/"+testCisCRN+"/"+testCisZone+"/origin", exposed["__id"].Value)
	assert.Equal(t, "origin.example.com", exposed["name"].Value)
	assert.Equal(t, "A", exposed["type"].Value)
	assert.Equal(t, "192.0.2.1", exposed["content"].Value)
	assert.Equal(t, true, exposed["proxiable"].Value)
	assert.Equal(t, false, exposed["proxied"].Value)
	assert.Equal(t, int64(1), exposed["ttl"].Value)
	assert.NotNil(t, exposed["createdAt"].Value)

	txt := cisDnsRecordArgs(testCisCRN, testCisZone, records[101])
	assert.Equal(t, false, txt["proxiable"].Value)

	// A record without the flags is neither proxiable nor proxied.
	bare := cisDnsRecordArgs(testCisCRN, testCisZone, dnsrecordsv1.DnsrecordDetails{})
	assert.Equal(t, false, bare["proxiable"].Value)
	assert.Equal(t, false, bare["proxied"].Value)
	assert.Nil(t, bare["ttl"].Value)
}

func TestListCisGlobalLoadBalancers(t *testing.T) {
	u := cisServer(t, byPath(t, map[string]string{
		"/v1/" + testCisCRN + "/zones/" + testCisZone + "/load_balancers": `{"success": true, "errors": [], "messages": [],
			"result": [
				{"id": "lb-1", "created_on": "2026-10-01T08:00:00Z", "modified_on": "2026-10-02T08:00:00Z",
				 "description": "web", "name": "www.example.com", "ttl": 30, "fallback_pool": "pool-3",
				 "default_pools": ["pool-1", "pool-2"], "region_pools": {}, "pop_pools": {},
				 "proxied": true, "enabled": true, "session_affinity": "none", "steering_policy": "geo"},
				{"id": "lb-2", "created_on": "2026-10-01T08:00:00Z", "modified_on": "2026-10-01T08:00:00Z",
				 "description": "", "name": "api.example.com", "ttl": 60, "fallback_pool": "pool-1",
				 "default_pools": ["pool-1"], "region_pools": {}, "pop_pools": {},
				 "proxied": false, "enabled": false, "session_affinity": "cookie", "steering_policy": "off"}
			],
			"result_info": {"page": 1, "per_page": 20, "count": 2, "total_count": 2}}`,
	}), nil)

	lbs, err := listCisGlobalLoadBalancers(cisGlbClient(t, u))
	require.NoError(t, err)
	require.Len(t, lbs, 2)

	args := cisGlobalLoadBalancerArgs(testCisCRN, testCisZone, lbs[0])
	assert.Equal(t, "ibm.cis.globalLoadBalancer/"+testCisCRN+"/"+testCisZone+"/lb-1", args["__id"].Value)
	assert.Equal(t, "www.example.com", args["name"].Value)
	assert.Equal(t, "web", args["description"].Value)
	assert.Equal(t, true, args["enabled"].Value)
	assert.Equal(t, true, args["proxied"].Value)
	assert.Equal(t, int64(30), args["ttl"].Value)
	assert.Equal(t, []any{"pool-1", "pool-2"}, args["defaultPools"].Value)
	assert.Equal(t, "pool-3", args["fallbackPool"].Value)
	assert.Equal(t, "geo", args["steeringPolicy"].Value)
	assert.Equal(t, "none", args["sessionAffinity"].Value)
	assert.NotNil(t, args["createdAt"].Value)

	args = cisGlobalLoadBalancerArgs(testCisCRN, testCisZone, lbs[1])
	assert.Equal(t, false, args["enabled"].Value)
	assert.Equal(t, false, args["proxied"].Value)
	assert.Equal(t, "cookie", args["sessionAffinity"].Value)
}

func TestListCisGlobalLoadBalancersEmpty(t *testing.T) {
	u := cisServer(t, byPath(t, map[string]string{
		"/v1/" + testCisCRN + "/zones/" + testCisZone + "/load_balancers": `{"success": true, "errors": [], "messages": [], "result": [],
			"result_info": {"page": 1, "per_page": 20, "count": 0, "total_count": 0}}`,
	}), nil)
	lbs, err := listCisGlobalLoadBalancers(cisGlbClient(t, u))
	require.NoError(t, err)
	assert.Empty(t, lbs)
}

func TestCisServiceName(t *testing.T) {
	assert.Equal(t, cisService, crnService(testCisCRN))
}
