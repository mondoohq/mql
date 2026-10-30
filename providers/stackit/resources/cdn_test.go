// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	cdn "github.com/stackitcloud/stackit-sdk-go/services/cdn/v1api"
	"go.mondoo.com/mql/llx"
)

// argsContain reports whether any mapped value, rendered as text, contains
// needle. Used to prove a secret-shaped input never reaches a field.
func argsContain(args map[string]*llx.RawData, needle string) bool {
	for _, v := range args {
		if v != nil && strings.Contains(fmt.Sprintf("%v", v.Value), needle) {
			return true
		}
	}
	return false
}

const cdnHTTPDistribution = `{
  "id": "d-1", "projectId": "p-1", "status": "ACTIVE",
  "createdAt": "2026-09-01T10:00:00Z", "updatedAt": "2026-09-02T10:00:00Z",
  "domains": [{"name": "d-1.cdn.stackit.cloud", "type": "managed", "status": "ACTIVE", "certificateType": "managed"}],
  "errors": [{"en": "origin unreachable", "key": "ORIGIN_UNREACHABLE"}],
  "config": {
    "backend": {"type": "http", "originUrl": "https://origin.example.com", "originRequestHeaders": {"X-Origin-Auth": "s3cr3t-value", "Accept": "*/*"}, "geofencing": {}},
    "blockedCountries": ["RU"], "blockedIps": ["203.0.113.7"],
    "cacheConfig": {"cacheKeyHeaders": [], "queryStringVaryEnabled": false, "queryStringVaryParameters": []},
    "forwardHostHeader": true, "stripResponseCookies": false,
    "regions": ["EU", "US"],
    "tls": {"enableTls10": true, "enableTls11": false},
    "waf": {"mode": "LOG_ONLY", "type": "FREE", "enabledRuleIds": [], "disabledRuleIds": ["942100"]},
    "logSink": {"type": "otlp", "pushUrl": "https://otlp.example.com/v1/logs"},
    "monthlyLimitBytes": 1000
  }
}`

func TestCdnDistributionArgsHTTPOrigin(t *testing.T) {
	var d cdn.Distribution
	if err := json.Unmarshal([]byte(cdnHTTPDistribution), &d); err != nil {
		t.Fatalf("decoding distribution: %v", err)
	}
	args := cdnDistributionArgs(&d)

	if args["backendType"].Value != "http" || args["originUrl"].Value != "https://origin.example.com" || args["bucketUrl"].Value != "" {
		t.Fatalf("backend = %v %v %v", args["backendType"].Value, args["originUrl"].Value, args["bucketUrl"].Value)
	}
	names := args["originRequestHeaderNames"].Value.([]any)
	if len(names) != 2 || names[0] != "Accept" || names[1] != "X-Origin-Auth" {
		t.Fatalf("originRequestHeaderNames = %v", names)
	}
	if argsContain(args, "s3cr3t-value") {
		t.Fatal("an origin request header value reached the mapped fields")
	}
	if args["tls10Enabled"].Value != true || args["tls11Enabled"].Value != false {
		t.Fatalf("tls10/tls11 = %v/%v", args["tls10Enabled"].Value, args["tls11Enabled"].Value)
	}
	if args["wafMode"].Value != "LOG_ONLY" || args["wafType"].Value != "FREE" {
		t.Fatalf("waf mode/type = %v/%v", args["wafMode"].Value, args["wafType"].Value)
	}
	if args["wafParanoiaLevel"].Value != nil {
		t.Fatalf("absent paranoia level should be null, got %v", args["wafParanoiaLevel"].Value)
	}
	if got := args["wafDisabledRuleIds"].Value.([]any); len(got) != 1 || got[0] != "942100" {
		t.Fatalf("wafDisabledRuleIds = %v", got)
	}
	if args["logSinkType"].Value != "otlp" || args["logSinkPushUrl"].Value != "https://otlp.example.com/v1/logs" {
		t.Fatalf("log sink = %v %v", args["logSinkType"].Value, args["logSinkPushUrl"].Value)
	}
	if args["monthlyLimitBytes"].Value != int64(1000) {
		t.Fatalf("monthlyLimitBytes = %v", args["monthlyLimitBytes"].Value)
	}
	if got := args["regions"].Value.([]any); len(got) != 2 || got[1] != "US" {
		t.Fatalf("regions = %v", got)
	}
	if got := args["errors"].Value.([]any); len(got) != 1 || got[0] != "origin unreachable" {
		t.Fatalf("errors = %v", got)
	}
}

func TestCdnDistributionArgsBucketOrigin(t *testing.T) {
	var d cdn.Distribution
	body := strings.Replace(cdnHTTPDistribution,
		`{"type": "http", "originUrl": "https://origin.example.com", "originRequestHeaders": {"X-Origin-Auth": "s3cr3t-value", "Accept": "*/*"}, "geofencing": {}}`,
		`{"type": "bucket", "bucketUrl": "https://bucket.object.storage.eu01.onstackit.cloud", "region": "eu01"}`, 1)
	body = strings.Replace(body, `"logSink": {"type": "otlp", "pushUrl": "https://otlp.example.com/v1/logs"},`, `"waf2": null,`, 1)
	body = strings.Replace(body, `"monthlyLimitBytes": 1000`, `"defaultCacheDuration": null`, 1)
	body = strings.Replace(body, `"type": "FREE",`, `"type": "PREMIUM", "paranoiaLevel": "L3",`, 1)
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decoding distribution: %v", err)
	}
	args := cdnDistributionArgs(&d)
	if args["backendType"].Value != "bucket" || args["bucketRegion"].Value != "eu01" || args["originUrl"].Value != "" {
		t.Fatalf("backend = %v %v %v", args["backendType"].Value, args["bucketRegion"].Value, args["originUrl"].Value)
	}
	if got := args["originRequestHeaderNames"].Value.([]any); len(got) != 0 {
		t.Fatalf("bucket origin should carry no header names, got %v", got)
	}
	if args["logSinkType"].Value != "" || args["monthlyLimitBytes"].Value != nil {
		t.Fatalf("absent log sink/limit = %v/%v", args["logSinkType"].Value, args["monthlyLimitBytes"].Value)
	}
	if args["wafParanoiaLevel"].Value != "L3" {
		t.Fatalf("wafParanoiaLevel = %v", args["wafParanoiaLevel"].Value)
	}
}

func TestListAllCdnDistributionsPaginates(t *testing.T) {
	page := func(id, next string) *cdn.ListDistributionsResponse {
		r := &cdn.ListDistributionsResponse{Distributions: []cdn.Distribution{{Id: id}}}
		if next != "" {
			r.NextPageIdentifier = &next
		}
		return r
	}
	pages := map[string]*cdn.ListDistributionsResponse{
		"":   page("a", "p2"),
		"p2": page("b", "p3"),
		"p3": page("c", ""),
	}
	got, err := listAllCdnDistributions(func(p string) (*cdn.ListDistributionsResponse, error) { return pages[p], nil })
	if err != nil || len(got) != 3 || got[2].Id != "c" {
		t.Fatalf("got %d distributions, err %v", len(got), err)
	}

	calls := 0
	stuck, err := listAllCdnDistributions(func(p string) (*cdn.ListDistributionsResponse, error) {
		calls++
		return page("x", "same"), nil
	})
	if err != nil || calls != 2 || len(stuck) != 2 {
		t.Fatalf("stuck cursor: %d calls, %d items, err %v", calls, len(stuck), err)
	}

	boom := errors.New("boom")
	if _, err := listAllCdnDistributions(func(string) (*cdn.ListDistributionsResponse, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("error not propagated: %v", err)
	}
}
