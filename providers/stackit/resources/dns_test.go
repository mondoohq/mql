// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	dns "github.com/stackitcloud/stackit-sdk-go/services/dns/v1api"
)

func TestDnsLabels(t *testing.T) {
	if got := dnsLabels(nil); got != nil {
		t.Fatalf("nil input: got %#v, want nil", got)
	}

	k1, v1 := "env", "prod"
	k2, v2 := "team", "sec"
	in := []dns.Label{{Key: k1, Value: &v1}, {Key: k2, Value: &v2}}
	got := dnsLabels(in)
	want := map[string]string{"env": "prod", "team": "sec"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// dnsZoneJSON is a zone with every field the SDK requires, plus extra.
func dnsZoneJSON(extra string) string {
	return `{"acl":"0.0.0.0/0","creationFinished":"2026-01-01T00:00:00Z","creationStarted":"2026-01-01T00:00:00Z",` +
		`"defaultTTL":3600,"dnsName":"example.com.","expireTime":1209600,"id":"z-1","name":"example","negativeCache":60,` +
		`"primaryNameServer":"ns1.example.com.","refreshTime":3600,"retryTime":600,"serialNumber":1,"state":"CREATE_SUCCEEDED",` +
		`"type":"primary","updateFinished":"2026-02-01T10:05:00Z","updateStarted":"2026-02-01T10:00:00Z","visibility":"public"` + extra + `}`
}

func TestDnsZoneObservabilityInstanceID(t *testing.T) {
	// Synthetic: zones with and without the observability extension; no live account was checked.
	var z dns.Zone
	if err := json.Unmarshal([]byte(dnsZoneJSON(`,"extensions":{"observabilityExtension":{"observabilityInstanceId":"obs-1","state":"CREATE_SUCCEEDED"}}`)), &z); err != nil {
		t.Fatal(err)
	}
	if got := dnsZoneObservabilityInstanceID(&z); got != "obs-1" {
		t.Fatalf("got %q, want obs-1", got)
	}
	var bare dns.Zone
	if err := json.Unmarshal([]byte(dnsZoneJSON("")), &bare); err != nil {
		t.Fatal(err)
	}
	if got := dnsZoneObservabilityInstanceID(&bare); got != "" {
		t.Fatalf("got %q, want empty for a zone without the extension", got)
	}
}

func TestDnsZoneStatusFields(t *testing.T) {
	// Synthetic: a zone in an error state linked to an instance that the
	// project lists, and one linked to an instance it does not; no live
	// account was checked.
	obsPath := "GET /v1/projects/" + fakeProjectID + "/instances"
	runtime, api := fakeRuntime(t, map[string]fakeAnswer{
		obsPath: json200(`{"message":"ok","instances":[{"id":"obs-1","instance":"i","planName":"p","serviceName":"s","status":"CREATE_SUCCEEDED"}]}`),
	})
	var z dns.Zone
	if err := json.Unmarshal([]byte(dnsZoneJSON(`,"active":false,"error":"delegation failed",`+
		`"extensions":{"observabilityExtension":{"observabilityInstanceId":"obs-1"}}`)), &z); err != nil {
		t.Fatal(err)
	}
	res, err := buildDnsZone(runtime, &z)
	if err != nil {
		t.Fatal(err)
	}
	zone := res.(*mqlStackitDnsZone)
	if zone.Name.Data != "example" || zone.ErrorMessage.Data != "delegation failed" || zone.Active.Data {
		t.Fatalf("name/errorMessage/active = %q/%q/%v", zone.Name.Data, zone.ErrorMessage.Data, zone.Active.Data)
	}
	if want := time.Date(2026, 2, 1, 10, 5, 0, 0, time.UTC); !zone.UpdateFinishedAt.Data.Equal(want) {
		t.Fatalf("updateFinishedAt = %v, want %v", zone.UpdateFinishedAt.Data, want)
	}
	obs := zone.GetObservabilityInstance()
	if obs.Error != nil || obs.Data == nil || obs.Data.Id.Data != "obs-1" {
		t.Fatalf("observabilityInstance = %v, %v; want obs-1", obs.Data, obs.Error)
	}

	var other dns.Zone
	if err := json.Unmarshal([]byte(dnsZoneJSON(`,"id":"z-2","extensions":{"observabilityExtension":{"observabilityInstanceId":"obs-elsewhere"}}`)), &other); err != nil {
		t.Fatal(err)
	}
	res, err = buildDnsZone(runtime, &other)
	if err != nil {
		t.Fatal(err)
	}
	obs = res.(*mqlStackitDnsZone).GetObservabilityInstance()
	if obs.Error != nil || obs.Data != nil {
		t.Fatalf("an instance the project does not list must read null, got %v, %v", obs.Data, obs.Error)
	}
	if n := api.count(obsPath); n != 1 {
		t.Fatalf("instance list read %d times, want 1", n)
	}
}
