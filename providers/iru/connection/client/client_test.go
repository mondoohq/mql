// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// fixtures are compact, representative responses modeled on the real Iru
// (Kandji) API shapes, including its quirks: the /devices list is a bare
// array with a string-or-empty `user`, the detail endpoint serializes
// booleans as "True"/"False" and sizes as human strings, and the list
// endpoints are DRF envelopes paged with a `next` URL.
var fixtures = map[string]string{
	// Page 1 of a bare-array, offset-paged endpoint. The second device has
	// no assigned user, which the API returns as an empty string.
	"/api/v1/devices?limit=300&offset=0": `[
		{"device_id":"d1","device_name":"Laptop One","serial_number":"SN1","platform":"Mac",
		 "os_version":"15.0","mdm_enabled":true,"agent_installed":true,"agent_version":"1.2",
		 "blueprint_id":"bp1","blueprint_name":"Standard","is_missing":false,"is_removed":false,
		 "last_check_in":"2026-07-22T18:07:24.422285Z","tags":["exec"],
		 "user":{"id":"u1","name":"Ada","email":"ada@example.com"}},
		{"device_id":"d2","device_name":"Laptop Two","serial_number":"SN2","platform":"Mac",
		 "os_version":"15.1","mdm_enabled":false,"agent_installed":false,"blueprint_id":"",
		 "tags":[],"user":""}
	]`,
	"/api/v1/devices/d1/details": `{
		"general":{"system_version":"15.0 (24A335)","boot_volume":"Macintosh HD","last_user":"ada","time_since_boot":"1 month ago"},
		"mdm":{"mdm_enabled":"True","supervised":"True","install_date":"2026-02-18 14:42:04.257046+00:00"},
		"activation_lock":{"activation_lock_supported":true,"user_activation_lock_enabled":false},
		"filevault":{"filevault_enabled":true,"filevault_prk_escrowed":true,"filevault_recoverykey_type":"Personal","filevault_next_rotation":"2026-08-18T07:03:48.881548Z"},
		"hardware_overview":{"model_identifier":"Mac17,2","processor_name":"Apple M5","number_of_processors":"1","total_number_of_cores":"10","memory":"32 GB LPDDR5","battery_health":"normal"},
		"security_information":{"remote_desktop_enabled":false},
		"network":{"ip_address":"10.0.0.5","public_ip":"","local_hostname":"laptop-one","mac_address":"aa:bb:cc:dd:ee:ff"},
		"recovery_information":{"recovery_lock_enabled":false,"firmware_password_exist":false},
		"volumes":[{"name":"Macintosh HD","format":"APFS","identifier":"disk3s1","capacity":"926.3 GB","available":"95.38 GB","percent_used":"89%","encrypted":"Yes"}],
		"installed_profiles":[{"name":"Docker Settings","uuid":"pr1","identifier":"com.example.docker","organization":"Example, Inc.","verified":"verified","install_date":"2026-02-18 14:42:41 +0000","payload_types":["com.apple.servicemanagement"]}]
	}`,
	"/api/v1/devices/d1/apps": `{"device_id":"d1","apps":[
		{"app_id":"123","app_name":"1Password","bundle_id":"com.1password.1password","version":"8.12.8","bundle_size":"500357377","source":"Identified Developer","path":"/Applications/1Password.app"}
	]}`,
	"/api/v1/devices/d1/parameters": `{"device_id":"d1","parameters":[
		{"item_id":"p1","name":"Disable NFS Server","category":"Network","subcategory":"Sharing","status":"PASS"},
		{"item_id":"p2","name":"Report available macOS updates","category":"macOS Applications & Services","subcategory":"Software Update","status":"WARNING"}
	]}`,
	// Envelope, offset-paged across two pages to exercise `next`-following.
	"/api/v1/blueprints?limit=300": `{"count":2,"next":"https://host/api/v1/blueprints?limit=300&offset=1","previous":null,"results":[
		{"id":"bp1","name":"Standard","description":"first","icon":"ss-files","color":"aqua-800","type":"map","computers_count":39,"enrollment_code":{"code":"490278","is_active":true},"created_at":"2023-09-25T01:32:13.906795Z","updated_at":"2024-11-14T16:51:40.178674Z"}
	]}`,
	"/api/v1/blueprints?limit=300&offset=1": `{"count":2,"next":null,"previous":null,"results":[
		{"id":"bp2","name":"Second","description":"second","type":"map","computers_count":0,"enrollment_code":{"code":"111111","is_active":false},"created_at":"2023-01-01T00:00:00Z","updated_at":"2023-01-02T00:00:00Z"}
	]}`,
	// Envelope, cursor-paged (the `next` carries an opaque cursor).
	"/api/v1/users?limit=300": `{"next":"https://host/api/v1/users?cursor=abc&limit=300","previous":null,"results":[
		{"id":"u1","name":"Ada","email":"ada@example.com","active":true,"archived":false,"department":null,"job_title":null,"device_count":1,"created_at":"2026-07-03T16:18:45.351554Z","updated_at":"2026-07-03T16:18:45.351560Z","integration":{"id":1,"name":"Example GWS","uuid":"i1","type":"gsuite"}}
	]}`,
	"/api/v1/users?cursor=abc&limit=300": `{"next":null,"previous":null,"results":[
		{"id":"u2","name":"Grace","email":"grace@example.com","active":false,"archived":true,"department":"Eng","job_title":"SRE","device_count":0,"created_at":"2026-07-04T00:00:00Z","updated_at":"2026-07-04T00:00:00Z"}
	]}`,
	"/api/v1/library/custom-apps?limit=300": `{"count":1,"next":null,"previous":null,"results":[
		{"id":"la1","name":"Crowdstrike","active":true,"install_type":"zip","file_url":"https://x/y.zip","sha256":"abc","created_at":"2023-05-05T15:19:13.251836Z","updated_at":"2023-05-06T00:00:00Z"}
	]}`,
	"/api/v1/library/custom-profiles?limit=300": `{"count":1,"next":null,"previous":null,"results":[
		{"id":"lp1","name":"CrowdStrike Settings","active":true,"mdm_identifier":"com.example.cs","runs_on_mac":true,"created_at":"2023-05-08T03:23:38.242466Z","updated_at":"2023-05-09T00:00:00Z"}
	]}`,
	"/api/v1/library/custom-scripts?limit=300": `{"count":1,"next":null,"previous":null,"results":[
		{"id":"ls1","name":"Mondoo Evergreen","active":true,"execution_frequency":"every_15_min","script":"#!/bin/bash","created_at":"2022-04-13T14:11:50.052487Z","updated_at":"2022-04-14T00:00:00Z"}
	]}`,
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		body, ok := fixtures[key]
		if !ok {
			http.Error(w, "no fixture for "+key, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	// The fixtures' `next` URLs use host "host"; the client follows only the
	// path+query, so the test server host is used regardless.
	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestListDevices(t *testing.T) {
	c := newTestClient(t)
	devs, err := c.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("got %d devices, want 2", len(devs))
	}
	if !devs[0].MDMEnabled || !devs[0].AgentInstalled {
		t.Errorf("device 0 booleans not decoded: %+v", devs[0])
	}
	// Device 0 has an object user; device 1 has an empty-string user.
	if u := devs[0].EmbeddedUser(); u == nil || u.ID != "u1" {
		t.Errorf("device 0 EmbeddedUser = %v, want id u1", u)
	}
	if u := devs[1].EmbeddedUser(); u != nil {
		t.Errorf("device 1 EmbeddedUser = %v, want nil (empty-string user)", u)
	}
}

func TestPaginateArrayMultiPage(t *testing.T) {
	// The /devices endpoint is a bare array paged with limit/offset; the loop
	// must keep requesting until a page returns fewer than a full page and must
	// advance the offset by the number of rows already seen. Serve 300 (a full
	// page) then 50 so the second request is exercised and a truncation bug
	// (stopping after page one, or advancing the offset wrong) would be caught.
	const total = 350
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		requests++
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var b strings.Builder
		b.WriteByte('[')
		for i := offset; i < offset+limit && i < total; i++ {
			if i > offset {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"device_id":"d%d"}`, i)
		}
		b.WriteByte(']')
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(srv.Close)

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devs, err := c.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != total {
		t.Fatalf("got %d devices across pages, want %d", len(devs), total)
	}
	// First and last ids come from different pages, proving the offset advanced.
	if devs[0].DeviceID != "d0" || devs[total-1].DeviceID != "d349" {
		t.Errorf("unexpected boundary ids: first=%q last=%q", devs[0].DeviceID, devs[total-1].DeviceID)
	}
	if requests != 2 {
		t.Errorf("made %d requests, want 2 (300 + 50)", requests)
	}
}

func TestGetDeviceDetails(t *testing.T) {
	c := newTestClient(t)
	d, err := c.GetDeviceDetails("d1")
	if err != nil {
		t.Fatalf("GetDeviceDetails: %v", err)
	}
	if got := ParseBool(d.MDM.Supervised); !got {
		t.Errorf("supervised = %q parsed false, want true", d.MDM.Supervised)
	}
	if d.HardwareOverview.Memory != "32 GB LPDDR5" {
		t.Errorf("memory = %q, want human string", d.HardwareOverview.Memory)
	}
	if got := ParseInt(d.HardwareOverview.TotalNumberOfCores); got != 10 {
		t.Errorf("core count = %d, want 10", got)
	}
	if len(d.Volumes) != 1 || d.Volumes[0].Encrypted != "Yes" {
		t.Errorf("volume not decoded: %+v", d.Volumes)
	}
	if !d.FileVault.Enabled || !d.FileVault.PRKEscrowed {
		t.Errorf("filevault not decoded: %+v", d.FileVault)
	}
}

func TestGetDeviceAppsAndParameters(t *testing.T) {
	c := newTestClient(t)
	apps, err := c.GetDeviceApps("d1")
	if err != nil {
		t.Fatalf("GetDeviceApps: %v", err)
	}
	if len(apps) != 1 || apps[0].Name != "1Password" || ParseInt(apps[0].BundleSize) != 500357377 {
		t.Errorf("apps not decoded: %+v", apps)
	}
	params, err := c.GetDeviceParameters("d1")
	if err != nil {
		t.Fatalf("GetDeviceParameters: %v", err)
	}
	if len(params) != 2 || params[1].Status != "WARNING" {
		t.Errorf("parameters not decoded: %+v", params)
	}
}

func TestListBlueprintsPaginates(t *testing.T) {
	c := newTestClient(t)
	bps, err := c.ListBlueprints()
	if err != nil {
		t.Fatalf("ListBlueprints: %v", err)
	}
	if len(bps) != 2 {
		t.Fatalf("got %d blueprints across pages, want 2", len(bps))
	}
	if bps[0].EnrollmentCode.Code != "490278" || !bps[0].EnrollmentCode.IsActive {
		t.Errorf("enrollment code object not decoded: %+v", bps[0].EnrollmentCode)
	}
	if bps[0].ComputersCount != 39 {
		t.Errorf("computers_count = %d, want 39", bps[0].ComputersCount)
	}
}

func TestListUsersPaginatesCursor(t *testing.T) {
	c := newTestClient(t)
	users, err := c.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users across cursor pages, want 2", len(users))
	}
	// Second page user is archived and has an integration-less record.
	if !users[1].Archived {
		t.Errorf("user 1 archived = false, want true")
	}
	if users[0].Integration == nil || users[0].Integration.Type != "gsuite" {
		t.Errorf("user 0 integration not decoded: %+v", users[0].Integration)
	}
}

func TestListLibraryItemsAggregates(t *testing.T) {
	c := newTestClient(t)
	items, err := c.ListLibraryItems()
	if err != nil {
		t.Fatalf("ListLibraryItems: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d library items, want 3 (one per endpoint)", len(items))
	}
	kinds := map[string]LibraryItem{}
	for _, it := range items {
		kinds[it.Kind] = it
	}
	for _, want := range []string{"custom-app", "custom-profile", "custom-script"} {
		if _, ok := kinds[want]; !ok {
			t.Errorf("missing library item of kind %q", want)
		}
	}
	// Common fields are lifted out; kind-specific fields stay in payload.
	script := kinds["custom-script"]
	if script.Name != "Mondoo Evergreen" {
		t.Errorf("script name = %q", script.Name)
	}
	if _, ok := script.Payload["id"]; ok {
		t.Errorf("payload should not carry the lifted `id` field")
	}
	if freq, _ := script.Payload["execution_frequency"].(string); freq != "every_15_min" {
		t.Errorf("payload execution_frequency = %v, want every_15_min", script.Payload["execution_frequency"])
	}
}

func TestAPIErrorAndAccessDenied(t *testing.T) {
	c := newTestClient(t)
	// An unknown path returns a 404 fixture-miss, surfaced as an APIError.
	_, err := c.GetDeviceDetails("missing")
	if err == nil {
		t.Fatal("expected error for missing device details")
	}
	if IsAccessDenied(err) {
		t.Errorf("404 should not be reported as access-denied")
	}
	if !strings.Contains(err.Error(), "iru:") {
		t.Errorf("error not wrapped as APIError: %v", err)
	}
}

func TestIsAccessDenied(t *testing.T) {
	// A 401 on a listing endpoint must be classified as access-denied so the
	// resource layer can degrade to an empty list instead of failing the
	// whole query (Kandji tokens carry per-endpoint permission flags).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Invalid authentication"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "bad-token")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.ListBlueprints()
	if err == nil {
		t.Fatal("expected error from a 401 endpoint")
	}
	if !IsAccessDenied(err) {
		t.Errorf("401 not classified as access-denied: %v", err)
	}
}
