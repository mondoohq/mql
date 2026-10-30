// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strings"
	"testing"
)

// These records are decoded by struct tag alone, so a mistyped tag compiles and
// yields a zero value: a deploy preview would report an empty context, a public
// asset would report an empty visibility, and an unsigned webhook would report
// no destination. Each tag below is pinned against a payload shaped like the
// documented API response.

func TestSiteRecordDecodesCapabilitiesAndInstallation(t *testing.T) {
	const payload = `{
		"id": "site_abc",
		"capabilities": {
			"asset_optimization": {"included": true},
			"form_processing": {}
		},
		"build_settings": {
			"provider": "github",
			"installation_id": 4242
		}
	}`

	var rec siteRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.BuildSettings == nil {
		t.Fatal("build settings decoded as absent")
	}
	if rec.BuildSettings.InstallationID == nil {
		t.Fatal("installation_id decoded as absent")
	}
	if *rec.BuildSettings.InstallationID != 4242 {
		t.Errorf("installation_id decoded wrong: %d", *rec.BuildSettings.InstallationID)
	}

	var caps map[string]any
	if err := json.Unmarshal(rec.Capabilities, &caps); err != nil {
		t.Fatalf("capabilities not captured as JSON: %v", err)
	}
	if _, ok := caps["asset_optimization"]; !ok {
		t.Errorf("capabilities decoded wrong: %v", caps)
	}
}

func TestSiteRecordWithoutInstallationStaysAbsent(t *testing.T) {
	// A site deployed by hand has no app installation and no capability map.
	// Neither may become a zero value: an installation of 0 would name an
	// installation that does not exist, and an empty capability map would read
	// as a plan that offers nothing.
	const payload = `{"id": "site_abc", "build_settings": {"provider": "github"}}`

	var rec siteRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.BuildSettings.InstallationID != nil {
		t.Errorf("absent installation_id became %d", *rec.BuildSettings.InstallationID)
	}
	if len(rec.Capabilities) != 0 {
		t.Errorf("absent capabilities became %q", string(rec.Capabilities))
	}
}

func TestHookDestination(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantHost   string
		hostIsNull bool
		wantSecret string // "true", "false" or "null"
	}{
		{
			name:       "absent settings claim nothing",
			data:       "",
			hostIsNull: true,
			wantSecret: "null",
		},
		{
			name:       "explicit null claims nothing",
			data:       `null`,
			hostIsNull: true,
			wantSecret: "null",
		},
		{
			name:       "unreadable settings claim nothing",
			data:       `"not an object"`,
			hostIsNull: true,
			wantSecret: "null",
		},
		{
			name:       "webhook without a secret",
			data:       `{"url":"https://hooks.example.com/t/deadbeef?token=deadbeef"}`,
			wantHost:   "hooks.example.com",
			wantSecret: "false",
		},
		{
			name:       "webhook with a signing secret",
			data:       `{"url":"https://hooks.example.com/t/deadbeef","jwt_secret":"deadbeef"}`,
			wantHost:   "hooks.example.com",
			wantSecret: "true",
		},
		{
			name:       "signing secret present but blank",
			data:       `{"url":"https://hooks.example.com/t/deadbeef","jwt_secret":""}`,
			wantHost:   "hooks.example.com",
			wantSecret: "false",
		},
		{
			name:       "secret held under an alternate key",
			data:       `{"url":"https://hooks.example.com/t/deadbeef","signing_secret":"deadbeef"}`,
			wantHost:   "hooks.example.com",
			wantSecret: "true",
		},
		{
			name:       "email delivery has no host",
			data:       `{"email":"ops@example.com"}`,
			hostIsNull: true,
			wantSecret: "false",
		},
		{
			name:       "unparseable url has no host",
			data:       `{"url":"://not a url"}`,
			hostIsNull: true,
			wantSecret: "false",
		},
		{
			name:       "empty settings object claims no secret",
			data:       `{}`,
			hostIsNull: true,
			wantSecret: "false",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.data != "" {
				raw = json.RawMessage(tc.data)
			}

			host, secret := hookDestination(raw)

			if tc.hostIsNull {
				if host != nil {
					t.Errorf("expected a null host, got %q", *host)
				}
			} else {
				if host == nil {
					t.Fatalf("expected host %q, got null", tc.wantHost)
				}
				if *host != tc.wantHost {
					t.Errorf("expected host %q, got %q", tc.wantHost, *host)
				}
			}

			got := "null"
			if secret != nil {
				got = "false"
				if *secret {
					got = "true"
				}
			}
			if got != tc.wantSecret {
				t.Errorf("expected hasSigningSecret %s, got %s", tc.wantSecret, got)
			}
		})
	}
}

func TestHookDestinationNeverReportsTheFullAddress(t *testing.T) {
	// The path and query of a webhook address are the bearer part of it, so
	// neither may reach a field. Only the host does.
	const data = `{"url":"https://hooks.example.com/services/deadbeef/deadbeef?token=deadbeef","jwt_secret":"deadbeef"}`

	host, secret := hookDestination(json.RawMessage(data))
	if host == nil || secret == nil {
		t.Fatal("expected a host and a secret verdict")
	}
	if strings.Contains(*host, "deadbeef") || strings.Contains(*host, "/") {
		t.Errorf("host leaked part of the address: %q", *host)
	}
}

func TestDeployRecordDecodesExposureFields(t *testing.T) {
	const payload = `{
		"id": "deploy_1",
		"site_id": "site_abc",
		"state": "ready",
		"context": "deploy-preview",
		"title": "add a thing",
		"branch": "feature",
		"commit_ref": "deadbeef",
		"commit_url": "https://github.example.com/acme/www/commit/deadbeef",
		"deploy_url": "https://deadbeef--www.netlify.app",
		"deploy_ssl_url": "https://deadbeef--www.netlify.app",
		"review_id": 17,
		"review_url": "https://github.example.com/acme/www/pull/17",
		"draft": false,
		"locked": true,
		"skipped": false,
		"framework": "next",
		"error_message": "build failed",
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-02T03:14:05.000Z",
		"published_at": "2026-01-02T03:24:05.000Z"
	}`

	var rec deployRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.ID != "deploy_1" || rec.SiteID != "site_abc" || rec.State != "ready" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if rec.Context != "deploy-preview" {
		t.Errorf("context decoded wrong: %q", rec.Context)
	}
	if rec.ReviewID == nil || *rec.ReviewID != 17 {
		t.Errorf("review_id decoded wrong: %v", rec.ReviewID)
	}
	if rec.Locked == nil || !*rec.Locked {
		t.Errorf("locked decoded wrong: %v", rec.Locked)
	}
	if rec.Draft == nil || *rec.Draft {
		t.Errorf("draft decoded wrong: %v", rec.Draft)
	}
	if rec.Skipped == nil || *rec.Skipped {
		t.Errorf("skipped decoded wrong: %v", rec.Skipped)
	}
	if rec.Branch != "feature" || rec.CommitRef != "deadbeef" {
		t.Errorf("source fields decoded wrong: %+v", rec)
	}
	if rec.DeployURL == "" || rec.DeploySslURL == "" || rec.ReviewURL == "" || rec.CommitURL == "" {
		t.Errorf("address fields decoded wrong: %+v", rec)
	}
	if rec.Framework != "next" || rec.ErrorMessage != "build failed" || rec.Title != "add a thing" {
		t.Errorf("descriptive fields decoded wrong: %+v", rec)
	}
	if rec.PublishedAt.Time() == nil || rec.CreatedAt.Time() == nil || rec.UpdatedAt.Time() == nil {
		t.Errorf("timestamps decoded wrong: %+v", rec)
	}
}

func TestDeployRecordOmittedControlsStayAbsent(t *testing.T) {
	// A production deploy that was never pinned reports no locked key at all on
	// some responses. It must stay null: a fabricated false would say the
	// deploy is known not to be pinned, and a fabricated review_id of 0 would
	// name a pull request that does not exist.
	const payload = `{"id": "deploy_1", "state": "ready", "context": "production"}`

	var rec deployRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Locked != nil || rec.Draft != nil || rec.Skipped != nil {
		t.Errorf("absent controls became values: %+v", rec)
	}
	if rec.ReviewID != nil {
		t.Errorf("absent review_id became %d", *rec.ReviewID)
	}
	if rec.PublishedAt.Time() != nil {
		t.Errorf("absent published_at became %v", rec.PublishedAt.Time())
	}
}

func TestDeployedBranchRecordDecodes(t *testing.T) {
	const payload = `{
		"id": "branch_1",
		"deploy_id": "deploy_1",
		"name": "staging",
		"slug": "staging",
		"url": "http://staging--www.netlify.app",
		"ssl_url": "https://staging--www.netlify.app"
	}`

	var rec deployedBranchRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != "branch_1" || rec.DeployID != "deploy_1" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if rec.Name != "staging" || rec.Slug != "staging" {
		t.Errorf("name fields decoded wrong: %+v", rec)
	}
	if rec.URL == "" || rec.SslURL == "" {
		t.Errorf("address fields decoded wrong: %+v", rec)
	}
}

func TestSniCertificateRecordDecodes(t *testing.T) {
	const payload = `{
		"state": "issued",
		"domains": ["www.example.com", "example.com"],
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-02T03:04:05.000Z",
		"expires_at": "2026-04-02T03:04:05.000Z"
	}`

	var rec sniCertificateRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.State != "issued" {
		t.Errorf("state decoded wrong: %q", rec.State)
	}
	if len(rec.Domains) != 2 || rec.Domains[0] != "www.example.com" {
		t.Errorf("domains decoded wrong: %v", rec.Domains)
	}
	if rec.ExpiresAt.Time() == nil {
		t.Fatal("expires_at decoded as absent")
	}
	if got := rec.ExpiresAt.Time().Format("2006-01-02"); got != "2026-04-02" {
		t.Errorf("expires_at decoded wrong: %s", got)
	}
}

func TestSniCertificateWithoutExpiryStaysNull(t *testing.T) {
	// An expiry the API did not report must not become the zero time, which
	// would report the first of January in year one as a real expiry date and
	// make every certificate look long expired.
	const payload = `{"state": "pending", "domains": []}`

	var rec sniCertificateRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ExpiresAt.Time() != nil {
		t.Errorf("absent expires_at became %v", rec.ExpiresAt.Time())
	}
}

func TestFormRecordDecodesRetentionFields(t *testing.T) {
	const payload = `{
		"id": "form_1",
		"site_id": "site_abc",
		"name": "contact",
		"paths": ["/contact", "/contact/"],
		"submission_count": 1204,
		"created_at": "2026-01-02T03:04:05.000Z"
	}`

	var rec formRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != "form_1" || rec.Name != "contact" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if rec.SubmissionCount != 1204 {
		t.Errorf("submission_count decoded wrong: %d", rec.SubmissionCount)
	}
	if len(rec.Paths) != 2 {
		t.Errorf("paths decoded wrong: %v", rec.Paths)
	}
}

func TestAssetRecordDecodesVisibility(t *testing.T) {
	const payload = `{
		"id": "asset_1",
		"site_id": "site_abc",
		"name": "logo.png",
		"state": "uploaded",
		"content_type": "image/png",
		"url": "https://www.example.com/assets/logo.png",
		"key": "assets/logo.png",
		"visibility": "public",
		"size": 20481,
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-03T03:04:05.000Z"
	}`

	var rec assetRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Visibility != "public" {
		t.Errorf("visibility decoded wrong: %q", rec.Visibility)
	}
	if rec.ContentType != "image/png" || rec.Key != "assets/logo.png" {
		t.Errorf("content fields decoded wrong: %+v", rec)
	}
	if rec.Size != 20481 {
		t.Errorf("size decoded wrong: %d", rec.Size)
	}
	if rec.State != "uploaded" || rec.Name != "logo.png" || rec.URL == "" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
}

func TestSplitTestRecordDecodesActiveAndBranches(t *testing.T) {
	const payload = `{
		"id": "split_1",
		"site_id": "site_abc",
		"name": "homepage",
		"path": "/",
		"active": true,
		"branches": [
			{"branch_name": "main", "percentage": 90},
			{"branch_name": "experiment", "percentage": 10}
		],
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-03T03:04:05.000Z"
	}`

	var rec splitTestRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rec.Active {
		t.Error("active decoded as false on a running split test")
	}
	if len(rec.Branches) != 2 {
		t.Fatalf("branches decoded wrong: %v", rec.Branches)
	}
	entry, ok := rec.Branches[0].(map[string]any)
	if !ok {
		t.Fatalf("branch entry is not an object: %T", rec.Branches[0])
	}
	if entry["branch_name"] != "experiment" && entry["branch_name"] != "main" {
		t.Errorf("branch entry decoded wrong: %v", entry)
	}
	if rec.UnpublishedAt.Time() != nil {
		t.Errorf("absent unpublished_at became %v", rec.UnpublishedAt.Time())
	}
}

func TestServiceInstanceRecordDecodes(t *testing.T) {
	const payload = `{
		"id": "instance_1",
		"url": "https://addon.example.com/instance_1",
		"service_slug": "example-db",
		"service_path": "/.netlify/db",
		"service_name": "Example DB",
		"env": {"EXAMPLE_DB_SECRET": "deadbeef", "EXAMPLE_DB_URL": "deadbeef"},
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-03T03:04:05.000Z"
	}`

	var rec serviceInstanceRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ServiceSlug != "example-db" || rec.ServiceName != "Example DB" {
		t.Errorf("service fields decoded wrong: %+v", rec)
	}
	if rec.ServicePath != "/.netlify/db" || rec.URL == "" || rec.ID != "instance_1" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
}

func TestServiceInstanceEnvNamesReportsNamesOnly(t *testing.T) {
	env := map[string]string{
		"EXAMPLE_DB_URL":    "deadbeef",
		"EXAMPLE_DB_SECRET": "deadbeef",
	}

	names := serviceInstanceEnvNames(env)

	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %v", names)
	}
	// Sorted, so the same site reports the same list every scan.
	if names[0] != "EXAMPLE_DB_SECRET" || names[1] != "EXAMPLE_DB_URL" {
		t.Errorf("names not reported in a stable order: %v", names)
	}
	for _, name := range names {
		if name == "deadbeef" {
			t.Fatal("a variable value reached the name list")
		}
	}
}

func TestServiceInstanceEnvNamesHandlesNoVariables(t *testing.T) {
	if names := serviceInstanceEnvNames(nil); len(names) != 0 {
		t.Errorf("expected no names, got %v", names)
	}
}

func TestDevServerRecordDecodesLifecycle(t *testing.T) {
	const payload = `{
		"id": "dev_1",
		"site_id": "site_abc",
		"branch": "feature",
		"url": "https://dev--www.netlify.app",
		"state": "live",
		"title": "feature preview",
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-02T03:05:05.000Z",
		"live_at": "2026-01-02T03:06:05.000Z"
	}`

	var rec devServerRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.State != "live" || rec.Branch != "feature" || rec.URL == "" {
		t.Errorf("exposure fields decoded wrong: %+v", rec)
	}
	if rec.LiveAt.Time() == nil {
		t.Error("live_at decoded as absent")
	}
	// A server that is still running has no done_at, which must stay null.
	if rec.DoneAt.Time() != nil {
		t.Errorf("absent done_at became %v", rec.DoneAt.Time())
	}
}

func TestAgentRunnerRecordDecodesPullRequestFields(t *testing.T) {
	const payload = `{
		"id": "runner_1",
		"site_id": "site_abc",
		"state": "live",
		"title": "fix the thing",
		"branch": "main",
		"result_branch": "agent/fix-the-thing",
		"pr_url": "https://github.example.com/acme/www/pull/21",
		"pr_branch": "agent/fix-the-thing",
		"pr_state": "open",
		"pr_number": 21,
		"current_task": "running tests",
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-01-02T03:14:05.000Z"
	}`

	var rec agentRunnerRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.PrNumber == nil || *rec.PrNumber != 21 {
		t.Errorf("pr_number decoded wrong: %v", rec.PrNumber)
	}
	if rec.PrState != "open" || rec.PrURL == "" || rec.PrBranch == "" {
		t.Errorf("pull request fields decoded wrong: %+v", rec)
	}
	if rec.ResultBranch != "agent/fix-the-thing" || rec.Branch != "main" {
		t.Errorf("branch fields decoded wrong: %+v", rec)
	}
	if rec.State != "live" || rec.CurrentTask != "running tests" || rec.SiteID != "site_abc" {
		t.Errorf("state fields decoded wrong: %+v", rec)
	}
	// A run that is still going has no done_at, which must stay null.
	if rec.DoneAt.Time() != nil {
		t.Errorf("absent done_at became %v", rec.DoneAt.Time())
	}
}

func TestAgentRunnerWithoutPullRequestStaysAbsent(t *testing.T) {
	const payload = `{"id": "runner_1", "state": "live"}`

	var rec agentRunnerRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.PrNumber != nil {
		t.Errorf("absent pr_number became %d", *rec.PrNumber)
	}
}

func TestAuditLogRecordDecodesNestedPayload(t *testing.T) {
	// Everything but the event's identity sits under payload, so a tag read
	// against the top level decodes to nothing and the whole change loses its
	// attribution.
	const payload = `{
		"id": "audit_1",
		"account_id": "acct_1",
		"payload": {
			"actor_id": "user_1",
			"actor_name": "Sam Example",
			"actor_email": "sam@example.com",
			"action": "user_invited",
			"timestamp": "2026-01-02T03:04:05.000Z",
			"log_type": "team"
		}
	}`

	var rec auditLogRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != "audit_1" || rec.AccountID != "acct_1" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if rec.Payload.Action != "user_invited" || rec.Payload.LogType != "team" {
		t.Errorf("action fields decoded wrong: %+v", rec.Payload)
	}
	if rec.Payload.ActorID != "user_1" || rec.Payload.ActorEmail != "sam@example.com" {
		t.Errorf("actor fields decoded wrong: %+v", rec.Payload)
	}
	if rec.Payload.ActorName != "Sam Example" {
		t.Errorf("actor_name decoded wrong: %q", rec.Payload.ActorName)
	}
	if rec.Payload.Timestamp.Time() == nil {
		t.Fatal("timestamp decoded as absent")
	}
	if got := rec.Payload.Timestamp.Time().Format("2006-01-02"); got != "2026-01-02" {
		t.Errorf("timestamp decoded wrong: %s", got)
	}
}

func TestAuditLogRecordWithoutTimestampStaysNull(t *testing.T) {
	const payload = `{"id": "audit_1", "payload": {"action": "env_var_updated"}}`

	var rec auditLogRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Payload.Timestamp.Time() != nil {
		t.Errorf("absent timestamp became %v", rec.Payload.Timestamp.Time())
	}
}

func TestRawJSONToDictKeepsAbsentValuesNull(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNull bool
	}{
		{name: "absent", raw: "", wantNull: true},
		{name: "explicit null", raw: `null`, wantNull: true},
		{name: "unreadable", raw: `{oops`, wantNull: true},
		{name: "object", raw: `{"form_processing":{}}`},
		{name: "empty object", raw: `{}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.raw != "" {
				raw = json.RawMessage(tc.raw)
			}

			got := rawJSONToDict(raw)
			if tc.wantNull {
				if got.Value != nil {
					t.Errorf("expected null, got %v", got.Value)
				}
				return
			}
			if got.Value == nil {
				t.Error("expected a value, got null")
			}
		})
	}
}

func TestOptionalScalarsKeepAbsentValuesNull(t *testing.T) {
	if got := optionalInt(nil); got.Value != nil {
		t.Errorf("optionalInt(nil) reported %v", got.Value)
	}
	n := int64(7)
	if got := optionalInt(&n); got.Value != int64(7) {
		t.Errorf("optionalInt reported %v", got.Value)
	}
	if got := optionalString(nil); got.Value != nil {
		t.Errorf("optionalString(nil) reported %v", got.Value)
	}
	s := "hooks.example.com"
	if got := optionalString(&s); got.Value != s {
		t.Errorf("optionalString reported %v", got.Value)
	}
}

func TestIsNonEmptyValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want bool
	}{
		{name: "absent", in: nil},
		{name: "blank string", in: ""},
		{name: "string", in: "deadbeef", want: true},
		{name: "false", in: false},
		{name: "true", in: true, want: true},
		{name: "zero", in: float64(0)},
		{name: "number", in: float64(1), want: true},
		{name: "object", in: map[string]any{}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNonEmptyValue(tc.in); got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
