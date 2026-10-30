// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"
)

// The API records in this package are decoded by struct tag alone. A mistyped
// tag compiles, lints, and yields a zero value, which surfaces as a confident
// "false" or "" rather than an error. These tests pin each security-relevant
// tag against a payload shaped like the documented API response.

func TestSiteRecordDecodesPostureFields(t *testing.T) {
	const payload = `{
		"id": "site_abc",
		"name": "www",
		"state": "current",
		"plan": "nf_pro",
		"url": "https://www.example.com",
		"ssl_url": "https://www.example.com",
		"admin_url": "https://app.netlify.com/sites/www",
		"custom_domain": "www.example.com",
		"domain_aliases": ["example.com"],
		"branch_deploy_custom_domain": "branch.example.com",
		"deploy_preview_custom_domain": "preview.example.com",
		"notification_email": "ops@example.com",
		"id_domain": "abc.netlify.app",
		"ssl": true,
		"force_ssl": true,
		"managed_dns": true,
		"prevent_non_git_prod_deploys": true,
		"build_image": "noble",
		"prerender": "netlify",
		"functions_region": "us-east-1",
		"account_id": "acct_1",
		"account_slug": "acme",
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-02-03T04:05:06.000Z",
		"build_settings": {
			"provider": "github",
			"repo_url": "https://github.com/acme/www",
			"repo_branch": "main",
			"repo_path": "acme/www",
			"cmd": "npm run build",
			"dir": "dist",
			"functions_dir": "netlify/functions",
			"allowed_branches": ["main", "staging"],
			"public_repo": true,
			"private_logs": true,
			"stop_builds": true,
			"untrusted_flow": "review",
			"skip_prs": false,
			"deploy_key_id": "key_1"
		}
	}`

	var rec siteRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.ID != "site_abc" || rec.Name != "www" || rec.State != "current" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if !rec.Ssl || !rec.ForceSsl || !rec.ManagedDns || !rec.PreventNonGitProdDeploys {
		t.Errorf("boolean posture fields decoded wrong: %+v", rec)
	}
	if rec.AccountID != "acct_1" || rec.AccountSlug != "acme" {
		t.Errorf("account linkage decoded wrong: %q / %q", rec.AccountID, rec.AccountSlug)
	}
	if len(rec.DomainAliases) != 1 || rec.DomainAliases[0] != "example.com" {
		t.Errorf("domain aliases decoded wrong: %v", rec.DomainAliases)
	}
	if rec.FunctionsRegion != "us-east-1" || rec.BuildImage != "noble" || rec.Prerender != "netlify" {
		t.Errorf("build metadata decoded wrong: %+v", rec)
	}

	build := rec.BuildSettings
	if build == nil {
		t.Fatal("build_settings did not decode")
	}
	if build.Provider != "github" || build.RepoURL != "https://github.com/acme/www" || build.RepoBranch != "main" {
		t.Errorf("repository fields decoded wrong: %+v", build)
	}
	if build.Cmd != "npm run build" || build.Dir != "dist" || build.FunctionsDir != "netlify/functions" {
		t.Errorf("build command fields decoded wrong: %+v", build)
	}
	if !build.PublicRepo || !boolPtrValue(build.PrivateLogs) || !build.StopBuilds {
		t.Errorf("build guardrail booleans decoded wrong: %+v", build)
	}
	if build.UntrustedFlow != "review" {
		t.Errorf("untrusted_flow decoded wrong: %q", build.UntrustedFlow)
	}
	if build.SkipPrs == nil || *build.SkipPrs {
		t.Errorf("skip_prs decoded wrong: %v", build.SkipPrs)
	}
	if rec.IDDomain != "abc.netlify.app" {
		t.Errorf("id_domain decoded wrong: %q", rec.IDDomain)
	}
	if build.DeployKeyID != "key_1" {
		t.Errorf("deploy key linkage decoded wrong: %q", build.DeployKeyID)
	}
	if len(build.AllowedBranches) != 2 {
		t.Errorf("allowed branches decoded wrong: %v", build.AllowedBranches)
	}

	wantCreated := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := rec.CreatedAt.Time(); got == nil || !got.Equal(wantCreated) {
		t.Errorf("created_at decoded wrong: %v", got)
	}
}

// A site without build settings (an upload-only site) must not panic the
// creator, which relies on the pointer being absent rather than empty.
func TestSiteRecordWithoutBuildSettings(t *testing.T) {
	var rec siteRecord
	if err := json.Unmarshal([]byte(`{"id":"site_1"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.BuildSettings != nil {
		t.Fatalf("expected absent build settings, got %+v", rec.BuildSettings)
	}
}

// boolPtrValue dereferences an optional decoded boolean for assertions.
func boolPtrValue(v *bool) bool { return v != nil && *v }

// A build control the API omits must stay absent rather than decoding to false,
// which would report a site as having opted out of a guardrail it never set.
func TestBuildSettingsOmittedControlsStayAbsent(t *testing.T) {
	var rec siteRecord
	if err := json.Unmarshal([]byte(`{"id":"s1","build_settings":{"provider":"github"}}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.BuildSettings.PrivateLogs != nil {
		t.Errorf("expected absent private_logs, got %v", rec.BuildSettings.PrivateLogs)
	}
	if rec.BuildSettings.SkipPrs != nil || rec.BuildSettings.SkipAutomaticBuilds != nil {
		t.Error("expected absent skip flags to stay nil")
	}
}

func TestAccountRecordDecodesGovernance(t *testing.T) {
	const payload = `{
		"id": "acct_1",
		"slug": "acme",
		"lifecycle_state": "active",
		"billing_email": "billing@example.com",
		"members_count": 4,
		"enforce_mfa": "not_enforced",
		"enforce_saml": "enforced",
		"saml_enabled": true,
		"saml_session_expiration": 604800,
		"site_sso_login": true,
		"has_site_password": true,
		"site_password_context": "all",
		"block_site_transfers": true,
		"team_registration_domains": ["example.com"],
		"support_administration_enabled": true,
		"site_access": "all"
	}`

	var rec accountRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.EnforceMfa != "not_enforced" || rec.EnforceSaml != "enforced" {
		t.Errorf("enforcement fields decoded wrong: %+v", rec)
	}
	if !rec.SamlEnabled || rec.SamlSessionExpiration != 604800 {
		t.Errorf("saml fields decoded wrong: %+v", rec)
	}
	if !rec.HasSitePassword || rec.SitePasswordContext != "all" {
		t.Errorf("site password fields decoded wrong: %+v", rec)
	}
	if !rec.BlockSiteTransfers || !rec.SupportAdministrationEnabled {
		t.Errorf("account guardrails decoded wrong: %+v", rec)
	}
	if len(rec.TeamRegistrationDomains) != 1 || rec.TeamRegistrationDomains[0] != "example.com" {
		t.Errorf("registration domains decoded wrong: %v", rec.TeamRegistrationDomains)
	}
	if rec.MembersCount != 4 || rec.LifecycleState != "active" {
		t.Errorf("account metadata decoded wrong: %+v", rec)
	}
}

// The account records ownership against the user behind a membership, not the
// membership itself. Matching the wrong one finds nothing and reports an
// account with no owners at all.
func TestMemberRecordDistinguishesMembershipFromUser(t *testing.T) {
	const payload = `{
		"id": "6541f71117fd8b0220d36fcf",
		"user_id": "60a7e6bb375fd5110af858a4",
		"email": "ada@example.com",
		"role": "Owner",
		"mfa_enabled": true,
		"pending": false,
		"managed_by_directory_sync": true,
		"site_access": "all",
		"last_activity_date": "2026-08-10"
	}`

	var rec memberRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID == rec.UserID {
		t.Fatal("membership id and user id must stay distinct")
	}
	if rec.UserID != "60a7e6bb375fd5110af858a4" {
		t.Errorf("user_id decoded wrong: %q", rec.UserID)
	}
	if !rec.MfaEnabled || !rec.ManagedByDirectorySync || rec.Pending {
		t.Errorf("member governance fields decoded wrong: %+v", rec)
	}
	// The roster reports a plain calendar date, not a full timestamp.
	if rec.LastActivityDate.Time() == nil {
		t.Error("last_activity_date decoded to nil")
	}
}

func TestAccountRecordDecodesRoster(t *testing.T) {
	const payload = `{
		"id": "acct_1",
		"slug": "acme",
		"name": "Acme",
		"type": "pro",
		"type_name": "Pro",
		"owner_ids": ["user_1", "user_2"],
		"roles_allowed": ["Owner", "Collaborator"],
		"created_at": "2026-01-02T03:04:05.000Z",
		"updated_at": "2026-02-03T04:05:06.000Z"
	}`

	var rec accountRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != "acct_1" || rec.Slug != "acme" || rec.TypeName != "Pro" {
		t.Errorf("account fields decoded wrong: %+v", rec)
	}
	if len(rec.OwnerIDs) != 2 || rec.OwnerIDs[0] != "user_1" {
		t.Errorf("owner ids decoded wrong: %v", rec.OwnerIDs)
	}
	if len(rec.RolesAllowed) != 2 || rec.RolesAllowed[0] != "Owner" {
		t.Errorf("roles allowed decoded wrong: %v", rec.RolesAllowed)
	}
}

func TestMemberRecordDecodesRole(t *testing.T) {
	const payload = `{
		"id": "user_1",
		"full_name": "Ada Lovelace",
		"email": "ada@example.com",
		"role": "Owner",
		"avatar": "https://example.com/a.png"
	}`

	var rec memberRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != "user_1" || rec.Role != "Owner" || rec.Email != "ada@example.com" {
		t.Errorf("member fields decoded wrong: %+v", rec)
	}
	if rec.AvatarURL != "https://example.com/a.png" {
		t.Errorf("avatar decoded wrong: %q", rec.AvatarURL)
	}
}

func TestEnvVarRecordDecodesSecretAndContexts(t *testing.T) {
	const payload = `{
		"key": "API_TOKEN",
		"scopes": ["builds", "functions", "runtime"],
		"is_secret": true,
		"updated_at": "2026-01-02T03:04:05.000Z",
		"updated_by": {"email": "ada@example.com"},
		"values": [
			{"context": "production", "value": ""},
			{"context": "branch-deploy", "context_parameter": "staging", "value": "abc"}
		]
	}`

	var rec envVarRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Key != "API_TOKEN" || !rec.IsSecret {
		t.Errorf("env var identity decoded wrong: %+v", rec)
	}
	if len(rec.Scopes) != 3 || rec.Scopes[2] != "runtime" {
		t.Errorf("scopes decoded wrong: %v", rec.Scopes)
	}
	if rec.UpdatedBy == nil || rec.UpdatedBy.Email != "ada@example.com" {
		t.Errorf("updated_by decoded wrong: %+v", rec.UpdatedBy)
	}
	if len(rec.Values) != 2 {
		t.Fatalf("expected 2 values, got %d", len(rec.Values))
	}
	if rec.Values[1].Context != "branch-deploy" || rec.Values[1].ContextParameter != "staging" {
		t.Errorf("context parameter decoded wrong: %+v", rec.Values[1])
	}
}

func TestDnsRecordDecodesNumericFields(t *testing.T) {
	const payload = `{
		"id": "rec_1",
		"hostname": "www.example.com",
		"type": "CNAME",
		"value": "www.example.netlify.app",
		"ttl": 3600,
		"priority": 10,
		"flag": 128,
		"tag": "issue",
		"managed": true
	}`

	var rec dnsRecordRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.TTL != 3600 || rec.Priority != 10 || rec.Flag != 128 {
		t.Errorf("numeric fields decoded wrong: %+v", rec)
	}
	if rec.Type != "CNAME" || rec.Tag != "issue" || !rec.Managed {
		t.Errorf("record fields decoded wrong: %+v", rec)
	}
}

func TestDnsZoneRecordDecodesSiteLinkage(t *testing.T) {
	const payload = `{
		"id": "zone_1",
		"name": "example.com",
		"dedicated": true,
		"ipv6_enabled": true,
		"dns_servers": ["dns1.p01.nsone.net"],
		"account_id": "acct_1",
		"account_slug": "acme",
		"site_id": "site_abc"
	}`

	var rec dnsZoneRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.SiteID != "site_abc" {
		t.Errorf("site linkage decoded wrong: %q", rec.SiteID)
	}
	if !rec.Dedicated || !rec.Ipv6Enabled {
		t.Errorf("zone booleans decoded wrong: %+v", rec)
	}
	if len(rec.DNSServers) != 1 {
		t.Errorf("dns servers decoded wrong: %v", rec.DNSServers)
	}
}

func TestNotificationHookRecordDecodesDisabled(t *testing.T) {
	const payload = `{
		"id": "hook_1",
		"type": "slack",
		"event": "deploy_created",
		"disabled": true,
		"created_at": "2026-01-02T03:04:05.000Z"
	}`

	var rec notificationHookRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Type != "slack" || rec.Event != "deploy_created" || !rec.Disabled {
		t.Errorf("hook fields decoded wrong: %+v", rec)
	}
}

func TestSnippetRecordDecodesNumericID(t *testing.T) {
	const payload = `{
		"id": 42,
		"title": "analytics",
		"general": "<script src=\"https://example.com/a.js\"></script>",
		"general_position": "head",
		"goal": "<script>done()</script>",
		"goal_position": "body"
	}`

	var rec snippetRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != 42 || rec.GeneralPosition != "head" || rec.GoalPosition != "body" {
		t.Errorf("snippet fields decoded wrong: %+v", rec)
	}
	if rec.General == "" || rec.Goal == "" {
		t.Errorf("snippet markup decoded wrong: %+v", rec)
	}
}

func TestUserRecordDecodesMfaAndManagement(t *testing.T) {
	var rec userRecord
	if err := json.Unmarshal([]byte(`{"id":"u1","mfa_enabled":true,"managed_by_sso_or_directory_sync":true}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rec.MfaEnabled || !rec.ManagedBySso {
		t.Errorf("user governance fields decoded wrong: %+v", rec)
	}
}

func TestUserRecordDecodesLoginProviders(t *testing.T) {
	const payload = `{
		"id": "user_1",
		"uid": "uid_1",
		"email": "ada@example.com",
		"full_name": "Ada Lovelace",
		"avatar_url": "https://example.com/a.png",
		"login_providers": ["github", "email"],
		"site_count": 7,
		"created_at": "2026-01-02T03:04:05.000Z",
		"last_login": "2026-03-04T05:06:07.000Z"
	}`

	var rec userRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.SiteCount != 7 {
		t.Errorf("site count decoded wrong: %d", rec.SiteCount)
	}
	if len(rec.LoginProviders) != 2 || rec.LoginProviders[0] != "github" {
		t.Errorf("login providers decoded wrong: %v", rec.LoginProviders)
	}
	if rec.LastLogin.Time() == nil {
		t.Error("last_login decoded to nil")
	}
}

func TestNetlifyTimeHandlesAbsentAndInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantNil bool
	}{
		{"rfc3339", `"2026-01-02T03:04:05Z"`, false},
		{"fractional seconds", `"2026-01-02T03:04:05.123Z"`, false},
		{"offset", `"2026-01-02T03:04:05+02:00"`, false},
		{"null", `null`, true},
		{"empty string", `""`, true},
		{"date only", `"2026-08-10"`, false},
		{"unparseable", `"not a timestamp"`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var nt netlifyTime
			if err := json.Unmarshal([]byte(tc.payload), &nt); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := nt.Time(); (got == nil) != tc.wantNil {
				t.Fatalf("expected nil=%v, got %v", tc.wantNil, got)
			}
		})
	}
}

// A timestamp that is absent from the payload must stay null rather than
// decoding to the zero time, which would report 1 January year 1 as a real
// creation date.
func TestNetlifyTimeAbsentFieldStaysNull(t *testing.T) {
	var rec siteRecord
	if err := json.Unmarshal([]byte(`{"id":"site_1"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.CreatedAt.Time() != nil {
		t.Errorf("expected null created_at, got %v", rec.CreatedAt.Time())
	}
}

func TestStrSliceToAny(t *testing.T) {
	got := strSliceToAny([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected widening result: %v", got)
	}
	if empty := strSliceToAny(nil); len(empty) != 0 {
		t.Fatalf("expected an empty slice for nil input, got %v", empty)
	}
}

// The site password is a secret and is never modelled. Its presence is the
// finding, so the derivation has to survive every form the API may report the
// value in, and an unreported key must stay null rather than becoming a
// confident "not protected".
func TestSitePasswordProtected(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    *bool
	}{
		{
			name:    "key absent stays null",
			payload: `{"id":"site_1","name":"www"}`,
			want:    nil,
		},
		{
			name:    "explicit json null is a reported absence",
			payload: `{"id":"site_1","password":null}`,
			want:    new(false),
		},
		{
			name:    "empty string is no password",
			payload: `{"id":"site_1","password":""}`,
			want:    new(false),
		},
		{
			name:    "literal password is protected",
			payload: `{"id":"site_1","password":"correct-horse"}`,
			want:    new(true),
		},
		{
			name:    "redacted placeholder is still protected",
			payload: `{"id":"site_1","password":"****"}`,
			want:    new(true),
		},
		{
			name:    "boolean marker true is protected",
			payload: `{"id":"site_1","password":true}`,
			want:    new(true),
		},
		{
			name:    "boolean marker false is not protected",
			payload: `{"id":"site_1","password":false}`,
			want:    new(false),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rec siteRecord
			if err := json.Unmarshal([]byte(tc.payload), &rec); err != nil {
				t.Fatalf("decode: %v", err)
			}

			got := sitePasswordProtected(rec.Password)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("expected null, got %v", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("expected %v, got null", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("expected %v, got %v", *tc.want, *got)
			}
		})
	}
}

// The raw password must never be readable from the record as a string field:
// only the derived presence is exposed. This pins the type so a later change
// that widens it to a plain string fails here.
func TestSitePasswordIsNotExposedAsAValue(t *testing.T) {
	var rec siteRecord
	if err := json.Unmarshal([]byte(`{"id":"site_1","password":"correct-horse"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rec.Password) == 0 {
		t.Fatal("expected the raw password to decode so presence can be derived")
	}
	if got := sitePasswordProtected(rec.Password); got == nil || !*got {
		t.Fatalf("expected the site to read as password protected, got %v", got)
	}
}
