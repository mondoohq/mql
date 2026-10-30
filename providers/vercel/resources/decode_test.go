// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The API records in this package are decoded by struct tag alone. A mistyped
// tag compiles, lints, and yields a zero value, which surfaces as a confident
// "false" or "" rather than an error. These tests pin each security-relevant
// tag against a payload shaped like the documented API response.

func TestTeamRecordDecodesGovernanceFields(t *testing.T) {
	const payload = `{
		"id": "team_abc",
		"slug": "acme",
		"name": "Acme",
		"createdAt": 1600000000000,
		"updatedAt": 1600000001000,
		"creatorId": "user_1",
		"billing": {"plan": "enterprise"},
		"parentId": "org_1",
		"orgRootTeamId": "team_root",
		"saml": {
			"enforced": true,
			"roles": {"grp": "OWNER"},
			"connection": {
				"type": "Okta",
				"state": "active",
				"status": "linked",
				"connectedAt": 1600000002000
			},
			"directory": {
				"type": "Okta",
				"state": "active",
				"syncState": "SETUP",
				"connectedAt": 1600000003000,
				"lastSyncedAt": 1600000004000
			}
		},
		"emailDomain": "acme.com",
		"inviteCode": "super-secret-code",
		"dpAccessRequestsMode": "email-domain",
		"requireVerifiedCommits": true,
		"disableRepositoryDispatchEvents": true,
		"strictDeploymentProtectionSettings": {"enabled": true, "updatedAt": 1},
		"strictPasswordProtectionSettings": {"enabled": true, "updatedAt": 1},
		"strictShareableLinks": {"enabled": true, "updatedAt": 1},
		"defaultDeploymentProtection": {
			"passwordProtection": {"deploymentType": "preview"},
			"ssoProtection": {"deploymentType": "all"}
		},
		"defaultRoles": {
			"teamRoles": ["MEMBER"],
			"teamPermissions": ["CreateProject"]
		},
		"deploymentPolicy": {"gitSources": [{"enabled": true, "sources": []}]},
		"defaultExpirationSettings": {"expirationDays": 30, "deploymentsToKeep": 3},
		"sensitiveEnvironmentVariablePolicy": "on",
		"hideIpAddresses": true,
		"hideIpAddressesInLogDrains": true,
		"remoteCaching": {"enabled": true},
		"connect": {"enabled": true},
		"enablePreviewFeedback": "off-force",
		"enableProductionFeedback": "on",
		"previewDeploymentSuffix": "preview.acme.com",
		"stagingPrefix": "staging",
		"personalAccessTokensInvalidatedAt": 1600000005000,
		"appTokensInvalidatedAt": 1600000006000,
		"apiKeysInvalidatedAt": 1600000007000,
		"integrationTokensInvalidatedAt": 1600000008000
	}`

	var rec teamRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if billingPlan(rec.Billing) != "enterprise" {
		t.Errorf("billingPlan = %q, want enterprise", billingPlan(rec.Billing))
	}
	if rec.ParentID != "org_1" || rec.OrgRootTeamID != "team_root" {
		t.Errorf("org hierarchy: parentId=%q orgRootTeamId=%q", rec.ParentID, rec.OrgRootTeamID)
	}

	if rec.Saml == nil || rec.Saml.Connection == nil || rec.Saml.Directory == nil {
		t.Fatal("saml connection and directory must both decode")
	}
	if rec.Saml.Connection.Type != "Okta" || rec.Saml.Connection.State != "active" || rec.Saml.Connection.Status != "linked" {
		t.Errorf("saml connection: %+v", rec.Saml.Connection)
	}
	if rec.Saml.Connection.ConnectedAt.Time() == nil {
		t.Error("saml connectedAt should decode")
	}
	// SETUP means directory events are acknowledged but role mappings are not
	// applied, so it must not be flattened into the same value as ACTIVE.
	if rec.Saml.Directory.SyncState != "SETUP" {
		t.Errorf("directory syncState = %q, want SETUP", rec.Saml.Directory.SyncState)
	}
	if rec.Saml.Directory.LastSynced.Time() == nil {
		t.Error("directory lastSyncedAt should decode")
	}

	if rec.EmailDomain == nil || *rec.EmailDomain != "acme.com" {
		t.Errorf("emailDomain = %v", rec.EmailDomain)
	}
	// The code itself is a credential and must never reach a field; only its
	// presence is reported.
	if rec.InviteCode == "" {
		t.Error("inviteCode should decode so presence can be reported")
	}
	if rec.DpAccessRequestsMode == nil || *rec.DpAccessRequestsMode != "email-domain" {
		t.Errorf("dpAccessRequestsMode = %v", rec.DpAccessRequestsMode)
	}

	for name, got := range map[string]bool{
		"requireVerifiedCommits":             boolPtrOrFalse(rec.RequireVerifiedCommits),
		"disableRepositoryDispatchEvents":    boolPtrOrFalse(rec.DisableRepositoryDispatchEvents),
		"hideIpAddresses":                    boolPtrOrFalse(rec.HideIPAddresses),
		"hideIpAddressesInLogDrains":         boolPtrOrFalse(rec.HideIPAddressesInLogDrains),
		"strictDeploymentProtectionSettings": strictEnabled(rec.StrictDeploymentProtection),
		"strictPasswordProtectionSettings":   strictEnabled(rec.StrictPasswordProtection),
		"strictShareableLinks":               strictEnabled(rec.StrictShareableLinks),
	} {
		if !got {
			t.Errorf("%s decoded false, want true", name)
		}
	}

	if rec.DefaultDeploymentProtection == nil {
		t.Fatal("defaultDeploymentProtection must decode")
	}
	if got := holderType(rec.DefaultDeploymentProtection.SsoProtection); got == nil || *got != "all" {
		t.Errorf("default sso deploymentType = %v", got)
	}
	if got := holderType(rec.DefaultDeploymentProtection.PasswordProtection); got == nil || *got != "preview" {
		t.Errorf("default password deploymentType = %v", got)
	}

	if rec.DefaultRoles == nil || len(rec.DefaultRoles.TeamRoles) != 1 || len(rec.DefaultRoles.TeamPermissions) != 1 {
		t.Errorf("defaultRoles = %+v", rec.DefaultRoles)
	}
	if rec.DeploymentPolicy == nil {
		t.Error("deploymentPolicy should decode")
	}
	if rec.DefaultExpirationSettings == nil || intPtrOrZero(rec.DefaultExpirationSettings.ExpirationDays) != 30 {
		t.Errorf("defaultExpirationSettings = %+v", rec.DefaultExpirationSettings)
	}

	for name, got := range map[string]bool{
		"personalAccessTokensInvalidatedAt": rec.PersonalAccessTokensInvalidatedAt.Time() != nil,
		"appTokensInvalidatedAt":            rec.AppTokensInvalidatedAt.Time() != nil,
		"apiKeysInvalidatedAt":              rec.APIKeysInvalidatedAt.Time() != nil,
		"integrationTokensInvalidatedAt":    rec.IntegrationTokensInvalidatedAt.Time() != nil,
	} {
		if !got {
			t.Errorf("%s did not decode", name)
		}
	}
}

func TestTeamRecordAbsentNestedObjectsStayZero(t *testing.T) {
	// A team on a plan without these features omits the objects entirely. Each
	// extraction is nil-guarded, so this must not panic and must not invent
	// values.
	var rec teamRecord
	if err := json.Unmarshal([]byte(`{"id":"team_abc","slug":"acme"}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if billingPlan(rec.Billing) != "" {
		t.Error("absent billing should yield an empty plan")
	}
	if strictEnabled(rec.StrictDeploymentProtection) {
		t.Error("absent strict setting should be false")
	}
	if rec.Saml != nil || rec.DefaultRoles != nil || rec.DefaultExpirationSettings != nil {
		t.Error("absent nested objects should stay nil")
	}
	if boolPtrOrFalse(rec.RequireVerifiedCommits) {
		t.Error("absent requireVerifiedCommits should be false")
	}
}

func TestMemberRecordDecodesRolesAndJoinOrigin(t *testing.T) {
	const payload = `{
		"uid": "user_1",
		"email": "a@acme.com",
		"role": "MEMBER",
		"teamRoles": ["MEMBER", "SECURITY"],
		"teamPermissions": ["EnvVariableManager"],
		"joinedFrom": {"origin": "dsync", "idpUserId": "idp_1"},
		"confirmed": true,
		"accessRequestedAt": 1600000000000,
		"createdAt": 1600000001000
	}`

	var rec memberRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(rec.TeamRoles) != 2 || rec.TeamRoles[1] != "SECURITY" {
		t.Errorf("teamRoles = %v", rec.TeamRoles)
	}
	if len(rec.TeamPermissions) != 1 {
		t.Errorf("teamPermissions = %v", rec.TeamPermissions)
	}
	// Distinguishes an identity-provider provisioned member from one who
	// followed an invite link.
	if rec.JoinedFrom == nil || rec.JoinedFrom.Origin != "dsync" {
		t.Errorf("joinedFrom = %+v", rec.JoinedFrom)
	}
	if rec.AccessRequestedAt.Time() == nil {
		t.Error("accessRequestedAt should decode")
	}
}

func TestSharedEnvRecordDecodes(t *testing.T) {
	// projectId is an array despite the singular key, which is easy to get
	// wrong and would silently drop every project link.
	const payload = `{
		"id": "env_1",
		"key": "DATABASE_URL",
		"type": "sensitive",
		"target": ["production", "preview"],
		"applyToAllCustomEnvironments": true,
		"customEnvironmentIds": ["ce_1"],
		"decrypted": false,
		"comment": "shared db",
		"projectId": ["prj_1", "prj_2"],
		"createdBy": "user_1",
		"updatedBy": "user_2",
		"lastEditedByDisplayName": "Ada",
		"createdAt": 1600000000000,
		"updatedAt": 1600000001000
	}`

	var rec sharedEnvRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(rec.ProjectIDs) != 2 || rec.ProjectIDs[0] != "prj_1" {
		t.Errorf("projectId should decode as a list, got %v", rec.ProjectIDs)
	}
	if rec.Type != "sensitive" {
		t.Errorf("type = %q, want sensitive", rec.Type)
	}
	if len(rec.Target) != 2 || len(rec.CustomEnvironmentIDs) != 1 {
		t.Errorf("target=%v customEnvironmentIds=%v", rec.Target, rec.CustomEnvironmentIDs)
	}
	if !boolPtrOrFalse(rec.ApplyToAllCustomEnvironments) {
		t.Error("applyToAllCustomEnvironments should be true")
	}
	if boolPtrOrFalse(rec.Decrypted) {
		t.Error("decrypted should be false")
	}
}

func TestProjectRecordDecodesSecuritySettings(t *testing.T) {
	const payload = `{
		"id": "prj_1",
		"name": "web",
		"paused": true,
		"tier": "standard",
		"passport": {"deploymentType": "preview", "connectorId": "conn_1"},
		"trustedSources": {"deploymentType": "all"},
		"oidcTokenConfig": {"enabled": true, "issuerMode": "team"},
		"deploymentPolicy": {"deploymentSources": [{"enabled": true, "sources": []}]},
		"rollingRelease": {"target": "canary"},
		"deploymentExpiration": {"expirationDays": 7, "expirationDaysProduction": 90, "deploymentsToKeep": 5},
		"directoryListing": true,
		"sourceFilesOutsideRootDirectory": true,
		"customerSupportCodeVisibility": true,
		"serverlessFunctionZeroConfigFailover": true,
		"autoAssignCustomDomains": true,
		"commandForIgnoringBuildStep": "exit 1",
		"serverlessFunctionRegion": "iad1",
		"resourceConfig": {
			"functionDefaultRegions": ["iad1", "sfo1"],
			"functionDefaultTimeout": 60,
			"functionDefaultMemoryType": "performance",
			"buildMachineType": "enhanced",
			"buildMachineSelection": "elastic"
		},
		"staticIps": {"enabled": true, "builds": true, "regions": ["iad1"]},
		"connectConfigurations": [{
			"connectConfigurationId": "cc_1",
			"envId": "production",
			"dc": "iad1",
			"passive": false,
			"buildsEnabled": true,
			"aws": {"subnetIds": ["subnet-1", "subnet-2"]}
		}],
		"skewProtectionBoundaryAt": 1600000000000,
		"skewProtectionMaxAge": 3600,
		"skewProtectionAllowedDomains": ["acme.com"],
		"transferStartedAt": 1600000001000,
		"transferCompletedAt": 1600000002000,
		"transferToAccountId": "team_b",
		"transferredFromAccountId": "team_a",
		"gitProviderOptions": {
			"createDeployments": "disabled",
			"requireVerifiedCommits": true,
			"disableRepositoryDispatchEvents": true
		},
		"gitComments": {"onCommit": true, "onPullRequest": false}
	}`

	var rec projectRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rec.Passport == nil || rec.Passport.DeploymentType != "preview" || rec.Passport.ConnectorID != "conn_1" {
		t.Errorf("passport = %+v", rec.Passport)
	}
	if rec.OidcTokenConfig["issuerMode"] != "team" {
		t.Errorf("oidcTokenConfig issuerMode = %v", rec.OidcTokenConfig["issuerMode"])
	}
	if rec.TrustedSources == nil || rec.DeploymentPolicy == nil || rec.RollingRelease == nil {
		t.Error("trustedSources, deploymentPolicy and rollingRelease should all decode")
	}

	if rec.DeploymentExpiration == nil {
		t.Fatal("deploymentExpiration must decode")
	}
	if intPtrOrZero(rec.DeploymentExpiration.ExpirationDaysProduction) != 90 {
		t.Errorf("expirationDaysProduction = %d, want 90", intPtrOrZero(rec.DeploymentExpiration.ExpirationDaysProduction))
	}

	for name, got := range map[string]bool{
		"directoryListing":                     boolPtrOrFalse(rec.DirectoryListing),
		"sourceFilesOutsideRootDirectory":      boolPtrOrFalse(rec.SourceFilesOutsideRootDirectory),
		"customerSupportCodeVisibility":        boolPtrOrFalse(rec.CustomerSupportCodeVisibility),
		"serverlessFunctionZeroConfigFailover": boolPtrOrFalse(rec.ServerlessFunctionZeroConfigFailover),
		"autoAssignCustomDomains":              boolPtrOrFalse(rec.AutoAssignCustomDomains),
		"paused":                               boolPtrOrFalse(rec.Paused),
	} {
		if !got {
			t.Errorf("%s decoded false, want true", name)
		}
	}

	if rec.ResourceConfig == nil || len(rec.ResourceConfig.FunctionDefaultRegions) != 2 {
		t.Fatalf("resourceConfig = %+v", rec.ResourceConfig)
	}
	if intPtrOrZero(rec.ResourceConfig.FunctionDefaultTimeout) != 60 {
		t.Errorf("functionDefaultTimeout = %d", intPtrOrZero(rec.ResourceConfig.FunctionDefaultTimeout))
	}
	if rec.StaticIps == nil || !boolPtrOrFalse(rec.StaticIps.Enabled) || len(rec.StaticIps.Regions) != 1 {
		t.Errorf("staticIps = %+v", rec.StaticIps)
	}

	if len(rec.ConnectConfigurations) != 1 {
		t.Fatalf("connectConfigurations = %v", rec.ConnectConfigurations)
	}
	cc := rec.ConnectConfigurations[0]
	if cc.ConnectConfigurationID != "cc_1" || cc.EnvID != "production" || cc.DC != "iad1" {
		t.Errorf("connect configuration = %+v", cc)
	}
	if cc.AWS == nil || len(cc.AWS.SubnetIDs) != 2 {
		t.Errorf("aws subnetIds = %+v", cc.AWS)
	}

	if intPtrOrZero(rec.SkewProtectionMaxAge) != 3600 || rec.SkewProtectionBoundaryAt.Time() == nil {
		t.Error("skew protection fields should decode")
	}
	if rec.TransferToAccountID != "team_b" || rec.TransferredFromAccountID != "team_a" {
		t.Errorf("transfer accounts: to=%q from=%q", rec.TransferToAccountID, rec.TransferredFromAccountID)
	}

	if rec.GitProviderOptions == nil || !boolPtrOrFalse(rec.GitProviderOptions.RequireVerifiedCommits) {
		t.Errorf("gitProviderOptions = %+v", rec.GitProviderOptions)
	}
	if rec.GitComments == nil || !boolPtrOrFalse(rec.GitComments.OnCommit) || boolPtrOrFalse(rec.GitComments.OnPullRequest) {
		t.Errorf("gitComments = %+v", rec.GitComments)
	}
}

func TestFirewallConfigDecodesRulesetState(t *testing.T) {
	const payload = `{
		"firewallEnabled": true,
		"version": 12,
		"updatedAt": "2026-01-01T00:00:00Z",
		"botIdEnabled": true,
		"logHeaders": ["x-api-key"],
		"managedRules": {"owasp": {"active": true}},
		"crs": {"sqli": {"active": true, "action": "deny"}, "xss": {"active": false, "action": "log"}},
		"rules": [{"id": "r1", "name": "block-bots", "active": true, "action": "deny"}],
		"ips": [{"id": "ip1", "ip": "1.2.3.4", "action": "deny"}]
	}`

	var cfg firewallConfig
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !cfg.FirewallEnabled || intPtrOrZero(cfg.Version) != 12 {
		t.Errorf("firewallEnabled=%v version=%d", cfg.FirewallEnabled, intPtrOrZero(cfg.Version))
	}
	if cfg.UpdatedAt.Time() == nil {
		t.Error("updatedAt should decode from an RFC 3339 string")
	}
	if cfg.BotIDEnabled == nil || !*cfg.BotIDEnabled {
		t.Error("botIdEnabled should decode true")
	}
	if len(cfg.LogHeaders.values) != 1 || cfg.LogHeaders.values[0] != "x-api-key" {
		t.Errorf("logHeaders = %v", cfg.LogHeaders.values)
	}
	crs, ok := decodeAnyOrEmpty(cfg.CRS).(map[string]any)
	if !ok || len(crs) != 2 {
		t.Fatalf("crs should decode as an object, got %T", decodeAnyOrEmpty(cfg.CRS))
	}
	if len(cfg.Rules) != 1 || len(cfg.IPs) != 1 {
		t.Errorf("rules=%d ips=%d", len(cfg.Rules), len(cfg.IPs))
	}
}

func TestBypassRuleRecordDecodesPascalCaseKeys(t *testing.T) {
	// This endpoint is the only one in the provider that returns PascalCase
	// keys, so the tags here do not follow the pattern used everywhere else.
	const payload = `{
		"Id": "bp_1",
		"OwnerId": "team_1",
		"ProjectId": "prj_1",
		"Ip": "203.0.113.5",
		"Domain": "acme.com",
		"Action": "bypass",
		"IsProjectRule": true,
		"Note": "vendor scanner",
		"ActorId": "user_1",
		"ExpiresAt": 1600000000000,
		"CreatedAt": "2026-01-01T00:00:00Z",
		"UpdatedAt": "2026-01-02T00:00:00Z"
	}`

	var rec bypassRuleRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rec.ID != "bp_1" || rec.IP != "203.0.113.5" || rec.Domain != "acme.com" {
		t.Errorf("identity fields: %+v", rec)
	}
	// A bypass entry skips every other firewall rule, so mistaking it for a
	// block would invert the finding.
	if rec.Action != "bypass" {
		t.Errorf("action = %q, want bypass", rec.Action)
	}
	if !boolPtrOrFalse(rec.IsProjectRule) {
		t.Error("IsProjectRule should decode true")
	}
	if rec.Note == nil || *rec.Note != "vendor scanner" {
		t.Errorf("note = %v", rec.Note)
	}
	if rec.ActorID != "user_1" {
		t.Errorf("actorId = %q", rec.ActorID)
	}
	if rec.ExpiresAt.Time() == nil || rec.CreatedAt.Time() == nil || rec.UpdatedAt.Time() == nil {
		t.Error("timestamps should decode from both epoch millis and RFC 3339")
	}
}

func TestBypassRuleRecordPermanentEntryHasNoExpiry(t *testing.T) {
	var rec bypassRuleRecord
	if err := json.Unmarshal([]byte(`{"Id":"bp_2","Ip":"1.1.1.1","Action":"bypass","ExpiresAt":null}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// A permanent exemption is the higher-risk case, so a null expiry must stay
	// null rather than collapsing to the zero time.
	if rec.ExpiresAt.Time() != nil {
		t.Errorf("null ExpiresAt should stay nil, got %v", rec.ExpiresAt.Time())
	}
}

// --- firewall rule mitigation ---------------------------------------------

func TestFirewallRuleMitigationDecodesFullMitigation(t *testing.T) {
	const payload = `{
		"id": "r1",
		"name": "throttle",
		"active": true,
		"action": {"mitigate": {
			"action": "rate_limit",
			"actionDuration": "1h",
			"bypassSystem": true,
			"logHeaders": "*",
			"rateLimit": {"algo": "token_bucket", "window": 60, "limit": 100, "keys": ["ip"], "action": "deny"},
			"redirect": {"location": "https://example.invalid/blocked", "permanent": false}
		}}
	}`

	var rec firewallRuleRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	mit := firewallRuleMitigation(rec.Action)
	if mit.Action == nil || *mit.Action != "rate_limit" {
		t.Errorf("action = %v", mit.Action)
	}
	if mit.BypassSystem == nil || !*mit.BypassSystem {
		t.Fatalf("bypassSystem should decode true, got %v", mit.BypassSystem)
	}
	if mit.ActionDuration == nil || *mit.ActionDuration != "1h" {
		t.Errorf("actionDuration = %v", mit.ActionDuration)
	}
	if len(mit.LogHeaders.values) != 1 || mit.LogHeaders.values[0] != "*" {
		t.Errorf("logHeaders = %v", mit.LogHeaders.values)
	}
	if mit.RateLimit == nil {
		t.Fatal("rateLimit should decode")
	}
	if mit.RateLimit.Algo == nil || *mit.RateLimit.Algo != "token_bucket" {
		t.Errorf("rateLimit.algo = %v", mit.RateLimit.Algo)
	}
	if mit.RateLimit.Window == nil || *mit.RateLimit.Window != 60 {
		t.Errorf("rateLimit.window = %v", mit.RateLimit.Window)
	}
	if mit.RateLimit.Limit == nil || *mit.RateLimit.Limit != 100 {
		t.Errorf("rateLimit.limit = %v", mit.RateLimit.Limit)
	}
	if len(mit.RateLimit.Keys) != 1 || mit.RateLimit.Keys[0] != "ip" {
		t.Errorf("rateLimit.keys = %v", mit.RateLimit.Keys)
	}
	if mit.RateLimit.Action == nil || *mit.RateLimit.Action != "deny" {
		t.Errorf("rateLimit.action = %v", mit.RateLimit.Action)
	}
	if mit.Redirect == nil || mit.Redirect.Location == nil || *mit.Redirect.Location != "https://example.invalid/blocked" {
		t.Errorf("redirect.location = %v", mit.Redirect)
	}
	if mit.Redirect.Permanent == nil || *mit.Redirect.Permanent {
		t.Errorf("redirect.permanent = %v", mit.Redirect.Permanent)
	}
}

// A rule that does not set bypassSystem must report null, never false. A
// fabricated false would satisfy an assertion that no rule disables the system
// mitigations without anything having been read.
func TestFirewallRuleMitigationAbsentFieldsStayNull(t *testing.T) {
	cases := map[string]string{
		"bare verb":               `"deny"`,
		"mitigate object":         `{"mitigate": {"action": "deny"}}`,
		"inline object":           `{"action": "deny"}`,
		"explicit null bypass":    `{"mitigate": {"action": "deny", "bypassSystem": null}}`,
		"explicit null ratelimit": `{"mitigate": {"action": "deny", "rateLimit": null, "redirect": null}}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var action any
			if err := json.Unmarshal([]byte(raw), &action); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			mit := firewallRuleMitigation(action)
			if mit.Action == nil || *mit.Action != "deny" {
				t.Errorf("action = %v", mit.Action)
			}
			if mit.BypassSystem != nil {
				t.Errorf("bypassSystem should stay null, got %v", *mit.BypassSystem)
			}
			if mit.RateLimit != nil {
				t.Errorf("rateLimit should stay null, got %+v", mit.RateLimit)
			}
			if mit.Redirect != nil {
				t.Errorf("redirect should stay null, got %+v", mit.Redirect)
			}
			if mit.ActionDuration != nil {
				t.Errorf("actionDuration should stay null, got %v", *mit.ActionDuration)
			}
			if len(mit.LogHeaders.values) != 0 {
				t.Errorf("logHeaders should stay empty, got %v", mit.LogHeaders.values)
			}
		})
	}
}

func TestFirewallRuleMitigationBypassSystemFalseIsPreserved(t *testing.T) {
	var action any
	if err := json.Unmarshal([]byte(`{"mitigate": {"action": "deny", "bypassSystem": false}}`), &action); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mit := firewallRuleMitigation(action)
	if mit.BypassSystem == nil {
		t.Fatal("an explicit false must decode as false, not null")
	}
	if *mit.BypassSystem {
		t.Error("bypassSystem = true, want false")
	}
}

// --- managed rulesets and core rules --------------------------------------

func TestManagedRulesetDecodeAndOrdering(t *testing.T) {
	const payload = `{
		"vercel_ruleset": {"active": false},
		"owasp": {"active": true, "action": "log", "updatedAt": "2026-02-03T04:05:06Z", "userId": "u_1", "username": "someone"},
		"future_ruleset": {"active": true, "action": "deny"}
	}`

	got, err := decodeRulesetMap[managedRulesetRecord](json.RawMessage(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	owasp := got["owasp"]
	if owasp.Active == nil || !*owasp.Active {
		t.Errorf("owasp.active = %v", owasp.Active)
	}
	if owasp.Action == nil || *owasp.Action != "log" {
		t.Errorf("owasp.action = %v", owasp.Action)
	}
	if owasp.UpdatedAt.Time() == nil {
		t.Error("owasp.updatedAt should decode")
	}
	if owasp.UserID == nil || *owasp.UserID != "u_1" {
		t.Errorf("owasp.userId = %v", owasp.UserID)
	}
	if owasp.Username == nil || *owasp.Username != "someone" {
		t.Errorf("owasp.username = %v", owasp.Username)
	}

	// a ruleset reported without an action must not gain one
	if vr := got["vercel_ruleset"]; vr.Action != nil {
		t.Errorf("vercel_ruleset.action should stay null, got %q", *vr.Action)
	}

	keys := orderedKeys(got, managedRuleSetOrder)
	want := []string{"owasp", "vercel_ruleset", "future_ruleset"}
	if len(keys) != len(want) {
		t.Fatalf("orderedKeys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("orderedKeys = %v, want %v", keys, want)
		}
	}
}

func TestCoreRuleDecodePreservesLogAction(t *testing.T) {
	const payload = `{"sqli": {"active": true, "action": "log"}, "xss": {"active": false, "action": "deny"}}`

	got, err := decodeRulesetMap[coreRuleRecord](json.RawMessage(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sqli := got["sqli"]
	if sqli.Active == nil || !*sqli.Active {
		t.Errorf("sqli.active = %v", sqli.Active)
	}
	// an active category set to log detects without blocking; conflating that
	// with deny is the whole point of reporting the action
	if sqli.Action == nil || *sqli.Action != "log" {
		t.Errorf("sqli.action = %v", sqli.Action)
	}
	xss := got["xss"]
	if xss.Active == nil || *xss.Active {
		t.Errorf("xss.active = %v", xss.Active)
	}
}

func TestDecodeRulesetMapAbsentYieldsNoEntries(t *testing.T) {
	for _, raw := range []string{"", "null"} {
		got, err := decodeRulesetMap[coreRuleRecord](json.RawMessage(raw))
		if err != nil {
			t.Fatalf("decode(%q): %v", raw, err)
		}
		if len(got) != 0 {
			t.Errorf("decode(%q) = %v, want no entries", raw, got)
		}
	}
	if m := decodeAnyOrEmpty(json.RawMessage("null")); len(m.(map[string]any)) != 0 {
		t.Errorf("decodeAnyOrEmpty(null) = %v", m)
	}
}

// --- project environment variable sensitivity -----------------------------

func TestEnvRecordDecodesSensitivityMetadata(t *testing.T) {
	const payload = `{
		"id": "env_1",
		"key": "DATABASE_URL",
		"type": "encrypted",
		"target": ["production", "preview"],
		"gitBranch": "main",
		"decrypted": false,
		"visibility": "secret",
		"system": false,
		"comment": "primary database",
		"customEnvironmentIds": ["ce_1", "ce_2"],
		"contentHint": {"type": "postgres-url", "storeId": "store_1"},
		"createdAt": 1700000000000,
		"updatedAt": 1700000001000
	}`

	var rec envRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rec.Decrypted == nil || *rec.Decrypted {
		t.Errorf("decrypted = %v, want false", rec.Decrypted)
	}
	if rec.Visibility == nil || *rec.Visibility != "secret" {
		t.Errorf("visibility = %v", rec.Visibility)
	}
	if rec.System == nil || *rec.System {
		t.Errorf("system = %v, want false", rec.System)
	}
	if rec.Comment == nil || *rec.Comment != "primary database" {
		t.Errorf("comment = %v", rec.Comment)
	}
	if len(rec.CustomEnvironmentIDs) != 2 {
		t.Errorf("customEnvironmentIds = %v", rec.CustomEnvironmentIDs)
	}
	if rec.ContentHint["type"] != "postgres-url" {
		t.Errorf("contentHint = %v", rec.ContentHint)
	}
}

func TestEnvRecordDecryptedTrueIsPreserved(t *testing.T) {
	var rec envRecord
	if err := json.Unmarshal([]byte(`{"id":"env_1","key":"PUBLIC_URL","type":"plain","decrypted":true}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// a readable value is the risky reading; a mistyped tag would report the
	// safe one instead
	if rec.Decrypted == nil {
		t.Fatal("decrypted should decode, got null")
	}
	if !*rec.Decrypted {
		t.Error("decrypted = false, want true")
	}
}

func TestEnvRecordAbsentSensitivityStaysNull(t *testing.T) {
	var rec envRecord
	if err := json.Unmarshal([]byte(`{"id":"env_1","key":"LEGACY","type":"plain"}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Decrypted != nil {
		t.Errorf("decrypted should stay null, got %v", *rec.Decrypted)
	}
	if rec.Visibility != nil {
		t.Errorf("visibility should stay null, got %q", *rec.Visibility)
	}
	if rec.System != nil {
		t.Errorf("system should stay null, got %v", *rec.System)
	}
	if rec.Comment != nil {
		t.Errorf("comment should stay null, got %q", *rec.Comment)
	}
	if rec.ContentHint != nil {
		t.Errorf("contentHint should stay null, got %v", rec.ContentHint)
	}
	if rec.CreatedAt.Time() != nil {
		t.Error("an absent createdAt must stay null rather than becoming the zero time")
	}
}

// The env endpoint can return values. Nothing in the provider may decode one,
// so the record must carry no field bound to a value-bearing key however the
// payload is shaped.
func TestEnvRecordCarriesNoValueField(t *testing.T) {
	assertNoJSONFields(t, reflect.TypeFor[envRecord](), "value", "vsmValue", "legacyValue")

	const payload = `{"id":"env_1","key":"SECRET","type":"encrypted","value":"zero-entropy-fake","vsmValue":"zero-entropy-fake","legacyValue":"zero-entropy-fake"}`
	var rec envRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", rec), "zero-entropy-fake") {
		t.Error("a value present in the payload reached the decoded record")
	}
}

// assertNoJSONFields fails when the struct binds any of the named JSON keys.
func assertNoJSONFields(t *testing.T, typ reflect.Type, keys ...string) {
	t.Helper()
	banned := make(map[string]bool, len(keys))
	for _, k := range keys {
		banned[k] = true
	}
	for field := range typ.Fields() {
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if banned[name] {
			t.Errorf("%s binds the JSON key %q, which carries credential material", typ.Name(), name)
		}
	}
}

// --- pending team invitations ---------------------------------------------

func TestInviteRecordDecodesGrant(t *testing.T) {
	const payload = `{
		"id": "inv_1",
		"email": "invitee@example.invalid",
		"role": "OWNER",
		"teamRoles": ["OWNER", "SECURITY"],
		"teamPermissions": ["OrgAdmin"],
		"isDSyncUser": false,
		"createdAt": 1700000000000,
		"projects": {"prj_b": "ADMIN", "prj_a": "PROJECT_VIEWER"}
	}`

	var rec inviteRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Role == nil || *rec.Role != "OWNER" {
		t.Errorf("role = %v", rec.Role)
	}
	if len(rec.TeamRoles) != 2 || len(rec.TeamPermissions) != 1 {
		t.Errorf("teamRoles=%v teamPermissions=%v", rec.TeamRoles, rec.TeamPermissions)
	}
	if rec.IsDSyncUser == nil || *rec.IsDSyncUser {
		t.Errorf("isDSyncUser = %v, want false", rec.IsDSyncUser)
	}
	if rec.CreatedAt.Time() == nil {
		t.Error("createdAt should decode")
	}

	// Vercel reports expired only once the invitation has expired, so an
	// invitation that is still redeemable must read null rather than false.
	if rec.Expired != nil {
		t.Errorf("expired should stay null on a live invitation, got %v", *rec.Expired)
	}

	ids := inviteProjectIDs(&rec)
	if len(ids) != 2 || ids[0] != "prj_a" || ids[1] != "prj_b" {
		t.Errorf("inviteProjectIDs = %v, want sorted [prj_a prj_b]", ids)
	}
}

func TestInviteRecordExpiredIsPreserved(t *testing.T) {
	var rec inviteRecord
	if err := json.Unmarshal([]byte(`{"id":"inv_1","expired":true}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Expired == nil || !*rec.Expired {
		t.Errorf("expired = %v, want true", rec.Expired)
	}
}

// The invitations arrive alongside the paginated member list, so a walk over
// several member pages can hand back the same invitations more than once.
func TestDedupeInvites(t *testing.T) {
	in := []inviteRecord{
		{ID: "inv_1"}, {ID: "inv_2"}, {ID: "inv_1"}, {ID: ""}, {ID: ""}, {ID: "inv_3"},
	}
	got := dedupeInvites(in)
	// two id-less records cannot be told apart and are both kept, since
	// dropping one would under-report an outstanding invitation
	if len(got) != 5 {
		t.Fatalf("dedupeInvites returned %d records, want 5", len(got))
	}
	want := []string{"inv_1", "inv_2", "", "", "inv_3"}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("dedupeInvites ids = %v, want %v", got, want)
		}
	}
}

func TestInviteProjectIDsEmpty(t *testing.T) {
	var rec inviteRecord
	if ids := inviteProjectIDs(&rec); len(ids) != 0 {
		t.Errorf("inviteProjectIDs = %v, want empty", ids)
	}
	rec.Projects = map[string]string{"": "ADMIN"}
	if ids := inviteProjectIDs(&rec); len(ids) != 0 {
		t.Errorf("an empty project id must be dropped, got %v", ids)
	}
}

// --- deployment checks (blocking gates) -----------------------------------

func TestCheckRecordDecodesBlockingGate(t *testing.T) {
	const payload = `{
		"id": "check_1",
		"name": "lighthouse",
		"blocks": "deployment-promotion",
		"requires": "deployment-url",
		"targets": ["production"],
		"timeout": 600,
		"sourceKind": "integration",
		"sourceIntegrationConfigurationId": "icfg_1",
		"source": {"kind": "integration", "integrationId": "int_1", "integrationConfigurationId": "icfg_1"},
		"isRerequestable": true,
		"createdAt": 1700000000000,
		"updatedAt": 1700000001000
	}`

	var rec checkRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Blocks == nil || *rec.Blocks != "deployment-promotion" {
		t.Errorf("blocks = %v", rec.Blocks)
	}
	if rec.Requires == nil || *rec.Requires != "deployment-url" {
		t.Errorf("requires = %v", rec.Requires)
	}
	if len(rec.Targets) != 1 || rec.Targets[0] != "production" {
		t.Errorf("targets = %v", rec.Targets)
	}
	if rec.Timeout == nil || *rec.Timeout != 600 {
		t.Errorf("timeout = %v", rec.Timeout)
	}
	if rec.IsRerequestable == nil || !*rec.IsRerequestable {
		t.Errorf("isRerequestable = %v", rec.IsRerequestable)
	}
	if rec.DeletedAt.Time() != nil {
		t.Error("an absent deletedAt must stay null rather than becoming the zero time")
	}
	if id := checkIntegrationConfigurationID(&rec); id == nil || *id != "icfg_1" {
		t.Errorf("checkIntegrationConfigurationID = %v", id)
	}
	if k := checkSourceKind(&rec); k == nil || *k != "integration" {
		t.Errorf("checkSourceKind = %v", k)
	}
}

// blocks:none is a check that reports a result and stops nothing. It must be
// reported as the value "none" and never conflated with a check whose blocks
// could not be read.
func TestCheckRecordBlocksNoneIsDistinctFromAbsent(t *testing.T) {
	var reported checkRecord
	if err := json.Unmarshal([]byte(`{"id":"c1","name":"advisory","blocks":"none"}`), &reported); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reported.Blocks == nil || *reported.Blocks != "none" {
		t.Fatalf("blocks = %v, want \"none\"", reported.Blocks)
	}

	var absent checkRecord
	if err := json.Unmarshal([]byte(`{"id":"c2","name":"unknown"}`), &absent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if absent.Blocks != nil {
		t.Errorf("an absent blocks must stay null, got %q", *absent.Blocks)
	}
}

func TestCheckSourceFallsBackToSourceObject(t *testing.T) {
	// A git-provider check carries the kind only inside the source object, and
	// carries no integration installation at all.
	const payload = `{
		"id": "check_2",
		"name": "ci",
		"blocks": "build-start",
		"source": {"kind": "git-provider", "provider": "github", "externalCheckName": "build"}
	}`

	var rec checkRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if k := checkSourceKind(&rec); k == nil || *k != "git-provider" {
		t.Errorf("checkSourceKind = %v", k)
	}
	if rec.Source.Provider == nil || *rec.Source.Provider != "github" {
		t.Errorf("source.provider = %v", rec.Source.Provider)
	}
	if rec.Source.ExternalCheckName == nil || *rec.Source.ExternalCheckName != "build" {
		t.Errorf("source.externalCheckName = %v", rec.Source.ExternalCheckName)
	}
	if id := checkIntegrationConfigurationID(&rec); id != nil {
		t.Errorf("a git-provider check names no installation, got %q", *id)
	}
}

func TestCheckIntegrationConfigurationIDFallsBackToSourceObject(t *testing.T) {
	var rec checkRecord
	if err := json.Unmarshal([]byte(`{"id":"c1","source":{"kind":"integration","integrationConfigurationId":"icfg_2"}}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if id := checkIntegrationConfigurationID(&rec); id == nil || *id != "icfg_2" {
		t.Errorf("checkIntegrationConfigurationID = %v", id)
	}

	var empty checkRecord
	if err := json.Unmarshal([]byte(`{"id":"c2","sourceIntegrationConfigurationId":""}`), &empty); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if id := checkIntegrationConfigurationID(&empty); id != nil {
		t.Errorf("an empty installation id must not resolve, got %q", *id)
	}
	if k := checkSourceKind(&empty); k != nil {
		t.Errorf("an absent source kind must stay null, got %q", *k)
	}
}

func TestDeploymentRecordDecodesChecksState(t *testing.T) {
	const payload = `{"uid":"dpl_1","name":"web","readyState":"READY","checksState":"completed","checksConclusion":"failed"}`

	var rec deploymentRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.ChecksState == nil || *rec.ChecksState != "completed" {
		t.Errorf("checksState = %v", rec.ChecksState)
	}
	// a deployment serving traffic with a failed conclusion was promoted past
	// a check that reported a failure
	if rec.ChecksConclusion == nil || *rec.ChecksConclusion != "failed" {
		t.Errorf("checksConclusion = %v", rec.ChecksConclusion)
	}

	var absent deploymentRecord
	if err := json.Unmarshal([]byte(`{"uid":"dpl_2","readyState":"READY"}`), &absent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if absent.ChecksState != nil || absent.ChecksConclusion != nil {
		t.Errorf("absent check fields must stay null, got %v/%v", absent.ChecksState, absent.ChecksConclusion)
	}
}

// --- Edge Config read tokens ----------------------------------------------

func TestDecodeEdgeConfigTokensAcceptsBothShapes(t *testing.T) {
	const item = `{"id": "tok_1", "label": "ci", "createdAt": 1700000000000, "edgeConfigId": "ecfg_1"}`

	for name, payload := range map[string]string{
		"bare array": `[` + item + `]`,
		"wrapped":    `{"tokens": [` + item + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeEdgeConfigTokens(json.RawMessage(payload))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("decoded %d tokens, want 1", len(got))
			}
			if got[0].ID != "tok_1" {
				t.Errorf("id = %q", got[0].ID)
			}
			if got[0].Label == nil || *got[0].Label != "ci" {
				t.Errorf("label = %v", got[0].Label)
			}
			if got[0].CreatedAt.Time() == nil {
				t.Error("createdAt should decode; it is what a rotation audit reads")
			}
		})
	}
}

func TestDecodeEdgeConfigTokensAbsent(t *testing.T) {
	for _, raw := range []string{"", "null", "  null  "} {
		got, err := decodeEdgeConfigTokens(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("decode(%q): %v", raw, err)
		}
		if len(got) != 0 {
			t.Errorf("decode(%q) = %v, want no tokens", raw, got)
		}
	}
}

// A read token is a standing credential for the store's contents. Neither the
// token nor its masked prefix may be decoded: the mask still discloses the
// leading characters of the secret.
func TestEdgeConfigTokenRecordCarriesNoTokenValue(t *testing.T) {
	assertNoJSONFields(t, reflect.TypeFor[edgeConfigTokenRecord](), "token", "partialToken")

	const payload = `[{"id":"tok_1","label":"ci","token":"zero-entropy-fake","partialToken":"zer********"}]`
	got, err := decodeEdgeConfigTokens(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "zero-entropy-fake") || strings.Contains(fmt.Sprintf("%+v", got), "zer***") {
		t.Error("a token value present in the payload reached the decoded record")
	}
}

// The mitigation is decoded from an already-decoded object, where every number
// arrived as a float64. A large rate limit must survive that round trip as an
// integer rather than being re-rendered in exponent form and rejected.
func TestFirewallRuleMitigationLargeRateLimitRoundTrips(t *testing.T) {
	var action any
	if err := json.Unmarshal([]byte(`{"mitigate":{"action":"rate_limit","rateLimit":{"algo":"fixed_window","window":3600,"limit":1000000,"keys":["ip"]}}}`), &action); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mit := firewallRuleMitigation(action)
	if mit.RateLimit == nil {
		t.Fatal("rateLimit should decode")
	}
	if mit.RateLimit.Limit == nil || *mit.RateLimit.Limit != 1000000 {
		t.Errorf("rateLimit.limit = %v, want 1000000", mit.RateLimit.Limit)
	}
	if mit.RateLimit.Window == nil || *mit.RateLimit.Window != 3600 {
		t.Errorf("rateLimit.window = %v, want 3600", mit.RateLimit.Window)
	}
	// the exceeded action is optional and must not be invented
	if mit.RateLimit.Action != nil {
		t.Errorf("rateLimit.action should stay null, got %q", *mit.RateLimit.Action)
	}
}
