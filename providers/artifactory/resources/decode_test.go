// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The API records in this package are decoded by struct tag alone. A mistyped
// tag compiles, lints, and yields a zero value, which surfaces as a confident
// "false" or "" rather than an error. A permission target whose actions decode
// to nothing reports an instance as safe that is not, so each tag is pinned
// against a payload shaped like the documented response.

func TestPermissionTargetRecordDecodesGrants(t *testing.T) {
	const payload = `{
		"name": "example-publishers",
		"repo": {
			"include-patterns": ["example/**"],
			"exclude-patterns": ["example/private/**"],
			"repositories": ["example-docker", "ANY REMOTE"],
			"actions": {
				"users": {"anonymous": ["read"], "build-account": ["read", "write"]},
				"groups": {"platform-admins": ["read", "write", "manage"]}
			}
		},
		"build": {
			"include-patterns": [""],
			"exclude-patterns": [],
			"repositories": ["artifactory-build-info"],
			"actions": {"groups": {"ci": ["read"]}}
		},
		"releaseBundle": {
			"include-patterns": ["**"],
			"exclude-patterns": [],
			"repositories": ["release-bundles"],
			"actions": {"users": {"release-manager": ["read", "distribute"]}}
		}
	}`

	var rec permissionTargetRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.Name != "example-publishers" {
		t.Errorf("name = %q", rec.Name)
	}
	if rec.Repo == nil || rec.Build == nil || rec.ReleaseBundle == nil {
		t.Fatalf("a scope decoded as absent: %+v", rec)
	}

	repo := rec.Repo
	if len(repo.IncludePatterns) != 1 || repo.IncludePatterns[0] != "example/**" {
		t.Errorf("include patterns decoded wrong: %v", repo.IncludePatterns)
	}
	if len(repo.ExcludePatterns) != 1 || repo.ExcludePatterns[0] != "example/private/**" {
		t.Errorf("exclude patterns decoded wrong: %v", repo.ExcludePatterns)
	}
	if len(repo.Repositories) != 2 || repo.Repositories[1] != "ANY REMOTE" {
		t.Errorf("repositories decoded wrong: %v", repo.Repositories)
	}
	if got := repo.Actions.Users["anonymous"]; len(got) != 1 || got[0] != "read" {
		t.Errorf("anonymous actions decoded wrong: %v", got)
	}
	if got := repo.Actions.Groups["platform-admins"]; len(got) != 3 {
		t.Errorf("group actions decoded wrong: %v", got)
	}
	if got := rec.ReleaseBundle.Actions.Users["release-manager"]; len(got) != 2 {
		t.Errorf("release bundle actions decoded wrong: %v", got)
	}
}

// A permission target that grants over repositories only must leave the other
// scopes absent rather than empty, so a query can tell "no grant" from "a
// grant that names nothing".
func TestPermissionTargetRecordKeepsAbsentScopesNull(t *testing.T) {
	const payload = `{"name":"example","repo":{"repositories":["example-docker"],"actions":{"users":{}}}}`

	var rec permissionTargetRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Repo == nil {
		t.Fatal("repo scope decoded as absent")
	}
	if rec.Build != nil || rec.ReleaseBundle != nil {
		t.Errorf("an absent scope decoded as present: %+v", rec)
	}
}

func TestRepositoryRecordsDecode(t *testing.T) {
	const listPayload = `[
		{"key":"example-docker","description":"images","type":"LOCAL","packageType":"Docker"},
		{"key":"example-remote","type":"REMOTE","url":"https://registry.example.com","packageType":"Docker"}
	]`

	var list []repositoryRecord
	if err := json.Unmarshal([]byte(listPayload), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 repositories, got %d", len(list))
	}
	if list[1].URL != "https://registry.example.com" {
		t.Errorf("upstream URL decoded wrong: %q", list[1].URL)
	}

	const detailPayload = `{
		"key": "example-remote",
		"rclass": "remote",
		"packageType": "docker",
		"url": "https://registry.example.com",
		"repositories": ["example-docker", "example-remote"],
		"xrayIndex": true,
		"blackedOut": false,
		"offline": false,
		"includesPattern": "**/*",
		"excludesPattern": "secret/**",
		"repoLayoutRef": "simple-default",
		"allowAnyHostAuth": true,
		"externalDependenciesEnabled": true
	}`

	var detail repositoryDetailRecord
	if err := json.Unmarshal([]byte(detailPayload), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.RClass != "remote" {
		t.Errorf("rclass decoded wrong: %q", detail.RClass)
	}
	if detail.XrayIndex == nil || !*detail.XrayIndex {
		t.Errorf("xrayIndex decoded wrong: %v", detail.XrayIndex)
	}
	if detail.AllowAnyHostAuth == nil || !*detail.AllowAnyHostAuth {
		t.Errorf("allowAnyHostAuth decoded wrong: %v", detail.AllowAnyHostAuth)
	}
	if detail.ExternalDependenciesEnabled == nil || !*detail.ExternalDependenciesEnabled {
		t.Errorf("externalDependenciesEnabled decoded wrong: %v", detail.ExternalDependenciesEnabled)
	}
	if len(detail.Repositories) != 2 {
		t.Errorf("member repositories decoded wrong: %v", detail.Repositories)
	}
	if detail.ExcludesPattern != "secret/**" {
		t.Errorf("excludesPattern decoded wrong: %q", detail.ExcludesPattern)
	}
}

// A setting the instance does not report for a repository type must stay
// absent, so a local repository is not reported as one that proxies with
// host authentication turned off.
func TestRepositoryDetailKeepsAbsentSettingsNull(t *testing.T) {
	const payload = `{"key":"example-docker","rclass":"local","packageType":"docker"}`

	var detail repositoryDetailRecord
	if err := json.Unmarshal([]byte(payload), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.AllowAnyHostAuth != nil || detail.ExternalDependenciesEnabled != nil || detail.XrayIndex != nil {
		t.Errorf("an absent setting decoded as present: %+v", detail)
	}
}

func TestUserRecordDecodes(t *testing.T) {
	const payload = `{
		"username": "example-admin",
		"email": "admin@example.com",
		"admin": true,
		"profile_updatable": false,
		"internal_password_disabled": true,
		"disable_ui_access": false,
		"realm": "internal",
		"status": "enabled",
		"groups": ["platform-admins", "readers"],
		"last_logged_in": "2026-01-02T03:04:05.000Z"
	}`

	var rec userRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.Username != "example-admin" || rec.Email != "admin@example.com" {
		t.Errorf("identity decoded wrong: %+v", rec)
	}
	if !boolValue(rec.Admin) {
		t.Error("admin decoded as false, want true")
	}
	if boolValue(rec.ProfileUpdatable) {
		t.Error("profile_updatable decoded as true, want false")
	}
	if !boolValue(rec.InternalPasswordDisabled) {
		t.Error("internal_password_disabled decoded as false, want true")
	}
	if rec.Realm != "internal" || rec.Status != "enabled" {
		t.Errorf("realm or status decoded wrong: %+v", rec)
	}
	if len(rec.Groups) != 2 {
		t.Errorf("groups decoded wrong: %v", rec.Groups)
	}
	if rec.LastLoggedIn.Time() == nil {
		t.Fatal("last_logged_in decoded as null")
	}
	if got := rec.LastLoggedIn.Time().UTC(); got.Year() != 2026 || got.Month() != time.January {
		t.Errorf("last_logged_in decoded wrong: %v", got)
	}
}

// An account that never signed in reports no timestamp. It must stay null
// rather than becoming the zero time, which would read as a sign-in in year 1.
func TestUserRecordKeepsAbsentLoginNull(t *testing.T) {
	const payload = `{"username":"example","realm":"internal"}`

	var rec userRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.LastLoggedIn.Time() != nil {
		t.Errorf("last_logged_in = %v, want null", rec.LastLoggedIn.Time())
	}
	if boolValue(rec.Admin) {
		t.Error("an absent admin flag decoded as true")
	}
}

func TestGroupRecordDecodes(t *testing.T) {
	const payload = `{
		"name": "platform-admins",
		"description": "publishes platform artifacts",
		"auto_join": false,
		"admin_privileges": true,
		"realm": "ldap",
		"realm_attributes": "ldapGroupName=platform;groupsStrategy=STATIC",
		"external_id": "cn=platform,ou=groups,dc=example,dc=com",
		"members": ["example-admin", "build-account"]
	}`

	var rec groupRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !boolValue(rec.AdminPrivileges) {
		t.Error("admin_privileges decoded as false, want true")
	}
	if boolValue(rec.AutoJoin) {
		t.Error("auto_join decoded as true, want false")
	}
	if rec.Realm != "ldap" || rec.RealmAttributes == "" || rec.ExternalID == "" {
		t.Errorf("realm fields decoded wrong: %+v", rec)
	}
	if len(rec.Members) != 2 {
		t.Errorf("members decoded wrong: %v", rec.Members)
	}
}

func TestTokenRecordDecodes(t *testing.T) {
	const payload = `{"tokens":[
		{"token_id":"1","subject":"jfrt@01ab2c3d/users/build-account","expiry":1798761600,"issued_at":1767225600,"issuer":"jfrt@01ab2c3d","refreshable":true,"description":"ci","scope":"applied-permissions/groups:ci member-of-groups:ci"},
		{"token_id":"2","subject":"jfrt@01ab2c3d/users/example-admin","issued_at":1767225600,"issuer":"jfrt@01ab2c3d","scope":"applied-permissions/admin"}
	]}`

	var response tokenListResponse
	if err := json.Unmarshal([]byte(payload), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(response.Tokens))
	}

	first := response.Tokens[0]
	if first.TokenID != "1" || !first.Refreshable || first.Description != "ci" {
		t.Errorf("token decoded wrong: %+v", first)
	}
	if epochTime(first.Expiry) == nil {
		t.Error("expiry decoded as null on a token that expires")
	}

	// A token without an expiry never expires. That must stay null so a policy
	// can find it, rather than becoming 1 January 1970.
	second := response.Tokens[1]
	if second.Expiry != 0 {
		t.Errorf("expiry = %d, want it absent", second.Expiry)
	}
	if epochTime(second.Expiry) != nil {
		t.Error("an absent expiry produced a timestamp")
	}
	if !grantsAdmin(splitScope(second.Scope)) {
		t.Error("an admin-scoped token was not recognised")
	}
}

func TestCleanupPolicyDecodesBothShapes(t *testing.T) {
	const criteria = `{
		"key": "example-retention",
		"description": "keeps the last builds",
		"cronExp": "0 0 2 * * ?",
		"durationInMinutes": 60,
		"enabled": true,
		"skipTrashcan": false,
		"searchCriteria": {
			"packageTypes": ["docker"],
			"repos": ["example-docker"],
			"excludedRepos": ["example-docker-release"],
			"createdBeforeInMonths": 6,
			"lastDownloadedBeforeInMonths": 3,
			"keepLastNVersions": 5
		}
	}`

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "bare array", body: "[" + criteria + "]"},
		{name: "wrapped in an object", body: `{"policies":[` + criteria + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := decodeCleanupPolicies([]byte(tc.body))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("expected 1 policy, got %d", len(records))
			}

			rec := records[0]
			if rec.Key != "example-retention" || !rec.Enabled || rec.CronExp != "0 0 2 * * ?" {
				t.Errorf("policy decoded wrong: %+v", rec)
			}
			if rec.DurationInMinutes == nil || *rec.DurationInMinutes != 60 {
				t.Errorf("durationInMinutes decoded wrong: %v", rec.DurationInMinutes)
			}
			if len(rec.SearchCriteria.Repos) != 1 || rec.SearchCriteria.Repos[0] != "example-docker" {
				t.Errorf("repos decoded wrong: %v", rec.SearchCriteria.Repos)
			}
			if rec.SearchCriteria.KeepLastNVersions == nil || *rec.SearchCriteria.KeepLastNVersions != 5 {
				t.Errorf("keepLastNVersions decoded wrong: %v", rec.SearchCriteria.KeepLastNVersions)
			}
		})
	}
}

func TestCleanupPolicyKeepsAbsentThresholdsNull(t *testing.T) {
	records, err := decodeCleanupPolicies([]byte(`[{"key":"example","enabled":false,"searchCriteria":{}}]`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	criteria := records[0].SearchCriteria
	if criteria.CreatedBeforeInMonths != nil || criteria.LastDownloadedBeforeInMonths != nil || criteria.KeepLastNVersions != nil {
		t.Errorf("an absent threshold decoded as zero: %+v", criteria)
	}
}

func TestSecurityConfigDecodes(t *testing.T) {
	const payload = `<?xml version="1.0" encoding="UTF-8"?>
<config xmlns="http://artifactory.jfrog.org/xsd/1.0.0">
  <security>
    <anonAccessEnabled>true</anonAccessEnabled>
    <anonAccessToBuildInfosDisabled>true</anonAccessToBuildInfosDisabled>
    <hideUnauthorizedResources>false</hideUnauthorizedResources>
    <userLockPolicy>
      <enabled>true</enabled>
      <loginAttempts>5</loginAttempts>
    </userLockPolicy>
    <passwordSettings>
      <encryptionPolicy>REQUIRED</encryptionPolicy>
      <expirationPolicy>
        <enabled>true</enabled>
        <passwordMaxAge>60</passwordMaxAge>
      </expirationPolicy>
    </passwordSettings>
  </security>
</config>`

	var config securityConfig
	if err := xml.Unmarshal([]byte(payload), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}

	security := config.Security
	if !boolValue(security.AnonAccessEnabled) {
		t.Error("anonAccessEnabled decoded as false, want true")
	}
	if !boolValue(security.AnonAccessToBuildInfosDisabled) {
		t.Error("anonAccessToBuildInfosDisabled decoded as false, want true")
	}
	if boolValue(security.HideUnauthorizedResources) {
		t.Error("hideUnauthorizedResources decoded as true, want false")
	}
	if !boolValue(security.UserLockPolicy.Enabled) || security.UserLockPolicy.LoginAttempts == nil || *security.UserLockPolicy.LoginAttempts != 5 {
		t.Errorf("user lock policy decoded wrong: %+v", security.UserLockPolicy)
	}
	if security.PasswordSettings.EncryptionPolicy != "REQUIRED" {
		t.Errorf("encryptionPolicy decoded wrong: %q", security.PasswordSettings.EncryptionPolicy)
	}
	if !boolValue(security.PasswordSettings.ExpirationPolicy.Enabled) || security.PasswordSettings.ExpirationPolicy.MaxAgeDays == nil {
		t.Errorf("expiration policy decoded wrong: %+v", security.PasswordSettings.ExpirationPolicy)
	}
}

// An instance that leaves anonymous access out of its configuration has it
// off. The absent element must not read as enabled.
func TestSecurityConfigKeepsAbsentSettingsNull(t *testing.T) {
	var config securityConfig
	if err := xml.Unmarshal([]byte(`<config><security></security></config>`), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if config.Security.AnonAccessEnabled != nil {
		t.Errorf("anonAccessEnabled = %v, want it absent", config.Security.AnonAccessEnabled)
	}
	if boolValue(config.Security.AnonAccessEnabled) {
		t.Error("an absent anonAccessEnabled read as enabled")
	}
}

func TestVersionRecordDecodes(t *testing.T) {
	const payload = `{"version":"7.90.10","revision":"79010900","addons":["docker","xray"]}`

	var rec versionRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Version != "7.90.10" || rec.Revision != "79010900" || len(rec.Addons) != 2 {
		t.Errorf("version record decoded wrong: %+v", rec)
	}
}

// The batched configuration endpoint groups repositories under their class.
// A missed class key silently drops every repository in it, and the resources
// then fall back to a per-repository read that an ordinary account cannot make.
func TestRepositoryConfigurationsDecodeEveryClass(t *testing.T) {
	const payload = `{
		"LOCAL": [{"key":"example-docker","rclass":"local","packageType":"docker","blockPushingSchema1":true,"xrayIndex":true}],
		"REMOTE": [{"key":"example-remote","rclass":"remote","packageType":"docker","url":"https://registry.example.com","username":"reader","storeArtifactsLocally":false,"contentSynchronisation":{"enabled":true}}],
		"VIRTUAL": [{"key":"example-virtual","rclass":"virtual","repositories":["example-docker","example-remote"]}],
		"FEDERATED": [{"key":"example-federated","rclass":"federated"}],
		"RELEASE_BUNDLE": [{"key":"release-bundles","rclass":"releasebundle"}],
		"DISTRIBUTION": [{"key":"example-dist","rclass":"distribution"}]
	}`

	var configurations repositoryConfigurations
	if err := json.Unmarshal([]byte(payload), &configurations); err != nil {
		t.Fatalf("decode: %v", err)
	}

	all := configurations.all()
	if len(all) != 6 {
		t.Fatalf("expected 6 repositories across every class, got %d: %+v", len(all), all)
	}

	byKey := map[string]repositoryDetailRecord{}
	for _, rec := range all {
		byKey[rec.Key] = rec
	}
	for _, key := range []string{"example-docker", "example-remote", "example-virtual", "example-federated", "release-bundles", "example-dist"} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("%q was dropped by the class grouping", key)
		}
	}

	local := byKey["example-docker"]
	if local.BlockPushingSchema1 == nil || !*local.BlockPushingSchema1 {
		t.Errorf("blockPushingSchema1 decoded wrong: %v", local.BlockPushingSchema1)
	}

	remote := byKey["example-remote"]
	if remote.Username != "reader" {
		t.Errorf("upstream user name decoded wrong: %q", remote.Username)
	}
	if remote.StoreArtifactsLocally == nil || *remote.StoreArtifactsLocally {
		t.Errorf("storeArtifactsLocally decoded wrong: %v", remote.StoreArtifactsLocally)
	}
	if remote.ContentSynchronisation == nil || remote.ContentSynchronisation.Enabled == nil || !*remote.ContentSynchronisation.Enabled {
		t.Errorf("contentSynchronisation decoded wrong: %+v", remote.ContentSynchronisation)
	}
	if len(byKey["example-virtual"].Repositories) != 2 {
		t.Errorf("virtual members decoded wrong: %v", byKey["example-virtual"].Repositories)
	}
}

// An empty response must produce no repositories rather than a panic, and an
// entry without a key must not become a map entry keyed by the empty string.
func TestRepositoryConfigurationsHandleAnEmptyResponse(t *testing.T) {
	var configurations repositoryConfigurations
	if err := json.Unmarshal([]byte(`{}`), &configurations); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(configurations.all()) != 0 {
		t.Errorf("an empty response produced %d repositories", len(configurations.all()))
	}
}

func TestRepositoryDetailDecodesTheDeliverySettings(t *testing.T) {
	const payload = `{
		"key": "example-docker",
		"rclass": "local",
		"downloadRedirect": true,
		"cdnRedirect": false,
		"archiveBrowsingEnabled": true,
		"priorityResolution": true,
		"signedUrlTtl": 90,
		"xrayDataTtl": 30,
		"projectKey": "example",
		"propertySets": ["artifactory"],
		"notes": "example note"
	}`

	var detail repositoryDetailRecord
	if err := json.Unmarshal([]byte(payload), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.DownloadRedirect == nil || !*detail.DownloadRedirect {
		t.Errorf("downloadRedirect decoded wrong: %v", detail.DownloadRedirect)
	}
	if detail.CdnRedirect == nil || *detail.CdnRedirect {
		t.Errorf("cdnRedirect decoded wrong: %v", detail.CdnRedirect)
	}
	if detail.SignedURLTTL == nil || *detail.SignedURLTTL != 90 {
		t.Errorf("signedUrlTtl decoded wrong: %v", detail.SignedURLTTL)
	}
	if detail.XrayDataTTL == nil || *detail.XrayDataTTL != 30 {
		t.Errorf("xrayDataTtl decoded wrong: %v", detail.XrayDataTTL)
	}
	if detail.ProjectKey != "example" || detail.Notes != "example note" || len(detail.PropertySets) != 1 {
		t.Errorf("repository metadata decoded wrong: %+v", detail)
	}
}

// A repository resolved by key is built from the configuration response rather
// than from the list, so every field the list would have set must be taken from
// it. A missed field reports empty on a repository that has one.
func TestRepositoryDetailCarriesTheListFields(t *testing.T) {
	const payload = `{"key":"example-docker","rclass":"local","packageType":"docker","description":"platform images","url":""}`

	var detail repositoryDetailRecord
	if err := json.Unmarshal([]byte(payload), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// These are the fields newArtifactoryRepository sets at creation time. Each
	// one must be readable from the configuration response.
	if detail.Key == "" || detail.RClass == "" || detail.PackageType == "" || detail.Description == "" {
		t.Errorf("a field the list would have set is missing from the detail: %+v", detail)
	}
	if detail.Description != "platform images" {
		t.Errorf("description decoded wrong: %q", detail.Description)
	}
}

// The identity integrations decide who becomes a principal on the instance.
// A mistyped element name decodes to a nil pointer, which this provider reports
// as null rather than as "off", so the tags are pinned against the descriptor
// shape.
func TestSecurityConfigDecodesTheIdentityIntegrations(t *testing.T) {
	const payload = `<config>
  <security>
    <anonAccessEnabled>false</anonAccessEnabled>
    <buildGlobalBasicReadAllowed>true</buildGlobalBasicReadAllowed>
    <buildGlobalBasicReadForAnonymous>false</buildGlobalBasicReadForAnonymous>
    <ldapSettings>
      <ldapSetting>
        <key>example-ldap</key>
        <enabled>true</enabled>
        <ldapUrl>ldaps://ldap.example.com:636/dc=example,dc=com</ldapUrl>
        <userDnPattern>uid={0},ou=People</userDnPattern>
        <autoCreateUser>true</autoCreateUser>
        <emailAttribute>mail</emailAttribute>
        <ldapPoisoningProtection>true</ldapPoisoningProtection>
        <allowUserToAccessProfile>false</allowUserToAccessProfile>
        <search>
          <searchFilter>(uid={0})</searchFilter>
          <searchBase>ou=users</searchBase>
          <searchSubTree>true</searchSubTree>
          <managerDn>cn=reader,dc=example,dc=com</managerDn>
        </search>
      </ldapSetting>
    </ldapSettings>
    <ldapGroupSettings>
      <ldapGroupSetting>
        <name>example-groups</name>
        <groupBaseDn>ou=groups,dc=example,dc=com</groupBaseDn>
        <groupNameAttribute>cn</groupNameAttribute>
        <groupMemberAttribute>uniqueMember</groupMemberAttribute>
        <filter>(objectClass=groupOfNames)</filter>
        <strategy>STATIC</strategy>
        <subTree>true</subTree>
        <enabledLdap>example-ldap</enabledLdap>
      </ldapGroupSetting>
    </ldapGroupSettings>
    <samlSettings>
      <enableIntegration>true</enableIntegration>
      <loginUrl>https://idp.example.com/sso</loginUrl>
      <serviceProviderName>artifactory</serviceProviderName>
      <noAutoUserCreation>false</noAutoUserCreation>
      <autoRedirect>true</autoRedirect>
      <syncGroups>true</syncGroups>
      <verifyAudienceRestriction>true</verifyAudienceRestriction>
      <certificate>MIIBExample</certificate>
    </samlSettings>
    <oauthSettings>
      <enableIntegration>true</enableIntegration>
      <persistUsers>true</persistUsers>
      <oauthProvidersSettings>
        <oauthProviderSettings>
          <name>example-github</name>
          <enabled>true</enabled>
          <providerType>github</providerType>
          <id>example-client-id</id>
          <apiUrl>https://api.github.com/user</apiUrl>
          <domain>example</domain>
        </oauthProviderSettings>
      </oauthProvidersSettings>
    </oauthSettings>
    <httpSsoSettings>
      <httpSsoProxied>true</httpSsoProxied>
      <remoteUserRequestVariable>REMOTE_USER</remoteUserRequestVariable>
      <noAutoUserCreation>false</noAutoUserCreation>
    </httpSsoSettings>
    <crowdSettings>
      <enableIntegration>true</enableIntegration>
      <serverUrl>https://crowd.example.com</serverUrl>
      <applicationName>artifactory</applicationName>
      <sessionValidationInterval>60</sessionValidationInterval>
      <directAuthentication>true</directAuthentication>
    </crowdSettings>
  </security>
  <backups>
    <backup>
      <key>backup-daily</key>
      <enabled>true</enabled>
      <cronExp>0 0 2 ? * MON-FRI</cronExp>
      <retentionPeriodHours>168</retentionPeriodHours>
      <createArchive>false</createArchive>
      <excludeBuilds>false</excludeBuilds>
      <excludeNewRepositories>true</excludeNewRepositories>
      <sendMailOnError>true</sendMailOnError>
      <excludedRepositories>
        <repositoryRef>example-docker</repositoryRef>
        <repositoryRef>example-generic</repositoryRef>
      </excludedRepositories>
    </backup>
  </backups>
</config>`

	var config securityConfig
	if err := xml.Unmarshal([]byte(payload), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	security := config.Security

	if !boolValue(security.BuildGlobalBasicReadAllowed) || boolValue(security.BuildGlobalBasicReadForAnonymous) {
		t.Errorf("global build read decoded wrong: %+v", security)
	}

	if len(security.LdapSettings) != 1 {
		t.Fatalf("expected 1 LDAP server, got %d", len(security.LdapSettings))
	}
	ldap := security.LdapSettings[0]
	if ldap.Key != "example-ldap" || !boolValue(ldap.Enabled) || !boolValue(ldap.AutoCreateUser) {
		t.Errorf("LDAP server decoded wrong: %+v", ldap)
	}
	if ldap.Search.SearchFilter != "(uid={0})" || ldap.Search.ManagerDn == "" || !boolValue(ldap.Search.SearchSubTree) {
		t.Errorf("LDAP search decoded wrong: %+v", ldap.Search)
	}

	if len(security.LdapGroupSettings) != 1 {
		t.Fatalf("expected 1 LDAP group mapping, got %d", len(security.LdapGroupSettings))
	}
	if security.LdapGroupSettings[0].EnabledLdap != "example-ldap" || security.LdapGroupSettings[0].Strategy != "STATIC" {
		t.Errorf("LDAP group mapping decoded wrong: %+v", security.LdapGroupSettings[0])
	}

	if security.SamlSettings == nil {
		t.Fatal("SAML settings decoded as absent")
	}
	if !boolValue(security.SamlSettings.EnableIntegration) || !boolValue(security.SamlSettings.AutoRedirect) ||
		!boolValue(security.SamlSettings.VerifyAudienceRestriction) || security.SamlSettings.Certificate == "" {
		t.Errorf("SAML settings decoded wrong: %+v", security.SamlSettings)
	}

	if security.OauthSettings == nil || len(security.OauthSettings.Providers) != 1 {
		t.Fatalf("OAuth providers decoded wrong: %+v", security.OauthSettings)
	}
	provider := security.OauthSettings.Providers[0]
	if provider.Name != "example-github" || provider.ProviderType != "github" || provider.ID != "example-client-id" || provider.Domain != "example" {
		t.Errorf("OAuth provider decoded wrong: %+v", provider)
	}

	if security.HttpSsoSettings == nil || !boolValue(security.HttpSsoSettings.HttpSsoProxied) ||
		security.HttpSsoSettings.RemoteUserRequestVariable != "REMOTE_USER" {
		t.Errorf("HTTP single sign-on decoded wrong: %+v", security.HttpSsoSettings)
	}

	if security.CrowdSettings == nil || !boolValue(security.CrowdSettings.EnableIntegration) ||
		security.CrowdSettings.SessionValidationInterval == nil || *security.CrowdSettings.SessionValidationInterval != 60 {
		t.Errorf("Crowd settings decoded wrong: %+v", security.CrowdSettings)
	}

	if len(config.Backups) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(config.Backups))
	}
	backup := config.Backups[0]
	if backup.Key != "backup-daily" || !boolValue(backup.Enabled) || !boolValue(backup.ExcludeNewRepositories) {
		t.Errorf("backup decoded wrong: %+v", backup)
	}
	if len(backup.ExcludedRepositories) != 2 || backup.ExcludedRepositories[1] != "example-generic" {
		t.Errorf("excluded repositories decoded wrong: %v", backup.ExcludedRepositories)
	}
	if backup.RetentionPeriodHours == nil || *backup.RetentionPeriodHours != 168 {
		t.Errorf("retention decoded wrong: %v", backup.RetentionPeriodHours)
	}
}

// An instance that never configured an integration carries no element for it.
// That must stay absent rather than decoding to a zero block, which the
// provider would report as a configured but disabled integration.
func TestSecurityConfigKeepsAbsentIntegrationsNull(t *testing.T) {
	var config securityConfig
	if err := xml.Unmarshal([]byte(`<config><security><anonAccessEnabled>false</anonAccessEnabled></security></config>`), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}

	security := config.Security
	if security.SamlSettings != nil || security.OauthSettings != nil ||
		security.HttpSsoSettings != nil || security.CrowdSettings != nil {
		t.Errorf("an absent integration decoded as present: %+v", security)
	}
	if len(security.LdapSettings) != 0 || len(security.LdapGroupSettings) != 0 {
		t.Errorf("an absent LDAP block decoded as configured: %+v", security)
	}
	if len(config.Backups) != 0 {
		t.Errorf("an absent backup block decoded as %d backups", len(config.Backups))
	}
}

// An empty integration element is a configured integration, which is a
// different answer from an absent one.
func TestSecurityConfigDistinguishesEmptyFromAbsent(t *testing.T) {
	var config securityConfig
	if err := xml.Unmarshal([]byte(`<config><security><samlSettings></samlSettings></security></config>`), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if config.Security.SamlSettings == nil {
		t.Fatal("an empty SAML element decoded as absent")
	}
	if boolValue(config.Security.SamlSettings.EnableIntegration) {
		t.Error("an empty SAML element decoded as enabled")
	}
}

// The instance also returns the stored password in this response. It is left
// out of the fixture on purpose, because the record has no field for it and a
// secret-shaped literal in a test is worth avoiding.
//
// The replication endpoint answers with one object for a single replication and
// an array for several. Reading only one shape would drop every replication on
// a repository configured with more than one, which is the push case that
// matters most.
func TestReplicationsDecodeBothShapes(t *testing.T) {
	const single = `{
		"url": "https://artifactory.example.com/artifactory/example-docker",
		"socketTimeoutMillis": 15000,
		"username": "replicator",
		"enableEventReplication": true,
		"enabled": true,
		"cronExp": "0 0 12 * * ?",
		"syncDeletes": true,
		"syncProperties": true,
		"syncStatistics": false,
		"repoKey": "example-docker",
		"replicationKey": "example-docker_https_1234",
		"includePathPrefixPattern": "/example",
		"excludePathPrefixPattern": "/private"
	}`

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{name: "single object", body: single, want: 1},
		{name: "array", body: "[" + single + "," + single + "]", want: 2},
		{name: "empty body", body: "", want: 0},
		{name: "null body", body: "null", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := decodeReplications([]byte(tc.body))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(records) != tc.want {
				t.Fatalf("expected %d replications, got %d", tc.want, len(records))
			}
			if tc.want == 0 {
				return
			}

			rec := records[0]
			if rec.RepoKey != "example-docker" || rec.ReplicationKey != "example-docker_https_1234" {
				t.Errorf("replication identity decoded wrong: %+v", rec)
			}
			if rec.URL != "https://artifactory.example.com/artifactory/example-docker" {
				t.Errorf("replication URL decoded wrong: %q", rec.URL)
			}
			if !boolValue(rec.Enabled) || !boolValue(rec.SyncDeletes) || !boolValue(rec.EnableEventReplication) {
				t.Errorf("replication flags decoded wrong: %+v", rec)
			}
			if boolValue(rec.SyncStatistics) {
				t.Error("syncStatistics decoded as true, want false")
			}
			if rec.Username != "replicator" {
				t.Errorf("replication user name decoded wrong: %q", rec.Username)
			}
			if rec.SocketTimeoutMillis == nil || *rec.SocketTimeoutMillis != 15000 {
				t.Errorf("socket timeout decoded wrong: %v", rec.SocketTimeoutMillis)
			}
			if rec.IncludePathPrefixPattern != "/example" || rec.ExcludePathPrefixPattern != "/private" {
				t.Errorf("replication path patterns decoded wrong: %+v", rec)
			}
		})
	}
}

// The instance returns the stored password with the replication. It must not
// reach a struct field, so it cannot reach a resource field, a log line, or a
// recording.
func TestReplicationRecordHasNoPasswordField(t *testing.T) {
	value := reflect.TypeFor[replicationRecord]()
	for field := range value.Fields() {
		field := field
		tag := strings.ToLower(field.Tag.Get("json"))
		name := strings.ToLower(field.Name)
		if strings.Contains(tag, "password") || strings.Contains(name, "password") {
			t.Errorf("replicationRecord decodes the stored password in field %s", field.Name)
		}
	}
}

func TestXrayWatchRecordDecodes(t *testing.T) {
	const payload = `[
	  {
	    "general_data": {"id":"1","name":"example-watch","description":"platform repositories","active":true},
	    "project_resources": {"resources":[
	      {"type":"repository","name":"example-docker","bin_mgr_id":"default","repo_type":"local",
	       "filters":[{"type":"package-type","value":"docker"},{"type":"path-ant-patterns","value":["example/**"]}]},
	      {"type":"all-builds","bin_mgr_id":"default"}
	    ]},
	    "assigned_policies": [{"name":"example-security","type":"security"},{"name":"example-license","type":"license"}]
	  }
	]`

	var records []xrayWatchRecord
	if err := json.Unmarshal([]byte(payload), &records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 watch, got %d", len(records))
	}

	rec := records[0]
	if rec.GeneralData.Name != "example-watch" || !boolValue(rec.GeneralData.Active) {
		t.Errorf("watch identity decoded wrong: %+v", rec.GeneralData)
	}
	if len(rec.ProjectResources.Resources) != 2 {
		t.Fatalf("watch resources decoded wrong: %+v", rec.ProjectResources)
	}
	repo := rec.ProjectResources.Resources[0]
	if repo.Type != "repository" || repo.Name != "example-docker" || repo.RepoType != "local" {
		t.Errorf("repository resource decoded wrong: %+v", repo)
	}
	if len(repo.Filters) != 2 || repo.Filters[0].Type != "package-type" {
		t.Errorf("resource filters decoded wrong: %+v", repo.Filters)
	}
	if len(rec.AssignedPolicies) != 2 || rec.AssignedPolicies[1].Name != "example-license" {
		t.Errorf("assigned policies decoded wrong: %+v", rec.AssignedPolicies)
	}
}

func TestXrayPolicyRecordDecodes(t *testing.T) {
	const payload = `[
	  {
	    "name": "example-security",
	    "type": "security",
	    "description": "blocks critical findings",
	    "rules": [
	      {
	        "name": "critical",
	        "priority": 1,
	        "criteria": {"min_severity":"Critical","fix_version_dependant":true,"applicable_cves_only":false,"malicious_package":true},
	        "actions": {
	          "block_download": {"unscanned": true, "active": true},
	          "fail_build": true,
	          "block_release_bundle_distribution": true,
	          "build_failure_grace_period_in_days": 5,
	          "notify_watch_recipients": true,
	          "custom_severity": "High"
	        }
	      },
	      {
	        "name": "cvss",
	        "criteria": {"cvss_range":{"from":7.0,"to":10.0}},
	        "actions": {"block_download": {"unscanned": false, "active": false}}
	      }
	    ]
	  }
	]`

	var records []xrayPolicyRecord
	if err := json.Unmarshal([]byte(payload), &records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 1 || len(records[0].Rules) != 2 {
		t.Fatalf("policy decoded wrong: %+v", records)
	}

	first := records[0].Rules[0]
	if first.Criteria.MinSeverity != "Critical" || !boolValue(first.Criteria.FixVersionDependant) || !boolValue(first.Criteria.MaliciousPackage) {
		t.Errorf("criteria decoded wrong: %+v", first.Criteria)
	}
	if first.Actions.BlockDownload == nil || !boolValue(first.Actions.BlockDownload.Active) || !boolValue(first.Actions.BlockDownload.Unscanned) {
		t.Errorf("block download decoded wrong: %+v", first.Actions.BlockDownload)
	}
	if !boolValue(first.Actions.FailBuild) || first.Actions.CustomSeverity != "High" {
		t.Errorf("actions decoded wrong: %+v", first.Actions)
	}
	if first.Actions.BuildFailureGracePeriodInDays == nil || *first.Actions.BuildFailureGracePeriodInDays != 5 {
		t.Errorf("grace period decoded wrong: %v", first.Actions.BuildFailureGracePeriodInDays)
	}
	if first.Priority == nil || *first.Priority != 1 {
		t.Errorf("priority decoded wrong: %v", first.Priority)
	}

	second := records[0].Rules[1]
	if second.Criteria.CvssRange == nil || second.Criteria.CvssRange.From == nil || *second.Criteria.CvssRange.From != 7.0 {
		t.Errorf("CVSS range decoded wrong: %+v", second.Criteria.CvssRange)
	}
	// A rule without a severity criterion must leave it empty rather than
	// inventing one, and a rule without a grace period must stay null.
	if second.Criteria.MinSeverity != "" || second.Actions.BuildFailureGracePeriodInDays != nil {
		t.Errorf("absent criteria decoded as present: %+v", second)
	}
}

func TestXrayIgnoreRuleRecordDecodes(t *testing.T) {
	const payload = `{"data":[
	  {"id":"rule-1","author":"example-admin","notes":"accepted","created":"2026-01-02T03:04:05Z","expires_at":"2026-06-02T03:04:05Z",
	   "is_expired":false,"vulnerabilities":["CVE-2026-0001"],"ignore_filters":{"repositories":["example-docker"]}},
	  {"id":"rule-2","author":"example-admin","notes":"permanent","vulnerabilities":["CVE-2026-0002"]}
	]}`

	var response xrayIgnoreRulesResponse
	if err := json.Unmarshal([]byte(payload), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Data) != 2 {
		t.Fatalf("expected 2 ignore rules, got %d", len(response.Data))
	}

	first := response.Data[0]
	if first.ID != "rule-1" || first.Notes != "accepted" || len(first.Vulnerabilities) != 1 {
		t.Errorf("ignore rule decoded wrong: %+v", first)
	}
	if first.ExpiresAt.Time() == nil {
		t.Error("an expiry decoded as null")
	}
	if len(first.IgnoreFilters.Repositories) != 1 || first.IgnoreFilters.Repositories[0] != "example-docker" {
		t.Errorf("ignore scope decoded wrong: %+v", first.IgnoreFilters)
	}

	// A rule with no expiry suppresses its finding until somebody removes it.
	// That must stay null so a policy can find it.
	if response.Data[1].ExpiresAt.Time() != nil {
		t.Errorf("an absent expiry produced %v", response.Data[1].ExpiresAt.Time())
	}
}

// The suppression list is paged. Reading the first page only would report
// fewer permanent suppressions than exist, and an audit looking for them would
// pass because the rest were never fetched.
func TestIgnoreRulesPaginationWalksEveryPage(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Query().Get("page_num"))

		page := r.URL.Query().Get("page_num")
		rows := 100
		start := 0
		if page == "2" {
			start = rows
			rows = 30
		}

		entries := make([]string, 0, rows)
		for i := 0; i < rows; i++ {
			entries = append(entries, fmt.Sprintf(`{"id":"rule-%d"}`, start+i))
		}
		fmt.Fprintf(w, `{"total_count":130,"page_num":%s,"num_of_rows":%d,"data":[%s]}`, page, rows, strings.Join(entries, ","))
	}))
	defer server.Close()

	records, err := fetchXrayIgnoreRules(context.Background(), testXrayConnection(t, server.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 130 {
		t.Fatalf("expected 130 suppressions across both pages, got %d", len(records))
	}
	if len(requested) != 2 || requested[0] != "1" || requested[1] != "2" {
		t.Errorf("pages requested: %v", requested)
	}
	if records[129].ID != "rule-129" {
		t.Errorf("last suppression is %q", records[129].ID)
	}
}

// An endpoint that ignores the page parameter answers every request with the
// first page. That must stop the walk rather than multiply every suppression
// up to the page cap.
func TestIgnoreRulesPaginationStopsOnARepeatedPage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		entries := make([]string, 0, 100)
		for i := range 100 {
			entries = append(entries, fmt.Sprintf(`{"id":"rule-%d"}`, i))
		}
		fmt.Fprintf(w, `{"total_count":0,"data":[%s]}`, strings.Join(entries, ","))
	}))
	defer server.Close()

	records, err := fetchXrayIgnoreRules(context.Background(), testXrayConnection(t, server.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 100 {
		t.Fatalf("a repeated page produced %d suppressions, want 100", len(records))
	}
	if calls != 2 {
		t.Errorf("the walk made %d calls, want it to stop after the repeat", calls)
	}
}

// An empty first page is an instance with no suppressions at all.
func TestIgnoreRulesPaginationHandlesAnEmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"total_count":0,"data":[]}`)
	}))
	defer server.Close()

	records, err := fetchXrayIgnoreRules(context.Background(), testXrayConnection(t, server.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("an empty list produced %d suppressions", len(records))
	}
}

func testXrayConnection(t *testing.T, baseURL string) *connection.ArtifactoryConnection {
	t.Helper()

	conf := &inventory.Config{
		Options: map[string]string{connection.OptionURL: baseURL},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_bearer, Secret: []byte("example-token")},
		},
	}
	conn, err := connection.NewArtifactoryConnection(1, &inventory.Asset{}, conf)
	if err != nil {
		t.Fatalf("could not build the connection: %v", err)
	}
	return conn
}

// A page of records the platform reports without an identifier cannot be
// deduplicated by identifier. If the endpoint also ignores the page parameter,
// counting those as new would run the walk to the page cap and multiply every
// suppression. The page marker stops it instead.
func TestIgnoreRulesPaginationStopsOnRepeatedIdentifierlessRecords(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		entries := make([]string, 0, 100)
		for range 100 {
			entries = append(entries, `{"notes":"accepted"}`)
		}
		fmt.Fprintf(w, `{"total_count":0,"data":[%s]}`, strings.Join(entries, ","))
	}))
	defer server.Close()

	records, err := fetchXrayIgnoreRules(context.Background(), testXrayConnection(t, server.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 100 {
		t.Fatalf("a repeated identifier-less page produced %d suppressions, want 100", len(records))
	}
	if calls != 2 {
		t.Errorf("the walk made %d calls, want it to stop after the repeat", calls)
	}
}

func TestPageMarkerDistinguishesPages(t *testing.T) {
	first := []xrayIgnoreRuleRecord{{ID: "a"}, {ID: "b"}}
	same := []xrayIgnoreRuleRecord{{ID: "a"}, {ID: "b"}}
	other := []xrayIgnoreRuleRecord{{ID: "c"}, {ID: "d"}}
	shorter := []xrayIgnoreRuleRecord{{ID: "a"}}

	if pageMarker(first) != pageMarker(same) {
		t.Error("the same page produced different markers")
	}
	if pageMarker(first) == pageMarker(other) {
		t.Error("different pages produced the same marker")
	}
	if pageMarker(first) == pageMarker(shorter) {
		t.Error("a shorter page produced the same marker")
	}
	if pageMarker(nil) == pageMarker(shorter) {
		t.Error("an empty page produced the same marker as a page with a record")
	}
}

// A project delegates part of the instance to its own administrators. The
// privilege flags decide what those administrators may do without a platform
// administrator, so a mistyped tag would report a delegated project as locked
// down.
func TestProjectRecordDecodes(t *testing.T) {
	const payload = `[
	  {
	    "project_key": "example",
	    "display_name": "Example",
	    "description": "platform artifacts",
	    "admin_privileges": {"manage_members": true, "manage_resources": true, "index_resources": false},
	    "storage_quota_bytes": 1073741824,
	    "soft_limit": true
	  },
	  {"project_key": "minimal", "display_name": "Minimal"}
	]`

	var records []projectRecord
	if err := json.Unmarshal([]byte(payload), &records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(records))
	}

	first := records[0]
	if first.ProjectKey != "example" || first.DisplayName != "Example" || first.Description != "platform artifacts" {
		t.Errorf("project identity decoded wrong: %+v", first)
	}
	if !boolValue(first.AdminPrivileges.ManageMembers) || !boolValue(first.AdminPrivileges.ManageResources) {
		t.Errorf("admin privileges decoded wrong: %+v", first.AdminPrivileges)
	}
	if boolValue(first.AdminPrivileges.IndexResources) {
		t.Error("index_resources decoded as true, want false")
	}
	if first.StorageQuotaBytes == nil || *first.StorageQuotaBytes != 1073741824 {
		t.Errorf("storage quota decoded wrong: %v", first.StorageQuotaBytes)
	}

	// A project the instance reports without privileges or a quota must keep
	// them absent. Reading a missing quota as zero would report a project that
	// may store nothing.
	second := records[1]
	if second.AdminPrivileges.ManageMembers != nil || second.StorageQuotaBytes != nil || second.SoftLimit != nil {
		t.Errorf("an absent value decoded as present: %+v", second)
	}
	if boolValue(second.AdminPrivileges.ManageMembers) {
		t.Error("an absent privilege read as granted")
	}
}

func TestProjectMembersDecode(t *testing.T) {
	const payload = `{"members":[
	  {"name":"example-admin","roles":["Project Admin","Developer"]},
	  {"name":"build-account","roles":["Contributor"]},
	  {"name":"viewer"}
	]}`

	var response projectMembersResponse
	if err := json.Unmarshal([]byte(payload), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(response.Members))
	}
	if response.Members[0].Name != "example-admin" || len(response.Members[0].Roles) != 2 {
		t.Errorf("member decoded wrong: %+v", response.Members[0])
	}
	if response.Members[2].Roles != nil {
		t.Errorf("a member with no roles decoded as %v", response.Members[2].Roles)
	}
}
