// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
)

// The API records in this package are decoded by struct tag alone. A mistyped
// tag compiles, lints, and yields a zero value, which for this provider means
// reporting a project as not blocking public connections when it does. These
// tests pin each security-relevant tag against a payload shaped like the
// documented API response.

func TestProjectRecordDecodesSettings(t *testing.T) {
	const payload = `{
		"id": "proj-1",
		"name": "production",
		"platform_id": "aws",
		"region_id": "aws-us-east-1",
		"pg_version": 17,
		"provisioner": "k8s-neonvm",
		"proxy_host": "us-east-1.aws.neon.tech",
		"store_passwords": true,
		"history_retention_seconds": 604800,
		"hipaa_enabled_at": "2026-01-02T03:04:05Z",
		"org_id": "org-1",
		"owner": {"email": "ada@example.com"},
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-02-03T04:05:06Z",
		"compute_last_active_at": "2026-03-04T05:06:07Z",
		"settings": {
			"allowed_ips": {"ips": ["10.0.0.0/8", "192.0.2.1"], "protected_branches_only": true},
			"audit_log_level": "full",
			"block_public_connections": true,
			"block_vpc_connections": false,
			"enable_logical_replication": true,
			"hipaa": true
		}
	}`

	var rec projectRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.ID != "proj-1" || rec.Name != "production" || rec.RegionID != "aws-us-east-1" {
		t.Errorf("identity fields decoded wrong: %+v", rec)
	}
	if rec.PgVersion != 17 {
		t.Errorf("pg_version decoded wrong: %d", rec.PgVersion)
	}
	if !rec.StorePasswords {
		t.Error("store_passwords decoded wrong")
	}
	if rec.HistoryRetentionSeconds == nil || *rec.HistoryRetentionSeconds != 604800 {
		t.Errorf("history retention decoded wrong: %v", rec.HistoryRetentionSeconds)
	}
	if rec.OrgID == nil || *rec.OrgID != "org-1" {
		t.Errorf("org linkage decoded wrong: %v", rec.OrgID)
	}
	if rec.Owner == nil || rec.Owner.Email != "ada@example.com" {
		t.Errorf("owner decoded wrong: %+v", rec.Owner)
	}

	settings := rec.Settings
	if settings == nil {
		t.Fatal("settings did not decode")
	}
	if !boolPtr(settings.BlockPublicConnections) {
		t.Error("block_public_connections decoded wrong")
	}
	if boolPtr(settings.BlockVpcConnections) {
		t.Error("block_vpc_connections decoded wrong")
	}
	if !boolPtr(settings.EnableLogicalReplication) || !boolPtr(settings.Hipaa) {
		t.Errorf("settings booleans decoded wrong: %+v", settings)
	}
	if strPtr(settings.AuditLogLevel) != "full" {
		t.Errorf("audit log level decoded wrong: %v", settings.AuditLogLevel)
	}
	if settings.AllowedIps == nil || settings.AllowedIps.Ips == nil {
		t.Fatal("allowed_ips did not decode")
	}
	if ips := *settings.AllowedIps.Ips; len(ips) != 2 || ips[0] != "10.0.0.0/8" {
		t.Errorf("allowed ips decoded wrong: %v", ips)
	}
	if !boolPtr(settings.AllowedIps.ProtectedBranchesOnly) {
		t.Error("protected_branches_only decoded wrong")
	}

	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := rec.CreatedAt.Time(); got == nil || !got.Equal(want) {
		t.Errorf("created_at decoded wrong: %v", got)
	}
}

// A project with no settings block must report every control as off rather than
// panicking or reporting a control as enabled.
func TestProjectRecordWithoutSettings(t *testing.T) {
	var rec projectRecord
	if err := json.Unmarshal([]byte(`{"id":"proj-1"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Settings != nil {
		t.Fatalf("expected absent settings, got %+v", rec.Settings)
	}
	if rec.OrgID != nil {
		t.Errorf("expected absent org id, got %v", rec.OrgID)
	}
	if rec.HipaaEnabledAt.Time() != nil {
		t.Errorf("expected null hipaa timestamp, got %v", rec.HipaaEnabledAt.Time())
	}
}

// An absent optional boolean means the control was never switched on. Reporting
// it as true would invert the finding.
func TestBoolPtrTreatsAbsentAsOff(t *testing.T) {
	yes, no := true, false
	if boolPtr(nil) {
		t.Error("nil must decode as false")
	}
	if boolPtr(&no) {
		t.Error("false must stay false")
	}
	if !boolPtr(&yes) {
		t.Error("true must stay true")
	}
}

func TestStrPtrTreatsAbsentAsEmpty(t *testing.T) {
	value := "full"
	if strPtr(nil) != "" {
		t.Error("nil must decode as an empty string")
	}
	if strPtr(&value) != "full" {
		t.Error("a set value must be returned unchanged")
	}
}

func TestBranchRecordDecodesProtection(t *testing.T) {
	const payload = `{
		"id": "br-1",
		"project_id": "proj-1",
		"parent_id": "br-parent",
		"name": "main",
		"default": true,
		"protected": true,
		"current_state": "ready",
		"logical_size": 1048576,
		"init_source": "parent-data",
		"restricted_actions": [
			{"name": "delete-rw-endpoint", "reason": "branch is protected"}
		],
		"expires_at": "2026-06-01T00:00:00Z",
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-02-03T04:05:06Z",
		"last_reset_at": "2026-03-04T05:06:07Z"
	}`

	var rec branchRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rec.Default || !rec.Protected {
		t.Errorf("protection booleans decoded wrong: %+v", rec)
	}
	if rec.ParentID == nil || *rec.ParentID != "br-parent" {
		t.Errorf("parent linkage decoded wrong: %v", rec.ParentID)
	}
	if rec.LogicalSize == nil || *rec.LogicalSize != 1048576 {
		t.Errorf("logical size decoded wrong: %v", rec.LogicalSize)
	}
	if strPtr(rec.InitSource) != "parent-data" {
		t.Errorf("init source decoded wrong: %v", rec.InitSource)
	}
	if len(rec.RestrictedActions) != 1 || rec.RestrictedActions[0].Name != "delete-rw-endpoint" {
		t.Errorf("restricted actions decoded wrong: %+v", rec.RestrictedActions)
	}
	if rec.RestrictedActions[0].Reason == "" {
		t.Error("restricted action reason decoded wrong")
	}
	if rec.ExpiresAt.Time() == nil {
		t.Error("expires_at decoded to nil")
	}
}

// A root branch carries no parent, and a branch with no expiry carries no
// timestamp. Both must stay null rather than becoming an empty reference or the
// zero time.
func TestBranchRecordRootBranch(t *testing.T) {
	var rec branchRecord
	if err := json.Unmarshal([]byte(`{"id":"br-1","name":"main","default":true}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ParentID != nil {
		t.Errorf("expected no parent, got %v", rec.ParentID)
	}
	if rec.ExpiresAt.Time() != nil {
		t.Errorf("expected no expiry, got %v", rec.ExpiresAt.Time())
	}
	if rec.Protected {
		t.Error("expected an unprotected branch")
	}
}

func TestEndpointRecordDecodesExposureFields(t *testing.T) {
	const payload = `{
		"id": "ep-1",
		"project_id": "proj-1",
		"branch_id": "br-1",
		"host": "ep-1.us-east-1.aws.neon.tech",
		"type": "read_write",
		"current_state": "idle",
		"disabled": true,
		"passwordless_access": true,
		"pooler_enabled": true,
		"pooler_mode": "transaction",
		"autoscaling_limit_min_cu": 0.25,
		"autoscaling_limit_max_cu": 4,
		"suspend_timeout_seconds": 300,
		"region_id": "aws-us-east-1",
		"provisioner": "k8s-neonvm",
		"created_at": "2026-01-02T03:04:05Z",
		"last_active": "2026-03-04T05:06:07Z",
		"started_at": "2026-03-04T05:00:00Z",
		"suspended_at": "2026-03-04T06:00:00Z"
	}`

	var rec endpointRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rec.Disabled || !rec.PasswordlessAccess || !rec.PoolerEnabled {
		t.Errorf("exposure booleans decoded wrong: %+v", rec)
	}
	if rec.BranchID != "br-1" || rec.ProjectID != "proj-1" {
		t.Errorf("linkage decoded wrong: %+v", rec)
	}
	if rec.AutoscalingLimitMinCu != 0.25 || rec.AutoscalingLimitMaxCu != 4 {
		t.Errorf("autoscaling limits decoded wrong: %v / %v", rec.AutoscalingLimitMinCu, rec.AutoscalingLimitMaxCu)
	}
	if rec.SuspendTimeoutSeconds != 300 {
		t.Errorf("suspend timeout decoded wrong: %d", rec.SuspendTimeoutSeconds)
	}
	if rec.PoolerMode != "transaction" || rec.Type != "read_write" {
		t.Errorf("mode fields decoded wrong: %+v", rec)
	}
}

func TestRoleRecordDecodesProtected(t *testing.T) {
	var rec roleRecord
	if err := json.Unmarshal([]byte(`{"name":"neon_superuser","protected":true,"authentication_method":"password","created_at":"2026-01-02T03:04:05Z"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Name != "neon_superuser" || !boolPtr(rec.Protected) {
		t.Errorf("role fields decoded wrong: %+v", rec)
	}
	if rec.AuthenticationMethod != "password" {
		t.Errorf("authentication_method decoded wrong: %q", rec.AuthenticationMethod)
	}

	var plain roleRecord
	if err := json.Unmarshal([]byte(`{"name":"app"}`), &plain); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if boolPtr(plain.Protected) {
		t.Error("an absent protected flag must decode as false")
	}
}

func TestDatabaseRecordDecodesOwner(t *testing.T) {
	const payload = `{
		"id": 42,
		"branch_id": "br-1",
		"name": "neondb",
		"owner_name": "app",
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-02-03T04:05:06Z"
	}`

	var rec databaseRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != 42 || rec.Name != "neondb" || rec.OwnerName != "app" {
		t.Errorf("database fields decoded wrong: %+v", rec)
	}
	if rec.BranchID != "br-1" {
		t.Errorf("branch linkage decoded wrong: %q", rec.BranchID)
	}
}

func TestPermissionRecordDecodesRevocation(t *testing.T) {
	const live = `{"id":"perm-1","granted_to_email":"ada@example.com","granted_at":"2026-01-02T03:04:05Z"}`
	var rec permissionRecord
	if err := json.Unmarshal([]byte(live), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.GrantedToEmail != "ada@example.com" {
		t.Errorf("grantee decoded wrong: %q", rec.GrantedToEmail)
	}
	// A live grant carries no revocation timestamp, which is what separates it
	// from one that has been withdrawn.
	if rec.RevokedAt.Time() != nil {
		t.Errorf("expected a live grant, got revoked at %v", rec.RevokedAt.Time())
	}

	const revoked = `{"id":"perm-2","granted_to_email":"bob@example.com","granted_at":"2026-01-02T03:04:05Z","revoked_at":"2026-04-05T06:07:08Z"}`
	var gone permissionRecord
	if err := json.Unmarshal([]byte(revoked), &gone); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gone.RevokedAt.Time() == nil {
		t.Error("expected a revoked grant")
	}
}

func TestJwksRecordDecodesRoleNames(t *testing.T) {
	const payload = `{
		"id": "jwks-1",
		"project_id": "proj-1",
		"branch_id": "br-1",
		"jwks_url": "https://example.clerk.accounts.dev/.well-known/jwks.json",
		"provider_name": "Clerk",
		"jwt_audience": "authenticated",
		"role_names": ["authenticated", "anon"],
		"created_at": "2026-01-02T03:04:05Z"
	}`

	var rec jwksRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ProviderName != "Clerk" || rec.JwksURL == "" {
		t.Errorf("provider fields decoded wrong: %+v", rec)
	}
	if strPtr(rec.BranchID) != "br-1" {
		t.Errorf("branch linkage decoded wrong: %v", rec.BranchID)
	}
	if rec.RoleNames == nil || len(*rec.RoleNames) != 2 {
		t.Errorf("role names decoded wrong: %v", rec.RoleNames)
	}
	if strPtr(rec.JwtAudience) != "authenticated" {
		t.Errorf("audience decoded wrong: %v", rec.JwtAudience)
	}
}

func TestOrganizationRecordDecodesHipaaAllowance(t *testing.T) {
	const payload = `{
		"id": "org-1",
		"name": "Acme",
		"handle": "acme",
		"plan": "scale",
		"managed_by": "console",
		"allow_hipaa_projects": true,
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-02-03T04:05:06Z"
	}`

	var rec organizationRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Handle != "acme" || rec.Plan != "scale" || rec.ManagedBy != "console" {
		t.Errorf("organization fields decoded wrong: %+v", rec)
	}
	if !boolPtr(rec.AllowHipaaProjects) {
		t.Error("allow_hipaa_projects decoded wrong")
	}
}

// require_mfa is absent on plans that do not offer it. Absent must read as "not
// required" rather than defaulting the other way.
func TestOrganizationRecordDecodesRequireMfa(t *testing.T) {
	var on organizationRecord
	if err := json.Unmarshal([]byte(`{"id":"org-1","require_mfa":true}`), &on); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !boolPtr(on.RequireMfa) {
		t.Error("require_mfa true decoded wrong")
	}

	var off organizationRecord
	if err := json.Unmarshal([]byte(`{"id":"org-1","require_mfa":false}`), &off); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if boolPtr(off.RequireMfa) {
		t.Error("require_mfa false decoded wrong")
	}

	var absent organizationRecord
	if err := json.Unmarshal([]byte(`{"id":"org-1"}`), &absent); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if boolPtr(absent.RequireMfa) {
		t.Error("an absent require_mfa must read as not required")
	}
}

// The member roster nests the role and the email under different objects, so a
// flattened struct tag would silently produce a roster with no email addresses.
func TestMemberWithUserRecordDecodesNesting(t *testing.T) {
	const payload = `{
		"member": {"id":"mem-1","org_id":"org-1","user_id":"user-1","role":"admin","joined_at":"2026-01-02T03:04:05Z"},
		"user": {"email":"ada@example.com"}
	}`

	var rec memberWithUserRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Member.Role != "admin" || rec.Member.ID != "mem-1" {
		t.Errorf("member fields decoded wrong: %+v", rec.Member)
	}
	if rec.User.Email != "ada@example.com" {
		t.Errorf("member email decoded wrong: %q", rec.User.Email)
	}
	if rec.Member.JoinedAt.Time() == nil {
		t.Error("joined_at decoded to nil")
	}
	if rec.User.HasMfa {
		t.Error("has_mfa decoded wrong")
	}

	// has_mfa rides on the nested user object, so a flattened tag would report
	// every member as having no second factor.
	const enrolled = `{"member":{"id":"mem-1","role":"admin"},"user":{"email":"ada@example.com","has_mfa":true}}`
	var mfa memberWithUserRecord
	if err := json.Unmarshal([]byte(enrolled), &mfa); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !mfa.User.HasMfa {
		t.Error("has_mfa true decoded wrong")
	}
}

func TestApiKeyRecordDecodesUsage(t *testing.T) {
	const payload = `{
		"id": 4242,
		"name": "ci",
		"created_at": "2026-01-02T03:04:05Z",
		"created_by": {"id":"user-1","name":"Ada Lovelace"},
		"last_used_at": "2026-03-04T05:06:07Z",
		"last_used_from_addr": "192.0.2.10"
	}`

	var rec apiKeyRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ID != 4242 || rec.Name != "ci" {
		t.Errorf("key fields decoded wrong: %+v", rec)
	}
	if rec.CreatedBy == nil || rec.CreatedBy.Name != "Ada Lovelace" {
		t.Errorf("creator decoded wrong: %+v", rec.CreatedBy)
	}
	if rec.LastUsedFromAddr != "192.0.2.10" || rec.LastUsedAt.Time() == nil {
		t.Errorf("usage fields decoded wrong: %+v", rec)
	}
}

// A key that has never been used carries neither a timestamp nor an address.
// Both must stay null so an unused key is distinguishable from one used at the
// zero time or from an unknown address.
func TestApiKeyRecordNeverUsed(t *testing.T) {
	var rec apiKeyRecord
	if err := json.Unmarshal([]byte(`{"id":1,"name":"unused","created_at":"2026-01-02T03:04:05Z"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.LastUsedAt.Time() != nil {
		t.Errorf("expected no last-used timestamp, got %v", rec.LastUsedAt.Time())
	}
	if rec.LastUsedFromAddr != "" {
		t.Errorf("expected no last-used address, got %q", rec.LastUsedFromAddr)
	}
}

func TestUserRecordDecodesAuthAccounts(t *testing.T) {
	const payload = `{
		"id": "user-1",
		"email": "ada@example.com",
		"name": "Ada",
		"last_name": "Lovelace",
		"plan": "scale",
		"projects_limit": 10,
		"branches_limit": 20,
		"auth_accounts": [{"provider":"github"},{"provider":"google"}]
	}`

	var rec userRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ProjectsLimit != 10 || rec.BranchesLimit != 20 {
		t.Errorf("limits decoded wrong: %+v", rec)
	}
	if len(rec.AuthAccounts) != 2 || rec.AuthAccounts[1].Provider != "google" {
		t.Errorf("auth accounts decoded wrong: %+v", rec.AuthAccounts)
	}
}

func TestVpcEndpointRecordDecodes(t *testing.T) {
	var rec vpcEndpointRecord
	if err := json.Unmarshal([]byte(`{"vpc_endpoint_id":"vpce-1","label":"prod"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.VpcEndpointID != "vpce-1" || rec.Label != "prod" {
		t.Errorf("vpc endpoint decoded wrong: %+v", rec)
	}
}

func TestNeonTimeHandlesAbsentAndInvalidValues(t *testing.T) {
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
		{"unparseable", `"not a timestamp"`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var nt neonTime
			if err := json.Unmarshal([]byte(tc.payload), &nt); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := nt.Time(); (got == nil) != tc.wantNil {
				t.Fatalf("expected nil=%v, got %v", tc.wantNil, got)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	if got := itoa(42); got != "42" {
		t.Fatalf("expected %q, got %q", "42", got)
	}
	if got := itoa(0); got != "0" {
		t.Fatalf("expected %q, got %q", "0", got)
	}
}

// A plan-gated setting the API omits must report null, not an empty string: a
// policy asking "is audit logging set to full" should see "not answered"
// rather than a value that looks deliberately blank.
func TestOptionalStringReportsAbsentAsNull(t *testing.T) {
	if got := optionalString(nil); got != llx.NilData {
		t.Errorf("nil must map to null, got %v", got)
	}
	empty := ""
	if got := optionalString(&empty); got != llx.NilData {
		t.Errorf("an empty value must map to null, got %v", got)
	}
	value := "full"
	got := optionalString(&value)
	if got == llx.NilData || got.Value != "full" {
		t.Errorf("a set value must be carried through, got %v", got)
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

// --- coverage expansion ---------------------------------------------------

func TestDataApiRecordDecodesPublicExposure(t *testing.T) {
	const payload = `{
		"url": "https://app-deadbeef.dataapi.example.test",
		"status": "ready",
		"available_schemas": ["public", "internal"],
		"settings": {
			"db_aggregates_enabled": true,
			"db_anon_role": "authenticated",
			"db_extra_search_path": "extensions",
			"db_max_rows": 1000,
			"db_schemas": ["public"],
			"jwt_role_claim_key": ".role",
			"jwt_cache_max_lifetime": 300,
			"openapi_mode": "follow-privileges",
			"server_cors_allowed_origins": "*",
			"server_timing_enabled": true
		}
	}`

	var rec dataApiRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.Status != "ready" {
		t.Errorf("status decoded wrong: %q", rec.Status)
	}
	if rec.Settings == nil {
		t.Fatal("settings decoded as absent")
	}
	// The anonymous role and the CORS allowlist together are the reachable
	// path to the data, so both tags have to hold.
	if rec.Settings.DbAnonRole == nil || *rec.Settings.DbAnonRole != "authenticated" {
		t.Errorf("db_anon_role decoded wrong: %v", rec.Settings.DbAnonRole)
	}
	if rec.Settings.ServerCorsAllowedOrigin == nil || *rec.Settings.ServerCorsAllowedOrigin != "*" {
		t.Errorf("server_cors_allowed_origins decoded wrong: %v", rec.Settings.ServerCorsAllowedOrigin)
	}
	if rec.Settings.DbSchemas == nil || len(*rec.Settings.DbSchemas) != 1 || (*rec.Settings.DbSchemas)[0] != "public" {
		t.Errorf("db_schemas decoded wrong: %v", rec.Settings.DbSchemas)
	}
	if rec.Settings.DbMaxRows == nil || *rec.Settings.DbMaxRows != 1000 {
		t.Errorf("db_max_rows decoded wrong: %v", rec.Settings.DbMaxRows)
	}
	if rec.Settings.JwtCacheMaxLifetime == nil || *rec.Settings.JwtCacheMaxLifetime != 300 {
		t.Errorf("jwt_cache_max_lifetime decoded wrong: %v", rec.Settings.JwtCacheMaxLifetime)
	}
	if rec.Settings.DbAggregatesEnabled == nil || !*rec.Settings.DbAggregatesEnabled {
		t.Errorf("db_aggregates_enabled decoded wrong: %v", rec.Settings.DbAggregatesEnabled)
	}
	if rec.AvailableSchemas == nil || len(*rec.AvailableSchemas) != 2 {
		t.Errorf("available_schemas decoded wrong: %v", rec.AvailableSchemas)
	}
}

func TestDataApiRecordWithoutSettingsKeepsEveryFieldAbsent(t *testing.T) {
	const payload = `{"url": "https://app-deadbeef.dataapi.example.test", "status": "pending"}`

	var rec dataApiRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// An unlimited row cap and an unset CORS allowlist must stay absent. A
	// zero row cap would read as a limit of no rows at all.
	if rec.Settings != nil {
		t.Errorf("settings invented: %+v", rec.Settings)
	}
	if rec.AvailableSchemas != nil {
		t.Errorf("available_schemas invented: %v", rec.AvailableSchemas)
	}
	if llx.IntDataPtr[int64](nil) != llx.NilData {
		t.Error("an absent row cap must report as null, not as zero")
	}
}

func TestAdvisorIssueRecordDecodesFacing(t *testing.T) {
	const payload = `{
		"name": "rls_disabled_in_public",
		"title": "RLS Disabled in Public",
		"level": "ERROR",
		"facing": "EXTERNAL",
		"categories": ["SECURITY"],
		"description": "Table is public but row level security is not enabled.",
		"detail": "Table public.orders is exposed.",
		"remediation": "Enable row level security on the table.",
		"metadata": {"schema": "public", "name": "orders", "type": "table"},
		"cache_key": "rls_disabled_in_public_public_orders"
	}`

	var rec advisorIssueRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// `facing` is what separates a finding an outside caller can reach from
	// one confined to the project, so it carries the whole finding's weight.
	if rec.Facing != "EXTERNAL" {
		t.Errorf("facing decoded wrong: %q", rec.Facing)
	}
	if rec.Level != "ERROR" {
		t.Errorf("level decoded wrong: %q", rec.Level)
	}
	if len(rec.Categories) != 1 || rec.Categories[0] != "SECURITY" {
		t.Errorf("categories decoded wrong: %v", rec.Categories)
	}
	if rec.CacheKey != "rls_disabled_in_public_public_orders" {
		t.Errorf("cache_key decoded wrong: %q", rec.CacheKey)
	}
	if rec.Metadata["schema"] != "public" {
		t.Errorf("metadata decoded wrong: %v", rec.Metadata)
	}
	if rec.Title == "" || rec.Description == "" || rec.Remediation == "" {
		t.Errorf("prose fields decoded wrong: %+v", rec)
	}
}

func TestBucketRecordDecodesPublicAccessLevel(t *testing.T) {
	const payload = `{
		"name": "assets",
		"access_level": "public_read",
		"created_at": "2026-01-02T03:04:05Z"
	}`

	var rec bucketRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// A mistyped tag here reports every bucket as private.
	if rec.AccessLevel != "public_read" {
		t.Errorf("access_level decoded wrong: %q", rec.AccessLevel)
	}
	if rec.Name != "assets" {
		t.Errorf("name decoded wrong: %q", rec.Name)
	}
	if rec.CreatedAt.Time() == nil {
		t.Error("created_at decoded as absent")
	}
}

func TestCredentialRecordDecodesScopesAndExpiry(t *testing.T) {
	const payload = `{
		"token_id": "deadbeefdeadbeefdeadbeefdeadbeef",
		"token_id_short": "deadbeefdead",
		"name": "backup writer",
		"scopes": ["storage:read", "storage:write"],
		"branch_id": "br-deadbeef",
		"principal_type": "user",
		"created_at": "2026-01-02T03:04:05Z",
		"last_used_at": "2026-02-03T04:05:06Z"
	}`

	var rec credentialRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(rec.Scopes) != 2 || rec.Scopes[1] != "storage:write" {
		t.Errorf("scopes decoded wrong: %v", rec.Scopes)
	}
	if rec.TokenIDShort != "deadbeefdead" {
		t.Errorf("token_id_short decoded wrong: %q", rec.TokenIDShort)
	}
	// An absent expiry means the credential never expires, which is the
	// finding. It must not decode to the zero time and read as long expired.
	if rec.ExpiresAt.Time() != nil {
		t.Errorf("an absent expiry must stay null, got %v", rec.ExpiresAt.Time())
	}
	if rec.RevokedAt.Time() != nil {
		t.Errorf("an absent revocation must stay null, got %v", rec.RevokedAt.Time())
	}
	if rec.LastUsedAt.Time() == nil {
		t.Error("last_used_at decoded as absent")
	}
	if rec.BranchID == nil || *rec.BranchID != "br-deadbeef" {
		t.Errorf("branch_id decoded wrong: %v", rec.BranchID)
	}
	if rec.FunctionID != nil {
		t.Errorf("function_id invented: %v", rec.FunctionID)
	}
}

func TestAuthRecordDecodesMockProvider(t *testing.T) {
	const payload = `{
		"auth_provider": "mock",
		"auth_provider_project_id": "deadbeef-0000-0000-0000-000000000000",
		"branch_id": "br-deadbeef",
		"db_name": "neondb",
		"created_at": "2026-01-02T03:04:05Z",
		"owned_by": "user",
		"jwks_url": "https://api.example.test/.well-known/jwks.json"
	}`

	var rec authRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// A branch backed by the mock provider is not authenticating anyone, so
	// this tag is the whole point of the resource.
	if rec.AuthProvider != "mock" {
		t.Errorf("auth_provider decoded wrong: %q", rec.AuthProvider)
	}
	if rec.OwnedBy != "user" {
		t.Errorf("owned_by decoded wrong: %q", rec.OwnedBy)
	}
	if rec.JwksURL == "" {
		t.Error("jwks_url decoded as absent")
	}
	if rec.TransferStatus != nil {
		t.Errorf("transfer_status invented: %v", rec.TransferStatus)
	}
	if rec.BaseURL != nil {
		t.Errorf("base_url invented: %v", rec.BaseURL)
	}
}

func TestEmailPasswordRecordDecodesSelfRegistration(t *testing.T) {
	const payload = `{
		"enabled": true,
		"email_verification_method": "otp",
		"require_email_verification": false,
		"auto_sign_in_after_verification": true,
		"send_verification_email_on_sign_up": true,
		"send_verification_email_on_sign_in": false,
		"disable_sign_up": false
	}`

	var rec emailPasswordRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// This is the open-self-registration case: verification not required and
	// sign-up not disabled. Both must decode as reported false, not as absent.
	if rec.RequireEmailVerification == nil || *rec.RequireEmailVerification {
		t.Errorf("require_email_verification decoded wrong: %v", rec.RequireEmailVerification)
	}
	if rec.DisableSignUp == nil || *rec.DisableSignUp {
		t.Errorf("disable_sign_up decoded wrong: %v", rec.DisableSignUp)
	}
	if rec.Enabled == nil || !*rec.Enabled {
		t.Errorf("enabled decoded wrong: %v", rec.Enabled)
	}
	if rec.EmailVerificationMethod == nil || *rec.EmailVerificationMethod != "otp" {
		t.Errorf("email_verification_method decoded wrong: %v", rec.EmailVerificationMethod)
	}
	if rec.AutoSignInAfterVerification == nil || !*rec.AutoSignInAfterVerification {
		t.Errorf("auto_sign_in_after_verification decoded wrong: %v", rec.AutoSignInAfterVerification)
	}
	if rec.SendVerificationEmailOnSignUp == nil || !*rec.SendVerificationEmailOnSignUp {
		t.Errorf("send_verification_email_on_sign_up decoded wrong: %v", rec.SendVerificationEmailOnSignUp)
	}
	if rec.SendVerificationEmailOnSignIn == nil || *rec.SendVerificationEmailOnSignIn {
		t.Errorf("send_verification_email_on_sign_in decoded wrong: %v", rec.SendVerificationEmailOnSignIn)
	}
}

func TestEmailPasswordRecordAbsentFieldsStayNull(t *testing.T) {
	var rec emailPasswordRecord
	if err := json.Unmarshal([]byte(`{}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// A field the API stopped sending must read as unknown. Reporting it as
	// false would claim verification is not required on a tenant that does
	// require it.
	if rec.RequireEmailVerification != nil || rec.DisableSignUp != nil || rec.Enabled != nil {
		t.Errorf("absent controls were invented: %+v", rec)
	}
	if llx.BoolDataPtr(rec.RequireEmailVerification) != llx.NilData {
		t.Error("an absent control must report as null")
	}
}

func TestOauthProviderRecordDecodesSharedCredentials(t *testing.T) {
	const payload = `{
		"id": "google",
		"type": "shared",
		"client_id": "deadbeef.apps.example.test",
		"client_secret": "deadbeefdeadbeefdeadbeefdeadbeef"
	}`

	var rec oauthProviderRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// `shared` means Neon's own development registration signs users in.
	if rec.Type != "shared" {
		t.Errorf("type decoded wrong: %q", rec.Type)
	}
	if rec.ID != "google" {
		t.Errorf("id decoded wrong: %q", rec.ID)
	}
	if rec.ClientID == nil || *rec.ClientID != "deadbeef.apps.example.test" {
		t.Errorf("client_id decoded wrong: %v", rec.ClientID)
	}
}

func TestAuthDomainRecordDecodes(t *testing.T) {
	const payload = `{"domain": "https://app.example.test", "auth_provider": "stack"}`

	var rec authDomainRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Domain != "https://app.example.test" {
		t.Errorf("domain decoded wrong: %q", rec.Domain)
	}
	if rec.AuthProvider != "stack" {
		t.Errorf("auth_provider decoded wrong: %q", rec.AuthProvider)
	}
}

func TestFunctionRecordDecodesInvocationSurface(t *testing.T) {
	const payload = `{
		"id": "fn-deadbeef",
		"slug": "checkout",
		"name": "Checkout handler",
		"invocation_url": "https://br-deadbeef-checkout.functions.example.test",
		"created_at": "2026-01-02T03:04:05Z",
		"active_deployment": {
			"id": 7,
			"status": "completed",
			"memory_mib": 512,
			"runtime": "nodejs24",
			"created_at": "2026-01-02T03:04:05Z",
			"environment": ["DATABASE_URL", "STRIPE_KEY"]
		},
		"current_deployment": {
			"id": 8,
			"status": "failed",
			"memory_mib": 512,
			"runtime": "nodejs24",
			"created_at": "2026-01-03T03:04:05Z",
			"error": "build failed"
		}
	}`

	var rec functionRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The invocation URL is the internet-facing surface the finding is about.
	if rec.InvocationURL != "https://br-deadbeef-checkout.functions.example.test" {
		t.Errorf("invocation_url decoded wrong: %q", rec.InvocationURL)
	}
	if rec.Slug != "checkout" {
		t.Errorf("slug decoded wrong: %q", rec.Slug)
	}
	if rec.ActiveDeployment == nil || rec.ActiveDeployment.ID != 7 {
		t.Fatalf("active_deployment decoded wrong: %+v", rec.ActiveDeployment)
	}
	// Neon returns variable names only; the values are never sent.
	if len(rec.ActiveDeployment.Environment) != 2 || rec.ActiveDeployment.Environment[0] != "DATABASE_URL" {
		t.Errorf("environment decoded wrong: %v", rec.ActiveDeployment.Environment)
	}
	if rec.ActiveDeployment.MemoryMib == nil || *rec.ActiveDeployment.MemoryMib != 512 {
		t.Errorf("memory_mib decoded wrong: %v", rec.ActiveDeployment.MemoryMib)
	}
	if rec.CurrentDeployment == nil || rec.CurrentDeployment.Status != "failed" {
		t.Fatalf("current_deployment decoded wrong: %+v", rec.CurrentDeployment)
	}
	if rec.CurrentDeployment.Error == nil || *rec.CurrentDeployment.Error != "build failed" {
		t.Errorf("deployment error decoded wrong: %v", rec.CurrentDeployment.Error)
	}
	// A build that has not failed must report no error rather than an empty
	// one, and a function with no live build must report none.
	if rec.ActiveDeployment.Error != nil {
		t.Errorf("deployment error invented: %v", rec.ActiveDeployment.Error)
	}
}

func TestFunctionRecordWithoutDeployments(t *testing.T) {
	const payload = `{
		"id": "fn-deadbeef",
		"slug": "checkout",
		"name": "Checkout handler",
		"invocation_url": "https://br-deadbeef-checkout.functions.example.test",
		"created_at": "2026-01-02T03:04:05Z"
	}`

	var rec functionRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ActiveDeployment != nil || rec.CurrentDeployment != nil {
		t.Errorf("deployments invented: %+v %+v", rec.ActiveDeployment, rec.CurrentDeployment)
	}
}

func TestInvitationRecordDecodesRole(t *testing.T) {
	const payload = `{
		"id": "deadbeef-0000-0000-0000-000000000000",
		"email": "outsider@example.test",
		"org_id": "org-deadbeef",
		"invited_by": "beefdead-0000-0000-0000-000000000000",
		"invited_at": "2026-01-02T03:04:05Z",
		"role": "admin"
	}`

	var rec invitationRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// An outstanding admin invitation is org-wide access waiting to be claimed.
	if rec.Role != "admin" {
		t.Errorf("role decoded wrong: %q", rec.Role)
	}
	if rec.Email != "outsider@example.test" {
		t.Errorf("email decoded wrong: %q", rec.Email)
	}
	if rec.InvitedBy != "beefdead-0000-0000-0000-000000000000" {
		t.Errorf("invited_by decoded wrong: %q", rec.InvitedBy)
	}
	if rec.InvitedAt.Time() == nil {
		t.Error("invited_at decoded as absent")
	}
}

func TestOperationRecordDecodesProtectionChange(t *testing.T) {
	const payload = `{
		"id": "deadbeef-0000-0000-0000-000000000000",
		"project_id": "proj-deadbeef",
		"branch_id": "br-deadbeef",
		"action": "timeline_update_protected_config",
		"status": "finished",
		"failures_count": 0,
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-01-02T03:04:09Z",
		"total_duration_ms": 4200
	}`

	var rec operationRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// This action is where a branch losing its protection shows up.
	if rec.Action != "timeline_update_protected_config" {
		t.Errorf("action decoded wrong: %q", rec.Action)
	}
	if rec.Status != "finished" {
		t.Errorf("status decoded wrong: %q", rec.Status)
	}
	if rec.BranchID == nil || *rec.BranchID != "br-deadbeef" {
		t.Errorf("branch_id decoded wrong: %v", rec.BranchID)
	}
	if rec.EndpointID != nil {
		t.Errorf("endpoint_id invented: %v", rec.EndpointID)
	}
	// A reported zero must stay a zero, and an absent count must stay absent.
	if rec.FailuresCount == nil || *rec.FailuresCount != 0 {
		t.Errorf("failures_count decoded wrong: %v", rec.FailuresCount)
	}
	if rec.TotalDurationMs == nil || *rec.TotalDurationMs != 4200 {
		t.Errorf("total_duration_ms decoded wrong: %v", rec.TotalDurationMs)
	}
	if rec.RetryAt.Time() != nil {
		t.Errorf("an absent retry must stay null, got %v", rec.RetryAt.Time())
	}
}

func TestSnapshotRecordDecodesRetention(t *testing.T) {
	const payload = `{
		"id": "snap-deadbeef",
		"name": "nightly",
		"lsn": "0/3000000",
		"timestamp": "2026-01-02T03:04:05Z",
		"source_branch_id": "br-deadbeef",
		"created_at": "2026-01-02T03:04:06Z",
		"manual": false,
		"full_size": 1048576,
		"diff_size": 4096
	}`

	var rec snapshotRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec.SourceBranchID == nil || *rec.SourceBranchID != "br-deadbeef" {
		t.Errorf("source_branch_id decoded wrong: %v", rec.SourceBranchID)
	}
	if rec.Manual == nil || *rec.Manual {
		t.Errorf("manual decoded wrong: %v", rec.Manual)
	}
	if rec.FullSize == nil || *rec.FullSize != 1048576 {
		t.Errorf("full_size decoded wrong: %v", rec.FullSize)
	}
	if rec.DiffSize == nil || *rec.DiffSize != 4096 {
		t.Errorf("diff_size decoded wrong: %v", rec.DiffSize)
	}
	if rec.Timestamp.Time() == nil {
		t.Error("timestamp decoded as absent")
	}
	// A snapshot that never expires must not report the zero time, which
	// would read as one that expired in the year 1.
	if rec.ExpiresAt.Time() != nil {
		t.Errorf("an absent expiry must stay null, got %v", rec.ExpiresAt.Time())
	}
}

func TestProjectMemberRecordDecodesEffectivePermission(t *testing.T) {
	const payload = `{
		"member_id": "deadbeef-0000-0000-0000-000000000000",
		"user_id": "beefdead-0000-0000-0000-000000000000",
		"email": "ada@example.test",
		"name": "Ada",
		"org_role": "admin",
		"org_default_project_permission": "VIEWER",
		"effective_project_permission": "ADMIN",
		"grant_source": "org_admin_override"
	}`

	var rec projectMemberRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Rights held only by virtue of organization administration are exactly
	// what the project's own grant list cannot show.
	if rec.EffectiveProjectPermission == nil || *rec.EffectiveProjectPermission != "ADMIN" {
		t.Errorf("effective_project_permission decoded wrong: %v", rec.EffectiveProjectPermission)
	}
	if rec.GrantSource == nil || *rec.GrantSource != "org_admin_override" {
		t.Errorf("grant_source decoded wrong: %v", rec.GrantSource)
	}
	if rec.OrgRole != "admin" {
		t.Errorf("org_role decoded wrong: %q", rec.OrgRole)
	}
	if rec.UserID != "beefdead-0000-0000-0000-000000000000" {
		t.Errorf("user_id decoded wrong: %q", rec.UserID)
	}
	// No explicit grant was made on the project itself.
	if rec.ExplicitProjectPermission != nil {
		t.Errorf("explicit_project_permission invented: %v", rec.ExplicitProjectPermission)
	}
	if rec.ProjectRole != nil {
		t.Errorf("project_role invented: %v", rec.ProjectRole)
	}
}

func TestMemberUserRecordDecodesDeactivation(t *testing.T) {
	const payload = `{
		"member": {
			"id": "deadbeef-0000-0000-0000-000000000000",
			"org_id": "org-deadbeef",
			"user_id": "beefdead-0000-0000-0000-000000000000",
			"role": "editor",
			"joined_at": "2026-01-02T03:04:05Z"
		},
		"user": {
			"email": "ada@example.test",
			"has_mfa": true,
			"deactivated_at": "2026-05-06T07:08:09Z"
		}
	}`

	var rec memberWithUserRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	deactivated := rec.User.DeactivatedAt.Time()
	if deactivated == nil {
		t.Fatal("deactivated_at decoded as absent")
	}
	if !deactivated.Equal(time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Errorf("deactivated_at decoded wrong: %v", deactivated)
	}
	// The role enum grew past admin and member; a value outside the old pair
	// must survive the decode.
	if rec.Member.Role != "editor" {
		t.Errorf("role decoded wrong: %q", rec.Member.Role)
	}
	if rec.Member.UserID != "beefdead-0000-0000-0000-000000000000" {
		t.Errorf("user_id decoded wrong: %q", rec.Member.UserID)
	}
}

func TestMemberUserRecordActiveAccountStaysNull(t *testing.T) {
	const payload = `{
		"member": {"id": "m-1", "user_id": "u-1", "org_id": "o-1", "role": "member"},
		"user": {"email": "ada@example.test", "has_mfa": false}
	}`

	var rec memberWithUserRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// A live account must not report a deactivation time.
	if rec.User.DeactivatedAt.Time() != nil {
		t.Errorf("deactivation invented for a live account: %v", rec.User.DeactivatedAt.Time())
	}
}

func TestVpcEndpointDetailRecordDecodesState(t *testing.T) {
	const payload = `{
		"vpc_endpoint_id": "vpce-deadbeef",
		"label": "prod",
		"state": "new",
		"num_restricted_projects": 4,
		"example_restricted_projects": ["proj-a", "proj-b", "proj-c"]
	}`

	var rec vpcEndpointDetailRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// `new` means Neon has not accepted the connection, so nothing reaches the
	// project over it.
	if rec.State != "new" {
		t.Errorf("state decoded wrong: %q", rec.State)
	}
	if rec.NumRestrictedProjects == nil || *rec.NumRestrictedProjects != 4 {
		t.Errorf("num_restricted_projects decoded wrong: %v", rec.NumRestrictedProjects)
	}
	// The list is a sample capped at three, so it under-reports the count.
	if len(rec.ExampleRestrictedProjects) != 3 {
		t.Errorf("example_restricted_projects decoded wrong: %v", rec.ExampleRestrictedProjects)
	}
}

// TestNoRecordDecodesSecretMaterial guards the boundary that keeps credentials
// out of the schema. Several Neon payloads carry secrets beside the metadata
// this provider reports: an OAuth client secret sits next to the client id, and
// the credential issuance response returns a bearer token and an object storage
// secret key. Decoding one is all it takes for it to reach a schema field, so
// no record type may name one.
func TestNoRecordDecodesSecretMaterial(t *testing.T) {
	secretTags := map[string]bool{
		"client_secret":        true,
		"api_token":            true,
		"s3_secret_access_key": true,
		"s3_access_key_id":     true,
		"password":             true,
		"secret":               true,
		"secret_access_key":    true,
		"connection_uri":       true,
		"connection_string":    true,
	}

	records := []any{
		projectRecord{}, projectSettingsData{}, allowedIpsData{},
		branchRecord{}, roleRecord{}, databaseRecord{},
		endpointRecord{}, organizationRecord{}, memberWithUserRecord{},
		memberRecord{}, memberUserRecord{}, apiKeyRecord{}, userRecord{},
		permissionRecord{}, jwksRecord{}, vpcEndpointRecord{},
		vpcEndpointDetailRecord{}, dataApiRecord{}, dataApiSettings{},
		advisorIssueRecord{}, bucketRecord{}, credentialRecord{},
		authRecord{}, emailPasswordRecord{}, authDomainRecord{},
		oauthProviderRecord{}, functionRecord{}, functionDeploymentRecord{},
		invitationRecord{}, operationRecord{}, snapshotRecord{},
		projectMemberRecord{},
	}

	var walk func(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool)
	walk = func(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true

		for field := range typ.Fields() {
			field := field
			tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if secretTags[tag] {
				t.Errorf("%s.%s decodes secret material (json:%q); it must not reach a schema field",
					typ.Name(), field.Name, tag)
			}
			walk(t, field.Type, seen)
		}
	}

	seen := map[reflect.Type]bool{}
	for _, rec := range records {
		walk(t, reflect.TypeOf(rec), seen)
	}
}
