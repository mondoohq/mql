// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openai/connection"
)

func TestUnixToTime(t *testing.T) {
	// A zero unix timestamp is how the OpenAI API surfaces a null/absent time
	// (e.g. a never-used API key). It must map to the Go zero time so callers
	// can detect it and emit null instead of a year-1 timestamp.
	assert.True(t, unixToTime(0).IsZero())

	ts := int64(1719878400) // 2024-07-02T00:00:00Z
	got := unixToTime(ts)
	assert.False(t, got.IsZero())
	assert.Equal(t, ts, got.Unix())
}

func TestUnixToNullableTime(t *testing.T) {
	// A zero timestamp must become a nil pointer so llx.TimeDataPtr emits null
	// rather than a year-1 timestamp.
	assert.Nil(t, unixToNullableTime(0))

	ts := int64(1719878400)
	got := unixToNullableTime(ts)
	require.NotNil(t, got)
	assert.Equal(t, ts, got.Unix())
}

func TestIsAccessDenied(t *testing.T) {
	assert.False(t, isAccessDenied(nil))
	assert.True(t, isAccessDenied(&openai.Error{StatusCode: 401}))
	assert.True(t, isAccessDenied(&openai.Error{StatusCode: 403}))
	assert.False(t, isAccessDenied(&openai.Error{StatusCode: 404}))
	assert.False(t, isAccessDenied(&openai.Error{StatusCode: 500}))
	assert.False(t, isAccessDenied(assert.AnError))
}

func newTestConn(t *testing.T, token string) *connection.OpenaiConnection {
	t.Helper()
	// Clear env so an ambient key can't leak into the no-token case, and set an
	// organization so the constructor skips its best-effort /v1/me network call.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_ORG_ID", "")
	t.Setenv("OPENAI_PROJECT_ID", "")
	conf := &inventory.Config{Options: map[string]string{
		connection.OrganizationOption: "org-test",
	}}
	if token != "" {
		conf.Options[connection.TokenOption] = token
	}
	conn, err := connection.NewOpenaiConnection(0, &inventory.Asset{}, conf)
	require.NoError(t, err)
	return conn
}

func TestDataPlaneClient(t *testing.T) {
	// A project key can read data-plane resources.
	c, err := dataPlaneClient(newTestConn(t, "sk-proj-abc"), "openai.models")
	assert.NoError(t, err)
	assert.NotNil(t, c)

	// An admin key cannot; it must surface a descriptive error rather than an
	// empty result that looks like "no models".
	c, err = dataPlaneClient(newTestConn(t, "sk-admin-abc"), "openai.models")
	assert.Error(t, err)
	assert.Nil(t, c)

	// No credentials degrades to (nil, nil) so the collection returns empty.
	c, err = dataPlaneClient(newTestConn(t, ""), "openai.models")
	assert.NoError(t, err)
	assert.Nil(t, c)
}

func TestAdminPlaneClient(t *testing.T) {
	// An admin key can read organization resources.
	c, err := adminPlaneClient(newTestConn(t, "sk-admin-abc"), "openai.users")
	assert.NoError(t, err)
	assert.NotNil(t, c)

	// A project key cannot; it must surface a descriptive error.
	c, err = adminPlaneClient(newTestConn(t, "sk-proj-abc"), "openai.users")
	assert.Error(t, err)
	assert.Nil(t, c)

	// No credentials degrades to (nil, nil).
	c, err = adminPlaneClient(newTestConn(t, ""), "openai.users")
	assert.NoError(t, err)
	assert.Nil(t, c)
}

func TestAuditLogActor(t *testing.T) {
	session := openai.AdminOrganizationAuditLogListResponseActor{
		Type: "session",
		Session: openai.AdminOrganizationAuditLogListResponseActorSession{
			User: openai.AdminOrganizationAuditLogListResponseActorSessionUser{Email: "user@example.com"},
		},
	}
	at, id := auditLogActor(session)
	assert.Equal(t, "session", at)
	assert.Equal(t, "user@example.com", id)

	apiKey := openai.AdminOrganizationAuditLogListResponseActor{
		Type:   "api_key",
		APIKey: openai.AdminOrganizationAuditLogListResponseActorAPIKey{ID: "key_123"},
	}
	at, id = auditLogActor(apiKey)
	assert.Equal(t, "api_key", at)
	assert.Equal(t, "key_123", id)

	// Unknown actor types fall back to the type string.
	other := openai.AdminOrganizationAuditLogListResponseActor{Type: "scim"}
	at, id = auditLogActor(other)
	assert.Equal(t, "scim", at)
	assert.Equal(t, "scim", id)
}

func TestIsNotFound(t *testing.T) {
	// 404 means "not configured" on the spend limit and model policy endpoints,
	// which has to read as null rather than as a failure.
	assert.False(t, isNotFound(nil))
	assert.True(t, isNotFound(&openai.Error{StatusCode: 404}))
	assert.False(t, isNotFound(&openai.Error{StatusCode: 403}))
	assert.False(t, isNotFound(&openai.Error{StatusCode: 500}))
	assert.False(t, isNotFound(assert.AnError))
}

func TestNullableInt(t *testing.T) {
	// An allowance the API did not send must stay nil. Emitting 0 would report a
	// ceiling of zero for a model that simply has no such allowance.
	assert.Nil(t, nullableInt(0, false))
	assert.Nil(t, nullableInt(500, false))

	got := nullableInt(0, true)
	require.NotNil(t, got)
	assert.Equal(t, int64(0), *got)

	got = nullableInt(500, true)
	require.NotNil(t, got)
	assert.Equal(t, int64(500), *got)
}

func TestSpendAlertArgsScopesCacheKey(t *testing.T) {
	orgAlert := spendAlertArgs("org", "alert_1", 5000, "USD", "month", "email", []string{"a@example.com"}, "")
	projectAlert := spendAlertArgs("project/proj_1", "alert_1", 5000, "USD", "month", "email", []string{"a@example.com"}, "")

	// The organization and a project can both carry an alert with the same id.
	// An unscoped cache key would make the second one resolve to the first.
	assert.NotEqual(t, orgAlert["__id"].Value, projectAlert["__id"].Value)
	assert.Equal(t, "org/alert_1", orgAlert["__id"].Value)
	assert.Equal(t, "project/proj_1/alert_1", projectAlert["__id"].Value)

	// The user-facing id stays the plain alert id in both cases.
	assert.Equal(t, "alert_1", orgAlert["id"].Value)
	assert.Equal(t, "alert_1", projectAlert["id"].Value)
	assert.Equal(t, []any{"a@example.com"}, orgAlert["notificationRecipients"].Value)
}

func TestCertificateArgsScopesCacheKey(t *testing.T) {
	// The same certificate is listed at the organization and again at every
	// project it is activated for, and `active` means something different at
	// each scope. An unscoped cache key would make whichever scope was read
	// first answer for both.
	org := certificateArgs("org", "cert_1", "mtls", true, 100, 200, 300)
	project := certificateArgs("project/proj_1", "cert_1", "mtls", false, 100, 200, 300)

	assert.Equal(t, "org/cert_1", org["__id"].Value)
	assert.Equal(t, "project/proj_1/cert_1", project["__id"].Value)
	assert.Equal(t, true, org["active"].Value)
	assert.Equal(t, false, project["active"].Value)

	// The user-facing id stays the plain certificate id at both scopes.
	assert.Equal(t, "cert_1", org["id"].Value)
	assert.Equal(t, "cert_1", project["id"].Value)
}

func TestRoleArgs(t *testing.T) {
	args := roleArgs("role_1", "Owner", "full access", "organization", []string{"api.keys.write", "users.write"}, true)

	assert.Equal(t, "role_1", args["__id"].Value)
	assert.Equal(t, "role_1", args["id"].Value)
	assert.Equal(t, "Owner", args["name"].Value)
	assert.Equal(t, "full access", args["description"].Value)
	assert.Equal(t, "organization", args["resourceType"].Value)
	assert.Equal(t, true, args["isPredefined"].Value)
	// permissions crosses the plugin boundary as []any, so the conversion has to
	// happen here rather than handing llx a []string
	assert.Equal(t, []any{"api.keys.write", "users.write"}, args["permissions"].Value)

	// A role with no permissions must emit an empty list, not null, so
	// permissions.length == 0 is answerable.
	empty := roleArgs("role_2", "None", "", "project", nil, false)
	assert.Equal(t, []any{}, empty["permissions"].Value)
}

func TestOpenaiAdminApiKeyOwnerIsNullForServiceAccount(t *testing.T) {
	// A key owned by a service account has no organization member behind it. The
	// accessor must mark the field set-and-null; returning a bare nil leaves the
	// runtime believing the field was never resolved.
	key := &mqlOpenaiAdminApiKey{OwnerType: plugin.TValue[string]{Data: "service_account"}}
	key.cacheOwnerId = "sa_123"

	owner, err := key.owner()
	assert.NoError(t, err)
	assert.Nil(t, owner)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, key.Owner.State)

	// Same for a user-owned key whose owner id never came back from the API.
	missing := &mqlOpenaiAdminApiKey{OwnerType: plugin.TValue[string]{Data: "user"}}
	owner, err = missing.owner()
	assert.NoError(t, err)
	assert.Nil(t, owner)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, missing.Owner.State)
}

func newTestModel(id string) *mqlOpenaiModel {
	return &mqlOpenaiModel{Id: plugin.TValue[string]{Data: id}}
}

func TestOpenaiModelIsFineTuned(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"gpt-4o", false},
		{"o3-mini", false},
		{"ft:gpt-4o-mini:my-org:custom:abc123", true},
		{"", false},
	}
	for _, tc := range tests {
		got, err := newTestModel(tc.id).isFineTuned()
		assert.NoError(t, err)
		assert.Equal(t, tc.want, got, tc.id)
	}
}

func TestOpenaiModelBaseModel(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"gpt-4o", ""}, // base model, not fine-tuned
		{"ft:gpt-4o-mini:my-org:custom:abc123", "gpt-4o-mini"}, // full fine-tuned form
		{"ft:gpt-3.5-turbo:acme::xyz", "gpt-3.5-turbo"},        // base name unaffected by later colons
		{"ft:", ""}, // degenerate, no base
	}
	for _, tc := range tests {
		got, err := newTestModel(tc.id).baseModel()
		assert.NoError(t, err)
		assert.Equal(t, tc.want, got, tc.id)
	}
}

func TestBothPlanesOnADualKeyConnection(t *testing.T) {
	// Reading which projects a fine-tuning checkpoint is shared into needs the
	// project key for the checkpoint list and the admin key for its
	// permissions, so both helpers have to answer on one connection.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_ADMIN_KEY", "")
	t.Setenv("OPENAI_ORG_ID", "")
	t.Setenv("OPENAI_PROJECT_ID", "")
	conf := &inventory.Config{Options: map[string]string{
		connection.OrganizationOption: "org-test",
		connection.TokenOption:        "sk-proj-abc",
		connection.AdminTokenOption:   "sk-admin-abc",
	}}
	conn, err := connection.NewOpenaiConnection(0, &inventory.Asset{}, conf)
	require.NoError(t, err)

	dataClient, err := dataPlaneClient(conn, "openai.fineTuningJob.checkpoints")
	require.NoError(t, err)
	assert.NotNil(t, dataClient)

	adminClient, err := adminPlaneClient(conn, "openai.fineTuningJob.checkpoint.permissions")
	require.NoError(t, err)
	assert.NotNil(t, adminClient)
}
