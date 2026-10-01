// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

// Every payload below goes through the SDK's discriminator factory, so the
// model holds exactly what Kiota builds from a real Graph response: typed
// getters for declared properties, AdditionalData (as pointers) for the rest.

func parseGraph(t *testing.T, payload string, factory serialization.ParsableFactory) serialization.Parsable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(factory)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	return parsed
}

func dictTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// requireDictConverts fails when a value cannot be sent as an llx primitive,
// which is what makes a dict field error with "unsupported child type".
func requireDictConverts(t *testing.T, raw *llx.RawData) {
	t.Helper()
	res := raw.Result()
	require.NotNil(t, res)
	require.Empty(t, res.Error)
}

// ---------------------------------------------------------------------------
// defaultAppManagementPolicy credential restrictions
// ---------------------------------------------------------------------------

const tenantAppManagementPolicyJSON = `{
  "id": "00000000-0000-0000-0000-000000000000",
  "displayName": "Default app management tenant policy",
  "isEnabled": true,
  "applicationRestrictions": {
    "passwordCredentials": [
      {
        "restrictionType": "passwordLifetime",
        "maxLifetime": "P90D",
        "state": "enabled",
        "restrictForAppsCreatedAfterDateTime": "2019-10-19T10:37:00Z"
      }
    ],
    "keyCredentials": [
      {
        "restrictionType": "asymmetricKeyLifetime",
        "maxLifetime": "P365D"
      }
    ]
  }
}`

func TestAppManagementCredentialRestrictionsAreJSONNative(t *testing.T) {
	policy := parseGraph(t, tenantAppManagementPolicyJSON, models.CreateTenantAppManagementPolicyFromDiscriminatorValue).(models.TenantAppManagementPolicyable)

	res, err := newAppManagementConfiguration(dictTestRuntime(), policy.GetApplicationRestrictions(), "policy/applicationRestrictions")
	require.NoError(t, err)

	passwords := res.PasswordCredentials.Data
	requireDictConverts(t, llx.ArrayData(passwords, types.Dict))
	require.Len(t, passwords, 1)
	pw := passwords[0].(map[string]any)
	assert.Equal(t, "2019-10-19T10:37:00Z", pw["restrictForAppsCreatedAfterDateTime"])
	assert.Equal(t, "passwordLifetime", pw["restrictionType"])
	assert.Equal(t, "enabled", pw["state"])

	keys := res.KeyCredentials.Data
	requireDictConverts(t, llx.ArrayData(keys, types.Dict))
	require.Len(t, keys, 1)
	key := keys[0].(map[string]any)
	_, hasDate := key["restrictForAppsCreatedAfterDateTime"]
	assert.False(t, hasDate, "an absent date stays absent")
	assert.Equal(t, "asymmetricKeyLifetime", key["restrictionType"])
}

// ---------------------------------------------------------------------------
// crossTenantAccessPolicy B2B setting with an unset target configuration
// ---------------------------------------------------------------------------

// Graph leaves out applications (or usersAndGroups) on a B2B setting that only
// configures the other one, and may return a null entry in targets.
const b2bSettingUsersOnlyJSON = `{
  "usersAndGroups": {
    "accessType": "allowed",
    "targets": [
      { "target": "AllUsers", "targetType": "user" },
      null
    ]
  }
}`

func TestB2BSettingWithoutApplicationsIsNullNotPanic(t *testing.T) {
	setting := parseGraph(t, b2bSettingUsersOnlyJSON, models.CreateCrossTenantAccessPolicyB2BSettingFromDiscriminatorValue).(models.CrossTenantAccessPolicyB2BSettingable)
	require.Nil(t, setting.GetApplications())

	var res *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
	require.NotPanics(t, func() {
		var err error
		res, err = newB2BSetting(dictTestRuntime(), setting, "policy-b2bCollaborationInbound")
		require.NoError(t, err)
	})

	apps := res.GetApplications()
	require.NoError(t, apps.Error)
	assert.Nil(t, apps.Data)
	assert.True(t, apps.IsNull(), "an unset configuration reads null")

	users := res.GetUsersAndGroups()
	require.NoError(t, users.Error)
	require.NotNil(t, users.Data)
	assert.Equal(t, "allowed", users.Data.AccessType.Data)
	require.Len(t, users.Data.Targets.Data, 1)
	target := users.Data.Targets.Data[0].(*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTarget)
	assert.Equal(t, "AllUsers", target.Target.Data)
	assert.Equal(t, "user", target.TargetType.Data)
}

// ---------------------------------------------------------------------------
// access review definition: reviewers and recurrence
// ---------------------------------------------------------------------------

func TestAccessReviewReviewersDictIsJSONNative(t *testing.T) {
	withRoot := parseReviewerScope(t, queryReviewerScopeJSON)
	noRoot := parseReviewerScope(t, `{"query": "/users/abc", "queryType": "MicrosoftGraph"}`)

	reviewers := accessReviewReviewersDict([]models.AccessReviewReviewerScopeable{withRoot, nil, noRoot})
	requireDictConverts(t, llx.DictData(reviewers))

	require.Len(t, reviewers, 2)
	first := reviewers[0].(map[string]any)
	assert.Equal(t, "/groups/07a3f2d1-8b6c-4d5e-9f0a-1b2c3d4e5f60/owners", first["reviewer"])
	assert.Equal(t, "MicrosoftGraph", first["queryType"])
	assert.Equal(t, "decisions", first["queryRoot"])

	second := reviewers[1].(map[string]any)
	assert.Equal(t, "/users/abc", second["reviewer"])
	assert.Nil(t, second["queryRoot"])
}

const accessReviewRecurrenceJSON = `{
  "pattern": {
    "type": "absoluteMonthly",
    "interval": 3,
    "month": 0,
    "dayOfMonth": 0,
    "daysOfWeek": [],
    "firstDayOfWeek": "sunday",
    "index": "first"
  },
  "range": {
    "type": "noEnd",
    "numberOfOccurrences": 0,
    "recurrenceTimeZone": null,
    "startDate": "2024-04-01",
    "endDate": "9999-12-31"
  }
}`

func TestAccessReviewRecurrenceDictCarriesValues(t *testing.T) {
	recurrence := parseGraph(t, accessReviewRecurrenceJSON, models.CreatePatternedRecurrenceFromDiscriminatorValue).(models.PatternedRecurrenceable)

	d, err := accessReviewRecurrenceDict(recurrence)
	require.NoError(t, err)
	requireDictConverts(t, llx.DictData(d))

	pattern, ok := d["pattern"].(map[string]any)
	require.True(t, ok, "pattern is a dict")
	assert.Equal(t, "absoluteMonthly", pattern["type"])
	assert.Equal(t, int64(3), pattern["interval"])
	assert.Equal(t, "first", pattern["index"])
	assert.Equal(t, "sunday", pattern["firstDayOfWeek"])
	assert.Equal(t, []any{}, pattern["daysOfWeek"])

	rng, ok := d["range"].(map[string]any)
	require.True(t, ok, "range is a dict")
	assert.Equal(t, "noEnd", rng["type"])
	assert.Equal(t, "2024-04-01", rng["startDate"])
	assert.Equal(t, "9999-12-31", rng["endDate"])
	assert.Equal(t, int64(0), rng["numberOfOccurrences"])
	_, hasTZ := rng["recurrenceTimeZone"]
	assert.False(t, hasTZ, "a null property is left out")

	empty, err := accessReviewRecurrenceDict(nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"pattern": nil, "range": nil}, empty)
	requireDictConverts(t, llx.DictData(empty))
}

// ---------------------------------------------------------------------------
// mobile app properties
// ---------------------------------------------------------------------------

const iosStoreAppJSON = `{
  "@odata.type": "#microsoft.graph.iosStoreApp",
  "id": "9b2d1c0e-5f4a-4d3b-8c2e-1a0f9e8d7c6b",
  "displayName": "Example",
  "publisher": "Example Inc.",
  "publishingState": "published",
  "isFeatured": false,
  "createdDateTime": "2026-09-01T12:00:00Z",
  "bundleId": "com.example.app",
  "appStoreUrl": "https://apps.apple.com/us/app/example/id123456789",
  "applicableDeviceType": { "iPad": true, "iPhoneAndIPod": false },
  "minimumSupportedOperatingSystem": { "v8_0": false, "v17_0": true }
}`

func TestMobileAppPropertiesKnownType(t *testing.T) {
	app := parseGraph(t, iosStoreAppJSON, models.CreateMobileAppFromDiscriminatorValue).(models.MobileAppable)

	props, err := mobileAppProperties(app)
	require.NoError(t, err)
	requireDictConverts(t, llx.DictData(props))

	assert.Equal(t, "iosStoreApp", props["@odata.type"])
	assert.Equal(t, "com.example.app", props["bundleId"])
	assert.Equal(t, "https://apps.apple.com/us/app/example/id123456789", props["appStoreUrl"])
	assert.Equal(t, map[string]any{"iPad": true, "iPhoneAndIPod": false}, props["applicableDeviceType"])
	osReq, ok := props["minimumSupportedOperatingSystem"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, osReq["v17_0"])

	for _, base := range []string{"id", "displayName", "publisher", "publishingState", "isFeatured", "createdDateTime"} {
		_, present := props[base]
		assert.False(t, present, "base property %q has its own field", base)
	}
}

// A type this SDK version does not model falls back to the base mobileApp and
// keeps its own properties in AdditionalData as pointers.
const unknownMobileAppJSON = `{
  "@odata.type": "#microsoft.graph.futureExampleApp",
  "id": "1f2e3d4c-5b6a-4987-8a7b-6c5d4e3f2a1b",
  "displayName": "Future",
  "packageIdentifier": "Example.Future",
  "installTimeoutMinutes": 30,
  "allowUninstall": true,
  "rules": [ { "ruleType": "detection", "path": "C:\\Program Files\\Future" } ]
}`

func TestMobileAppPropertiesUnknownType(t *testing.T) {
	app := parseGraph(t, unknownMobileAppJSON, models.CreateMobileAppFromDiscriminatorValue).(models.MobileAppable)
	require.NotEmpty(t, app.GetAdditionalData(), "unknown properties land in AdditionalData")

	props, err := mobileAppProperties(app)
	require.NoError(t, err)
	requireDictConverts(t, llx.DictData(props))

	assert.Equal(t, "futureExampleApp", props["@odata.type"])
	assert.Equal(t, "Example.Future", props["packageIdentifier"])
	assert.Equal(t, int64(30), props["installTimeoutMinutes"])
	assert.Equal(t, true, props["allowUninstall"])
	assert.Equal(t, []any{map[string]any{"ruleType": "detection", "path": `C:\Program Files\Future`}}, props["rules"])
	_, present := props["displayName"]
	assert.False(t, present)
}

// ---------------------------------------------------------------------------
// permission grant policies and the authorization policy
// ---------------------------------------------------------------------------

const permissionGrantPolicyJSON = `{
  "id": "microsoft-user-default-low",
  "displayName": "All low risk permissions",
  "description": "Includes all application permissions classified low.",
  "includes": [
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000001",
      "permissionClassification": "low",
      "permissionType": "delegated",
      "resourceApplication": "any",
      "permissions": ["all"],
      "clientApplicationIds": ["all"],
      "clientApplicationTenantIds": ["all"],
      "clientApplicationPublisherIds": ["all"],
      "clientApplicationsFromVerifiedPublisherOnly": false
    },
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000002",
      "permissionType": "application"
    },
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000003"
    }
  ],
  "excludes": []
}`

func TestPermissionGrantConditionSetPermissionTypeIsName(t *testing.T) {
	policy := parseGraph(t, permissionGrantPolicyJSON, models.CreatePermissionGrantPolicyFromDiscriminatorValue).(models.PermissionGrantPolicyable)

	dicts, err := convert.JsonToDictSlice(newPermissionGrantPolicies([]models.PermissionGrantPolicyable{policy, nil}))
	require.NoError(t, err)
	requireDictConverts(t, llx.ArrayData(dicts, types.Dict))
	require.Len(t, dicts, 1)

	includes := dicts[0].(map[string]any)["includes"].([]any)
	require.Len(t, includes, 3)
	assert.Equal(t, "delegated", includes[0].(map[string]any)["permissionType"])
	assert.Equal(t, "application", includes[1].(map[string]any)["permissionType"])
	assert.Nil(t, includes[2].(map[string]any)["permissionType"], "absent is null, not delegatedUserConsentable")
}

const authorizationPolicyJSON = `{
  "@odata.type": "#microsoft.graph.authorizationPolicy",
  "id": "authorizationPolicy",
  "displayName": "Authorization Policy",
  "description": "Used to manage authorization related settings across the company.",
  "allowInvitesFrom": "adminsAndGuestInviters",
  "allowedToUseSSPR": true,
  "blockMsolPowerShell": false,
  "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
  "defaultUserRolePermissions": {
    "allowedToCreateApps": false,
    "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
  }
}`

func TestAuthorizationPolicyDictHasDocumentedKeys(t *testing.T) {
	policy := parseGraph(t, authorizationPolicyJSON, models.CreateAuthorizationPolicyFromDiscriminatorValue).(models.AuthorizationPolicyable)

	d, err := convert.JsonToDict(newAuthorizationPolicy(policy))
	require.NoError(t, err)
	requireDictConverts(t, llx.DictData(d))

	assert.Equal(t, "authorizationPolicy", d["id"])
	assert.Equal(t, "Authorization Policy", d["displayName"])
	assert.Equal(t, "Used to manage authorization related settings across the company.", d["description"])
	assert.Equal(t, "10dae51f-b6af-4016-8d66-8c2a99b929b3", d["guestUserRoleId"])
	assert.Equal(t, "ADMINSANDGUESTINVITERS", d["allowInvitesFrom"])
	assert.Equal(t, true, d["allowedToUseSSPR"])
}

func TestAuthorizationPolicyAbsentGuestRoleIsNull(t *testing.T) {
	policy := parseGraph(t, `{"id": "authorizationPolicy"}`, models.CreateAuthorizationPolicyFromDiscriminatorValue).(models.AuthorizationPolicyable)

	d, err := convert.JsonToDict(newAuthorizationPolicy(policy))
	require.NoError(t, err)
	v, ok := d["guestUserRoleId"]
	assert.True(t, ok)
	assert.Nil(t, v, "absent is null, not an empty string")
}

func TestVerifiedPublisherNilDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.Equal(t, VerifiedPublisher{}, newVerifiedPublisher(nil))
	})
}
