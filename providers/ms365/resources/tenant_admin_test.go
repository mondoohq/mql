// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestClassifyGraphError_NamesTenantAdminPermission(t *testing.T) {
	t.Run("403 is forbidden and names the permission", func(t *testing.T) {
		err := classifyGraphError(odataErrWithStatus("Authorization_RequestDenied", 403), permServiceHealthRead)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		var e *llx.Error
		require.True(t, errors.As(err, &e))
		assert.Equal(t, []string{permServiceHealthRead}, e.Permissions)
		assert.Contains(t, err.Error(), "Authorization_RequestDenied")
	})

	t.Run("403 already passed through transformError is still forbidden", func(t *testing.T) {
		err := classifyGraphError(transformError(odataErrWithStatus("Authorization_RequestDenied", 403)), permPeopleSettingsRead)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	})
}

// Shape of an entry returned by GET /admin/serviceAnnouncement/issues.
const serviceHealthIssueJSON = `{
  "startDateTime": "2026-09-28T07:00:00Z",
  "endDateTime": null,
  "lastModifiedDateTime": "2026-09-29T19:50:21.243Z",
  "title": "Users may be unable to access Exchange Online via any connection method",
  "id": "EX123456",
  "impactDescription": "Users may be unable to access Exchange Online.",
  "classification": "incident",
  "origin": "microsoft",
  "status": "serviceDegradation",
  "service": "Exchange Online",
  "feature": "E-Mail and calendar access",
  "featureGroup": "Networking",
  "isResolved": false,
  "details": [],
  "posts": []
}`

func decodeServiceHealthIssue(t *testing.T, body string) models.ServiceHealthIssueable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(body))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateServiceHealthIssueFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.ServiceHealthIssueable)
}

func TestServiceHealthIssueArgs(t *testing.T) {
	args := serviceHealthIssueArgs(decodeServiceHealthIssue(t, serviceHealthIssueJSON))

	assert.Equal(t, "microsoft.serviceHealthIssue/EX123456", args["__id"].Value)
	assert.Equal(t, "EX123456", args["id"].Value)
	assert.Equal(t, "Exchange Online", args["service"].Value)
	assert.Equal(t, "E-Mail and calendar access", args["feature"].Value)
	assert.Equal(t, "Networking", args["featureGroup"].Value)
	assert.Equal(t, "Users may be unable to access Exchange Online.", args["impactDescription"].Value)
	assert.Equal(t, "incident", args["classification"].Value)
	assert.Equal(t, "microsoft", args["origin"].Value)
	assert.Equal(t, "serviceDegradation", args["status"].Value)
	assert.Equal(t, false, args["isResolved"].Value)

	start, ok := args["startDateTime"].Value.(*time.Time)
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC), start.UTC())

	// an open issue has no end: null, not year 1
	assert.Nil(t, args["endDateTime"].Value)
}

func TestServiceHealthIssueArgsAbsentEnums(t *testing.T) {
	args := serviceHealthIssueArgs(decodeServiceHealthIssue(t, `{"id":"MO1","title":"t"}`))
	assert.Nil(t, args["classification"].Value)
	assert.Nil(t, args["status"].Value)
	assert.Nil(t, args["origin"].Value)
	assert.Nil(t, args["isResolved"].Value)
	assert.Nil(t, args["lastModifiedDateTime"].Value)
}

func TestServiceHealthOverviewDecodesExpandedIssues(t *testing.T) {
	body := `{"id":"Exchange","service":"Exchange Online","status":"serviceOperational",
	  "issues":[` + serviceHealthIssueJSON + `]}`
	node, err := kjson.NewJsonParseNode([]byte(body))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateServiceHealthFromDiscriminatorValue)
	require.NoError(t, err)
	overview := parsed.(models.ServiceHealthable)

	assert.Equal(t, "serviceOperational", *enumStringPtr(overview.GetStatus()))
	require.Len(t, overview.GetIssues(), 1)
	assert.Equal(t, "EX123456", *overview.GetIssues()[0].GetId())
}

// Shape of an entry returned by GET /admin/people/profileCardProperties.
const profileCardPropertyJSON = `{
  "directoryPropertyName": "CustomAttribute1",
  "annotations": [
    {
      "displayName": "Cost Center",
      "localizations": [
        {"languageTag": "ru", "displayName": "Центр затрат"},
        {"languageTag": "de"}
      ]
    }
  ]
}`

func TestProfileCardAnnotations(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(profileCardPropertyJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateProfileCardPropertyFromDiscriminatorValue)
	require.NoError(t, err)
	prop := parsed.(models.ProfileCardPropertyable)

	got := profileCardAnnotations(prop.GetAnnotations())
	assert.Equal(t, []any{
		map[string]any{
			"displayName": "Cost Center",
			"localizations": []any{
				map[string]any{"languageTag": "ru", "displayName": "Центр затрат"},
				map[string]any{"languageTag": "de", "displayName": nil},
			},
		},
	}, got)
}

func TestProfileCardAnnotationsEmpty(t *testing.T) {
	assert.Equal(t, []any{}, profileCardAnnotations(nil))
}
