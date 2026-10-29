// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iterateEach hands over every item of every page, following
// @odata.nextLink. A null element makes the SDK panic converting its page, so
// that page is lost, but the walk ends with the earlier pages' items kept
// rather than crashing the scan.
func TestIterateEachPages(t *testing.T) {
	f := newFakeGraph(t, map[string]fakeRoute{
		"/reports/authenticationMethods/userRegistrationDetails": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/reports/authenticationMethods/userRegistrationDetails/page2",
			"value": [{"id": "u1", "isMfaCapable": true}, {"id": "u2", "isMfaCapable": false}]}`},
		"/reports/authenticationMethods/userRegistrationDetails/page2": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/reports/authenticationMethods/userRegistrationDetails/page3",
			"value": [{"id": "u3", "isMfaCapable": true}]}`},
		"/reports/authenticationMethods/userRegistrationDetails/page3": {status: 200, body: `{
			"value": [{"id": "u4"}, null, {"id": "u5"}]}`},
	})
	client := f.client()
	ctx := context.Background()
	resp, err := client.Reports().AuthenticationMethods().UserRegistrationDetails().Get(ctx, nil)
	require.NoError(t, err)

	ids := []string{}
	err = iterateEach(ctx, resp, client.GetAdapter(),
		models.CreateUserRegistrationDetailsCollectionResponseFromDiscriminatorValue,
		func(d models.UserRegistrationDetailsable) error {
			ids = append(ids, *d.GetId())
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"u1", "u2", "u3"}, ids)
}

// The registration report is held for the whole scan as
// userRegistrationDetail values; every field the resource exposes must
// survive the reduction from the kiota model.
func TestNewMqlUserRegistrationDetailsFromReportRow(t *testing.T) {
	runtime, _ := licenseTestEnv(t, nil, nil, nil)
	row := models.NewUserRegistrationDetails()
	id, upn, yes, no := "u1", "alice@example.com", true, false
	row.SetId(&id)
	row.SetUserPrincipalName(&upn)
	row.SetIsMfaCapable(&yes)
	row.SetIsSsprRegistered(&no)
	row.SetMethodsRegistered([]string{"microsoftAuthenticatorPush", "mobilePhone"})
	userType := models.MEMBER_SIGNINUSERTYPE
	row.SetUserType(&userType)

	res, err := newMqlUserRegistrationDetails(runtime, newUserRegistrationDetail(row))
	require.NoError(t, err)
	assert.Equal(t, id, res.Id.Data)
	assert.Equal(t, upn, res.UserPrincipalName.Data)
	assert.True(t, res.IsMfaCapable.Data)
	assert.False(t, res.IsSsprRegistered.Data)
	assert.Equal(t, []any{"microsoftAuthenticatorPush", "mobilePhone"}, res.MethodsRegistered.Data)
	assert.Equal(t, "member", res.UserType.Data)
}
