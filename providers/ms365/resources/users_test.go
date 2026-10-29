// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// job()/contact() resolve from the bulk user list response (userSelectFields)
// instead of an N+1 per-user Get. That optimization only holds if every field
// the job/contact dicts read is also requested by the bulk list. This guards
// against silently reintroducing the N+1 (or dropping data) by removing a field
// from userSelectFields.
func TestUserSelectFieldsCoverJobContactFields(t *testing.T) {
	selected := make(map[string]bool, len(userSelectFields))
	for _, f := range userSelectFields {
		selected[f] = true
	}
	for _, f := range userJobContactFields {
		assert.Truef(t, selected[f],
			"userJobContactFields[%q] is not in userSelectFields; job()/contact() "+
				"would fall back to an N+1 per-user Get (or lose this field)", f)
	}
}

// authMethods.registrationDetails comes from the tenant-wide registration
// report. Reaching it must not list the methods of every user: CIS
// isMfaCapable walks all members that way. The runtime here has no
// connection, so a per-user fetch would fail the test.
func TestUserAuthMethodsRegistrationDetailsSkipsMethodListing(t *testing.T) {
	runtime, ms := licenseTestEnv(t, nil, nil, nil)
	details := models.NewUserRegistrationDetails()
	id, capable := "alice", true
	details.SetId(&id)
	details.SetIsMfaCapable(&capable)
	ms.regOnce.Do(func() {
		ms.regDetails = map[string]models.UserRegistrationDetailsable{id: details}
	})

	authMethods, err := testUser(t, runtime, id).authMethods()
	require.NoError(t, err)
	reg, err := authMethods.registrationDetails()
	require.NoError(t, err)
	assert.True(t, reg.IsMfaCapable.Data)
	assert.Nil(t, ms.userBatches.authMethods.loaded, "the per-user method listing ran")

	// the method fields still read the per-user listing
	phone := models.NewPhoneAuthenticationMethod()
	phoneID, number := "p1", "+1 555 0100"
	phone.SetId(&phoneID)
	phone.SetPhoneNumber(&number)
	ms.userBatches.authMethods.data = map[string]any{id: buildUserAuthentication(id, []models.AuthenticationMethodable{phone})}
	ms.userBatches.authMethods.errs = map[string]error{}
	ms.userBatches.authMethods.loaded = map[string]bool{id: true}

	count, err := authMethods.count()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	phones, err := authMethods.phoneMethods()
	require.NoError(t, err)
	require.Len(t, phones, 1)
	assert.Equal(t, number, phones[0].(map[string]any)["phoneNumber"])
	emails, err := authMethods.emailMethods()
	require.NoError(t, err)
	assert.Empty(t, emails)
}
