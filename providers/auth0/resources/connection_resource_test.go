// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/auth0/go-auth0/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOtpSettings(t *testing.T) {
	// Synthetic: database connection with both channels configured; no target showed this.
	var both management.Connection
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "con_1",
		"strategy": "auth0",
		"options": {
			"otp_settings": {
				"email": {"otp_length": 8, "otp_expiry": 300},
				"phone": {"otp_length": 6, "otp_expiry": 120}
			}
		}
	}`), &both))
	opts, ok := both.Options.(*management.ConnectionOptions)
	require.True(t, ok)
	got := otpSettings(opts.OTPSettings)
	require.NotNil(t, got.emailLength)
	require.NotNil(t, got.emailExpiry)
	require.NotNil(t, got.phoneLength)
	require.NotNil(t, got.phoneExpiry)
	assert.Equal(t, 8, *got.emailLength)
	assert.Equal(t, 300, *got.emailExpiry)
	assert.Equal(t, 6, *got.phoneLength)
	assert.Equal(t, 120, *got.phoneExpiry)

	// Synthetic: only the email expiry configured; everything else stays null, not zero.
	var emailOnly management.Connection
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "con_2",
		"strategy": "auth0",
		"options": {"otp_settings": {"email": {"otp_expiry": 600}}}
	}`), &emailOnly))
	got = otpSettings(emailOnly.Options.(*management.ConnectionOptions).OTPSettings)
	assert.Nil(t, got.emailLength)
	require.NotNil(t, got.emailExpiry)
	assert.Equal(t, 600, *got.emailExpiry)
	assert.Nil(t, got.phoneLength)
	assert.Nil(t, got.phoneExpiry)

	// Synthetic: feature not enabled, so the API omits otp_settings.
	var absent management.Connection
	require.NoError(t, json.Unmarshal([]byte(`{"id": "con_3", "strategy": "auth0", "options": {}}`), &absent))
	got = otpSettings(absent.Options.(*management.ConnectionOptions).OTPSettings)
	assert.Nil(t, got.emailLength)
	assert.Nil(t, got.emailExpiry)
	assert.Nil(t, got.phoneLength)
	assert.Nil(t, got.phoneExpiry)
}
