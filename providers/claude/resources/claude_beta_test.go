// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeUserProfile(t *testing.T, payload string) anthropic.UserProfile {
	t.Helper()
	var p anthropic.UserProfile
	require.NoError(t, json.Unmarshal([]byte(payload), &p))
	return p
}

// Synthetic: payload shaped after the SDK's UserProfile type; no live
// organization was available.
//
// The generally available endpoint moved the platform's reference and the
// onboarding time under external_user_details. The shipped externalId and
// externalUserOnboardedAt fields must keep reading those values; reading the
// old top-level keys would leave both empty on every profile.
func TestUserProfileArgsReadsExternalUserDetails(t *testing.T) {
	p := decodeUserProfile(t, `{
		"id": "uprof_0001",
		"type": "user_profile",
		"name": "Example Corp",
		"access_type": "passthrough",
		"created_at": "2026-09-01T10:00:00Z",
		"updated_at": "2026-10-01T10:00:00Z",
		"metadata": {},
		"enforcement_status": "restricted",
		"enforcement_actions": [],
		"programs": {},
		"external_user_details": {
			"account_status": "active",
			"country": "US",
			"email_hash": null,
			"entity_type": "business",
			"name_hash": null,
			"onboarded_at": "2025-12-24T08:30:00Z",
			"reference_id": "cust-42"
		}
	}`)

	args := userProfileArgs(p)
	assert.Equal(t, "cust-42", args["externalId"].Value)
	assert.Equal(t, time.Date(2025, 12, 24, 8, 30, 0, 0, time.UTC), *(args["externalUserOnboardedAt"].Value.(*time.Time)))
	assert.Equal(t, "passthrough", args["accessType"].Value)
	assert.Equal(t, "restricted", args["enforcementStatus"].Value)
	assert.Nil(t, args["relationship"].Value)
}

// Synthetic: a profile the platform has not filled in yet. A missing
// onboarding time must read null, not 1 January year 1, and a response
// without an enforcement status must not report one.
func TestUserProfileArgsAbsentValuesReadNull(t *testing.T) {
	p := decodeUserProfile(t, `{
		"id": "uprof_0002",
		"type": "user_profile",
		"name": null,
		"created_at": "2026-09-01T10:00:00Z",
		"updated_at": "2026-09-01T10:00:00Z",
		"external_user_details": {
			"account_status": null,
			"country": null,
			"email_hash": null,
			"entity_type": null,
			"name_hash": null,
			"onboarded_at": null,
			"reference_id": null
		}
	}`)

	args := userProfileArgs(p)
	assert.Nil(t, args["externalUserOnboardedAt"].Value)
	assert.Nil(t, args["enforcementStatus"].Value)
	assert.Nil(t, args["accessType"].Value)
}

// Synthetic: one restriction the end user can clear and one ban, with the
// values the SDK documents for each variant.
func TestEnforcementActionArgs(t *testing.T) {
	p := decodeUserProfile(t, `{
		"id": "uprof_0003",
		"type": "user_profile",
		"created_at": "2026-09-01T10:00:00Z",
		"updated_at": "2026-09-01T10:00:00Z",
		"enforcement_status": "banned",
		"enforcement_actions": [
			{
				"id": "enac_0001",
				"type": "restriction",
				"action": "verify",
				"reason": "unsupported_region",
				"opened_at": "2026-10-01T12:00:00Z",
				"expires_at": "2026-11-01T12:00:00Z"
			},
			{
				"id": "enac_0002",
				"type": "ban",
				"action": null,
				"reason": "fraud_or_abuse",
				"opened_at": "2026-10-02T12:00:00Z",
				"expires_at": null
			}
		]
	}`)
	require.Len(t, p.EnforcementActions, 2)

	restriction := enforcementActionArgs(p.ID, p.EnforcementActions[0])
	assert.Equal(t, "uprof_0003/enforcementAction/enac_0001", restriction["__id"].Value)
	assert.Equal(t, "enac_0001", restriction["id"].Value)
	assert.Equal(t, "restriction", restriction["type"].Value)
	assert.Equal(t, "verify", restriction["nextStep"].Value)
	assert.Equal(t, "unsupported_region", restriction["reason"].Value)
	assert.Equal(t, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), *(restriction["openedAt"].Value.(*time.Time)))
	assert.Equal(t, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), *(restriction["expiresAt"].Value.(*time.Time)))

	// A ban has no next step and no end date: both must read null rather
	// than an empty step and a year-1 expiry that an expiry check would read
	// as long past.
	ban := enforcementActionArgs(p.ID, p.EnforcementActions[1])
	assert.Equal(t, "ban", ban["type"].Value)
	assert.Equal(t, "fraud_or_abuse", ban["reason"].Value)
	assert.Nil(t, ban["nextStep"].Value)
	assert.Nil(t, ban["expiresAt"].Value)
}
