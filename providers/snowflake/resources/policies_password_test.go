// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestPasswordPolicyIntProperties(t *testing.T) {
	// Rows as DESCRIBE PASSWORD POLICY returns them.
	values := passwordPolicyIntProperties([]sdk.PasswordPolicyProperty{
		{Property: "NAME", Value: "STRICT"},
		{Property: "OWNER", Value: "ACCOUNTADMIN"},
		{Property: "COMMENT", Value: "null"},
		{Property: "PASSWORD_MIN_LENGTH", Value: "14"},
		{Property: "PASSWORD_MAX_RETRIES", Value: " 5 "},
		{Property: "PASSWORD_HISTORY", Value: "0"},
	})

	assert.Equal(t, map[string]int64{
		"PASSWORD_MIN_LENGTH":  14,
		"PASSWORD_MAX_RETRIES": 5,
		"PASSWORD_HISTORY":     0,
	}, values)
}

func TestPasswordPolicyIntValue(t *testing.T) {
	values := map[string]int64{"PASSWORD_MIN_LENGTH": 14, "PASSWORD_HISTORY": 0}

	got := passwordPolicyIntValue(values, "PASSWORD_MIN_LENGTH")
	assert.Equal(t, int64(14), got.Data)
	assert.Equal(t, plugin.StateIsSet, got.State)

	// A reported zero is a value.
	got = passwordPolicyIntValue(values, "PASSWORD_HISTORY")
	assert.Equal(t, int64(0), got.Data)
	assert.Equal(t, plugin.StateIsSet, got.State)

	// A property DESCRIBE did not report is null, not zero.
	got = passwordPolicyIntValue(values, "PASSWORD_MAX_AGE_DAYS")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, got.State)
}
