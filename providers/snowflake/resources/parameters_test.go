// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestFindParameterValue(t *testing.T) {
	params := []*sdk.Parameter{
		{Key: "NETWORK_POLICY", Value: "my_policy"},
		{Key: "ABORT_DETACHED_QUERY", Value: "false"},
		nil,
		{Key: "STATEMENT_TIMEOUT_IN_SECONDS", Value: "3600"},
	}

	cases := []struct {
		name string
		in   []*sdk.Parameter
		key  string
		want string
	}{
		{"exact match", params, "NETWORK_POLICY", "my_policy"},
		{"case-insensitive match", params, "network_policy", "my_policy"},
		{"other parameter", params, "STATEMENT_TIMEOUT_IN_SECONDS", "3600"},
		{"missing key returns empty", params, "DOES_NOT_EXIST", ""},
		{"empty value parameter", []*sdk.Parameter{{Key: "NETWORK_POLICY", Value: ""}}, "NETWORK_POLICY", ""},
		{"nil slice returns empty", nil, "NETWORK_POLICY", ""},
		{"slice with only nil entry", []*sdk.Parameter{nil}, "NETWORK_POLICY", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findParameterValue(tc.in, tc.key)
			if got != tc.want {
				t.Errorf("findParameterValue(%v, %q) = %q, want %q", tc.in, tc.key, got, tc.want)
			}
		})
	}
}

func TestParameterBool(t *testing.T) {
	// Synthetic: SHOW PARAMETERS reports booleans as the strings true/false.
	params := []*sdk.Parameter{
		{Key: "ENABLE_CORTEX_ANALYST", Value: "false"},
		{Key: "OTHER", Value: "TRUE"},
		{Key: "BROKEN", Value: "maybe"},
	}

	v, ok := parameterBool(params, "enable_cortex_analyst")
	assert.True(t, ok)
	assert.False(t, v)

	v, ok = parameterBool(params, "OTHER")
	assert.True(t, ok)
	assert.True(t, v)

	_, ok = parameterBool(params, "BROKEN")
	assert.False(t, ok, "a value that is not a boolean is not reported as false")

	_, ok = parameterBool(params, "MISSING")
	assert.False(t, ok)
}

func TestParameterInt(t *testing.T) {
	// Synthetic: -1 is Snowflake's documented default (no limit), 0 blocks.
	params := []*sdk.Parameter{
		{Key: "CORTEX_CODE_CLI_DAILY_EST_CREDIT_LIMIT_PER_USER", Value: "-1"},
		{Key: "CORTEX_CODE_DESKTOP_DAILY_EST_CREDIT_LIMIT_PER_USER", Value: "0"},
		{Key: "CORTEX_CODE_SNOWSIGHT_DAILY_EST_CREDIT_LIMIT_PER_USER", Value: " 25 "},
		{Key: "BROKEN", Value: ""},
	}

	v, ok := parameterInt(params, "CORTEX_CODE_CLI_DAILY_EST_CREDIT_LIMIT_PER_USER")
	assert.True(t, ok)
	assert.Equal(t, int64(-1), v)

	v, ok = parameterInt(params, "CORTEX_CODE_DESKTOP_DAILY_EST_CREDIT_LIMIT_PER_USER")
	assert.True(t, ok)
	assert.Equal(t, int64(0), v)

	v, ok = parameterInt(params, "cortex_code_snowsight_daily_est_credit_limit_per_user")
	assert.True(t, ok)
	assert.Equal(t, int64(25), v)

	_, ok = parameterInt(params, "BROKEN")
	assert.False(t, ok, "an empty value is not reported as 0")

	_, ok = parameterInt(nil, "CORTEX_CODE_CLI_DAILY_EST_CREDIT_LIMIT_PER_USER")
	assert.False(t, ok)
}
