// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestUserParameterOverride pins the level check.
//
// SHOW PARAMETERS IN USER reports the effective value, so a user who has never
// been given a network policy still carries the account's in the value column.
// Reading the value without the level would report every user in an account
// that has a network policy as holding a per-user override, and a per-user
// override is precisely what lets a user out of the account restriction.
func TestUserParameterOverride(t *testing.T) {
	cases := []struct {
		name   string
		params []snowflakeParameterValue
		key    string
		want   string
		wantOK bool
	}{
		{
			name:   "set on the user",
			params: []snowflakeParameterValue{{key: "NETWORK_POLICY", value: "USER_BYPASS", level: "USER"}},
			key:    "NETWORK_POLICY",
			want:   "USER_BYPASS",
			wantOK: true,
		},
		{
			name:   "inherited from the account",
			params: []snowflakeParameterValue{{key: "NETWORK_POLICY", value: "CORP_ALLOWLIST", level: "ACCOUNT"}},
			key:    "NETWORK_POLICY",
			want:   "",
			wantOK: false,
		},
		{
			name:   "no level reported is not an override",
			params: []snowflakeParameterValue{{key: "NETWORK_POLICY", value: "CORP_ALLOWLIST", level: ""}},
			key:    "NETWORK_POLICY",
			want:   "",
			wantOK: false,
		},
		{
			name:   "parameter absent",
			params: []snowflakeParameterValue{{key: "TIMEZONE", value: "UTC", level: "USER"}},
			key:    "NETWORK_POLICY",
			want:   "",
			wantOK: false,
		},
		{
			name:   "no parameters at all",
			params: nil,
			key:    "NETWORK_POLICY",
			want:   "",
			wantOK: false,
		},
		{
			name:   "key and level match case insensitively",
			params: []snowflakeParameterValue{{key: "network_policy", value: "USER_BYPASS", level: "user"}},
			key:    "NETWORK_POLICY",
			want:   "USER_BYPASS",
			wantOK: true,
		},
		{
			name:   "value is trimmed",
			params: []snowflakeParameterValue{{key: "NETWORK_POLICY", value: "  USER_BYPASS  ", level: " USER "}},
			key:    "NETWORK_POLICY",
			want:   "USER_BYPASS",
			wantOK: true,
		},
		{
			name: "an inherited row does not mask a later override",
			params: []snowflakeParameterValue{
				{key: "NETWORK_POLICY", value: "CORP_ALLOWLIST", level: "ACCOUNT"},
				{key: "NETWORK_POLICY", value: "USER_BYPASS", level: "USER"},
			},
			key:    "NETWORK_POLICY",
			want:   "USER_BYPASS",
			wantOK: true,
		},
		{
			name:   "an override set to nothing is still an override",
			params: []snowflakeParameterValue{{key: "NETWORK_POLICY", value: "", level: "USER"}},
			key:    "NETWORK_POLICY",
			want:   "",
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := userParameterOverride(tc.params, tc.key)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("userParameterOverride() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParameterValuesSkipsNonParameters(t *testing.T) {
	got := parameterValues([]any{"not a parameter", (*mqlSnowflakeParameter)(nil), nil})
	if len(got) != 0 {
		t.Errorf("parameterValues() = %#v, want empty", got)
	}
}
