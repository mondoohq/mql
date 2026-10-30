// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestParseAuthPolicyList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []any
	}{
		{"empty string", "", []any{}},
		{"empty parens", "()", []any{}},
		{"single quoted", "('ALL')", []any{"ALL"}},
		{"multiple quoted", "('PASSWORD', 'SAML')", []any{"PASSWORD", "SAML"}},
		{"no parens", "ALL", []any{"ALL"}},
		{"double-quoted", `("PASSWORD","SAML")`, []any{"PASSWORD", "SAML"}},
		{"extra whitespace", "(  'PASSWORD' , 'SAML'  )", []any{"PASSWORD", "SAML"}},
		{"trailing comma yields no empty entry", "('PASSWORD',)", []any{"PASSWORD"}},
		// Snowflake actually returns these lists in square brackets, unquoted.
		{"bracket single", "[ALL]", []any{"ALL"}},
		{"bracket multiple", "[PASSWORD, SAML]", []any{"PASSWORD", "SAML"}},
		{"bracket empty", "[]", []any{}},
		{"bracket no space", "[PASSWORD,SAML]", []any{"PASSWORD", "SAML"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAuthPolicyList(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseAuthPolicyList(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAuthPolicyStruct(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]any
	}{
		{"empty string", "", map[string]any{}},
		{"empty braces", "{}", map[string]any{}},
		{
			// The shape a PAT policy at its defaults reports. The two expiry
			// bounds must come back as numbers or no policy can compare them.
			"pat policy defaults",
			"{DEFAULT_EXPIRY_IN_DAYS=15, MAX_EXPIRY_IN_DAYS=365, NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true}",
			map[string]any{
				"DEFAULT_EXPIRY_IN_DAYS":                     int64(15),
				"MAX_EXPIRY_IN_DAYS":                         int64(365),
				"NETWORK_POLICY_EVALUATION":                  "ENFORCED_REQUIRED",
				"REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS": true,
			},
		},
		{
			// Verbatim from DESCRIBE AUTHENTICATION POLICY on a live account
			// (Snowflake 9.x, 2026-08-20). Note the three sub-parameters the
			// CREATE reference does not list, the unquoted 12-digit account id,
			// and the lowercase booleans.
			"real payload: PAT_POLICY",
			"{DEFAULT_EXPIRY_IN_DAYS=7, MAX_EXPIRY_IN_DAYS=30, NETWORK_POLICY_EVALUATION=NOT_ENFORCED, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true, REQUIRE_ROLE_RESTRICTION_FOR_PERSON_USERS=false, BLOCKED_ROLES_LIST=[]}",
			map[string]any{
				"DEFAULT_EXPIRY_IN_DAYS":                     int64(7),
				"MAX_EXPIRY_IN_DAYS":                         int64(30),
				"NETWORK_POLICY_EVALUATION":                  "NOT_ENFORCED",
				"REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS": true,
				"REQUIRE_ROLE_RESTRICTION_FOR_PERSON_USERS":  false,
				"BLOCKED_ROLES_LIST":                         []any{},
			},
		},
		{
			// Verbatim from the same run. ALLOWED_AWS_ACCOUNTS holds a bare
			// 12-digit number: coercing list members would drop a leading zero
			// on any account id that has one.
			"real payload: WORKLOAD_IDENTITY_POLICY",
			"{ALLOWED_PROVIDERS=[AWS, AZURE], ALLOWED_AWS_ACCOUNTS=[123456789012], ALLOWED_AWS_PARTITIONS=[ALL], ALLOWED_AZURE_ISSUERS=[ALL], ALLOWED_OIDC_ISSUERS=[ALL]}",
			map[string]any{
				"ALLOWED_PROVIDERS":      []any{"AWS", "AZURE"},
				"ALLOWED_AWS_ACCOUNTS":   []any{"123456789012"},
				"ALLOWED_AWS_PARTITIONS": []any{"ALL"},
				"ALLOWED_AZURE_ISSUERS":  []any{"ALL"},
				"ALLOWED_OIDC_ISSUERS":   []any{"ALL"},
			},
		},
		{
			// MFA_POLICY is a third structured property in the same format,
			// still unmodelled. Parsed here to pin that the shape is shared.
			"real payload: MFA_POLICY",
			"{ALLOWED_METHODS=[ALL], ENFORCE_MFA_ON_EXTERNAL_AUTHENTICATION=NONE}",
			map[string]any{
				"ALLOWED_METHODS":                        []any{"ALL"},
				"ENFORCE_MFA_ON_EXTERNAL_AUTHENTICATION": "NONE",
			},
		},
		{
			// CLIENT_POLICY reports an empty struct rather than null when unset.
			"real payload: empty CLIENT_POLICY", "{}", map[string]any{},
		},
		{
			"pat policy with the unsafe network setting",
			"{MAX_EXPIRY_IN_DAYS=30, NETWORK_POLICY_EVALUATION=NOT_ENFORCED}",
			map[string]any{
				"MAX_EXPIRY_IN_DAYS":        int64(30),
				"NETWORK_POLICY_EVALUATION": "NOT_ENFORCED",
			},
		},
		{
			"booleans are case insensitive",
			"{A=TRUE, B=False}",
			map[string]any{"A": true, "B": false},
		},
		{
			// The comma inside the bracketed list must not split the entry.
			"workload identity policy with lists",
			"{ALLOWED_PROVIDERS=[AWS, AZURE], ALLOWED_AWS_ACCOUNTS=[123456789012, 210987654321]}",
			map[string]any{
				"ALLOWED_PROVIDERS":    []any{"AWS", "AZURE"},
				"ALLOWED_AWS_ACCOUNTS": []any{"123456789012", "210987654321"},
			},
		},
		{
			// An AWS account id may legitimately begin with a zero. Coercing
			// list members to numbers would silently rewrite the id.
			"account id keeps its leading zero",
			"{ALLOWED_AWS_ACCOUNTS=[012345678901]}",
			map[string]any{"ALLOWED_AWS_ACCOUNTS": []any{"012345678901"}},
		},
		{
			"issuer urls survive intact",
			"{ALLOWED_OIDC_ISSUERS=[https://token.actions.githubusercontent.com], ALLOWED_AZURE_ISSUERS=[https://login.microsoftonline.com/abc-123/v2.0]}",
			map[string]any{
				"ALLOWED_OIDC_ISSUERS":  []any{"https://token.actions.githubusercontent.com"},
				"ALLOWED_AZURE_ISSUERS": []any{"https://login.microsoftonline.com/abc-123/v2.0"},
			},
		},
		{
			"empty list", "{ALLOWED_PROVIDERS=[]}",
			map[string]any{"ALLOWED_PROVIDERS": []any{}},
		},
		{
			// The documented CLIENT_POLICY example: nesting is the reason the
			// entry split has to track depth, and the reason splitting the key
			// off at the first "=" rather than every "=" matters.
			"nested map, as the documented client policy example",
			"{GO_DRIVER={MINIMUM_VERSION=3.14.1}}",
			map[string]any{"GO_DRIVER": map[string]any{"MINIMUM_VERSION": "3.14.1"}},
		},
		{
			"version strings are not numbers",
			"{MINIMUM_VERSION=3.14.1}",
			map[string]any{"MINIMUM_VERSION": "3.14.1"},
		},
		{
			"empty value", "{A=}",
			map[string]any{"A": ""},
		},
		{
			"entry with no separator is skipped",
			"{JUSTAKEY}", map[string]any{},
		},
		{
			// A value Snowflake reports in place of a struct must not be
			// mistaken for one; an empty map is the honest reading.
			"unbracketed value is not a struct", "null", map[string]any{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAuthPolicyStruct(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseAuthPolicyStruct(%q)\n got: %#v\nwant: %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseAuthPolicyStructIsDictSerializable guards the dict contract: llx
// accepts only bool, int64, float64, string, []any, map[string]any and nil as
// dict values. A plain int or a []string compiles and passes every other test,
// then errors at query time on the first account that populates the field.
func TestParseAuthPolicyStructIsDictSerializable(t *testing.T) {
	inputs := []string{
		"{DEFAULT_EXPIRY_IN_DAYS=15, MAX_EXPIRY_IN_DAYS=365, NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true}",
		"{ALLOWED_PROVIDERS=[AWS, AZURE], ALLOWED_AWS_ACCOUNTS=[123456789012]}",
		"{GO_DRIVER={MINIMUM_VERSION=3.14.1}}",
		"{DEFAULT_EXPIRY_IN_DAYS=7, MAX_EXPIRY_IN_DAYS=30, NETWORK_POLICY_EVALUATION=NOT_ENFORCED, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true, REQUIRE_ROLE_RESTRICTION_FOR_PERSON_USERS=false, BLOCKED_ROLES_LIST=[]}",
		"{ALLOWED_PROVIDERS=[AWS, AZURE], ALLOWED_AWS_ACCOUNTS=[123456789012], ALLOWED_AWS_PARTITIONS=[ALL], ALLOWED_AZURE_ISSUERS=[ALL], ALLOWED_OIDC_ISSUERS=[ALL]}",
		"{}",
	}
	for _, in := range inputs {
		assertDictSerializable(t, parseAuthPolicyStruct(in))
	}
}

func assertDictSerializable(t *testing.T, v any) {
	t.Helper()
	switch val := v.(type) {
	case nil, bool, int64, float64, string:
	case []any:
		for _, member := range val {
			assertDictSerializable(t, member)
		}
	case map[string]any:
		for _, member := range val {
			assertDictSerializable(t, member)
		}
	default:
		t.Errorf("value %#v has type %T, which llx cannot convert to a dict", v, v)
	}
}

// TestParseAuthPolicyStructMfaAndClientPolicy pins the two properties added
// alongside PAT_POLICY and WORKLOAD_IDENTITY_POLICY.
//
// Neither value is JSON. Snowflake renders a structured DESCRIBE value the way
// a Java map prints itself, which is what the documented CLIENT_POLICY example
// shows, so a decoder written against JSON compiles, passes a hand-written
// fixture, and returns nothing on every real account.
func TestParseAuthPolicyStructMfaAndClientPolicy(t *testing.T) {
	t.Run("MFA_POLICY", func(t *testing.T) {
		got := parseAuthPolicyStruct("{ALLOWED_METHODS=[PASSKEY, TOTP, DUO], ENROLLMENT=REQUIRED}")
		want := map[string]any{
			"ALLOWED_METHODS": []any{"PASSKEY", "TOTP", "DUO"},
			"ENROLLMENT":      "REQUIRED",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseAuthPolicyStruct() = %#v, want %#v", got, want)
		}
	})

	t.Run("CLIENT_POLICY nests one map per driver", func(t *testing.T) {
		got := parseAuthPolicyStruct("{GO_DRIVER={MINIMUM_VERSION=3.14.1}, JDBC_DRIVER={MINIMUM_VERSION=3.13.30}}")
		want := map[string]any{
			"GO_DRIVER":   map[string]any{"MINIMUM_VERSION": "3.14.1"},
			"JDBC_DRIVER": map[string]any{"MINIMUM_VERSION": "3.13.30"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseAuthPolicyStruct() = %#v, want %#v", got, want)
		}
	})

	t.Run("a version stays a string", func(t *testing.T) {
		got := parseAuthPolicyStruct("{GO_DRIVER={MINIMUM_VERSION=3.14.1}}")
		driver, ok := got["GO_DRIVER"].(map[string]any)
		if !ok {
			t.Fatalf("GO_DRIVER = %#v, want a map", got["GO_DRIVER"])
		}
		if _, isString := driver["MINIMUM_VERSION"].(string); !isString {
			t.Errorf("MINIMUM_VERSION = %#v, want a string; coercing a version would drop its parts", driver["MINIMUM_VERSION"])
		}
	})

	t.Run("an unreported property yields an empty map, not an error", func(t *testing.T) {
		for _, in := range []string{"", "null", "not a map"} {
			if got := parseAuthPolicyStruct(in); len(got) != 0 {
				t.Errorf("parseAuthPolicyStruct(%q) = %#v, want empty", in, got)
			}
		}
	})
}
