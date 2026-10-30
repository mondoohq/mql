// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseSecurityIntegrationList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []any
	}{
		// A roles list arrives bare.
		{"bare", "ACCOUNTADMIN,SECURITYADMIN", []any{"ACCOUNTADMIN", "SECURITYADMIN"}},
		{"bare with spaces", "ACCOUNTADMIN, SECURITYADMIN", []any{"ACCOUNTADMIN", "SECURITYADMIN"}},
		{"single", "ACCOUNTADMIN", []any{"ACCOUNTADMIN"}},
		// A claim or audience list arrives bracketed with quoted members.
		{"bracketed single quotes", "['upn', 'sub']", []any{"upn", "sub"}},
		{"bracketed double quotes", `["upn","sub"]`, []any{"upn", "sub"}},
		{"bracketed bare", "[upn, sub]", []any{"upn", "sub"}},
		// A list property that is set to nothing is an empty list, not a list
		// holding one empty member.
		{"empty", "", []any{}},
		{"empty brackets", "[]", []any{}},
		{"only whitespace", "   ", []any{}},
		{"trailing comma", "ACCOUNTADMIN,", []any{"ACCOUNTADMIN"}},
		{"quoted with inner space", "[ 'a b' , 'c' ]", []any{"a b", "c"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSecurityIntegrationList(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseSecurityIntegrationList(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestStringPropertyAbsentIsNull pins the difference the whole DESCRIBE mapping
// turns on: an integration type that does not report a property leaves the
// field null, while a property Snowflake reports as empty is an empty string.
func TestStringPropertyAbsentIsNull(t *testing.T) {
	props := map[string]string{"EXTERNAL_OAUTH_ANY_ROLE_MODE": "DISABLE", "EXTERNAL_OAUTH_ISSUER": ""}

	field := plugin.TValue[string]{}
	got, err := stringProperty(props, "EXTERNAL_OAUTH_ANY_ROLE_MODE", &field)
	if err != nil || got != "DISABLE" {
		t.Fatalf("present property = (%q, %v), want (DISABLE, nil)", got, err)
	}
	if field.State&plugin.StateIsNull != 0 {
		t.Error("a present property marked the field null")
	}

	field = plugin.TValue[string]{}
	got, err = stringProperty(props, "EXTERNAL_OAUTH_ISSUER", &field)
	if err != nil || got != "" {
		t.Fatalf("empty property = (%q, %v), want (\"\", nil)", got, err)
	}
	if field.State&plugin.StateIsNull != 0 {
		t.Error("a property Snowflake reported as empty was marked null")
	}

	field = plugin.TValue[string]{}
	got, err = stringProperty(props, "SCIM_CLIENT", &field)
	if err != nil || got != "" {
		t.Fatalf("absent property = (%q, %v), want (\"\", nil)", got, err)
	}
	if field.State&plugin.StateIsNull == 0 {
		t.Error("an absent property did not mark the field null; it would read as an empty value")
	}
}

// TestBoolPropertyNeverInventsFalse is the one that matters for assertions.
// A missing OAUTH_ENFORCE_PKCE reported as false would claim a proof key is not
// enforced on a SAML integration that has no authorization code flow at all.
func TestBoolPropertyNeverInventsFalse(t *testing.T) {
	props := map[string]string{
		"OAUTH_ENFORCE_PKCE":         "true",
		"OAUTH_ISSUE_REFRESH_TOKENS": "false",
		"SYNC_PASSWORD":              "not a boolean",
	}

	cases := []struct {
		key      string
		want     bool
		wantNull bool
	}{
		{"OAUTH_ENFORCE_PKCE", true, false},
		{"OAUTH_ISSUE_REFRESH_TOKENS", false, false},
		{"SYNC_PASSWORD", false, true},
		{"OAUTH_ALLOW_NON_TLS_REDIRECT_URI", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			field := plugin.TValue[bool]{}
			got, err := boolProperty(props, tc.key, &field)
			if err != nil {
				t.Fatalf("boolProperty returned %v", err)
			}
			if got != tc.want {
				t.Errorf("value = %v, want %v", got, tc.want)
			}
			isNull := field.State&plugin.StateIsNull != 0
			if isNull != tc.wantNull {
				t.Errorf("null = %v, want %v", isNull, tc.wantNull)
			}
		})
	}
}

func TestIntProperty(t *testing.T) {
	props := map[string]string{
		"OAUTH_REFRESH_TOKEN_VALIDITY": " 7776000 ",
		"OAUTH_CLIENT_TYPE":            "CONFIDENTIAL",
	}

	field := plugin.TValue[int64]{}
	got, err := intProperty(props, "OAUTH_REFRESH_TOKEN_VALIDITY", &field)
	if err != nil || got != 7776000 {
		t.Fatalf("value = (%d, %v), want (7776000, nil)", got, err)
	}
	if field.State&plugin.StateIsNull != 0 {
		t.Error("a readable integer was marked null")
	}

	// A property that is present but not a number is unknown, not zero. Zero
	// would read as a refresh token that expires immediately.
	field = plugin.TValue[int64]{}
	got, err = intProperty(props, "OAUTH_CLIENT_TYPE", &field)
	if err != nil || got != 0 {
		t.Fatalf("unreadable value = (%d, %v), want (0, nil)", got, err)
	}
	if field.State&plugin.StateIsNull == 0 {
		t.Error("a value that is not an integer was reported as 0 rather than null")
	}

	field = plugin.TValue[int64]{}
	if _, err := intProperty(props, "MISSING", &field); err != nil {
		t.Fatalf("absent property returned %v", err)
	}
	if field.State&plugin.StateIsNull == 0 {
		t.Error("an absent integer property was reported as 0 rather than null")
	}
}

func TestListPropertyAbsentIsNull(t *testing.T) {
	props := map[string]string{"BLOCKED_ROLES_LIST": "ACCOUNTADMIN,SECURITYADMIN"}

	field := plugin.TValue[[]any]{}
	got, err := listProperty(props, "BLOCKED_ROLES_LIST", &field)
	if err != nil {
		t.Fatalf("listProperty returned %v", err)
	}
	if !reflect.DeepEqual(got, []any{"ACCOUNTADMIN", "SECURITYADMIN"}) {
		t.Errorf("value = %#v", got)
	}
	if field.State&plugin.StateIsNull != 0 {
		t.Error("a present list was marked null")
	}

	// An absent list has to stay null. An empty list would satisfy
	// "no privileged role is blocked from this integration" without evidence.
	field = plugin.TValue[[]any]{}
	got, err = listProperty(props, "EXTERNAL_OAUTH_ALLOWED_ROLES_LIST", &field)
	if err != nil || got != nil {
		t.Fatalf("absent list = (%#v, %v), want (nil, nil)", got, err)
	}
	if field.State&plugin.StateIsNull == 0 {
		t.Error("an absent list property was reported as an empty list rather than null")
	}
}
