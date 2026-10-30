// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRamBoolValue(t *testing.T) {
	assert.True(t, ramBoolValue(new(true)))
	assert.False(t, ramBoolValue(new(false)))
	// an absent preference must not report a restriction nobody confirmed
	assert.False(t, ramBoolValue(nil))
}

func TestRamNetworkMasks(t *testing.T) {
	tests := []struct {
		name     string
		raw      *string
		expected []any
	}{
		{"single mask", new("10.0.0.0/8"), []any{"10.0.0.0/8"}},
		{
			"semicolon separated",
			new("10.0.0.0/8;192.0.2.0/24"),
			[]any{"10.0.0.0/8", "192.0.2.0/24"},
		},
		{"whitespace trimmed", new(" 10.0.0.0/8 ; 192.0.2.0/24 "), []any{"10.0.0.0/8", "192.0.2.0/24"}},
		{"trailing separator", new("10.0.0.0/8;"), []any{"10.0.0.0/8"}},
		// an unrestricted account yields an empty list, never a list holding ""
		{"unset", new(""), []any{}},
		{"absent", nil, []any{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, ramNetworkMasks(test.raw))
		})
	}
}

// mustParseTrust decodes a trust policy document for the tests below.
func mustParseTrust(t *testing.T, doc string) []policyStatement {
	t.Helper()
	parsed, err := parsePolicyDocument(doc)
	require.NoError(t, err)
	return parsed
}

const trustAssumedByAccountAndService = `{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "RAM": ["acs:ram::123456789:root", "acs:ram::987654321:user/deploy"],
        "Service": ["ecs.aliyuncs.com"]
      }
    }
  ]
}`

func TestRamTrustPrincipals(t *testing.T) {
	parsed := mustParseTrust(t, trustAssumedByAccountAndService)
	assert.Equal(t, []string{
		"acs:ram::123456789:root",
		"acs:ram::987654321:user/deploy",
		"ecs.aliyuncs.com",
	}, ramTrustPrincipals(parsed))
}

func TestRamTrustPrincipalsSkipsDeny(t *testing.T) {
	// a denying statement narrows the trust; listing its principals would
	// report identities that cannot assume the role
	parsed := mustParseTrust(t, `{
      "Statement": [
        {"Effect": "Allow", "Principal": {"RAM": "acs:ram::111:root"}},
        {"Effect": "Deny", "Principal": {"RAM": "acs:ram::222:root"}}
      ]
    }`)
	assert.Equal(t, []string{"acs:ram::111:root"}, ramTrustPrincipals(parsed))
	assert.Equal(t, []string{"111"}, ramTrustedAccountIDs(parsed))
}

func TestRamTrustPrincipalsOfKind(t *testing.T) {
	parsed := mustParseTrust(t, trustAssumedByAccountAndService)
	assert.Equal(t, []string{"ecs.aliyuncs.com"}, ramTrustPrincipalsOfKind(parsed, "Service"))
	// the grammar accepts either casing for the principal kind
	assert.Equal(t, []string{"ecs.aliyuncs.com"}, ramTrustPrincipalsOfKind(parsed, "service"))
	assert.Empty(t, ramTrustPrincipalsOfKind(parsed, "Federated"))
}

func TestRamPrincipalAccountID(t *testing.T) {
	tests := []struct {
		principal string
		expected  string
	}{
		{"acs:ram::123456789:root", "123456789"},
		{"acs:ram::123456789:user/deploy", "123456789"},
		{"  acs:ram::123456789:root  ", "123456789"},
		// not a RAM principal, so it names no account
		{"ecs.aliyuncs.com", ""},
		{"*", ""},
		{"", ""},
		{"acs:ram::*:root", ""},
		// truncated: no colon after the uid means no account can be read out
		{"acs:ram::123456789", ""},
	}
	for _, test := range tests {
		t.Run(test.principal, func(t *testing.T) {
			assert.Equal(t, test.expected, ramPrincipalAccountID(test.principal))
		})
	}
}

func TestRamTrustedAccountIDs(t *testing.T) {
	parsed := mustParseTrust(t, trustAssumedByAccountAndService)
	assert.Equal(t, []string{"123456789", "987654321"}, ramTrustedAccountIDs(parsed))

	t.Run("service-only trust names no account", func(t *testing.T) {
		parsed := mustParseTrust(t, `{"Statement":[{"Effect":"Allow","Principal":{"Service":"fc.aliyuncs.com"}}]}`)
		assert.Empty(t, ramTrustedAccountIDs(parsed))
	})

	t.Run("duplicate accounts collapse", func(t *testing.T) {
		parsed := mustParseTrust(t, `{"Statement":[{"Effect":"Allow","Principal":{"RAM":["acs:ram::111:root","acs:ram::111:user/a"]}}]}`)
		assert.Equal(t, []string{"111"}, ramTrustedAccountIDs(parsed))
	})
}

func TestRamTrustWildcardPrincipal(t *testing.T) {
	wildcard := mustParseTrust(t, `{"Statement":[{"Effect":"Allow","Principal":{"RAM":"*"}}]}`)
	assert.True(t, policyGrantsAnonymousAccess(wildcard))
	assert.Equal(t, []string{"*"}, ramTrustPrincipals(wildcard))
	// a wildcard names no account, so it must not be reported as one
	assert.Empty(t, ramTrustedAccountIDs(wildcard))

	scoped := mustParseTrust(t, trustAssumedByAccountAndService)
	assert.False(t, policyGrantsAnonymousAccess(scoped))
}

func TestRamTrustEmptyDocument(t *testing.T) {
	// a role whose document could not be read yields no statements and no
	// error, and every derived field must read as "nothing is trusted"
	parsed := mustParseTrust(t, "")
	assert.Empty(t, ramTrustPrincipals(parsed))
	assert.Empty(t, ramTrustedAccountIDs(parsed))
	assert.Empty(t, ramTrustPrincipalsOfKind(parsed, "Service"))
	assert.False(t, policyGrantsAnonymousAccess(parsed))
}

func TestPolicyPrincipalDict(t *testing.T) {
	t.Run("permission policy statement stays null", func(t *testing.T) {
		// a null principal, not an empty object: an empty object would read as
		// "the statement names principals and there are none"
		assert.Nil(t, policyPrincipalDict(nil))
		assert.Nil(t, policyPrincipalDict(map[string][]string{}))
	})

	t.Run("trust statement renders JSON-native values", func(t *testing.T) {
		got := policyPrincipalDict(map[string][]string{"RAM": {"acs:ram::111:root"}})
		assert.Equal(t, map[string]any{"RAM": []any{"acs:ram::111:root"}}, got)
	})
}

func TestStrsToAny(t *testing.T) {
	assert.Equal(t, []any{"a", "b"}, strsToAny([]string{"a", "b"}))
	assert.Equal(t, []any{}, strsToAny(nil))
}
