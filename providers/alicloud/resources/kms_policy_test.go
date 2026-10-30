// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcsAccountID(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{"kms key arn", "acs:kms:cn-hangzhou:123456789:key/key-hzz6304", "123456789"},
		{"ram root", "acs:ram::123456789:root", "123456789"},
		{"whitespace tolerated", "  acs:kms:cn-hangzhou:123456789:key/k  ", "123456789"},
		// a wildcarded account names no account, so it must not be compared
		// against the key's own
		{"wildcard account", "acs:kms:cn-hangzhou:*:key/k", ""},
		{"not an acs name", "123456789", ""},
		{"truncated", "acs:kms:cn-hangzhou", ""},
		{"empty", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, acsAccountID(test.arn))
		})
	}
}

func TestKmsPolicyPrincipalAccountID(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		expected  string
	}{
		{"acs ram form", "acs:ram::119285303511:*", "119285303511"},
		{"bare account id", "119285303511", "119285303511"},
		{"padded bare account id", " 119285303511 ", "119285303511"},
		// the wildcard is reported by hasWildcardPrincipal, not as an account
		{"wildcard", "*", ""},
		{"empty", "", ""},
		{"service principal", "ecs.aliyuncs.com", ""},
		{"non-numeric", "acs:ram::abc:*", "abc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, kmsPolicyPrincipalAccountID(test.principal))
		})
	}
}

// mustParsePolicy decodes a policy document for the tests below.
func mustParsePolicy(t *testing.T, doc string) []policyStatement {
	t.Helper()
	parsed, err := parsePolicyDocument(doc)
	require.NoError(t, err)
	return parsed
}

// kmsDefaultPolicy is the shape KMS attaches to a key by default: the key's own
// account, and nobody else.
const kmsDefaultPolicy = `{
  "Version": "1",
  "Statement": [
    {
      "Sid": "kms-default-policy",
      "Effect": "Allow",
      "Principal": {"RAM": ["acs:ram::119285303511:*"]},
      "Action": ["kms:*"],
      "Resource": ["*"]
    }
  ]
}`

func TestKmsExternalAccountIDs(t *testing.T) {
	t.Run("default policy grants nobody outside", func(t *testing.T) {
		parsed := mustParsePolicy(t, kmsDefaultPolicy)
		assert.Empty(t, kmsExternalAccountIDs(parsed, "119285303511"))
	})

	t.Run("foreign account is reported", func(t *testing.T) {
		parsed := mustParsePolicy(t, `{
          "Statement": [
            {"Effect":"Allow","Principal":{"RAM":["acs:ram::119285303511:*","acs:ram::999999999:root"]},"Action":["kms:Decrypt"]}
          ]
        }`)
		assert.Equal(t, []string{"999999999"}, kmsExternalAccountIDs(parsed, "119285303511"))
	})

	t.Run("bare account ids are attributed", func(t *testing.T) {
		parsed := mustParsePolicy(t, `{"Statement":[{"Effect":"Allow","Principal":["999999999"],"Action":["kms:Decrypt"]}]}`)
		assert.Equal(t, []string{"999999999"}, kmsExternalAccountIDs(parsed, "119285303511"))
	})

	t.Run("denying statements withdraw rather than grant", func(t *testing.T) {
		parsed := mustParsePolicy(t, `{"Statement":[{"Effect":"Deny","Principal":{"RAM":["acs:ram::999999999:root"]}}]}`)
		assert.Empty(t, kmsExternalAccountIDs(parsed, "119285303511"))
	})

	t.Run("unknown own account classifies nothing", func(t *testing.T) {
		// guessing would report the account's own default policy as a
		// cross-account grant on every key whose ARN could not be read
		parsed := mustParsePolicy(t, kmsDefaultPolicy)
		assert.Empty(t, kmsExternalAccountIDs(parsed, ""))
	})

	t.Run("wildcard is not an account", func(t *testing.T) {
		parsed := mustParsePolicy(t, `{"Statement":[{"Effect":"Allow","Principal":{"RAM":"*"}}]}`)
		assert.Empty(t, kmsExternalAccountIDs(parsed, "119285303511"))
		// it is instead reported by the wildcard predicate
		assert.True(t, policyGrantsAnonymousAccess(parsed))
	})

	t.Run("duplicates collapse and the list is sorted", func(t *testing.T) {
		parsed := mustParsePolicy(t, `{
          "Statement": [
            {"Effect":"Allow","Principal":{"RAM":["acs:ram::333:root","acs:ram::222:root"]}},
            {"Effect":"Allow","Principal":{"RAM":["acs:ram::222:user/a"]}}
          ]
        }`)
		assert.Equal(t, []string{"222", "333"}, kmsExternalAccountIDs(parsed, "111"))
	})

	t.Run("unreadable policy grants nothing", func(t *testing.T) {
		// an empty document must not be reported as a grant
		parsed := mustParsePolicy(t, "")
		assert.Empty(t, kmsExternalAccountIDs(parsed, "119285303511"))
		assert.False(t, policyGrantsAnonymousAccess(parsed))
	})
}
