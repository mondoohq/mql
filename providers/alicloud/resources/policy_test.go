// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParsePolicyDocument covers the shape variance the policy grammar allows.
// Every list-valued member may arrive as a bare string, Statement may be a lone
// object, and Principal takes three different shapes depending on whether the
// document is a RAM permission policy, a role trust policy, or a bucket policy.
func TestParsePolicyDocument(t *testing.T) {
	t.Run("empty document yields no statements", func(t *testing.T) {
		got, err := parsePolicyDocument("")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("whitespace-only document yields no statements", func(t *testing.T) {
		got, err := parsePolicyDocument("   \n ")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("malformed JSON errors rather than reporting an empty policy", func(t *testing.T) {
		_, err := parsePolicyDocument("{not json")
		require.Error(t, err)
	})

	t.Run("scalar Action and Resource widen to lists", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"*"}, got[0].Action)
		assert.Equal(t, []string{"*"}, got[0].Resource)
	})

	t.Run("array Action and Resource are preserved", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":["oss:GetObject","oss:PutObject"],"Resource":["acs:oss:*:*:bucket/*"]}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"oss:GetObject", "oss:PutObject"}, got[0].Action)
		assert.Equal(t, []string{"acs:oss:*:*:bucket/*"}, got[0].Resource)
	})

	t.Run("a lone Statement object parses as one statement", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Version":"1","Statement":{"Effect":"Deny","Action":"ram:*","Resource":"*"}}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "Deny", got[0].Effect)
		assert.False(t, got[0].isAllow())
	})

	t.Run("NotAction and NotResource are captured", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","NotAction":"ram:*","NotResource":["acs:ram:*:*:*"]}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"ram:*"}, got[0].NotAction)
		assert.Equal(t, []string{"acs:ram:*:*:*"}, got[0].NotResource)
		assert.Empty(t, got[0].Action)
	})

	t.Run("Condition survives as a nested map", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"acs:SourceVpc":["vpc-1"]}}}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Contains(t, got[0].Condition, "StringEquals")
		inner, ok := got[0].Condition["StringEquals"].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, inner, "acs:SourceVpc")
	})

	t.Run("keyed Principal parses as a RAM trust policy", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"RAM":["acs:ram::123:root"],"Service":"ecs.aliyuncs.com"}}],"Version":"1"}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"acs:ram::123:root"}, got[0].Principal["RAM"])
		assert.Equal(t, []string{"ecs.aliyuncs.com"}, got[0].Principal["Service"])
	})

	t.Run("bare Principal array lands under the empty key", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Principal":["*"],"Resource":["acs:oss:*:123:bucket/*"]}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"*"}, got[0].Principal[""])
	})

	t.Run("scalar Principal lands under the empty key", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":"oss:GetObject","Principal":"*"}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"*"}, got[0].Principal[""])
	})

	t.Run("lowercase effect still reads as a grant", func(t *testing.T) {
		got, err := parsePolicyDocument(`{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.True(t, got[0].isAllow())
	})
}

// TestGrantsAllActions checks that only the bare wildcard counts as every
// action. A service wildcard is broad but not administrative.
func TestGrantsAllActions(t *testing.T) {
	assert.True(t, grantsAllActions([]string{"*"}))
	assert.True(t, grantsAllActions([]string{"oss:GetObject", "*"}))
	assert.False(t, grantsAllActions([]string{"oss:*"}))
	assert.False(t, grantsAllActions([]string{"ecs:Describe*"}))
	assert.False(t, grantsAllActions(nil))
}

// TestGrantsAllResources checks the ACS resource-name forms. Only a fully
// wildcarded name covers every resource; narrowing any segment does not.
func TestGrantsAllResources(t *testing.T) {
	assert.True(t, grantsAllResources([]string{"*"}))
	assert.True(t, grantsAllResources([]string{"acs:*:*:*:*"}))
	assert.True(t, grantsAllResources([]string{"acs:*"}))
	assert.False(t, grantsAllResources([]string{"acs:oss:*:*:*"}))
	assert.False(t, grantsAllResources([]string{"acs:oss:*:*:bucket/*"}))
	assert.False(t, grantsAllResources(nil))
}

// TestPolicyAllowsAdminAccess pins the definition of an administrative grant:
// Allow, every action, every resource, and no exception carved out of it.
func TestPolicyAllowsAdminAccess(t *testing.T) {
	parse := func(t *testing.T, doc string) []policyStatement {
		t.Helper()
		got, err := parsePolicyDocument(doc)
		require.NoError(t, err)
		return got
	}

	t.Run("the AdministratorAccess shape is admin", func(t *testing.T) {
		assert.True(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}],"Version":"1"}`)))
	})

	t.Run("a fully wildcarded ACS resource is admin", func(t *testing.T) {
		assert.True(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":["*"],"Effect":"Allow","Resource":["acs:*:*:*:*"]}]}`)))
	})

	t.Run("Deny on everything is not admin", func(t *testing.T) {
		assert.False(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"*","Effect":"Deny","Resource":"*"}]}`)))
	})

	t.Run("a service wildcard is not admin", func(t *testing.T) {
		assert.False(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"oss:*","Effect":"Allow","Resource":"*"}]}`)))
	})

	t.Run("every action on one service is not admin", func(t *testing.T) {
		assert.False(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"*","Effect":"Allow","Resource":"acs:oss:*:*:*"}]}`)))
	})

	t.Run("NotAction carves an exception, so it is not admin", func(t *testing.T) {
		assert.False(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"NotAction":"ram:*","Effect":"Allow","Resource":"*"}]}`)))
	})

	t.Run("a conditional grant is still admin wherever it applies", func(t *testing.T) {
		assert.True(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*","Condition":{"IpAddress":{"acs:SourceIp":["10.0.0.0/8"]}}}]}`)))
	})

	t.Run("one admin statement among many is enough", func(t *testing.T) {
		assert.True(t, policyAllowsAdminAccess(parse(t, `{"Statement":[{"Action":"oss:GetObject","Effect":"Allow","Resource":"acs:oss:*:*:b/*"},{"Action":"*","Effect":"Allow","Resource":"*"}]}`)))
	})
}

// TestResourceIsUnscoped pins the distinction that keeps the resource predicate
// useful: the region and account fields of an ACS name are wildcarded in almost
// every real policy, so only the relative-id decides whether a statement names
// a resource or a whole service.
func TestResourceIsUnscoped(t *testing.T) {
	t.Run("the bare wildcard is unscoped", func(t *testing.T) {
		assert.True(t, resourceIsUnscoped("*"))
	})
	t.Run("a wildcard relative-id is unscoped", func(t *testing.T) {
		assert.True(t, resourceIsUnscoped("acs:oss:*:*:*"))
		assert.True(t, resourceIsUnscoped("acs:ecs:cn-hangzhou:123456789:*"))
	})
	t.Run("a truncated name carries no relative-id", func(t *testing.T) {
		assert.True(t, resourceIsUnscoped("acs:*"))
	})
	t.Run("a named bucket is scoped even with wildcarded region and account", func(t *testing.T) {
		assert.False(t, resourceIsUnscoped("acs:oss:*:*:mybucket/*"))
		assert.False(t, resourceIsUnscoped("acs:oss:*:*:mybucket"))
	})
	t.Run("an empty region field does not shift the relative-id", func(t *testing.T) {
		assert.False(t, resourceIsUnscoped("acs:ram::123:user/alice"))
	})
	t.Run("a relative-id containing colons is kept whole", func(t *testing.T) {
		// the SplitN limit of 4 must not split inside the relative-id, which
		// would leave a bare "*" tail looking like a whole-service grant
		assert.False(t, resourceIsUnscoped("acs:ram::123:role/admin:extra"))
		assert.False(t, resourceIsUnscoped("acs:oss:*:*:bucket/prefix:*"))
	})
	t.Run("a non-ACS string is not a wildcard", func(t *testing.T) {
		assert.False(t, resourceIsUnscoped("mybucket"))
	})
}

// TestPolicyBreadthPredicates covers the two broad-grant predicates and their
// shared rule that a Deny statement never counts as a grant.
func TestPolicyBreadthPredicates(t *testing.T) {
	parse := func(t *testing.T, doc string) []policyStatement {
		t.Helper()
		got, err := parsePolicyDocument(doc)
		require.NoError(t, err)
		return got
	}

	t.Run("a prefix action wildcard counts, a named instance does not", func(t *testing.T) {
		stmts := parse(t, `{"Statement":[{"Action":"ecs:Describe*","Effect":"Allow","Resource":"acs:ecs:*:*:instance/i-1"}]}`)
		assert.True(t, policyHasWildcardAction(stmts))
		assert.False(t, policyHasUnscopedResource(stmts))
	})

	t.Run("a named bucket is scoped despite its object wildcard", func(t *testing.T) {
		stmts := parse(t, `{"Statement":[{"Action":"oss:GetObject","Effect":"Allow","Resource":"acs:oss:*:*:bucket/*"}]}`)
		assert.False(t, policyHasWildcardAction(stmts))
		assert.False(t, policyHasUnscopedResource(stmts))
	})

	t.Run("a whole-service grant is unscoped", func(t *testing.T) {
		stmts := parse(t, `{"Statement":[{"Action":["oss:GetObject"],"Effect":"Allow","Resource":["acs:oss:*:*:*"]}]}`)
		assert.True(t, policyHasUnscopedResource(stmts))
	})

	t.Run("wildcards under Deny do not count", func(t *testing.T) {
		stmts := parse(t, `{"Statement":[{"Action":"*","Effect":"Deny","Resource":"*"}]}`)
		assert.False(t, policyHasWildcardAction(stmts))
		assert.False(t, policyHasUnscopedResource(stmts))
	})

	t.Run("a fully enumerated grant is neither", func(t *testing.T) {
		stmts := parse(t, `{"Statement":[{"Action":["oss:GetObject"],"Effect":"Allow","Resource":["acs:oss:cn-hangzhou:123:mybucket/key"]}]}`)
		assert.False(t, policyHasWildcardAction(stmts))
		assert.False(t, policyHasUnscopedResource(stmts))
	})
}

// TestPolicyGrantsAnonymousAccess covers the bucket-policy case that decides
// whether an OSS bucket is readable without credentials.
func TestPolicyGrantsAnonymousAccess(t *testing.T) {
	parse := func(t *testing.T, doc string) []policyStatement {
		t.Helper()
		got, err := parsePolicyDocument(doc)
		require.NoError(t, err)
		return got
	}

	t.Run("a wildcard principal is anonymous", func(t *testing.T) {
		assert.True(t, policyGrantsAnonymousAccess(parse(t, `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Principal":["*"],"Resource":["acs:oss:*:123:b/*"]}]}`)))
	})

	t.Run("a named account principal is not anonymous", func(t *testing.T) {
		assert.False(t, policyGrantsAnonymousAccess(parse(t, `{"Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Principal":["123456789"],"Resource":["acs:oss:*:123:b/*"]}]}`)))
	})

	t.Run("a wildcard principal under Deny is not a grant", func(t *testing.T) {
		assert.False(t, policyGrantsAnonymousAccess(parse(t, `{"Statement":[{"Effect":"Deny","Action":["oss:*"],"Principal":["*"],"Resource":["acs:oss:*:123:b/*"]}]}`)))
	})

	t.Run("a wildcard under a keyed principal still counts", func(t *testing.T) {
		assert.True(t, policyGrantsAnonymousAccess(parse(t, `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"RAM":["*"]}}]}`)))
	})

	t.Run("no principal at all is not anonymous", func(t *testing.T) {
		assert.False(t, policyGrantsAnonymousAccess(parse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)))
	})
}
