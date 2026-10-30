// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnyAddressInList(t *testing.T) {
	cases := []struct {
		name      string
		addresses []any
		want      bool
	}{
		{"empty list allows nothing", []any{}, false},
		{"specific CIDRs only", []any{"10.0.0.0/8", "203.0.113.5/32"}, false},
		{"any-address IPv4", []any{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"any-address IPv6", []any{"::/0"}, true},
		{"non-string entries are skipped", []any{42, nil, "0.0.0.0/0"}, true},
		{"only non-string entries", []any{42, nil}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, anyAddressInList(c.addresses))
		})
	}
}

// parsePolicy decodes a bucket policy the way newSpacesBucket does, so the
// tests exercise the same shapes the resource actually stores.
func parsePolicy(t *testing.T, raw string) any {
	t.Helper()
	var parsed any
	require.NoError(t, json.Unmarshal([]byte(raw), &parsed))
	return parsed
}

func TestSpacesPolicyGrantsWildcard(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		want   bool
	}{
		{
			name:   "wildcard principal as a bare string",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`,
			want:   true,
		},
		{
			name:   "wildcard principal under the AWS key",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`,
			want:   true,
		},
		{
			name:   "wildcard principal in an AWS list",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root","*"]}}]}`,
			want:   true,
		},
		{
			name:   "a single statement object rather than a list",
			policy: `{"Statement":{"Effect":"Allow","Principal":"*"}}`,
			want:   true,
		},
		{
			name:   "lowercase effect still matches",
			policy: `{"Statement":[{"Effect":"allow","Principal":"*"}]}`,
			want:   true,
		},
		{
			name:   "named principal is not a wildcard",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"}}]}`,
			want:   false,
		},
		{
			name:   "wildcard on a Deny statement does not grant access",
			policy: `{"Statement":[{"Effect":"Deny","Principal":"*"}]}`,
			want:   false,
		},
		{
			name:   "no statements",
			policy: `{"Version":"2012-10-17"}`,
			want:   false,
		},
		{
			name:   "statement entries of the wrong shape are skipped",
			policy: `{"Statement":["not-a-statement",{"Effect":"Allow","Principal":"*"}]}`,
			want:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, spacesPolicyGrantsWildcard(parsePolicy(t, c.policy)))
		})
	}

	t.Run("an unparseable policy is stored as a string and grants nothing", func(t *testing.T) {
		assert.False(t, spacesPolicyGrantsWildcard("not json"))
	})

	t.Run("a missing policy grants nothing", func(t *testing.T) {
		assert.False(t, spacesPolicyGrantsWildcard(nil))
	})
}

func TestOpenWhiskWebUrl(t *testing.T) {
	const host = "https://faas-nyc1-2ef2e6cc.doserverless.co"

	t.Run("packaged action", func(t *testing.T) {
		assert.Equal(t,
			host+"/api/v1/web/fn-abc/mypkg/hello",
			openWhiskWebUrl(host, "fn-abc", "mypkg", "hello", true))
	})

	t.Run("unpackaged action falls into the default package", func(t *testing.T) {
		assert.Equal(t,
			host+"/api/v1/web/fn-abc/default/hello",
			openWhiskWebUrl(host, "fn-abc", "", "hello", true))
	})

	t.Run("a trailing slash on the API host is not doubled", func(t *testing.T) {
		assert.Equal(t,
			host+"/api/v1/web/fn-abc/default/hello",
			openWhiskWebUrl(host+"/", "fn-abc", "", "hello", true))
	})

	t.Run("an action that is not web-exported has no endpoint", func(t *testing.T) {
		assert.Empty(t, openWhiskWebUrl(host, "fn-abc", "mypkg", "hello", false))
	})

	t.Run("missing host or namespace yields no endpoint", func(t *testing.T) {
		assert.Empty(t, openWhiskWebUrl("", "fn-abc", "", "hello", true))
		assert.Empty(t, openWhiskWebUrl(host, "", "", "hello", true))
	})
}

func TestAsSlice(t *testing.T) {
	assert.Nil(t, asSlice(nil))
	assert.Equal(t, []any{"a", "b"}, asSlice([]any{"a", "b"}))
	assert.Equal(t, []any{"a"}, asSlice("a"))
	assert.Equal(t, []any{}, asSlice([]any{}))
}
