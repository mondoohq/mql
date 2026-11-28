// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAossPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, resource string
		want              bool
	}{
		{"collection/kb", "collection/kb", true},
		{"collection/kb", "collection/kb2", false},
		{"collection/kb*", "collection/kb", true},
		{"collection/kb*", "collection/kb-vectors", true},
		{"collection/kb*", "collection/other", false},
		{"collection/*", "collection/anything", true},
		{"*", "collection/anything", true},
		{"collection/*-prod", "collection/kb-prod", true},
		{"collection/*-prod", "collection/kb-dev", false},
		{"collection/a*a", "collection/a", false},
		{"collection/a*b*c", "collection/axbyc", true},
		{"collection/a*b*c", "collection/axcyb", false},
		{"collection/kb", "dashboard/kb", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, aossPatternMatches(c.pattern, c.resource), "%s vs %s", c.pattern, c.resource)
	}
}

func TestAossNetworkAccess(t *testing.T) {
	doc := mustJSON(t, `[
	  {"Rules":[{"ResourceType":"dashboard","Resource":["collection/kb"]}],"AllowFromPublic":true},
	  {"Rules":[{"ResourceType":"collection","Resource":["collection/kb*"]}],"AllowFromPublic":false,
	   "SourceServices":["bedrock.amazonaws.com"],"SourceVPCEs":["vpce-1"]},
	  {"Rules":[{"ResourceType":"collection","Resource":["collection/other"]}],"AllowFromPublic":true}
	]`)

	t.Run("private match, public dashboard rule ignored", func(t *testing.T) {
		var services, vpces stringSet
		matched, public := aossNetworkAccess(doc, "kb-vectors", &services, &vpces)
		assert.True(t, matched)
		assert.False(t, public)
		assert.Equal(t, []any{"bedrock.amazonaws.com"}, services.list())
		assert.Equal(t, []any{"vpce-1"}, vpces.list())
	})

	t.Run("public collection rule", func(t *testing.T) {
		var services, vpces stringSet
		matched, public := aossNetworkAccess(doc, "other", &services, &vpces)
		assert.True(t, matched)
		assert.True(t, public)
		assert.Equal(t, []any{}, services.list())
	})

	t.Run("no match", func(t *testing.T) {
		var services, vpces stringSet
		matched, public := aossNetworkAccess(doc, "unrelated", &services, &vpces)
		assert.False(t, matched)
		assert.False(t, public)
	})

	t.Run("single rule set document", func(t *testing.T) {
		single := mustJSON(t, `{"Rules":[{"ResourceType":"collection","Resource":"collection/*"}],"AllowFromPublic":true}`)
		var services, vpces stringSet
		matched, public := aossNetworkAccess(single, "kb", &services, &vpces)
		assert.True(t, matched)
		assert.True(t, public)
	})
}
