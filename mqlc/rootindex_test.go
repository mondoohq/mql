// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// rootIndex caches which roots carry a member so narrowing does not walk the
// whole schema per read (ADR 031). The cache answers for every read of that
// member, so narrowing must not mutate what it hands back.
func TestRootIndexIsNotMutatedByNarrowing(t *testing.T) {
	field := func(n string) map[string]*resources.Field {
		return map[string]*resources.Field{n: {Name: n, Type: string(types.String)}}
	}
	schema := &resources.Schema{
		ProviderRoots: map[string]string{"p": "p.any"},
		Resources: map[string]*resources.ResourceInfo{
			"p.base":    {Id: "p.base", Provider: "p", Root: true, Fields: field("hostname")},
			"p.linux":   {Id: "p.linux", Provider: "p", Root: true, Fields: field("hostname")},
			"p.windows": {Id: "p.windows", Provider: "p", Root: true, Fields: field("hostname")},
			"p.any":     {Id: "p.any", Provider: "p", Root: true, Fields: field("hostname")},
		},
	}
	// only linux carries this one
	schema.Resources["p.linux"].Fields["iptables"] = &resources.Field{Name: "iptables", Type: string(types.String)}

	c := &compiler{CompilerConfig: NewConfig(schema, mql.Features{})}
	idx := c.rootIdx()

	require.Len(t, idx.roots, 3, "the provider's declared union is not a candidate")

	universal := idx.carriersOf(schema, "hostname")
	require.Len(t, universal, 3)

	// narrow: every root carries hostname, only one carries iptables
	c.narrowRoots(schema.Resources["p.any"], "hostname")
	c.narrowRoots(schema.Resources["p.any"], "iptables")
	assert.Equal(t, map[string]struct{}{"p.linux": {}}, c.compatibleRoots)

	assert.Len(t, idx.carriersOf(schema, "hostname"), 3,
		"narrowing must not shrink the cached answer for a member every root carries")
}
