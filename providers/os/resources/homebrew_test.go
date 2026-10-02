// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/utils/syncx"
)

// A listing that cannot tell whether a newer version exists reports outdated
// as null, so homebrew.packages.list.none(outdated) no longer passes on a
// guess.
func TestHomebrewOutdatedUnknownIsNull(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	create := func(pkg packages.HomebrewPackage) *mqlHomebrewPackage {
		res, err := CreateResource(runtime, "homebrew.package", map[string]*llx.RawData{
			"__id":     llx.StringData("homebrew.package/formula/" + pkg.Name),
			"name":     llx.StringData(pkg.Name),
			"outdated": brewOutdated(pkg),
		})
		require.NoError(t, err)
		return res.(*mqlHomebrewPackage)
	}

	unknown := create(packages.HomebrewPackage{Name: "hello", OutdatedUnknown: true})
	assert.True(t, unknown.Outdated.IsNull())

	known := create(packages.HomebrewPackage{Name: "jq", Outdated: false})
	assert.False(t, known.Outdated.IsNull())
	assert.False(t, known.Outdated.Data)

	outdated := create(packages.HomebrewPackage{Name: "g03hello", Outdated: true})
	assert.True(t, outdated.Outdated.Data)
}
