// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestVulnmgmtSoftFailsWhenReportUnavailable(t *testing.T) {
	v := &mqlVulnmgmt{MqlRuntime: &plugin.Runtime{}}

	cves := v.GetCves()
	require.NoError(t, cves.Error)
	assert.True(t, cves.IsSet())
	assert.False(t, cves.IsNull())
	assert.Len(t, cves.Data, 0)

	advisories := v.GetAdvisories()
	require.NoError(t, advisories.Error)
	assert.Len(t, advisories.Data, 0)

	packages := v.GetPackages()
	require.NoError(t, packages.Error)
	assert.Len(t, packages.Data, 0)

	stats := v.GetStats()
	require.NoError(t, stats.Error)
	assert.True(t, stats.IsSet())
	assert.True(t, stats.IsNull())

	lastAssessment := v.GetLastAssessment()
	require.NoError(t, lastAssessment.Error)
	assert.True(t, lastAssessment.IsSet())
	assert.True(t, lastAssessment.IsNull())

	assert.True(t, v.warnedUnavailable)
}

func TestVulnPackageID(t *testing.T) {
	// Every vuln.package must produce a distinct, stable __id from its name and
	// version. Without this id() method they would all share the empty cache
	// key and collapse onto the first package (see the id() doc comment).
	pkg := func(name, version string) *mqlVulnPackage {
		return &mqlVulnPackage{
			Name:    plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
			Version: plugin.TValue[string]{Data: version, State: plugin.StateIsSet},
		}
	}

	id, err := pkg("openssl", "1.1.1k").id()
	require.NoError(t, err)
	assert.Equal(t, "openssl-1.1.1k", id)

	// distinct packages must not collide
	other, err := pkg("glibc", "2.34").id()
	require.NoError(t, err)
	assert.NotEqual(t, id, other)

	// same name, different version stays distinct
	v1, _ := pkg("kernel", "5.10.1").id()
	v2, _ := pkg("kernel", "5.10.2").id()
	assert.NotEqual(t, v1, v2)
}
