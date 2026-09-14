// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/fex"
	"go.mondoo.com/mql/utils/syncx"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestPopulateFromVex asserts the VEX -> vuln.* mapping preserves every field
// the compact-report path populated, so existing policies keep resolving. It
// feeds a fixed set of VEX documents and checks the resulting resources.
func TestPopulateFromVex(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	v := &mqlVulnmgmt{MqlRuntime: runtime}

	published := timestamppb.New(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))
	updated := timestamppb.New(time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC))

	vex := []*fex.VulnerabilityExchange{
		{
			Id:      "CVE-2024-3094",
			Summary: "malicious code in liblzma",
			Status:  fex.Status_STATUS_AFFECTED,
			Details: &fex.VulnerabilityDetails{
				Details:   "a backdoor was introduced into the build",
				Published: published,
				Updated:   updated,
			},
			Ratings: []*fex.Rating{
				{Score: 6.5, Vector: "CVSS:3.1/AV:L", Severity: "medium"},
				{Score: 10.0, Vector: "CVSS:3.1/AV:N/AC:L", Severity: "critical"},
			},
			Affects: []*fex.Affects{
				{
					SubComponents: []*fex.Component{
						{
							Id: "liblzma5",
							Identifiers: map[string]string{
								"purl":          "pkg:deb/debian/liblzma5@5.6.0",
								"version":       "5.6.0",
								"arch":          "amd64",
								"fixed_version": "5.6.2",
							},
						},
					},
				},
			},
		},
		{
			Id:      "USN-1234-1",
			Summary: "vendor advisory for liblzma",
			Status:  fex.Status_STATUS_FIXED,
			Details: &fex.VulnerabilityDetails{Details: "upgrade the package"},
			Ratings: []*fex.Rating{{Score: 7.5, Vector: "CVSS:3.1/AV:N"}},
		},
		// Skipped: an entry with no id must never produce a resource.
		{Id: ""},
	}

	require.NoError(t, v.populateFromVex(vex))

	// CVE ids route to vuln.cve; every field maps.
	require.Len(t, v.Cves.Data, 1)
	cve := v.Cves.Data[0].(*mqlVulnCve)
	assert.Equal(t, "CVE-2024-3094", cve.Id.Data)
	assert.Equal(t, "AFFECTED", cve.State.Data)
	assert.Equal(t, "malicious code in liblzma", cve.Summary.Data)
	require.NotNil(t, cve.Published.Data)
	assert.Equal(t, published.AsTime(), *cve.Published.Data)
	require.NotNil(t, cve.Modified.Data)
	assert.Equal(t, updated.AsTime(), *cve.Modified.Data)
	// Worst score picks the most severe rating (10.0), used directly on the
	// 0..10 scale.
	require.NotNil(t, cve.WorstScore.Data)
	assert.Equal(t, 10.0, cve.WorstScore.Data.Score.Data)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L", cve.WorstScore.Data.Vector.Data)

	// Non-CVE ids route to vuln.advisory.
	require.Len(t, v.Advisories.Data, 1)
	adv := v.Advisories.Data[0].(*mqlVulnAdvisory)
	assert.Equal(t, "USN-1234-1", adv.Id.Data)
	assert.Equal(t, "vendor advisory for liblzma", adv.Title.Data)
	assert.Equal(t, "upgrade the package", adv.Description.Data)

	// Affected components become PURL-native vuln.package entries; the fixed
	// version becomes the available upgrade target.
	require.Len(t, v.Packages.Data, 1)
	pkg := v.Packages.Data[0].(*mqlVulnPackage)
	assert.Equal(t, "debian/liblzma5", pkg.Name.Data)
	assert.Equal(t, "5.6.0", pkg.Version.Data)
	assert.Equal(t, "5.6.2", pkg.Available.Data)
	assert.Equal(t, "amd64", pkg.Arch.Data)

	// Rolled-up stats carry the worst score across all findings.
	require.NotNil(t, v.Stats.Data)
	assert.Equal(t, 10.0, v.Stats.Data.Score.Data)
}

// TestPopulateFromVexFixedVersionIsOrderIndependent guards the accuracy bug
// where two vulnerabilities affecting the same installed package with different
// fixed versions would let VEX ordering decide which upgrade target the user
// sees. A vuln.package's identity is name+version, so only one target can
// survive; the mapping aggregates and keeps the most conservative (highest)
// one, deterministically, regardless of input order.
func TestPopulateFromVexFixedVersionIsOrderIndependent(t *testing.T) {
	affected := func(fixedVersion string) []*fex.Affects {
		return []*fex.Affects{
			{
				SubComponents: []*fex.Component{
					{
						Id: "openssl",
						Identifiers: map[string]string{
							"purl":          "pkg:deb/debian/openssl@1.0.0",
							"version":       "1.0.0",
							"arch":          "amd64",
							"fixed_version": fixedVersion,
						},
					},
				},
			},
		}
	}

	// Note the segment ordering: 1.0.10 > 1.0.2 numerically, which a naive
	// lexical comparison would get wrong.
	lowFix := &fex.VulnerabilityExchange{
		Id:      "CVE-2024-0001",
		Summary: "first flaw in openssl",
		Ratings: []*fex.Rating{{Score: 5.0, Vector: "CVSS:3.1/AV:N"}},
		Affects: affected("1.0.2"),
	}
	highFix := &fex.VulnerabilityExchange{
		Id:      "CVE-2024-0002",
		Summary: "second flaw in openssl",
		Ratings: []*fex.Rating{{Score: 8.0, Vector: "CVSS:3.1/AV:N"}},
		Affects: affected("1.0.10"),
	}

	availableTargets := func(vex []*fex.VulnerabilityExchange) []string {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		v := &mqlVulnmgmt{MqlRuntime: runtime}
		require.NoError(t, v.populateFromVex(vex))
		got := make([]string, 0, len(v.Packages.Data))
		for _, p := range v.Packages.Data {
			pkg := p.(*mqlVulnPackage)
			// ComponentCoords resolves the name from the PURL, so the debian
			// namespace is preserved.
			assert.Equal(t, "debian/openssl", pkg.Name.Data)
			assert.Equal(t, "1.0.0", pkg.Version.Data)
			got = append(got, pkg.Available.Data)
		}
		sort.Strings(got)
		return got
	}

	forward := availableTargets([]*fex.VulnerabilityExchange{lowFix, highFix})
	reverse := availableTargets([]*fex.VulnerabilityExchange{highFix, lowFix})

	// The package collapses to a single row carrying the most conservative
	// upgrade target, identical regardless of input order.
	assert.Equal(t, []string{"1.0.10"}, forward)
	assert.Equal(t, forward, reverse)
}

// TestCompareVersions exercises the deterministic, ecosystem-agnostic ordering
// used to pick the most conservative fixed version.
func TestCompareVersions(t *testing.T) {
	assert.Equal(t, 1, compareVersions("1.0.10", "1.0.2"), "numeric segments compare numerically")
	assert.Equal(t, -1, compareVersions("1.0.2", "1.0.10"))
	assert.Equal(t, 0, compareVersions("1.2.3", "1.2.3"))
	assert.Equal(t, 1, compareVersions("2.0", "1.9.9"))
	assert.Equal(t, "1.0.10", higherVersion("1.0.2", "1.0.10"))
	assert.Equal(t, "1.0.10", higherVersion("1.0.10", "1.0.2"))
	assert.Equal(t, "1.2.3", higherVersion("", "1.2.3"))
	assert.Equal(t, "1.2.3", higherVersion("1.2.3", ""))
}

// TestPopulateFromVexDropsHalfPopulatedComponent confirms a component missing a
// name or a version does not produce a malformed vuln.package.
func TestPopulateFromVexDropsHalfPopulatedComponent(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	v := &mqlVulnmgmt{MqlRuntime: runtime}

	vex := []*fex.VulnerabilityExchange{
		{
			Id:      "CVE-2024-9999",
			Summary: "component with no version",
			Ratings: []*fex.Rating{{Score: 5.0, Vector: "CVSS:3.1/AV:N"}},
			Affects: []*fex.Affects{
				{
					SubComponents: []*fex.Component{
						// name present, version empty -> must be dropped.
						{Id: "somepkg", Identifiers: map[string]string{"name": "somepkg"}},
					},
				},
			},
		},
	}

	require.NoError(t, v.populateFromVex(vex))
	assert.Len(t, v.Packages.Data, 0)
	// The vulnerability itself is still recorded.
	require.Len(t, v.Cves.Data, 1)
}

// TestPopulateFromVexDistinctCvssPerCve guards a cache-collision: two CVEs that
// share an identical score+vector must still get their own audit.cvss resource.
// The cvss id is scoped by the finding id, so CreateResource does not return one
// CVE's cached cvss instance for the other.
func TestPopulateFromVexDistinctCvssPerCve(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	v := &mqlVulnmgmt{MqlRuntime: runtime}

	rating := []*fex.Rating{{Score: 7.5, Vector: "CVSS:3.1/AV:N"}}
	vex := []*fex.VulnerabilityExchange{
		{Id: "CVE-2024-1111", Summary: "first", Ratings: rating},
		{Id: "CVE-2024-2222", Summary: "second", Ratings: rating},
	}

	require.NoError(t, v.populateFromVex(vex))
	require.Len(t, v.Cves.Data, 2)

	first := v.Cves.Data[0].(*mqlVulnCve).WorstScore.Data
	second := v.Cves.Data[1].(*mqlVulnCve).WorstScore.Data
	require.NotNil(t, first)
	require.NotNil(t, second)
	// Distinct resource instances despite identical score+vector.
	assert.NotSame(t, first, second)
	assert.Equal(t, 7.5, first.Score.Data)
	assert.Equal(t, 7.5, second.Score.Data)
}

// TestPopulateFromVexEmpty confirms an empty report yields set-but-empty lists
// (not an error, not null), matching the resource's soft contract.
func TestPopulateFromVexEmpty(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	v := &mqlVulnmgmt{MqlRuntime: runtime}

	require.NoError(t, v.populateFromVex(nil))

	assert.True(t, v.Cves.IsSet())
	assert.Len(t, v.Cves.Data, 0)
	assert.True(t, v.Advisories.IsSet())
	assert.Len(t, v.Advisories.Data, 0)
	assert.True(t, v.Packages.IsSet())
	assert.Len(t, v.Packages.Data, 0)
	require.NotNil(t, v.Stats.Data)
	assert.Equal(t, 0.0, v.Stats.Data.Score.Data)
}
