// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/gql"
	"go.mondoo.com/mql/utils/syncx"
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

// TestPopulateFromReportSetsEveryCveField pins the compact-report mapping for
// managed assets: every vuln.cve field is set, including unscored, which used
// to be left unset. The report has no explicit unscored flag, so it is derived
// from the CVSS scores the report carries.
func TestPopulateFromReportSetsEveryCveField(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	v := &mqlVulnmgmt{MqlRuntime: runtime}

	scored := &gql.Cve{
		Id:          "CVE-2026-32177",
		Summary:     ".NET Framework cumulative update",
		State:       "PUBLIC",
		PublishedAt: "2026-08-11T07:00:00Z",
		ModifiedAt:  "2026-08-20T07:00:00Z",
	}
	scored.CvssScore.Value = 73
	scored.CvssScore.Vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"

	// Only an individual score carries the vector; the CVE is still scored.
	scoredByList := &gql.Cve{Id: "CVE-2024-0003", State: "PUBLIC"}
	scoredByList.CvssScores = append(scoredByList.CvssScores, scored.CvssScore)

	// No score anywhere and no modification date: unscored, modified null.
	unscored := &gql.Cve{Id: "CVE-2024-0001", State: "RESERVED", PublishedAt: "2024-01-02T03:04:05Z"}

	report := &gql.VulnReport{
		Cves:  []*gql.Cve{scored, scoredByList, unscored},
		Stats: &gql.ReportStats{},
	}
	require.NoError(t, v.populateFromReport(report))
	require.Len(t, v.Cves.Data, 3)

	want := map[string]bool{
		"CVE-2026-32177": false,
		"CVE-2024-0003":  false,
		"CVE-2024-0001":  true,
	}
	for _, c := range v.Cves.Data {
		cve := c.(*mqlVulnCve)
		for name, set := range map[string]bool{
			"id":         cve.Id.IsSet(),
			"state":      cve.State.IsSet(),
			"summary":    cve.Summary.IsSet(),
			"unscored":   cve.Unscored.IsSet(),
			"published":  cve.Published.IsSet(),
			"modified":   cve.Modified.IsSet(),
			"worstScore": cve.WorstScore.IsSet(),
		} {
			assert.True(t, set, "%s not set for %s", name, cve.Id.Data)
		}
		assert.Equal(t, want[cve.Id.Data], cve.Unscored.Data, cve.Id.Data)
	}

	first := v.Cves.Data[0].(*mqlVulnCve)
	require.NotNil(t, first.Modified.Data)
	assert.Equal(t, "2026-08-20T07:00:00Z", first.Modified.Data.UTC().Format(time.RFC3339))
	last := v.Cves.Data[2].(*mqlVulnCve)
	assert.True(t, last.Modified.IsNull())
}
