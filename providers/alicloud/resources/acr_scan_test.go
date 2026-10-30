// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	crclient "github.com/alibabacloud-go/cr-20181201/v3/client"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestAcrScanComplete(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"COMPLETE", true},
		{"complete", true},
		{" COMPLETE ", true},
		// a scan still running has produced no findings yet
		{"SCANNING", false},
		{"RETRYING", false},
		// a failed scan produced nothing, which is not the same as clean
		{"FAILED", false},
		// never scanned, or the status could not be read
		{"", false},
	}
	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			assert.Equal(t, test.expected, acrScanComplete(test.status))
		})
	}
}

// acrTestVuln builds a vulnerability resource with only the member the tally
// reads.
func acrTestVuln(severity string) *mqlAlicloudAcrVulnerability {
	return &mqlAlicloudAcrVulnerability{
		Severity: plugin.TValue[string]{Data: severity, State: plugin.StateIsSet},
	}
}

func TestAcrSeverityCounts(t *testing.T) {
	t.Run("clean image", func(t *testing.T) {
		counts := acrSeverityCounts([]any{})
		assert.Equal(t, int64(0), counts["high"])
		assert.Empty(t, counts)
	})

	t.Run("tallies by severity, case insensitively", func(t *testing.T) {
		counts := acrSeverityCounts([]any{
			acrTestVuln("High"),
			acrTestVuln("high"),
			acrTestVuln("HIGH"),
			acrTestVuln("Medium"),
			acrTestVuln("Low"),
		})
		assert.Equal(t, int64(3), counts["high"])
		assert.Equal(t, int64(1), counts["medium"])
		assert.Equal(t, int64(1), counts["low"])
	})

	t.Run("unrated findings are counted, not dropped", func(t *testing.T) {
		counts := acrSeverityCounts([]any{
			acrTestVuln(""),
			acrTestVuln("   "),
			acrTestVuln("Unknown"),
		})
		assert.Equal(t, int64(3), counts["unknown"])
	})

	t.Run("non-vulnerability entries are ignored", func(t *testing.T) {
		counts := acrSeverityCounts([]any{"not a finding", nil, acrTestVuln("High")})
		assert.Equal(t, int64(1), counts["high"])
		assert.Len(t, counts, 1)
	})
}

// TestAcrVulnerabilityIDSeparatesPackages pins the dimensions the cache key has
// to carry. A scan row is one CVE in one package, so the same CveName recurs
// across packages, versions, layers and paths. Any pair below that collapsed to
// a single key would be dropped by the runtime cache and never reported, which
// is a silent under-report on a vulnerability list.
func TestAcrVulnerabilityIDSeparatesPackages(t *testing.T) {
	base := func() *crclient.ListRepoTagScanResultResponseBodyVulnerabilities {
		return &crclient.ListRepoTagScanResultResponseBodyVulnerabilities{
			CveName:     new("CVE-2021-3711"),
			Feature:     new("openssl"),
			Version:     new("1.1.1k-1"),
			AddedBy:     new("sha256:aaaa"),
			CveLocation: new("/usr/lib/libssl.so.1.1"),
		}
	}

	tests := []struct {
		name   string
		mutate func(*crclient.ListRepoTagScanResultResponseBodyVulnerabilities)
	}{
		{"different package", func(v *crclient.ListRepoTagScanResultResponseBodyVulnerabilities) {
			v.Feature = new("libssl-dev")
		}},
		{"different package version", func(v *crclient.ListRepoTagScanResultResponseBodyVulnerabilities) {
			v.Version = new("1.1.1n-2")
		}},
		{"different image layer", func(v *crclient.ListRepoTagScanResultResponseBodyVulnerabilities) {
			v.AddedBy = new("sha256:bbbb")
		}},
		{"different location", func(v *crclient.ListRepoTagScanResultResponseBodyVulnerabilities) {
			v.CveLocation = new("/opt/app/libssl.so.1.1")
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := base()
			test.mutate(other)
			assert.NotEqual(t,
				acrVulnerabilityID("repo-1", "latest", base()),
				acrVulnerabilityID("repo-1", "latest", other),
				"the same CVE must not share a key across this dimension")
		})
	}
}

// TestAcrVulnerabilityIDIsStable checks the other direction: two readings of the
// same finding must collapse, so a repeated row is deduplicated rather than
// double counted, and the key does not change between scans.
func TestAcrVulnerabilityIDIsStable(t *testing.T) {
	v := &crclient.ListRepoTagScanResultResponseBodyVulnerabilities{
		CveName:     new("CVE-2009-5155"),
		Feature:     new("eglibc"),
		Version:     new("2.19-6.9"),
		AddedBy:     new("sha256:cccc"),
		CveLocation: new("/lib/x86_64-linux-gnu/libc.so.6"),
	}
	assert.Equal(t, acrVulnerabilityID("repo-1", "v1", v), acrVulnerabilityID("repo-1", "v1", v))

	// the repository and tag stay part of the identity, so the same finding in
	// a second image is a second finding
	assert.NotEqual(t, acrVulnerabilityID("repo-1", "v1", v), acrVulnerabilityID("repo-2", "v1", v))
	assert.NotEqual(t, acrVulnerabilityID("repo-1", "v1", v), acrVulnerabilityID("repo-1", "v2", v))
}

// TestAcrVulnerabilityIDToleratesAbsentFields checks that a row missing the
// optional discriminators still produces a key rather than panicking, since
// every field but CveName is nullable in the API.
func TestAcrVulnerabilityIDToleratesAbsentFields(t *testing.T) {
	sparse := &crclient.ListRepoTagScanResultResponseBodyVulnerabilities{
		CveName: new("CVE-2020-0001"),
	}
	assert.NotEmpty(t, acrVulnerabilityID("repo-1", "latest", sparse))
	assert.NotEqual(t,
		acrVulnerabilityID("repo-1", "latest", sparse),
		acrVulnerabilityID("repo-1", "latest", &crclient.ListRepoTagScanResultResponseBodyVulnerabilities{
			CveName: new("CVE-2020-0002"),
		}))
}
