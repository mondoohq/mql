// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/datasafe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A COMPARTMENT-type assessment reports the same check once per target
// database, so the finding key alone collides across targets. CreateResource
// answers a repeated id with the cached first instance, which would make the
// second database report the first one's severity - and
// `findings.none(severity == "HIGH")` would pass on a database that has one.
func TestOciDataSafeFindingIDSeparatesTargets(t *testing.T) {
	assessment := "ocid1.datasafesecurityassessment.oc1..aaaa"

	first := ociDataSafeFindingID(assessment, "ocid1.datasafetargetdatabase.oc1..one", "ACCOUNT_DEFAULT_PWD")
	second := ociDataSafeFindingID(assessment, "ocid1.datasafetargetdatabase.oc1..two", "ACCOUNT_DEFAULT_PWD")

	assert.NotEqual(t, first, second)
	assert.Equal(t, assessment+"/ocid1.datasafetargetdatabase.oc1..one/ACCOUNT_DEFAULT_PWD", first)
}

// The same target is covered by a LATEST assessment and by every SAVED
// snapshot of it, so the assessment is the second dimension the key needs.
func TestOciDataSafeFindingIDSeparatesAssessments(t *testing.T) {
	target := "ocid1.datasafetargetdatabase.oc1..one"

	assert.NotEqual(t,
		ociDataSafeFindingID("ocid1.datasafesecurityassessment.oc1..latest", target, "ACCOUNT_DEFAULT_PWD"),
		ociDataSafeFindingID("ocid1.datasafesecurityassessment.oc1..saved", target, "ACCOUNT_DEFAULT_PWD"),
	)
}

func TestOciDataSafeFindingIDSeparatesChecks(t *testing.T) {
	assessment := "ocid1.datasafesecurityassessment.oc1..aaaa"
	target := "ocid1.datasafetargetdatabase.oc1..one"

	assert.NotEqual(t,
		ociDataSafeFindingID(assessment, target, "ACCOUNT_DEFAULT_PWD"),
		ociDataSafeFindingID(assessment, target, "AUDIT_TRAIL"),
	)
}

// A waiver is a finding in its own right: the risk Data Safe reported is still
// present, an operator has simply stopped it counting. Reading it as a genuine
// pass is the failure this guards.
func TestOciDataSafeFindingRiskAccepted(t *testing.T) {
	tests := []struct {
		name    string
		finding datasafe.FindingSummary
		want    bool
	}{
		{
			name: "waived by an operator",
			finding: datasafe.FindingSummary{
				IsRiskModified: new(true),
				Severity:       datasafe.FindingSummarySeverityPass,
			},
			want: true,
		},
		{
			// Data Safe graded this one a pass itself. It was never a risk, so
			// reporting it as an accepted one would count clean checks as
			// suppressed ones.
			name: "passed on its own merits",
			finding: datasafe.FindingSummary{
				IsRiskModified: new(false),
				Severity:       datasafe.FindingSummarySeverityPass,
			},
			want: false,
		},
		{
			// Modified, but not to a pass. Downgraded from HIGH to LOW is a
			// different thing from waived, and isRiskModified reports it.
			name: "downgraded but still a risk",
			finding: datasafe.FindingSummary{
				IsRiskModified: new(true),
				Severity:       datasafe.FindingSummarySeverityLow,
			},
			want: false,
		},
		{
			name:    "flag absent",
			finding: datasafe.FindingSummary{Severity: datasafe.FindingSummarySeverityPass},
			want:    false,
		},
		{
			name:    "empty finding",
			finding: datasafe.FindingSummary{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociDataSafeFindingRiskAccepted(tt.finding))
		})
	}
}

// A lapsed deferral still reads DEFERRED, which is why this is computed rather
// than a comparison the caller could write against severity: the severity says
// the finding was deferred, not that the deferral still applies.
func TestOciDataSafeFindingOpenDeferral(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sdkTime := func(t time.Time) *common.SDKTime { return &common.SDKTime{Time: t} }

	tests := []struct {
		name    string
		finding datasafe.FindingSummary
		want    bool
	}{
		{
			name: "deferred until a future date",
			finding: datasafe.FindingSummary{
				Severity:       datasafe.FindingSummarySeverityDeferred,
				TimeValidUntil: sdkTime(now.Add(24 * time.Hour)),
			},
			want: true,
		},
		{
			// No end date means the suppression never lapses, which is the
			// worst version of it rather than the absent one.
			name:    "deferred with no end date",
			finding: datasafe.FindingSummary{Severity: datasafe.FindingSummarySeverityDeferred},
			want:    true,
		},
		{
			name: "deferral has lapsed",
			finding: datasafe.FindingSummary{
				Severity:       datasafe.FindingSummarySeverityDeferred,
				TimeValidUntil: sdkTime(now.Add(-24 * time.Hour)),
			},
			want: false,
		},
		{
			// A validUntil on a non-deferred finding covers a plain severity
			// change, which is not a deferral.
			name: "modified severity with an end date",
			finding: datasafe.FindingSummary{
				Severity:       datasafe.FindingSummarySeverityLow,
				TimeValidUntil: sdkTime(now.Add(24 * time.Hour)),
			},
			want: false,
		},
		{
			name:    "not deferred",
			finding: datasafe.FindingSummary{Severity: datasafe.FindingSummarySeverityHigh},
			want:    false,
		},
		{
			name:    "empty finding",
			finding: datasafe.FindingSummary{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociDataSafeFindingOpenDeferral(tt.finding, now))
		})
	}
}

// A framework the check does not map to has to be absent from the map, so
// `references["gdpr"] != null` answers whether the check carries a GDPR
// section instead of always being true.
func TestOciDataSafeFindingReferences(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("absent block", func(t *testing.T) {
		assert.Empty(t, ociDataSafeFindingReferences(nil))
	})

	t.Run("empty sections dropped", func(t *testing.T) {
		got := ociDataSafeFindingReferences(&datasafe.References{
			Stig: str(""),
			Gdpr: str("Article 32"),
		})
		assert.Equal(t, map[string]any{"gdpr": "Article 32"}, got)
	})

	t.Run("every framework", func(t *testing.T) {
		got := ociDataSafeFindingReferences(&datasafe.References{
			Stig: str("V-1234"),
			Cis:  str("2.1"),
			Gdpr: str("Article 32"),
			Obp:  str("OBP-7"),
			Orp:  str("ORP-3"),
		})
		assert.Len(t, got, 5)
		assert.Equal(t, "V-1234", got["stig"])
		assert.Equal(t, "ORP-3", got["orp"])
	})
}

// Payload shaped after the ListFindings response. The security-relevant fields
// here are the two severities and the waiver flags, so a wrong reading is a
// finding reported at the wrong grade, or a suppressed one reported as clean.
func TestOciDataSafeFindingSummaryDecode(t *testing.T) {
	var finding datasafe.FindingSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"key": "ACCOUNT_DEFAULT_PWD",
		"assessmentId": "ocid1.datasafesecurityassessment.oc1..aaaa",
		"targetId": "ocid1.datasafetargetdatabase.oc1..bbbb",
		"severity": "PASS",
		"oracleDefinedSeverity": "HIGH",
		"isRiskModified": true,
		"hasTargetDbRiskLevelChanged": false,
		"isTopFinding": true,
		"justification": "accepted by the database team",
		"timeValidUntil": "2027-01-01T00:00:00.000Z",
		"title": "Users with Default Passwords",
		"category": "User Accounts",
		"summary": "No accounts were found with default passwords.",
		"remarks": "Default passwords are widely known.",
		"oneline": "Change the password of every listed account.",
		"doclink": "https://docs.oracle.com/en/cloud/paas/data-safe/",
		"references": {"stig": "V-1234", "gdpr": "Article 32"},
		"details": {"accountCount": 0},
		"lifecycleState": "ACTIVE"
	}`), &finding))

	// The pair that matters: Data Safe graded this HIGH and an operator waived
	// it. Reading only `severity` would report a clean pass.
	assert.Equal(t, datasafe.FindingSummarySeverityPass, finding.Severity)
	assert.Equal(t, datasafe.FindingSeverityHigh, finding.OracleDefinedSeverity)
	assert.True(t, ociDataSafeFindingRiskAccepted(finding))
	assert.False(t, ociDataSafeFindingOpenDeferral(finding, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)))

	assert.Equal(t, "ocid1.datasafetargetdatabase.oc1..bbbb", stringValue(finding.TargetId))
	assert.Equal(t, "accepted by the database team", stringValue(finding.Justification))
	assert.True(t, boolValue(finding.IsTopFinding))
	assert.Equal(t, "https://docs.oracle.com/en/cloud/paas/data-safe/", stringValue(finding.Doclink))
	assert.Equal(t, datasafe.FindingLifecycleStateActive, finding.LifecycleState)

	require.NotNil(t, finding.References)
	assert.Equal(t, map[string]any{"stig": "V-1234", "gdpr": "Article 32"},
		ociDataSafeFindingReferences(finding.References))
	require.NotNil(t, finding.Details)
	require.NotNil(t, finding.TimeValidUntil)
}

// A minimal finding: no references block, no severity change, no end date.
// The absent cases have to stay absent rather than becoming zero values.
func TestOciDataSafeFindingSummaryDecodeMinimal(t *testing.T) {
	var finding datasafe.FindingSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"key": "AUDIT_TRAIL",
		"severity": "HIGH",
		"title": "Audit Trail"
	}`), &finding))

	assert.Nil(t, finding.References)
	assert.Nil(t, finding.TimeValidUntil)
	assert.Nil(t, finding.TimeUpdated)
	assert.Nil(t, finding.IsRiskModified)
	assert.False(t, boolValue(finding.IsRiskModified))
	assert.False(t, ociDataSafeFindingRiskAccepted(finding))
	assert.Empty(t, ociDataSafeFindingReferences(finding.References))
	assert.Empty(t, stringValue(finding.TargetId))
}

// Data Safe answers `details` with a plain multi-line string on most checks,
// not with an object, even though the SDK types it as an open interface.
// Routing it through convert.JsonToDict unmarshals into a map and fails with
// "cannot unmarshal string into Go value of type map[string]interface {}" -
// and because the conversion happens while building the list, that took down
// every finding of the assessment rather than one field of one finding. Found
// against a live Data Safe assessment, where 66 of 67 non-passing findings
// carried a string here.
func TestOciDataSafeFindingDetails(t *testing.T) {
	t.Run("string details", func(t *testing.T) {
		var finding datasafe.FindingSummary
		require.NoError(t, json.Unmarshal([]byte(`{
			"key": "USER.TABLESPACE",
			"details": "User with objects on SYSTEM tablespace: \n    OADC_CATALOG_USER(3)\n"
		}`), &finding))

		got := ociDataSafeFindingDetails(finding.Details)
		assert.Equal(t, "User with objects on SYSTEM tablespace: \n    OADC_CATALOG_USER(3)\n", got)
	})

	t.Run("empty string details", func(t *testing.T) {
		var finding datasafe.FindingSummary
		require.NoError(t, json.Unmarshal([]byte(`{"key": "USER.TOEXPIRE", "details": ""}`), &finding))
		assert.Equal(t, "", ociDataSafeFindingDetails(finding.Details))
	})

	t.Run("object details", func(t *testing.T) {
		var finding datasafe.FindingSummary
		require.NoError(t, json.Unmarshal([]byte(`{"key": "K", "details": {"accountCount": 3}}`), &finding))

		got, ok := ociDataSafeFindingDetails(finding.Details).(map[string]any)
		require.True(t, ok, "an object detail must stay a map")
		assert.Equal(t, float64(3), got["accountCount"])
	})

	t.Run("absent details", func(t *testing.T) {
		var finding datasafe.FindingSummary
		require.NoError(t, json.Unmarshal([]byte(`{"key": "K"}`), &finding))
		assert.Nil(t, finding.Details)
		assert.Nil(t, ociDataSafeFindingDetails(finding.Details))
	})
}
