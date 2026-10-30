// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/dlp/apiv2/dlppb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// verdictAction builds a PolicyAction returning the given verdict.
func verdictAction(v dlppb.ContentPolicyVerdict) *dlppb.ContentPolicy_PolicyAction {
	return &dlppb.ContentPolicy_PolicyAction{
		Action: &dlppb.ContentPolicy_PolicyAction_ReturnVerdict{ReturnVerdict: v},
	}
}

func TestDlpPolicyActionVerdict(t *testing.T) {
	// An absent action is not a decision. Collapsing it to ALLOW (or to any
	// other verdict) would report a policy as having ruled on a case it never
	// configured, so the absent case has to stay null.
	t.Run("nil action reports null, not a verdict", func(t *testing.T) {
		assert.Nil(t, dlpPolicyActionVerdict(nil))
	})

	t.Run("BLOCK verdict", func(t *testing.T) {
		got := dlpPolicyActionVerdict(verdictAction(dlppb.ContentPolicyVerdict_BLOCK))
		require.NotNil(t, got)
		assert.Equal(t, "BLOCK", *got)
	})

	t.Run("ALLOW verdict", func(t *testing.T) {
		got := dlpPolicyActionVerdict(verdictAction(dlppb.ContentPolicyVerdict_ALLOW))
		require.NotNil(t, got)
		assert.Equal(t, "ALLOW", *got)
	})

	// An action message that exists but carries no verdict is a third state,
	// distinct from both "no action" and a real verdict. It must not silently
	// become ALLOW.
	t.Run("action present with no verdict reports UNSPECIFIED", func(t *testing.T) {
		got := dlpPolicyActionVerdict(&dlppb.ContentPolicy_PolicyAction{})
		require.NotNil(t, got)
		assert.Equal(t, "CONTENT_POLICY_VERDICT_UNSPECIFIED", *got)
	})
}

func TestDlpDefaultVerdict(t *testing.T) {
	// The API documents an unset default action as allowing the content. A
	// policy that never set one is therefore at its most permissive, and
	// reporting that as ALLOW is what lets a check asserting BLOCK fail on it.
	// Reporting null or "" instead would make the permissive case unassertable.
	t.Run("nil default action reports the documented ALLOW default", func(t *testing.T) {
		assert.Equal(t, "ALLOW", dlpDefaultVerdict(nil))
	})

	t.Run("explicit BLOCK is reported as set", func(t *testing.T) {
		assert.Equal(t, "BLOCK", dlpDefaultVerdict(verdictAction(dlppb.ContentPolicyVerdict_BLOCK)))
	})

	t.Run("explicit ALLOW is reported as set", func(t *testing.T) {
		assert.Equal(t, "ALLOW", dlpDefaultVerdict(verdictAction(dlppb.ContentPolicyVerdict_ALLOW)))
	})
}

func TestDlpConditionMinCount(t *testing.T) {
	// Reporting an unset count as 0 would read as "no findings required", which
	// inverts the field: a check asserting a positive threshold would pass on a
	// condition that actually fires on the first finding.
	for _, tc := range []struct {
		name string
		in   int64
		want int64
	}{
		{"unset reports the documented default of 1", 0, 1},
		{"negative is clamped to the default", -3, 1},
		{"explicit 1 is preserved", 1, 1},
		{"explicit threshold is preserved", 25, 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dlpConditionMinCount(tc.in))
		})
	}
}

func TestDlpLoggingDestination(t *testing.T) {
	t.Run("BigQuery destination reports the table it names", func(t *testing.T) {
		dest, project, dataset, table := dlpLoggingDestination(&dlppb.ContentPolicy_LoggingConfig{
			Destination: &dlppb.ContentPolicy_LoggingConfig_LogToBigQuery_{
				LogToBigQuery: &dlppb.ContentPolicy_LoggingConfig_LogToBigQuery{
					ProjectId: "audit-project",
					DatasetId: "dlp_audit",
					TableId:   "content_policy_verdicts",
				},
			},
		})
		assert.Equal(t, "LOG_TO_BIG_QUERY", dest)
		assert.Equal(t, "audit-project", project)
		assert.Equal(t, "dlp_audit", dataset)
		assert.Equal(t, "content_policy_verdicts", table)
	})

	// A logging config whose destination oneof is empty, or carries a variant
	// added after this provider was built, must degrade to "no destination"
	// rather than panic or report a half-filled BigQuery table.
	t.Run("empty destination reports unspecified with no table", func(t *testing.T) {
		dest, project, dataset, table := dlpLoggingDestination(&dlppb.ContentPolicy_LoggingConfig{})
		assert.Equal(t, "DESTINATION_UNSPECIFIED", dest)
		assert.Empty(t, project)
		assert.Empty(t, dataset)
		assert.Empty(t, table)
	})

	t.Run("nil config does not panic", func(t *testing.T) {
		dest, project, dataset, table := dlpLoggingDestination(nil)
		assert.Equal(t, "DESTINATION_UNSPECIFIED", dest)
		assert.Empty(t, project)
		assert.Empty(t, dataset)
		assert.Empty(t, table)
	})
}

// infoTypeCondition wraps an InfoTypeCondition in the oneof the API delivers it
// in, so the tests below exercise the same shape the provider reads off the
// wire rather than a convenient stand-in.
func infoTypeCondition(itc *dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition) *dlppb.ContentPolicy_PolicyRule_PolicyCondition {
	return &dlppb.ContentPolicy_PolicyRule_PolicyCondition{
		Condition: &dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition_{
			InfoTypeCondition: itc,
		},
	}
}

func TestReadDlpContentPolicyCondition(t *testing.T) {
	t.Run("named infoTypes are reported with their threshold", func(t *testing.T) {
		got := readDlpContentPolicyCondition(infoTypeCondition(
			&dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition{
				MinCount: 3,
				InfoTypeCondition: &dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition_InfoTypes_{
					InfoTypes: &dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition_InfoTypes{
						InfoTypeNames: []string{"US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER"},
					},
				},
			}))

		assert.True(t, got.Known)
		assert.Equal(t, int64(3), got.MinCount)
		assert.False(t, got.AnyInfoType)
		assert.Equal(t,
			[]string{"US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER"},
			got.InfoTypeNames)
	})

	// The two arms of the oneof mean opposite things. Reading the wrong one, or
	// defaulting the list to empty, would report "matches no infoType" for a
	// condition that in fact matches every one of them, and a check asserting a
	// narrow match would pass on the broadest possible rule.
	t.Run("anyInfoType reports a nil name list, not an empty one", func(t *testing.T) {
		got := readDlpContentPolicyCondition(infoTypeCondition(
			&dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition{
				InfoTypeCondition: &dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition_AnyInfoType{
					AnyInfoType: &emptypb.Empty{},
				},
			}))

		assert.True(t, got.Known)
		assert.True(t, got.AnyInfoType)
		assert.Nil(t, got.InfoTypeNames)
		// The threshold still applies to an any-infoType match.
		assert.Equal(t, int64(1), got.MinCount)
	})

	// A oneof variant added after this provider was built must come back
	// unknown, so the resource reports null rather than a zero threshold and an
	// empty infoType list it never read.
	t.Run("unmodelled condition shape reads as unknown", func(t *testing.T) {
		got := readDlpContentPolicyCondition(&dlppb.ContentPolicy_PolicyRule_PolicyCondition{})

		assert.False(t, got.Known)
		assert.Nil(t, got.InfoTypeNames)
		assert.Zero(t, got.MinCount)
		assert.False(t, got.AnyInfoType)
	})

	t.Run("nil condition does not panic and reads as unknown", func(t *testing.T) {
		assert.False(t, readDlpContentPolicyCondition(nil).Known)
	})

	// An infoType condition with neither arm of the inner oneof set is still a
	// condition that was read: the threshold is real, but it names no infoTypes.
	t.Run("infoType condition with no inner arm keeps its threshold", func(t *testing.T) {
		got := readDlpContentPolicyCondition(infoTypeCondition(
			&dlppb.ContentPolicy_PolicyRule_PolicyCondition_InfoTypeCondition{MinCount: 7}))

		assert.True(t, got.Known)
		assert.Equal(t, int64(7), got.MinCount)
		assert.False(t, got.AnyInfoType)
		assert.Nil(t, got.InfoTypeNames)
	})
}
