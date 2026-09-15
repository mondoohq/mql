// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AWS-managed patch baselines report their BaselineId as a full ARN owned by an
// AWS service account. Wrapping that in ssmPatchBaselineArnPattern produced a
// doubled ARN, and because id() returns Arn.Data it became the cache key too.
func TestSsmPatchBaselineArn(t *testing.T) {
	const (
		region  = "us-east-1"
		account = "111122223333"
	)

	for _, tc := range []struct {
		name       string
		baselineID string
		want       string
	}{
		{
			name:       "customer baseline reports a bare id",
			baselineID: "pb-0123456789abcdef0",
			want:       "arn:aws:ssm:us-east-1:111122223333:patchbaseline/pb-0123456789abcdef0",
		},
		{
			// The exact shape observed live: DescribePatchBaselines returns the
			// full ARN, owned by AWS's baseline account, not the caller's.
			name:       "AWS-managed baseline already reports an ARN",
			baselineID: "arn:aws:ssm:us-east-1:075727635805:patchbaseline/pb-0028ca011460d5eaf",
			want:       "arn:aws:ssm:us-east-1:075727635805:patchbaseline/pb-0028ca011460d5eaf",
		},
		{
			name:       "a GovCloud ARN is passed through unchanged",
			baselineID: "arn:aws-us-gov:ssm:us-gov-west-1:075727635805:patchbaseline/pb-abc",
			want:       "arn:aws-us-gov:ssm:us-gov-west-1:075727635805:patchbaseline/pb-abc",
		},
		{
			name:       "an empty id still yields the account's pattern",
			baselineID: "",
			want:       "arn:aws:ssm:us-east-1:111122223333:patchbaseline/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ssmPatchBaselineArn(region, account, tc.baselineID))
		})
	}
}

// The doubled ARN is the specific shape to keep out. Pin it so a regression that
// reintroduces the bare fmt.Sprintf fails here.
func TestSsmPatchBaselineArnIsNeverDoubled(t *testing.T) {
	awsManaged := "arn:aws:ssm:us-east-1:075727635805:patchbaseline/pb-0028ca011460d5eaf"

	got := ssmPatchBaselineArn("us-east-1", "111122223333", awsManaged)

	assert.NotContains(t, got, "patchbaseline/arn:",
		"an ARN must never be wrapped inside another ARN")
	assert.Equal(t, 1, strings.Count(got, "arn:aws:ssm:"),
		"the result must contain exactly one ARN")
	assert.NotContains(t, got, "111122223333",
		"an AWS-owned baseline must not be re-attributed to the caller's account")
}

// TestSsmPatchApprovalRulesAreDictSerializable pins the approval-rule dict to
// JSON-native values. dict2primitive accepts only bool, int64, float64,
// string, []any, map[string]any and nil, so leaving the SDK's *int32 and *bool
// in place fails the whole field at query time rather than degrading it.
func TestSsmPatchApprovalRulesAreDictSerializable(t *testing.T) {
	rules := ssmPatchApprovalRules(&types.PatchRuleGroup{
		PatchRules: []types.PatchRule{
			{
				ApproveAfterDays:  aws.Int32(7),
				EnableNonSecurity: aws.Bool(true),
				ComplianceLevel:   types.PatchComplianceLevelCritical,
				PatchFilterGroup: &types.PatchFilterGroup{
					PatchFilters: []types.PatchFilter{
						{Key: types.PatchFilterKeyClassification, Values: []string{"Security"}},
					},
				},
			},
		},
	})

	require.Len(t, rules, 1)
	rule, ok := rules[0].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, int64(7), rule["approveAfterDays"])
	assert.Equal(t, true, rule["enableNonSecurity"])
	assert.Equal(t, "CRITICAL", rule["complianceLevel"])
	assertDictSerializable(t, rule)
}

// TestSsmPatchApprovalRulesAbsentPointers covers a baseline whose rules omit
// the optional members, and the nil rule group itself.
func TestSsmPatchApprovalRulesAbsentPointers(t *testing.T) {
	assert.Equal(t, []any{}, ssmPatchApprovalRules(nil))

	rules := ssmPatchApprovalRules(&types.PatchRuleGroup{
		PatchRules: []types.PatchRule{{}},
	})
	require.Len(t, rules, 1)
	rule := rules[0].(map[string]any)
	assert.Equal(t, int64(0), rule["approveAfterDays"])
	assert.Equal(t, false, rule["enableNonSecurity"])
	assertDictSerializable(t, rule)
}

// assertDictSerializable walks a dict value and fails on any type the llx dict
// conversion does not accept.
func assertDictSerializable(t *testing.T, v any) {
	t.Helper()
	switch val := v.(type) {
	case nil, bool, int64, float64, string:
	case []any:
		for _, item := range val {
			assertDictSerializable(t, item)
		}
	case map[string]any:
		for _, item := range val {
			assertDictSerializable(t, item)
		}
	default:
		t.Fatalf("dict carries a value of type %T, which dict2primitive rejects", v)
	}
}
