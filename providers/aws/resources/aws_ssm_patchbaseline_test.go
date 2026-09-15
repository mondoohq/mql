// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
