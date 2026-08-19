// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kmsRef(t *testing.T, region, account, keyRef string) (string, string) {
	t.Helper()
	args := kmsKeyRefArgs(region, account, keyRef)
	require.Contains(t, args, "arn")
	require.Contains(t, args, "region", "the init needs the region to resolve an alias")
	return args["arn"].Value.(string), args["region"].Value.(string)
}

func TestKmsKeyRefArgs(t *testing.T) {
	const (
		region  = "us-east-1"
		account = "111122223333"
	)

	for _, tc := range []struct {
		name    string
		keyRef  string
		wantArn string
	}{
		{
			// The shape that was broken: SQS and SSM Parameter Store report the
			// service default key as a bare alias, and wrapping it produced
			// "...:key/alias/aws/sqs", which DescribeKey rejects.
			name:    "bare alias is passed through",
			keyRef:  "alias/aws/sqs",
			wantArn: "alias/aws/sqs",
		},
		{
			name:    "customer alias is passed through",
			keyRef:  "alias/my-app",
			wantArn: "alias/my-app",
		},
		{
			name:    "bare key id gets the region and account it cannot carry",
			keyRef:  "5fcdd4f3-26dc-40c8-a3cb-02007dfb8996",
			wantArn: "arn:aws:kms:us-east-1:111122223333:key/5fcdd4f3-26dc-40c8-a3cb-02007dfb8996",
		},
		{
			name:    "multi-region key id gets the pattern too",
			keyRef:  "mrk-1234567890abcdef1234567890abcdef",
			wantArn: "arn:aws:kms:us-east-1:111122223333:key/mrk-1234567890abcdef1234567890abcdef",
		},
		{
			name:    "full key arn is passed through",
			keyRef:  "arn:aws:kms:eu-west-1:999988887777:key/5fcdd4f3-26dc-40c8-a3cb-02007dfb8996",
			wantArn: "arn:aws:kms:eu-west-1:999988887777:key/5fcdd4f3-26dc-40c8-a3cb-02007dfb8996",
		},
		{
			name:    "full alias arn is passed through",
			keyRef:  "arn:aws:kms:eu-west-1:999988887777:alias/aws/sqs",
			wantArn: "arn:aws:kms:eu-west-1:999988887777:alias/aws/sqs",
		},
		{
			name:    "a GovCloud arn keeps its partition",
			keyRef:  "arn:aws-us-gov:kms:us-gov-west-1:999988887777:key/abc",
			wantArn: "arn:aws-us-gov:kms:us-gov-west-1:999988887777:key/abc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotArn, gotRegion := kmsRef(t, region, account, tc.keyRef)
			assert.Equal(t, tc.wantArn, gotArn)
			assert.Equal(t, region, gotRegion)
		})
	}
}

// Pin the specific malformed shape this fixes, so a regression that reintroduces
// the unconditional wrap fails here.
func TestKmsKeyRefArgsNeverNestsAnAliasUnderKey(t *testing.T) {
	for _, alias := range []string{
		"alias/aws/sqs",
		"alias/aws/ssm",
		"alias/aws/dynamodb",
		"arn:aws:kms:us-east-1:111122223333:alias/aws/s3",
	} {
		gotArn, _ := kmsRef(t, "us-east-1", "111122223333", alias)
		assert.NotContains(t, gotArn, ":key/alias/",
			"an alias must never be wrapped as a key resource")
	}
}
