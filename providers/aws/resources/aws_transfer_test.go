// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransferLogGroupArn(t *testing.T) {
	const want = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/transfer/wf:*"
	// The documented form already carries ":*" and must not gain a second one.
	assert.Equal(t, want, transferLogGroupArn("arn:aws:logs:us-east-1:123456789012:log-group:/aws/transfer/wf:*"))
	// A bare ARN gains the suffix so it matches the log group's cached ARN.
	assert.Equal(t, want, transferLogGroupArn("arn:aws:logs:us-east-1:123456789012:log-group:/aws/transfer/wf"))
	assert.Equal(t, "", transferLogGroupArn(""))
	assert.Equal(t, "", transferLogGroupArn("  "))
}

func TestTransferWorkflowIds(t *testing.T) {
	assert.Nil(t, transferWorkflowIds(nil))
	assert.Empty(t, transferWorkflowIds(&transfertypes.WorkflowDetails{}))
	// Synthetic: one workflow on both triggers is listed once; an entry without an id is skipped.
	got := transferWorkflowIds(&transfertypes.WorkflowDetails{
		OnUpload: []transfertypes.WorkflowDetail{
			{WorkflowId: aws.String("w-1111")},
			{WorkflowId: aws.String("w-2222")},
		},
		OnPartialUpload: []transfertypes.WorkflowDetail{
			{WorkflowId: aws.String("w-1111")},
			{WorkflowId: nil},
			{WorkflowId: aws.String("w-3333")},
		},
	})
	assert.Equal(t, []string{"w-1111", "w-2222", "w-3333"}, got)
}
