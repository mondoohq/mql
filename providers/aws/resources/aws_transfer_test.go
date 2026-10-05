// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
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
