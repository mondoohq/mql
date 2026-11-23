// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSsmInstanceArnPartition(t *testing.T) {
	assert.Equal(t, "arn:aws:ssm:us-east-1:123456789012:instance/i-0abc", ssmInstanceArn("123456789012", "us-east-1", "i-0abc"))
	assert.Equal(t, "arn:aws-us-gov:ssm:us-gov-west-1:123456789012:instance/i-0abc", ssmInstanceArn("123456789012", "us-gov-west-1", "i-0abc"))
	assert.Equal(t, "arn:aws-cn:ssm:cn-north-1:123456789012:instance/i-0abc", ssmInstanceArn("123456789012", "cn-north-1", "i-0abc"))
}
