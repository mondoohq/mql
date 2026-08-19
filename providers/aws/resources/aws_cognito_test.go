// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCognitoUserPoolArn pins the ARN shape the listing path and the reference
// resolver share. It is also the pool's __id, so the two have to agree or a
// sub-resource's userPool reference misses the cache and re-fetches.
func TestCognitoUserPoolArn(t *testing.T) {
	assert.Equal(t,
		"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_AbCdEf",
		cognitoUserPoolArn("us-east-1", "123456789012", "us-east-1_AbCdEf"))
}
