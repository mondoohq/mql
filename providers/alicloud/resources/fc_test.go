// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRamRoleNameFromArn covers the RAM role ARN parser that maps a Function
// Compute execution/invocation role ARN to the role name used to resolve the
// typed ram.role reference. A parsing bug would break those cross-references.
func TestRamRoleNameFromArn(t *testing.T) {
	assert.Equal(t, "my-fc-role", ramRoleNameFromArn("acs:ram::1234567890:role/my-fc-role"))
	assert.Equal(t, "AliyunFCDefaultRole", ramRoleNameFromArn("acs:ram::1234567890:role/AliyunFCDefaultRole"))
	// service-linked role path form
	assert.Equal(t, "aliyunserviceroleforfc", ramRoleNameFromArn("acs:ram::1234567890:role/aliyunserviceroleforfc"))
	// no role segment
	assert.Equal(t, "", ramRoleNameFromArn("acs:ram::1234567890:user/bob"))
	assert.Equal(t, "", ramRoleNameFromArn(""))
}
