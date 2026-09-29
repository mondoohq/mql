// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDenyPolicyParent(t *testing.T) {
	// The project form is the literal the project listing always sent.
	assert.Equal(t,
		"policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fmy-project/denypolicies",
		denyPolicyParent("projects/my-project"))
	assert.Equal(t,
		"policies/cloudresourcemanager.googleapis.com%2Forganizations%2F123456/denypolicies",
		denyPolicyParent("organizations/123456"))
	assert.Equal(t,
		"policies/cloudresourcemanager.googleapis.com%2Ffolders%2F987/denypolicies",
		denyPolicyParent("folders/987"))
}

func TestOrganizationResourceName(t *testing.T) {
	assert.Equal(t, "organizations/123", organizationResourceName("organizations/123"))
	assert.Equal(t, "organizations/123", organizationResourceName("123"))
}

func TestSccCustomModuleParents(t *testing.T) {
	assert.Equal(t, "organizations/1/securityHealthAnalyticsSettings", sccShaCustomModulesParent("organizations/1"))
	assert.Equal(t, "folders/2/eventThreatDetectionSettings", sccEtdCustomModulesParent("folders/2"))
}
