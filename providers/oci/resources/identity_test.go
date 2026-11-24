// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOciPolicySubjectNamesGroup(t *testing.T) {
	admins := ociGroupRef{id: "ocid1.group.oc1..admins", name: "Admins"}
	// Synthetic: the principal forms the policy reference documents.
	assert.True(t, ociPolicySubjectNamesGroup("Admins", admins))
	assert.True(t, ociPolicySubjectNamesGroup("admins", admins))
	assert.True(t, ociPolicySubjectNamesGroup("ocid1.group.oc1..admins", admins))
	assert.True(t, ociPolicySubjectNamesGroup("'Default'/'Admins'", admins))
	assert.False(t, ociPolicySubjectNamesGroup("'OtherDomain'/'Admins'", admins))
	assert.False(t, ociPolicySubjectNamesGroup("ocid1.group.oc1..other", admins))
	assert.False(t, ociPolicySubjectNamesGroup("Operators", admins))
}

func TestOciStatementsGrantToGroups(t *testing.T) {
	admins := []ociGroupRef{{id: "ocid1.group.oc1..admins", name: "Admins"}}
	// Synthetic: statements in the forms the policy reference documents.
	assert.True(t, ociStatementsGrantToGroups([]any{
		"Allow group Operators, Admins to manage all-resources in tenancy",
	}, admins))
	assert.True(t, ociStatementsGrantToGroups([]any{
		"allow group id ocid1.group.oc1..admins to read buckets in compartment app",
	}, admins))
	assert.False(t, ociStatementsGrantToGroups([]any{
		"Allow dynamic-group Admins to read buckets in tenancy",
		"Allow any-group to inspect users in tenancy",
		"Allow group Operators to use instances in tenancy",
	}, admins))
	assert.False(t, ociStatementsGrantToGroups([]any{}, admins))
}
