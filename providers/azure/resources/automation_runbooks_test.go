// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// A runbook whose properties already carry the provisioning state answers
// from them. The resource has no runtime, so reaching for the API would panic.
func TestRunbookDetailsFromCompleteProperties(t *testing.T) {
	rb := &mqlAzureSubscriptionAutomationServiceAccountRunbook{}
	rb.cacheDetails = &armautomation.RunbookProperties{
		Description:       to.Ptr("nightly cleanup"),
		ProvisioningState: to.Ptr("Succeeded"),
	}
	desc, err := rb.description()
	require.NoError(t, err)
	assert.Equal(t, "nightly cleanup", desc)
	state, err := rb.provisioningState()
	require.NoError(t, err)
	assert.Equal(t, "Succeeded", state)
}

func TestRunbookWithoutDescriptionIsNull(t *testing.T) {
	rb := &mqlAzureSubscriptionAutomationServiceAccountRunbook{}
	rb.cacheDetails = &armautomation.RunbookProperties{ProvisioningState: to.Ptr("Succeeded")}
	_, err := rb.description()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, rb.Description.State)
}

// The runbook list leaves out the provisioning state. Its properties must not
// be taken as the answer, or description and provisioningState read null on
// every runbook; the detail fetch has to run instead.
func TestRunbookListPropertiesNeedTheDetailFetch(t *testing.T) {
	rb := &mqlAzureSubscriptionAutomationServiceAccountRunbook{}
	rb.cacheDetails = &armautomation.RunbookProperties{RunbookType: to.Ptr(armautomation.RunbookTypeEnumPowerShell72)}
	assert.Panics(t, func() { _, _ = rb.fetchDetails() },
		"with no runtime, a detail fetch panics; no panic means the list properties were used")
}
