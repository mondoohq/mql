// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHandleTargets covers the discovery-target expansion: auto and all expand
// to every fine-grained target, while explicit targets pass through unchanged.
func TestHandleTargets(t *testing.T) {
	fineGrained := []string{
		DiscoveryK8sClusters, DiscoveryAlbs, DiscoveryNlbs,
		DiscoveryVpcs, DiscoveryWaf, DiscoveryCloudFirewall,
		DiscoveryOssBuckets, DiscoveryRdsInstances,
		DiscoverySlbs, DiscoveryRedisInstances, DiscoveryMongodbInstances,
		DiscoveryPolardbClusters, DiscoveryFcFunctions, DiscoveryAcrInstances,
		DiscoveryEsClusters,
	}

	assert.ElementsMatch(t, fineGrained, handleTargets([]string{DiscoveryAuto}))
	assert.ElementsMatch(t, fineGrained, handleTargets([]string{DiscoveryAll}))
	assert.ElementsMatch(t, fineGrained, handleTargets([]string{DiscoveryAuto, DiscoveryAlbs}))

	assert.Equal(t, []string{DiscoveryAlbs}, handleTargets([]string{DiscoveryAlbs}))
	assert.Equal(t, []string{DiscoveryVpcs}, handleTargets([]string{DiscoveryVpcs}))
	assert.Equal(t, []string{DiscoveryAccounts}, handleTargets([]string{DiscoveryAccounts}))
}
