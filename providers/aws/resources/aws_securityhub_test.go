// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
)

// TestFindingAggregatorCacheKeyIsTheArn pins where the finding aggregator's
// cache key comes from. The creator passes no explicit "__id", which is only
// safe because id() reads Arn and the generated constructor runs SetAllData
// before id() - so the arn argument is already in place. Point id() at a
// cache* field on the Internal struct instead, or stop passing arn, and the
// key collapses to the empty string for every aggregator in the account.
func TestFindingAggregatorCacheKeyIsTheArn(t *testing.T) {
	const arn = "arn:aws:securityhub:us-east-1:000000000000:finding-aggregator/abc"

	runtime := testRuntime()
	res, err := CreateResource(runtime, "aws.securityhub.findingAggregator",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	require.NoError(t, err)

	assert.Equal(t, arn, res.MqlID(),
		"the aggregator keys on its own arn, not on the empty string")

	other := "arn:aws:securityhub:eu-west-1:000000000000:finding-aggregator/def"
	res2, err := CreateResource(runtime, "aws.securityhub.findingAggregator",
		map[string]*llx.RawData{"arn": llx.StringData(other)})
	require.NoError(t, err)

	assert.NotEqual(t, res.MqlID(), res2.MqlID(),
		"two aggregators must not share a cache row")
	assert.Equal(t, other, res2.(*mqlAwsSecurityhubFindingAggregator).Arn.Data,
		"the second aggregator must not resolve to the first one's cached instance")
}
