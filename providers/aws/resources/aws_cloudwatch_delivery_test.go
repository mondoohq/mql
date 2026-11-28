// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func testLogDelivery(region, source string) *mqlAwsCloudwatchLogDelivery {
	d := &mqlAwsCloudwatchLogDelivery{}
	d.Region = plugin.TValue[string]{Data: region, State: plugin.StateIsSet}
	d.DeliverySourceName = plugin.TValue[string]{Data: source, State: plugin.StateIsSet}
	return d
}

func TestFilterLogDeliveries(t *testing.T) {
	cfInUsEast := testLogDelivery("us-east-1", "cloudfront-source")
	cfInEuWest := testLogDelivery("eu-west-1", "cloudfront-source")
	other := testLogDelivery("us-east-1", "bedrock-source")

	all := []any{cfInUsEast, cfInEuWest, other, "not a delivery"}

	t.Run("matches source name and region together", func(t *testing.T) {
		sources := map[string]struct{}{deliverySourceKey("us-east-1", "cloudfront-source"): {}}
		assert.Equal(t, []any{cfInUsEast}, filterLogDeliveries(all, sources))
	})

	t.Run("a same-named source in another region is a different source", func(t *testing.T) {
		sources := map[string]struct{}{deliverySourceKey("eu-west-1", "cloudfront-source"): {}}
		assert.Equal(t, []any{cfInEuWest}, filterLogDeliveries(all, sources))
	})

	t.Run("several sources", func(t *testing.T) {
		sources := map[string]struct{}{
			deliverySourceKey("us-east-1", "cloudfront-source"): {},
			deliverySourceKey("us-east-1", "bedrock-source"):    {},
		}
		assert.Equal(t, []any{cfInUsEast, other}, filterLogDeliveries(all, sources))
	})

	t.Run("no sources returns an empty list, not nil", func(t *testing.T) {
		res := filterLogDeliveries(all, map[string]struct{}{})
		assert.NotNil(t, res)
		assert.Empty(t, res)
	})
}
