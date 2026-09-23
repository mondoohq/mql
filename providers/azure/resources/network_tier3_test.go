// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// TestPublicIpPrefixIpTagsDict guards the assumption behind
// publicIpPrefix.ipTags: converting []*IPTag through JsonToDictSlice preserves
// the ipTagType and tag keys. If the SDK's MarshalJSON changes them, the
// ipTags dict silently loses its shape.
func TestPublicIpPrefixIpTagsDict(t *testing.T) {
	tags := []*network.IPTag{
		{IPTagType: strPtr("FirstPartyUsage"), Tag: strPtr("SQL")},
	}

	dicts, err := convert.JsonToDictSlice(tags)
	require.NoError(t, err)
	require.Len(t, dicts, 1)

	tag, ok := dicts[0].(map[string]any)
	require.True(t, ok, "ip tag should serialize to an object")
	assert.Equal(t, "FirstPartyUsage", tag["ipTagType"])
	assert.Equal(t, "SQL", tag["tag"])
}
