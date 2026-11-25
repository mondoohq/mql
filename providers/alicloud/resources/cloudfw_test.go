// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	cloudfwclient "github.com/alibabacloud-go/cloudfw-20171207/v12/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: the SDK documents Agentic as 1 when Agentic 2.0 is enabled; no
// target showed this.
func TestCloudfwAgenticEnabled(t *testing.T) {
	assert.Nil(t, cloudfwAgenticEnabled(nil), "no response reads null")
	assert.Nil(t, cloudfwAgenticEnabled(&cloudfwclient.DescribeUserBuyVersionResponseBody{}),
		"an absent flag reads null, not false")

	on := cloudfwAgenticEnabled(&cloudfwclient.DescribeUserBuyVersionResponseBody{Agentic: tea.Int32(1)})
	require.NotNil(t, on)
	assert.True(t, *on)

	off := cloudfwAgenticEnabled(&cloudfwclient.DescribeUserBuyVersionResponseBody{Agentic: tea.Int32(0)})
	require.NotNil(t, off)
	assert.False(t, *off)
}
