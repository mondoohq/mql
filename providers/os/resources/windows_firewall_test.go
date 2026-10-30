// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestFirewallRuleConditionPresence(t *testing.T) {
	// An absent filter must reach MQL as null, not as an empty value. A
	// rule with no application filter reporting program "" would state as
	// fact that the rule is scoped to no program, and a check written as
	// program != "" would pass on a condition that was never read.
	assert.Equal(t, llx.NilData, stringData("", false))
	assert.Equal(t, llx.NilData, stringListData(nil, false))

	// A filter that is present but carries no value is a real, empty value.
	assert.Equal(t, llx.StringData(""), stringData("", true))
	assert.Equal(t, llx.ArrayData([]any{}, types.String), stringListData(nil, true))

	assert.Equal(t, llx.StringData("Any"), stringData("Any", true))
	assert.Equal(t,
		llx.ArrayData([]any{"5985", "49152-65535"}, types.String),
		stringListData([]string{"5985", "49152-65535"}, true),
	)
}
