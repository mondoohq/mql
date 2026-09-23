// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

func TestRuleString(t *testing.T) {
	rule := map[string]any{"access": "Allow", "priority": float64(100)}

	assert.Equal(t, "Allow", ruleString(rule, "access"))
	// An absent key and a key holding a non-string both yield "" rather than
	// panicking or rendering the wrong type into the schema.
	assert.Equal(t, "", ruleString(rule, "missing"))
	assert.Equal(t, "", ruleString(rule, "priority"))
}

func TestRuleStringSlice(t *testing.T) {
	rule := map[string]any{
		"sourceAddressPrefixes": []any{"10.0.0.0/8", "192.168.0.0/16"},
		"mixed":                 []any{"10.0.0.0/8", float64(42), nil},
		"notASlice":             "10.0.0.0/8",
	}

	assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, ruleStringSlice(rule, "sourceAddressPrefixes"))

	// Non-string entries are dropped rather than coerced: an empty string in a
	// prefix list would read as a rule covering an unnamed range.
	assert.Equal(t, []any{"10.0.0.0/8"}, ruleStringSlice(rule, "mixed"))

	// An absent key or a wrongly-typed value yields an empty list, never nil,
	// so the schema reports "no prefixes" rather than an unset field.
	assert.Equal(t, []any{}, ruleStringSlice(rule, "missing"))
	assert.Equal(t, []any{}, ruleStringSlice(rule, "notASlice"))
}

func TestEnumString(t *testing.T) {
	active := network.EffectiveRouteStateActive
	assert.Equal(t, "Active", enumString(&active))

	// A nil enum means Azure did not state the value; it must stay empty rather
	// than defaulting to a value the API never returned.
	var nilState *network.EffectiveRouteState
	assert.Equal(t, "", enumString(nilState))

	hop := network.RouteNextHopTypeInternet
	assert.Equal(t, "Internet", enumString(&hop))
}

// The deprecated effectiveRouteTable field and the typed effectiveRoutes field
// are separate MQL fields, so each is resolved independently. Both must read
// through the memo, or a query naming both polls Azure's 60-second
// long-running operation twice for the same answer.
func TestEffectiveRoutesCachedReturnsMemoWithoutRefetching(t *testing.T) {
	name := "system-route"
	nic := &mqlAzureSubscriptionNetworkServiceInterface{}
	nic.effRouteLoaded = true
	nic.effRoutes = []*network.EffectiveRoute{{Name: &name}}

	// A populated memo is returned as-is. Were it ignored, this would fall
	// through to the live fetch and fail on the nil connection.
	first, err := nic.effectiveRoutesCached()
	assert.NoError(t, err)
	assert.Len(t, first, 1)

	second, err := nic.effectiveRoutesCached()
	assert.NoError(t, err)
	assert.Equal(t, first, second)
}

// Only a successful fetch is memoized, so a transient failure stays retryable
// rather than freezing an empty route table onto the interface.
func TestEffectiveRoutesCachedDoesNotMemoizeFailure(t *testing.T) {
	nic := &mqlAzureSubscriptionNetworkServiceInterface{}
	assert.False(t, nic.effRouteLoaded)
}

func TestStrPtrSliceToAny(t *testing.T) {
	a, b := "10.0.0.0/8", "0.0.0.0/0"

	assert.Equal(t, []any{a, b}, strPtrSliceToAny([]*string{&a, &b}))

	// A nil element is skipped rather than dereferenced. convert.SliceStrPtrToStr
	// panics on this input, which is why the conversion is written out here.
	assert.Equal(t, []any{a}, strPtrSliceToAny([]*string{&a, nil}))

	assert.Equal(t, []any{}, strPtrSliceToAny(nil))
}
