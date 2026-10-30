// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDictStringPtr(t *testing.T) {
	m := map[string]any{
		"present": "value",
		"empty":   "",
		"number":  42,
		"null":    nil,
		"object":  map[string]any{"a": "b"},
	}

	got := dictStringPtr(m, "present")
	require.NotNil(t, got)
	assert.Equal(t, "value", *got)

	// The distinction the helper exists for: ARM reporting "" is a value it
	// reported, and must not be confused with a key it never sent.
	got = dictStringPtr(m, "empty")
	require.NotNil(t, got, `an explicit "" is a reported value, not an absence`)
	assert.Equal(t, "", *got)

	assert.Nil(t, dictStringPtr(m, "absent"), "a key ARM never sent is unknown")
	assert.Nil(t, dictStringPtr(m, "number"))
	assert.Nil(t, dictStringPtr(m, "null"))
	assert.Nil(t, dictStringPtr(m, "object"))
	assert.Nil(t, dictStringPtr(nil, "anything"))
}

// pecEntry is the JSON shape every Azure SDK uses for a private endpoint
// connection, which is why the converter goes through a dict rather than a
// per-SDK type.
func pecEntry(id string, connectionState map[string]any) map[string]any {
	return map[string]any{
		"id":   id,
		"name": "conn",
		"type": "Microsoft.Storage/storageAccounts/privateEndpointConnections",
		"properties": map[string]any{
			"privateEndpoint":                   map[string]any{"id": "/subscriptions/sub/…/privateEndpoints/pe"},
			"privateLinkServiceConnectionState": connectionState,
			"provisioningState":                 "Succeeded",
		},
	}
}

func connectionStateOf(t *testing.T, entry map[string]any) *mqlAzureSubscriptionPrivateEndpointConnectionConnectionState {
	t.Helper()
	res, err := azurePrivateEndpointConnectionToMql(cacheIDTestRuntime(), entry)
	require.NoError(t, err)
	require.NotNil(t, res)

	conn := res.(*mqlAzureSubscriptionPrivateEndpointConnection)
	require.True(t, conn.PrivateLinkServiceConnectionState.State&plugin.StateIsSet != 0,
		"the connection state field must be set")
	require.NotNil(t, conn.PrivateLinkServiceConnectionState.Data)
	return conn.PrivateLinkServiceConnectionState.Data
}

// The defect: this path built the state's args by hand and only added a key when
// the value was non-empty, so an absent field stayed UNSET rather than null. An
// unset TValue crosses the plugin boundary as an empty DataRes and surfaces
// client-side as "primitive with no type information, coercing to null", once per
// field with nothing naming which field it was.
//
// actionsRequired is what exposed it, because a connection needing no action is
// the normal case -- so the normal case was the broken one.
func TestPrivateEndpointConnectionStateFieldsAreAlwaysSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state map[string]any
	}{
		{
			// What ARM sends for an approved connection that needs nothing.
			name:  "only status is reported",
			state: map[string]any{"status": "Approved"},
		},
		{
			name:  "an empty connection state object",
			state: map[string]any{},
		},
		{
			name:  "status and description but no actionsRequired",
			state: map[string]any{"status": "Pending", "description": "Awaiting approval"},
		},
		{
			name:  "every field reported",
			state: map[string]any{"status": "Approved", "description": "Auto-approved", "actionsRequired": "None"},
		},
		{
			name:  "fields reported as empty strings",
			state: map[string]any{"status": "", "description": "", "actionsRequired": ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := connectionStateOf(t, pecEntry("/subscriptions/sub/…/privateEndpointConnections/conn", tc.state))

			for name, field := range map[string]plugin.TValue[string]{
				"actionsRequired": state.ActionsRequired,
				"description":     state.Description,
				"status":          state.Status,
			} {
				assert.NotZero(t, field.State&plugin.StateIsSet,
					"%s must be set -- unset is what surfaces as an unattributed null", name)
			}
		})
	}
}

// An absent field must read as null, and a reported one must keep its value.
func TestPrivateEndpointConnectionStateDistinguishesAbsentFromEmpty(t *testing.T) {
	absent := connectionStateOf(t, pecEntry("/subscriptions/sub/…/privateEndpointConnections/a",
		map[string]any{"status": "Approved"}))
	assert.NotZero(t, absent.ActionsRequired.State&plugin.StateIsNull,
		"a field ARM never sent must be null, not an empty string")
	assert.Equal(t, "Approved", absent.Status.Data)

	reported := connectionStateOf(t, pecEntry("/subscriptions/sub/…/privateEndpointConnections/b",
		map[string]any{"status": "Approved", "actionsRequired": ""}))
	assert.Zero(t, reported.ActionsRequired.State&plugin.StateIsNull,
		`a field ARM reported as "" must not be null`)
	assert.Equal(t, "", reported.ActionsRequired.Data)
}

// The state has no identity of its own, so it is keyed off the parent connection.
// Without that, every state in a scan collides and each connection reports
// whichever one resolved first.
func TestPrivateEndpointConnectionStatesAreKeyedByParent(t *testing.T) {
	runtime := cacheIDTestRuntime()
	mk := func(id, status string) *mqlAzureSubscriptionPrivateEndpointConnectionConnectionState {
		res, err := azurePrivateEndpointConnectionToMql(runtime,
			pecEntry(id, map[string]any{"status": status}))
		require.NoError(t, err)
		conn := res.(*mqlAzureSubscriptionPrivateEndpointConnection)
		return conn.PrivateLinkServiceConnectionState.Data
	}

	approved := mk("/subscriptions/sub/…/privateEndpointConnections/approved", "Approved")
	rejected := mk("/subscriptions/sub/…/privateEndpointConnections/rejected", "Rejected")

	assert.NotEqual(t, approved.MqlID(), rejected.MqlID())
	// The failure this guards: the rejected connection reporting Approved.
	assert.Equal(t, "Rejected", rejected.Status.Data)
	assert.Equal(t, "Approved", approved.Status.Data)
}

// A connection with no id has no stable cache key, so it is skipped rather than
// letting several of them collide on an empty one.
func TestPrivateEndpointConnectionWithoutIdIsSkipped(t *testing.T) {
	res, err := azurePrivateEndpointConnectionToMql(cacheIDTestRuntime(),
		pecEntry("", map[string]any{"status": "Approved"}))
	require.NoError(t, err)
	assert.Nil(t, res)
}
