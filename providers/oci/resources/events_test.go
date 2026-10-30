// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOciEventsCondition(t *testing.T) {
	t.Run("event type list and data filter", func(t *testing.T) {
		eventTypes, data, err := parseOciEventsCondition(`{"eventType":["com.oraclecloud.identitycontrolplane.createpolicy","com.oraclecloud.identitycontrolplane.deletepolicy"],"data":{"compartmentName":"prod"}}`)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"com.oraclecloud.identitycontrolplane.createpolicy",
			"com.oraclecloud.identitycontrolplane.deletepolicy",
		}, eventTypes)
		assert.Equal(t, map[string]any{"compartmentName": "prod"}, data)
	})

	t.Run("single event type string", func(t *testing.T) {
		eventTypes, data, err := parseOciEventsCondition(`{"eventType": "com.oraclecloud.virtualnetwork.createdrgattachment"}`)
		require.NoError(t, err)
		assert.Equal(t, []string{"com.oraclecloud.virtualnetwork.createdrgattachment"}, eventTypes)
		assert.Nil(t, data)
	})

	t.Run("event type that is a prefix of the listed one does not match", func(t *testing.T) {
		eventTypes, _, err := parseOciEventsCondition(`{"eventType":["com.oraclecloud.virtualnetwork.createdrgattachment"]}`)
		require.NoError(t, err)
		assert.NotContains(t, eventTypes, "com.oraclecloud.virtualnetwork.createdrg")
	})

	t.Run("event type text inside the data filter is not an event type", func(t *testing.T) {
		eventTypes, data, err := parseOciEventsCondition(`{"data":{"resourceName":"com.oraclecloud.identitycontrolplane.createpolicy"}}`)
		require.NoError(t, err)
		assert.Empty(t, eventTypes)
		assert.Equal(t, "com.oraclecloud.identitycontrolplane.createpolicy", data["resourceName"])
	})

	t.Run("match-all condition", func(t *testing.T) {
		for _, cond := range []string{"", "{}", `{"eventType":null}`} {
			eventTypes, data, err := parseOciEventsCondition(cond)
			require.NoError(t, err, cond)
			assert.NotNil(t, eventTypes, cond)
			assert.Empty(t, eventTypes, cond)
			assert.Nil(t, data, cond)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		for _, cond := range []string{`{"eventType":`, `{"eventType":42}`, `{"eventType":["a",1]}`, `[]`} {
			_, _, err := parseOciEventsCondition(cond)
			assert.Error(t, err, cond)
		}
	})
}

func TestOciOnsActionTopicIDs(t *testing.T) {
	// Shape of a GetRule response; the SDK picks the action type from actionType.
	var rule events.Rule
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "ocid1.eventrule.oc1..r",
		"actions": {"actions": [
			{"actionType": "ONS", "id": "a1", "isEnabled": true,  "lifecycleState": "ACTIVE",   "topicId": "ocid1.onstopic.oc1..t1"},
			{"actionType": "ONS", "id": "a2", "isEnabled": false, "lifecycleState": "ACTIVE",   "topicId": "ocid1.onstopic.oc1..t2"},
			{"actionType": "ONS", "id": "a3", "isEnabled": true,  "lifecycleState": "FAILED",   "topicId": "ocid1.onstopic.oc1..t3"},
			{"actionType": "OSS", "id": "a4", "isEnabled": true,  "lifecycleState": "ACTIVE",   "streamId": "ocid1.stream.oc1..s"},
			{"actionType": "ONS", "id": "a5", "isEnabled": true,  "lifecycleState": "ACTIVE",   "topicId": "ocid1.onstopic.oc1..t1"},
			{"actionType": "ONS", "id": "a6", "isEnabled": true,  "lifecycleState": "ACTIVE"}
		]}
	}`), &rule))

	assert.Equal(t, []string{"ocid1.onstopic.oc1..t1", "ocid1.onstopic.oc1..t2", "ocid1.onstopic.oc1..t3"},
		ociOnsActionTopicIDs(&rule, false))
	assert.Equal(t, []string{"ocid1.onstopic.oc1..t1"}, ociOnsActionTopicIDs(&rule, true))

	assert.Empty(t, ociOnsActionTopicIDs(&events.Rule{}, false))
	assert.Empty(t, ociOnsActionTopicIDs(nil, true))
}

func TestOciEventsRuleNotifies(t *testing.T) {
	deliveries := map[string]ociTopicDelivery{
		"active-with-sub":     {topicState: "ACTIVE", subscriptionStates: []string{"PENDING", "ACTIVE"}},
		"active-pending-only": {topicState: "ACTIVE", subscriptionStates: []string{"PENDING"}},
		"active-no-subs":      {topicState: "ACTIVE"},
		"deleting-with-sub":   {topicState: "DELETING", subscriptionStates: []string{"ACTIVE"}},
	}
	denied := errors.New("NotAuthorizedOrNotFound")
	lookup := func(id string) (ociTopicDelivery, error) {
		switch id {
		case "gone":
			return ociTopicDelivery{}, fmt.Errorf("%w: %s", errOciOnsTopicNotFound, id)
		case "denied":
			return ociTopicDelivery{}, denied
		}
		return deliveries[id], nil
	}

	tests := []struct {
		name    string
		topics  []string
		want    bool
		wantErr error
	}{
		{"no topics", nil, false, nil},
		{"active topic with an active subscription", []string{"active-with-sub"}, true, nil},
		{"only pending subscriptions", []string{"active-pending-only"}, false, nil},
		{"no subscriptions", []string{"active-no-subs"}, false, nil},
		{"topic not active", []string{"deleting-with-sub"}, false, nil},
		{"deleted topic does not count and is not an error", []string{"gone"}, false, nil},
		{"deleted topic beside a delivering one", []string{"gone", "active-with-sub"}, true, nil},
		{"unreadable topic with no delivering one is an error", []string{"active-no-subs", "denied"}, false, denied},
		{"delivering topic settles it despite an unreadable one", []string{"denied", "active-with-sub"}, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ociEventsRuleNotifies(tt.topics, lookup)
			assert.Equal(t, tt.want, got)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
