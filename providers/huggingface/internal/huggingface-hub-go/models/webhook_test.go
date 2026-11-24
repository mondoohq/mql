// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: webhook records shaped after the Hub OpenAPI document
// (GET /api/settings/webhooks); no live account was checked.
func TestWebhookListDecode(t *testing.T) {
	data := []byte(`[
		{"id":"w1","url":"https://example.com/hook","watched":[],"domains":["repo"],
		 "disabled":false,"hasSecret":true,"lastTriggerAt":"2026-03-04T05:06:07.000Z",
		 "job":{"dockerImage":"python:3.12","environment":{},"flavor":"cpu-basic","timeoutSeconds":null,"secrets":["HF_TOKEN"]}},
		{"id":"w2","watched":[],"domains":["discussion"],"disabled":"suspended-after-failure","hasSecret":false,
		 "job":{"spaceId":"acme/runner","environment":{},"flavor":"cpu-basic","timeoutSeconds":null}},
		{"id":"w3","watched":[],"domains":[],"disabled":true}
	]`)

	var list WebhookList
	require.NoError(t, json.Unmarshal(data, &list))
	require.Len(t, list, 3)

	assert.False(t, bool(list[0].Disabled))
	require.NotNil(t, list[0].HasSecret)
	assert.True(t, *list[0].HasSecret)
	assert.Equal(t, "2026-03-04T05:06:07.000Z", list[0].LastTriggerAt)
	require.NotNil(t, list[0].Job)
	assert.Equal(t, "python:3.12", list[0].Job.DockerImage)
	assert.Empty(t, list[0].Job.SpaceID)

	// A webhook the Hub suspended after failed deliveries reports a string;
	// it must decode as disabled instead of failing the whole list.
	assert.True(t, bool(list[1].Disabled))
	require.NotNil(t, list[1].HasSecret)
	assert.False(t, *list[1].HasSecret)
	require.NotNil(t, list[1].Job)
	assert.Equal(t, "acme/runner", list[1].Job.SpaceID)

	assert.True(t, bool(list[2].Disabled))
	assert.Nil(t, list[2].HasSecret, "an unreported secret flag must stay nil, not read as false")
	assert.Nil(t, list[2].Job)
	assert.Empty(t, list[2].LastTriggerAt)
}

// Synthetic: a disabled value that is neither a boolean nor a string; no live
// account showed this.
func TestWebhookDisabledRejectsOtherTypes(t *testing.T) {
	var d WebhookDisabled
	assert.Error(t, json.Unmarshal([]byte(`42`), &d))
}
