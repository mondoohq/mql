// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/logging/v2"
)

func TestLogExclusionArgs(t *testing.T) {
	args := logExclusionArgs("sink/parent", &logging.LogExclusion{
		Name:        "exclude-dataflow",
		Description: "drops Dataflow worker chatter",
		Filter:      `resource.type="dataflow_step"`,
		Disabled:    false,
		CreateTime:  "2024-03-01T10:00:00Z",
		UpdateTime:  "2024-06-02T11:30:00Z",
	})

	assert.Equal(t, "exclude-dataflow", args["name"].Value)
	assert.Equal(t, "drops Dataflow worker chatter", args["description"].Value)
	assert.Equal(t, `resource.type="dataflow_step"`, args["filter"].Value)
	// An enabled exclusion is the one that actually drops entries, so false has
	// to read as false rather than as an unread field.
	assert.Equal(t, false, args["disabled"].Value)
	assert.NotNil(t, args["created"].Value)
	assert.NotNil(t, args["updated"].Value)
}

// createTime and updateTime are output-only and absent on an exclusion that has
// never been updated. They must stay null: the zero time would report
// 1 January year 1 as a real "last changed" date.
func TestLogExclusionArgsAbsentTimestampsStayNull(t *testing.T) {
	args := logExclusionArgs("sink/parent", &logging.LogExclusion{Name: "no-timestamps"})

	assert.Nil(t, args["created"].Value)
	assert.Nil(t, args["updated"].Value)
}

// An exclusion name is only unique within the sink it hangs off. Two sinks in
// one project are free to name an exclusion the same thing, and without the
// parent in the cache key the second would resolve to the first.
func TestLogExclusionArgsScopesTheCacheKeyToTheParent(t *testing.T) {
	a := logExclusionArgs("gcp.project.loggingservice.sink/p/sink-a", &logging.LogExclusion{Name: "shared"})
	b := logExclusionArgs("gcp.project.loggingservice.sink/p/sink-b", &logging.LogExclusion{Name: "shared"})

	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}

// The _Default sink override is what makes every project created under a node
// retain less than its own sink configuration suggests, so the three values the
// override carries have to survive the decode. A mistyped tag here reads as
// "no override configured" on a node that has one.
func TestSettingsDefaultSinkConfigDecode(t *testing.T) {
	payload := []byte(`{
	  "name": "organizations/1234/settings",
	  "disableDefaultSink": true,
	  "storageLocation": "us-east1",
	  "defaultSinkConfig": {
	    "filter": "severity >= ERROR",
	    "mode": "OVERWRITE",
	    "exclusions": [
	      {
	        "name": "drop-audit",
	        "filter": "logName:\"cloudaudit.googleapis.com\"",
	        "disabled": false
	      }
	    ]
	  }
	}`)

	var settings logging.Settings
	require.NoError(t, json.Unmarshal(payload, &settings))

	assert.True(t, settings.DisableDefaultSink)
	assert.Equal(t, "us-east1", settings.StorageLocation)
	require.NotNil(t, settings.DefaultSinkConfig)
	assert.Equal(t, "severity >= ERROR", settings.DefaultSinkConfig.Filter)
	assert.Equal(t, "OVERWRITE", settings.DefaultSinkConfig.Mode)
	require.Len(t, settings.DefaultSinkConfig.Exclusions, 1)
	assert.Equal(t, "drop-audit", settings.DefaultSinkConfig.Exclusions[0].Name)
	assert.Equal(t, `logName:"cloudaudit.googleapis.com"`, settings.DefaultSinkConfig.Exclusions[0].Filter)
	assert.False(t, settings.DefaultSinkConfig.Exclusions[0].Disabled)
}

// A node with no override must leave DefaultSinkConfig nil, so the flattened
// fields report empty rather than inventing an override that is not configured.
func TestSettingsWithoutDefaultSinkConfig(t *testing.T) {
	var settings logging.Settings
	require.NoError(t, json.Unmarshal([]byte(`{"name":"projects/p/settings"}`), &settings))

	assert.Nil(t, settings.DefaultSinkConfig)
	assert.False(t, settings.DisableDefaultSink)
}
