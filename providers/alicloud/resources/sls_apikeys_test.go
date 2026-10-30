// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlsAllowedStoreNames covers the store-scope flattening. The SDK models the
// scope as a slice of pointers whose elements may each be nil, so the shared
// convert helpers that dereference without a guard would panic here; this pins
// the nil-safe reading.
func TestSlsAllowedStoreNames(t *testing.T) {
	t.Run("nil slice yields an empty scope", func(t *testing.T) {
		assert.Empty(t, slsAllowedStoreNames(nil))
	})
	t.Run("a nil element is dropped, not dereferenced", func(t *testing.T) {
		assert.Equal(t, []string{"access-log"},
			slsAllowedStoreNames([]*string{nil, new("access-log"), nil}))
	})
	t.Run("blank names are dropped", func(t *testing.T) {
		// a blank name would otherwise be handed to a logstore lookup, which
		// resolves nothing and would surface as a spurious warning
		assert.Equal(t, []string{"access-log"},
			slsAllowedStoreNames([]*string{new(""), new("access-log")}))
	})
	t.Run("order is preserved", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b", "c"},
			slsAllowedStoreNames([]*string{new("a"), new("b"), new("c")}))
	})
}

// TestSlsApiKeyAllowsAllStores covers the unrestricted-scope predicate. Log
// Service reads an empty scope as "every store in the project", so the empty
// case is the widest scope and not the narrowest: reporting it as narrow would
// pass a "no unrestricted keys" check on exactly the keys that fail it.
func TestSlsApiKeyAllowsAllStores(t *testing.T) {
	t.Run("nil scope is unrestricted", func(t *testing.T) {
		assert.True(t, slsApiKeyAllowsAllStores(nil))
	})
	t.Run("empty scope is unrestricted", func(t *testing.T) {
		assert.True(t, slsApiKeyAllowsAllStores([]string{}))
	})
	t.Run("a named store restricts the key", func(t *testing.T) {
		assert.False(t, slsApiKeyAllowsAllStores([]string{"access-log"}))
	})
	t.Run("several named stores still restrict the key", func(t *testing.T) {
		assert.False(t, slsApiKeyAllowsAllStores([]string{"access-log", "audit-log"}))
	})
}

// TestSlsOffsetListDone covers the pagination stop conditions, including the
// page cap. Without the cap, a server that ignores the offset parameter and
// answers every request with the same full page walks forever, multiplying the
// same records until the scan is killed.
func TestSlsOffsetListDone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pageLen int
		size    int
		offset  int32
		total   int32
		pages   int
		want    bool
	}{
		{"full page with more to come", 100, 100, 100, 250, 1, false},
		{"short page is the last one", 40, 100, 40, 0, 1, true},
		{"empty page ends the walk", 0, 100, 100, 0, 2, true},
		{"offset caught up with the total", 100, 100, 200, 200, 2, true},
		{"offset past the total", 100, 100, 300, 200, 3, true},
		{"unknown total keeps walking", 100, 100, 500, 0, 5, false},
		{"page cap stops a server that ignores the offset", 100, 100, 100000, 0, slsMaxListPages, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want,
				slsOffsetListDone(tc.pageLen, tc.size, tc.offset, tc.total, tc.pages))
		})
	}
}

// TestLogApiKeyArgsOmitsKeyMaterial pins the rule that the plaintext key never
// becomes a field. ListApiKeys returns it alongside the metadata, so adding it
// to the map would put the credential into every report and every recording of
// a query that touched the resource.
func TestLogApiKeyArgsOmitsKeyMaterial(t *testing.T) {
	const plaintext = "sls-plaintext-key-value"
	args := logApiKeyArgs("cn-hangzhou", "audit-project", &slsclient.ListApiKeysResponseBodyApiKeys{
		ApiKeyName: new("ingest-key"),
		ApiKey:     tea.String(plaintext),
	})

	_, ok := args["apiKey"]
	assert.False(t, ok, "the plaintext key must not become a field")
	for name, raw := range args {
		if s, isString := raw.Value.(string); isString {
			assert.NotEqual(t, plaintext, s, "field %q carries the plaintext key", name)
		}
	}
}

// TestLogApiKeyArgs covers the mapping of a ListApiKeys record onto the resource
// fields, including the absent cases: an absent timestamp has to stay null
// rather than becoming 1 January 1970, which a report would render as a real
// creation date.
func TestLogApiKeyArgs(t *testing.T) {
	t.Run("a restricted key", func(t *testing.T) {
		args := logApiKeyArgs("cn-hangzhou", "audit-project", &slsclient.ListApiKeysResponseBodyApiKeys{
			ApiKeyName:    new("ingest-key"),
			Description:   new("ingest from the collector"),
			Status:        new("Enabled"),
			AllowedStores: []*string{new("access-log"), nil},
			CreateTime:    tea.Int32(1788420000),
			UpdateTime:    tea.Int32(1788430000),
		})

		assert.Equal(t, "cn-hangzhou/audit-project/ingest-key", args["__id"].Value)
		assert.Equal(t, "ingest-key", args["apiKeyName"].Value)
		assert.Equal(t, "audit-project", args["projectName"].Value)
		assert.Equal(t, "Enabled", args["status"].Value)
		assert.Equal(t, []any{"access-log"}, args["allowedStores"].Value)
		assert.Equal(t, false, args["allowsAllStores"].Value)

		created, ok := args["createTime"].Value.(*time.Time)
		require.True(t, ok)
		require.NotNil(t, created)
		assert.Equal(t, time.Unix(1788420000, 0).UTC(), created.UTC())
	})

	t.Run("an unrestricted key with no timestamps", func(t *testing.T) {
		args := logApiKeyArgs("cn-hangzhou", "audit-project", &slsclient.ListApiKeysResponseBodyApiKeys{
			ApiKeyName: new("wide-key"),
			Status:     new("Enabled"),
		})

		assert.Equal(t, []any{}, args["allowedStores"].Value)
		assert.Equal(t, true, args["allowsAllStores"].Value)
		assert.Nil(t, args["createTime"].Value)
		assert.Nil(t, args["updateTime"].Value)
	})
}

// TestListApiKeysDecode pins the struct tags of the ListApiKeys record against a
// payload shaped like the documented response. A tag that drifts on an SDK bump
// decodes to a zero value rather than to an error, so an unrestricted key would
// silently read as restricted and a disabled key as having no status at all.
func TestListApiKeysDecode(t *testing.T) {
	payload := []byte(`{
	  "apiKeys": [
	    {
	      "apiKeyName": "ingest-key",
	      "apiKey": "sls-plaintext-key-value",
	      "description": "ingest from the collector",
	      "status": "Enabled",
	      "allowedStores": ["access-log", "audit-log"],
	      "createTime": 1788420000,
	      "updateTime": 1788430000
	    }
	  ],
	  "count": 1,
	  "total": 1
	}`)

	var body slsclient.ListApiKeysResponseBody
	require.NoError(t, json.Unmarshal(payload, &body))
	require.Len(t, body.ApiKeys, 1)

	key := body.ApiKeys[0]
	assert.Equal(t, "ingest-key", tea.StringValue(key.ApiKeyName))
	assert.Equal(t, "Enabled", tea.StringValue(key.Status))
	assert.Equal(t, "ingest from the collector", tea.StringValue(key.Description))
	assert.Equal(t, []string{"access-log", "audit-log"}, slsAllowedStoreNames(key.AllowedStores))
	assert.Equal(t, int32(1788420000), tea.Int32Value(key.CreateTime))
	assert.Equal(t, int32(1), tea.Int32Value(body.Total))
}
