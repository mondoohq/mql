// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/generativeaiagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOciToolConfigRefs(t *testing.T) {
	decode := func(t *testing.T, raw string) generativeaiagent.ToolConfig {
		t.Helper()
		var ts generativeaiagent.ToolSummary
		require.NoError(t, json.Unmarshal([]byte(raw), &ts))
		return ts.ToolConfig
	}

	t.Run("http endpoint tool", func(t *testing.T) {
		// Synthetic: shape follows the Generative AI Agents API reference;
		// the test tenancy has no agent tools.
		cfg := decode(t, `{"toolConfig": {
			"toolConfigType": "HTTP_ENDPOINT_TOOL_CONFIG",
			"subnetId": "ocid1.subnet.oc1.iad.s1",
			"apiSchema": {"apiSchemaInputLocationType": "INLINE", "content": "{}"},
			"httpEndpointAuthConfig": {}
		}}`)
		subnet, kbs := ociToolConfigRefs(cfg)
		assert.Equal(t, "ocid1.subnet.oc1.iad.s1", subnet)
		assert.Empty(t, kbs)
	})

	t.Run("rag tool", func(t *testing.T) {
		// Synthetic: a RAG tool retrieving from two knowledge bases.
		cfg := decode(t, `{"toolConfig": {
			"toolConfigType": "RAG_TOOL_CONFIG",
			"knowledgeBaseConfigs": [
				{"knowledgeBaseId": "ocid1.genaiagentknowledgebase.oc1.iad.k1"},
				{"knowledgeBaseId": "ocid1.genaiagentknowledgebase.oc1.iad.k2"}
			]
		}}`)
		subnet, kbs := ociToolConfigRefs(cfg)
		assert.Empty(t, subnet)
		assert.Equal(t, []string{"ocid1.genaiagentknowledgebase.oc1.iad.k1", "ocid1.genaiagentknowledgebase.oc1.iad.k2"}, kbs)
	})

	t.Run("function calling tool references neither", func(t *testing.T) {
		// Synthetic: other tool types carry no subnet or knowledge base.
		cfg := decode(t, `{"toolConfig": {"toolConfigType": "FUNCTION_CALLING_TOOL_CONFIG", "function": {"name": "f"}}}`)
		subnet, kbs := ociToolConfigRefs(cfg)
		assert.Empty(t, subnet)
		assert.Empty(t, kbs)
	})

	t.Run("pointer and nil configurations", func(t *testing.T) {
		// Synthetic: pointer forms are handled like values; nil yields nothing.
		subnet, _ := ociToolConfigRefs(&generativeaiagent.HttpEndpointToolConfig{SubnetId: strPtr("ocid1.subnet.oc1.iad.s2")})
		assert.Equal(t, "ocid1.subnet.oc1.iad.s2", subnet)
		var nilRag *generativeaiagent.RagToolConfig
		subnet, kbs := ociToolConfigRefs(nilRag)
		assert.Empty(t, subnet)
		assert.Empty(t, kbs)
	})
}

func TestOciAgentEndpointOutput(t *testing.T) {
	decode := func(t *testing.T, raw string) generativeaiagent.AgentEndpointSummary {
		t.Helper()
		var e generativeaiagent.AgentEndpointSummary
		require.NoError(t, json.Unmarshal([]byte(raw), &e))
		return e
	}

	t.Run("object storage output with retention", func(t *testing.T) {
		// Synthetic: shape follows the Generative AI Agents API reference.
		e := decode(t, `{"outputConfig": {
			"outputLocation": {
				"outputLocationType": "OBJECT_STORAGE_PREFIX",
				"namespaceName": "ns1",
				"bucketName": "agent-output",
				"prefix": "chats/"
			},
			"retentionPeriodInMinutes": 1440
		}}`)
		got := ociAgentEndpointOutput(e.OutputConfig)
		assert.Equal(t, "ns1", got.namespace)
		assert.Equal(t, "agent-output", got.bucket)
		assert.Equal(t, "chats/", got.prefix)
		require.NotNil(t, got.retentionInMinutes)
		assert.Equal(t, 1440, *got.retentionInMinutes)
	})

	t.Run("output without retention", func(t *testing.T) {
		// Synthetic: an absent retention stays nil (null), not zero.
		e := decode(t, `{"outputConfig": {"outputLocation": {
			"outputLocationType": "OBJECT_STORAGE_PREFIX", "namespaceName": "ns1", "bucketName": "b"
		}}}`)
		got := ociAgentEndpointOutput(e.OutputConfig)
		assert.Equal(t, "b", got.bucket)
		assert.Empty(t, got.prefix)
		assert.Nil(t, got.retentionInMinutes)
	})

	t.Run("no output config", func(t *testing.T) {
		// Synthetic: endpoints that persist nothing.
		e := decode(t, `{"id": "ocid1.genaiagentendpoint.oc1.iad.e1"}`)
		assert.Equal(t, ociAgentOutput{}, ociAgentEndpointOutput(e.OutputConfig))
	})
}

type idOnlyResource struct {
	plugin.Resource
	id plugin.TValue[string]
}

func (r *idOnlyResource) GetId() *plugin.TValue[string] { return &r.id }

func TestOciSelectByID(t *testing.T) {
	// Synthetic: selection keeps the order of the requested ids and drops ids
	// the listing does not contain.
	a := &idOnlyResource{id: plugin.TValue[string]{Data: "a"}}
	b := &idOnlyResource{id: plugin.TValue[string]{Data: "b"}}
	c := &idOnlyResource{id: plugin.TValue[string]{Data: "c"}}
	items := []any{a, b, c}

	assert.Equal(t, []any{c, a}, ociSelectByID(items, []string{"c", "missing", "a"}))
	assert.Empty(t, ociSelectByID(items, []string{"missing", ""}))
	assert.Empty(t, ociSelectByID(nil, []string{"a"}))
}
