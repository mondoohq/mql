// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolardbKnowledgeSpaceIDs covers the only route to the knowledge spaces of
// an account: the space ids named by the knowledge bases, because Alibaba Cloud
// ships no listing of spaces. A duplicate would describe the same space once
// per knowledge base in it, and a nil record would take the whole region down
// on one malformed entry.
func TestPolardbKnowledgeSpaceIDs(t *testing.T) {
	t.Run("distinct ids in first-seen order", func(t *testing.T) {
		got := polardbKnowledgeSpaceIDs([]*polardb.DescribeKnowledgeBasesResponseBodyItems{
			{KnowledgeSpaceId: new("pks-b")},
			{KnowledgeSpaceId: new("pks-a")},
			{KnowledgeSpaceId: new("pks-b")},
		})
		assert.Equal(t, []string{"pks-b", "pks-a"}, got)
	})

	t.Run("nil records and blank ids are skipped", func(t *testing.T) {
		got := polardbKnowledgeSpaceIDs([]*polardb.DescribeKnowledgeBasesResponseBodyItems{
			nil,
			{KnowledgeSpaceId: nil},
			{KnowledgeSpaceId: new("")},
			{KnowledgeSpaceId: new("pks-a")},
		})
		assert.Equal(t, []string{"pks-a"}, got)
	})

	t.Run("no knowledge bases yields no spaces", func(t *testing.T) {
		assert.Empty(t, polardbKnowledgeSpaceIDs(nil))
	})
}

// TestPolardbSyncLinkKey covers the synchronization link cache key. Two links on
// one knowledge base that both came back without a LinkId would otherwise share
// a key, and the runtime hands back the first instance for a repeated key: the
// second unattended feed would report the first one's source directory and
// state, hiding it.
func TestPolardbSyncLinkKey(t *testing.T) {
	t.Run("the link id is the key", func(t *testing.T) {
		assert.Equal(t, "pkbl-bp1abc", polardbSyncLinkKey(&polardb.DescribeKBSyncLinksResponseBodyItems{
			LinkId:     new("pkbl-bp1abc"),
			ImPlatform: new("FEISHU"),
			SourceDir:  new("https://example.feishu.cn/wiki/space/a"),
		}))
	})

	t.Run("a link with no id falls back to its platform and source", func(t *testing.T) {
		assert.Equal(t, "FEISHU/https://example.feishu.cn/wiki/space/a",
			polardbSyncLinkKey(&polardb.DescribeKBSyncLinksResponseBodyItems{
				ImPlatform: new("FEISHU"),
				SourceDir:  new("https://example.feishu.cn/wiki/space/a"),
			}))
	})

	t.Run("two id-less links on one knowledge base stay distinct", func(t *testing.T) {
		a := polardbSyncLinkKey(&polardb.DescribeKBSyncLinksResponseBodyItems{
			ImPlatform: new("FEISHU"),
			SourceDir:  new("https://example.feishu.cn/wiki/space/a"),
		})
		b := polardbSyncLinkKey(&polardb.DescribeKBSyncLinksResponseBodyItems{
			ImPlatform: new("FEISHU"),
			SourceDir:  new("https://example.feishu.cn/wiki/space/b"),
		})
		assert.NotEqual(t, a, b)
	})

	t.Run("a nil link yields no key", func(t *testing.T) {
		assert.Equal(t, "", polardbSyncLinkKey(nil))
	})
}

// TestKnowledgeSpaceAttributeDecode pins the struct tags of the knowledge space
// detail. ACLMode and OSSBucket are the two fields the audit turns on, and a tag
// that drifts on an SDK bump decodes to a zero value rather than to an error:
// an ENFORCED space would read as having no access control at all.
func TestKnowledgeSpaceAttributeDecode(t *testing.T) {
	payload := []byte(`{
	  "ACLMode": "ENFORCED",
	  "CreationTime": "2026-06-25T09:53:44Z",
	  "DBClusterId": "pc-bp1example",
	  "DBName": "polar_rag_meta",
	  "DBType": "PostgreSQL",
	  "Description": "product corpus",
	  "EmbeddingDimension": 1536,
	  "EmbeddingModel": "text-embedding-v4",
	  "KnowledgeBaseCount": 2,
	  "KnowledgeSpaceId": "pks-bp1example",
	  "LLMModel": "qwen3.6-plus",
	  "Name": "product-space",
	  "OSSBucket": "rag-corpus-bucket",
	  "RerankModel": "qwen3-rerank",
	  "ShardSize": 512,
	  "Status": "Activation",
	  "Strategy": "hybrid",
	  "TotalDocs": 12,
	  "TotalSizeBytes": 318881
	}`)

	var body polardb.DescribeKnowledgeSpaceAttributeResponseBody
	require.NoError(t, json.Unmarshal(payload, &body))

	assert.Equal(t, "ENFORCED", tea.StringValue(body.ACLMode))
	assert.Equal(t, "rag-corpus-bucket", tea.StringValue(body.OSSBucket))
	assert.Equal(t, "pc-bp1example", tea.StringValue(body.DBClusterId))
	assert.Equal(t, "text-embedding-v4", tea.StringValue(body.EmbeddingModel))
	assert.Equal(t, "qwen3.6-plus", tea.StringValue(body.LLMModel))
	assert.Equal(t, "qwen3-rerank", tea.StringValue(body.RerankModel))
	assert.Equal(t, int32(1536), tea.Int32Value(body.EmbeddingDimension))
	assert.Equal(t, int64(318881), tea.Int64Value(body.TotalSizeBytes))

	created := polardbParseTime(body.CreationTime)
	require.NotNil(t, created)
	assert.Equal(t, 2026, created.Year())
}

// TestKnowledgeSpaceAttributeAbsentRefs covers a space with neither a bucket nor
// a cluster: both must decode as absent pointers, not as empty strings, so the
// accessors report null instead of resolving a blank name.
func TestKnowledgeSpaceAttributeAbsentRefs(t *testing.T) {
	var body polardb.DescribeKnowledgeSpaceAttributeResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"KnowledgeSpaceId": "pks-bp1example"}`), &body))

	assert.Nil(t, body.OSSBucket)
	assert.Nil(t, body.DBClusterId)
	assert.Nil(t, body.ACLMode)
	assert.Nil(t, polardbParseTime(body.CreationTime))
}

// TestKBSyncLinksDecode pins the struct tags of a synchronization link. The
// source directory and the interval are what make the feed unattended, and a
// drifted tag would report a running link as having no source and no schedule.
func TestKBSyncLinksDecode(t *testing.T) {
	payload := []byte(`{
	  "Items": [
	    {
	      "ClientId": "cli_a1b2c3be8",
	      "CreationTime": "2026-08-11T09:55:19Z",
	      "Description": "wiki sync",
	      "ImPlatform": "FEISHU",
	      "LinkId": "pkbl-bp1example",
	      "LinkName": "product-wiki",
	      "SourceDir": "https://example.feishu.cn/wiki/space/a",
	      "SyncIntervalMinutes": 30,
	      "SyncStatus": "RUNNING"
	    }
	  ]
	}`)

	var body polardb.DescribeKBSyncLinksResponseBody
	require.NoError(t, json.Unmarshal(payload, &body))
	require.Len(t, body.Items, 1)

	l := body.Items[0]
	assert.Equal(t, "FEISHU", tea.StringValue(l.ImPlatform))
	assert.Equal(t, "cli_a1b2c3be8", tea.StringValue(l.ClientId))
	assert.Equal(t, "https://example.feishu.cn/wiki/space/a", tea.StringValue(l.SourceDir))
	assert.Equal(t, int32(30), tea.Int32Value(l.SyncIntervalMinutes))
	assert.Equal(t, "RUNNING", tea.StringValue(l.SyncStatus))
}

// TestKnowledgeBasesDecode pins the struct tags of a knowledge base record.
// KnowledgeSpaceId is what the space listing is built from, so a drifted tag
// would report an account as having no knowledge spaces at all, and
// KnowledgeBaseType is the sharing scope the audit reads.
func TestKnowledgeBasesDecode(t *testing.T) {
	payload := []byte(`{
	  "Items": [
	    {
	      "BindingAppCount": 2,
	      "CreationTime": "2025-03-25T09:37:10Z",
	      "Description": "product docs",
	      "KnowledgeBaseId": "pkb-bp1example",
	      "KnowledgeBaseType": "PUBLIC",
	      "KnowledgeSpaceId": "pks-bp1example",
	      "Name": "product-docs",
	      "Status": "Activation",
	      "TotalDocs": 12,
	      "TotalSizeBytes": 231984
	    }
	  ],
	  "TotalRecordCount": 1
	}`)

	var body polardb.DescribeKnowledgeBasesResponseBody
	require.NoError(t, json.Unmarshal(payload, &body))
	require.Len(t, body.Items, 1)

	kb := body.Items[0]
	assert.Equal(t, "pkb-bp1example", tea.StringValue(kb.KnowledgeBaseId))
	assert.Equal(t, "pks-bp1example", tea.StringValue(kb.KnowledgeSpaceId))
	assert.Equal(t, "PUBLIC", tea.StringValue(kb.KnowledgeBaseType))
	assert.Equal(t, int32(2), tea.Int32Value(kb.BindingAppCount))
	assert.Equal(t, int64(231984), tea.Int64Value(kb.TotalSizeBytes))
	assert.Equal(t, []string{"pks-bp1example"}, polardbKnowledgeSpaceIDs(body.Items))
}
