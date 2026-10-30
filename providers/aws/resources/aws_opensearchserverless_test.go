// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	aossdocument "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/document"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, raw string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	return v
}

func TestSummarizeAossNetworkPolicy(t *testing.T) {
	// Two rule sets: the collection is private through a VPC endpoint, the
	// dashboards are open to the internet.
	doc := mustJSON(t, `[
	  {"Rules":[{"ResourceType":"collection","Resource":["collection/logs"]}],
	   "AllowFromPublic":false,
	   "SourceVPCEs":["vpce-050f79086ee71ac05"],
	   "SourceServices":["bedrock.amazonaws.com"]},
	  {"Rules":[{"ResourceType":"dashboard","Resource":["collection/logs"]}],
	   "AllowFromPublic":true}
	]`)
	sum := summarizeAossPolicy(doc)
	assert.True(t, sum.allowFromPublic, "one public rule set makes the policy public")
	assert.Equal(t, []any{"collection/logs"}, sum.resources, "a pattern named twice is listed once")
	assert.Equal(t, []any{"vpce-050f79086ee71ac05"}, sum.sourceVpces)
	assert.Equal(t, []any{"bedrock.amazonaws.com"}, sum.sourceServices)
	assert.Nil(t, sum.awsOwnedKey)
}

func TestSummarizeAossPrivateNetworkPolicy(t *testing.T) {
	doc := mustJSON(t, `[{"Rules":[{"ResourceType":"collection","Resource":["collection/a*"]}],"AllowFromPublic":false,"SourceVPCEs":["vpce-1"]}]`)
	sum := summarizeAossPolicy(doc)
	assert.False(t, sum.allowFromPublic)
	assert.Equal(t, []any{}, sum.sourceServices)
}

func TestSummarizeAossEncryptionPolicy(t *testing.T) {
	owned := summarizeAossPolicy(mustJSON(t, `{"Rules":[{"ResourceType":"collection","Resource":["collection/*"]}],"AWSOwnedKey":true}`))
	require.NotNil(t, owned.awsOwnedKey)
	assert.True(t, *owned.awsOwnedKey)
	assert.Empty(t, owned.kmsKeyArn)
	assert.Equal(t, []any{"collection/*"}, owned.resources)

	cmk := summarizeAossPolicy(mustJSON(t, `{"Rules":[{"ResourceType":"collection","Resource":["collection/secure"]}],"AWSOwnedKey":false,"KmsARN":"arn:aws:kms:us-east-1:123456789012:key/abcd"}`))
	require.NotNil(t, cmk.awsOwnedKey)
	assert.False(t, *cmk.awsOwnedKey)
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/abcd", cmk.kmsKeyArn)
}

func TestSummarizeAossAccessPolicy(t *testing.T) {
	doc := mustJSON(t, `[
	  {"Rules":[
	     {"ResourceType":"index","Resource":["index/logs/*"],"Permission":["aoss:ReadDocument","aoss:DescribeIndex"]},
	     {"ResourceType":"collection","Resource":["collection/logs"],"Permission":["aoss:DescribeCollectionItems"]}],
	   "Principal":["arn:aws:iam::123456789012:role/reader","saml/123456789012/okta/group/admins"],
	   "Description":"readers"},
	  {"Rules":[{"ResourceType":"index","Resource":["index/logs/*"],"Permission":["aoss:*"]}],
	   "Principal":["arn:aws:iam::123456789012:role/admin"]}
	]`)
	sum := summarizeAossPolicy(doc)
	assert.Equal(t, []any{
		"arn:aws:iam::123456789012:role/reader",
		"saml/123456789012/okta/group/admins",
		"arn:aws:iam::123456789012:role/admin",
	}, sum.principals)
	assert.Equal(t, []any{"aoss:ReadDocument", "aoss:DescribeIndex", "aoss:DescribeCollectionItems", "aoss:*"}, sum.permissions)
	assert.Equal(t, []any{"index/logs/*", "collection/logs"}, sum.resources)
}

func TestSummarizeAossEmptyDocument(t *testing.T) {
	sum := summarizeAossPolicy(nil)
	assert.Equal(t, []any{}, sum.resources)
	assert.False(t, sum.allowFromPublic)
}

func TestDecodeAossPolicy(t *testing.T) {
	doc, err := decodeAossPolicy(aossdocument.NewLazyDocument([]any{
		map[string]any{"AllowFromPublic": true, "SourceVPCEs": []any{"vpce-1"}},
	}))
	require.NoError(t, err)
	list, ok := doc.([]any)
	require.True(t, ok, "a network policy stays a list")
	entry := list[0].(map[string]any)
	assert.Equal(t, true, entry["AllowFromPublic"])
	assert.Equal(t, []any{"vpce-1"}, entry["SourceVPCEs"])

	none, err := decodeAossPolicy(nil)
	require.NoError(t, err)
	assert.Nil(t, none)
}

func TestAossHelpers(t *testing.T) {
	assert.Nil(t, aossTime(nil), "an absent timestamp is null, not the epoch")
	ts := aossTime(aws.Int64(1700000000123))
	require.NotNil(t, ts)
	assert.Equal(t, int64(1700000000123), ts.UnixMilli())

	assert.Nil(t, aossKmsKeyArn(aws.String("auto")), "an AWS owned key has no key resource")
	assert.Nil(t, aossKmsKeyArn(nil))
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/k", *aossKmsKeyArn(aws.String("arn:aws:kms:us-east-1:123456789012:key/k")))

	region, id, err := aossCollectionFromArn("arn:aws:aoss:eu-west-1:123456789012:collection/07tjusf2h91cunochc")
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", region)
	assert.Equal(t, "07tjusf2h91cunochc", id)

	_, _, err = aossCollectionFromArn("arn:aws:aoss:eu-west-1:123456789012:dashboards/default")
	assert.Error(t, err)
	_, _, err = aossCollectionFromArn("not-an-arn")
	assert.Error(t, err)
}

func TestAossPolicyCacheDeniedIsNullAndCached(t *testing.T) {
	calls := 0
	c := &aossPolicyCache{}
	fetch := func() (aossdocument.Interface, error) {
		calls++
		return nil, awsAPIErr(403, "AccessDeniedException", "not authorized to perform aoss:GetSecurityPolicy")
	}
	doc, sum, err := c.load("aoss:GetSecurityPolicy", fetch)
	require.NoError(t, err)
	assert.Nil(t, doc)
	assert.Nil(t, sum)
	_, _, _ = c.load("aoss:GetSecurityPolicy", fetch)
	assert.Equal(t, 1, calls)
}

func TestAossPolicyCacheOtherErrorsAreReturned(t *testing.T) {
	c := &aossPolicyCache{}
	_, _, err := c.load("aoss:GetSecurityPolicy", func() (aossdocument.Interface, error) {
		return nil, awsAPIErr(500, "InternalServerException", "boom")
	})
	assert.Error(t, err)
}
