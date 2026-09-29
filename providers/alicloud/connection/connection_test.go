// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestScopedObject(t *testing.T) {
	t.Run("resolves id and region from a discovered child asset", func(t *testing.T) {
		c := &AlicloudConnection{
			Conf: &inventory.Config{Options: map[string]string{
				OptionClusterID: "c123",
				OptionRegions:   "cn-hangzhou",
			}},
			regionFilter: []string{"cn-hangzhou"},
			region:       DefaultRegion,
		}
		id, region, ok := c.ScopedObject(OptionClusterID)
		assert.True(t, ok)
		assert.Equal(t, "c123", id)
		assert.Equal(t, "cn-hangzhou", region)
	})

	t.Run("not scoped when the option is absent (account root)", func(t *testing.T) {
		c := &AlicloudConnection{Conf: &inventory.Config{Options: map[string]string{}}}
		id, region, ok := c.ScopedObject(OptionAlbID)
		assert.False(t, ok)
		assert.Empty(t, id)
		assert.Empty(t, region)
	})

	t.Run("falls back to the default region when no region filter is set", func(t *testing.T) {
		c := &AlicloudConnection{
			Conf:   &inventory.Config{Options: map[string]string{OptionWafInstanceID: "waf-1"}},
			region: "cn-shanghai",
		}
		id, region, ok := c.ScopedObject(OptionWafInstanceID)
		assert.True(t, ok)
		assert.Equal(t, "waf-1", id)
		assert.Equal(t, "cn-shanghai", region)
	})

	t.Run("not scoped when options are nil", func(t *testing.T) {
		c := &AlicloudConnection{Conf: &inventory.Config{}}
		_, _, ok := c.ScopedObject(OptionVpcID)
		assert.False(t, ok)
	})
}

func TestFirstNonEmpty(t *testing.T) {
	assert.Equal(t, "", firstNonEmpty())
	assert.Equal(t, "", firstNonEmpty("", ""))
	assert.Equal(t, "a", firstNonEmpty("a", "b"))
	assert.Equal(t, "b", firstNonEmpty("", "b", "c"))
	assert.Equal(t, "c", firstNonEmpty("", "", "c"))
}

func TestEndpoint(t *testing.T) {
	t.Run("RAM is a global service", func(t *testing.T) {
		assert.Equal(t, "ram.aliyuncs.com", endpoint("ram", "cn-hangzhou"))
		assert.Equal(t, "ram.aliyuncs.com", endpoint("ram", "us-west-1"))
	})

	t.Run("regional services are region-scoped", func(t *testing.T) {
		assert.Equal(t, "ecs.cn-hangzhou.aliyuncs.com", endpoint("ecs", "cn-hangzhou"))
		assert.Equal(t, "vpc.ap-southeast-1.aliyuncs.com", endpoint("vpc", "ap-southeast-1"))
		assert.Equal(t, "r-kvstore.cn-beijing.aliyuncs.com", endpoint("r-kvstore", "cn-beijing"))
		assert.Equal(t, "mongodb.cn-hangzhou.aliyuncs.com", endpoint("mongodb", "cn-hangzhou"))
		assert.Equal(t, "polardb.us-east-1.aliyuncs.com", endpoint("polardb", "us-east-1"))
		assert.Equal(t, "kms.cn-hangzhou.aliyuncs.com", endpoint("kms", "cn-hangzhou"))
	})

	t.Run("ActionTrail and Resource Management are global", func(t *testing.T) {
		assert.Equal(t, "actiontrail.aliyuncs.com", endpoint("actiontrail", "cn-hangzhou"))
		assert.Equal(t, "resourcemanager.aliyuncs.com", endpoint("resourcemanager", "ap-southeast-1"))
	})

	t.Run("IMS is global", func(t *testing.T) {
		assert.Equal(t, "ims.aliyuncs.com", endpoint("ims", "cn-hangzhou"))
		assert.Equal(t, "ims.aliyuncs.com", endpoint("ims", "ap-southeast-1"))
	})

	t.Run("Certificate Management Service answers its China center on the bare host", func(t *testing.T) {
		assert.Equal(t, "cas.aliyuncs.com", endpoint("cas", "cn-hangzhou"))
		assert.Equal(t, "cas.ap-southeast-1.aliyuncs.com", endpoint("cas", "ap-southeast-1"))
	})

	t.Run("API Gateway and PrivateLink follow the usual layout", func(t *testing.T) {
		assert.Equal(t, "apigateway.cn-beijing.aliyuncs.com", endpoint("apigateway", "cn-beijing"))
		assert.Equal(t, "privatelink.eu-central-1.aliyuncs.com", endpoint("privatelink", "eu-central-1"))
	})

	t.Run("Cloud Enterprise Network is global", func(t *testing.T) {
		// CEN spans regions by design, so its endpoint carries none. Falling
		// back to the usual layout would address a host that does not serve it.
		assert.Equal(t, "cbn.aliyuncs.com", endpoint("cbn", "cn-hangzhou"))
		assert.Equal(t, "cbn.aliyuncs.com", endpoint("cbn", "us-east-1"))
	})

	t.Run("Security Center and CloudSSO follow the usual layout", func(t *testing.T) {
		// Both are reached at a fixed pair of regions rather than every region,
		// but the endpoint itself is built the ordinary way.
		assert.Equal(t, "sas.cn-hangzhou.aliyuncs.com", endpoint("sas", "cn-hangzhou"))
		assert.Equal(t, "sas.ap-southeast-1.aliyuncs.com", endpoint("sas", "ap-southeast-1"))
		assert.Equal(t, "cloudsso.cn-shanghai.aliyuncs.com", endpoint("cloudsso", "cn-shanghai"))
		assert.Equal(t, "cloudsso.us-east-1.aliyuncs.com", endpoint("cloudsso", "us-east-1"))
	})

	t.Run("Cloud Config is a cn-shanghai center service", func(t *testing.T) {
		// The region argument is ignored: Config resolves to the cn-shanghai
		// center regardless of the caller's region.
		assert.Equal(t, "config.cn-shanghai.aliyuncs.com", endpoint("config", "cn-hangzhou"))
		assert.Equal(t, "config.cn-shanghai.aliyuncs.com", endpoint("config", "us-west-1"))
	})

	t.Run("Log Service puts the region ahead of the log host", func(t *testing.T) {
		// SLS uses <region>.log.aliyuncs.com, not the usual
		// <service>.<region>.aliyuncs.com layout.
		assert.Equal(t, "cn-hangzhou.log.aliyuncs.com", endpoint("sls", "cn-hangzhou"))
		assert.Equal(t, "ap-southeast-1.log.aliyuncs.com", endpoint("sls", "ap-southeast-1"))
	})
}

func TestResolveCredential(t *testing.T) {
	t.Run("access key pair selects the access_key credential", func(t *testing.T) {
		cred, err := resolveCredential(map[string]string{}, "id", "secret", "")
		require.NoError(t, err)
		require.NotNil(t, cred)
		require.NotNil(t, cred.GetType())
		assert.Equal(t, "access_key", *cred.GetType())
	})

	t.Run("access key with STS token selects the sts credential", func(t *testing.T) {
		cred, err := resolveCredential(map[string]string{}, "id", "secret", "token")
		require.NoError(t, err)
		require.NotNil(t, cred)
		require.NotNil(t, cred.GetType())
		assert.Equal(t, "sts", *cred.GetType())
	})

	t.Run("role ARN with an access key selects the ram_role_arn credential", func(t *testing.T) {
		cred, err := resolveCredential(
			map[string]string{OptionRoleArn: "acs:ram::123456789012:role/mondoo"},
			"id", "secret", "",
		)
		require.NoError(t, err)
		require.NotNil(t, cred)
		require.NotNil(t, cred.GetType())
		assert.Equal(t, "ram_role_arn", *cred.GetType())
	})

	t.Run("role ARN without an access key does not select ram_role_arn", func(t *testing.T) {
		// With no static access key the role cannot be assumed directly, so the
		// resolver must fall through to the default credential chain rather than
		// building a ram_role_arn credential.
		cred, err := resolveCredential(
			map[string]string{OptionRoleArn: "acs:ram::123456789012:role/mondoo"},
			"", "", "",
		)
		if err == nil && cred != nil && cred.GetType() != nil {
			assert.NotEqual(t, "ram_role_arn", *cred.GetType())
		}
	})
}
