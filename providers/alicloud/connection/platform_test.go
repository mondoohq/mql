// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAlicloudPlatforms verifies every catalog entry is retrievable by name and
// that each constructor produces a platform consistent with its catalog entry.
func TestAlicloudPlatforms(t *testing.T) {
	for _, pi := range Platforms {
		assert.Same(t, pi, PlatformByName(pi.Name), pi.Name)
	}
	assert.True(t, PlatformByName("alicloud-account").Consistent(NewAccountPlatform("1234567890")))
	assert.True(t, PlatformByName("alicloud-ack-cluster").Consistent(NewAckClusterPlatform("c-abc")))
	assert.True(t, PlatformByName("alicloud-alb-loadbalancer").Consistent(NewAlbPlatform("alb-abc")))
	assert.True(t, PlatformByName("alicloud-nlb-loadbalancer").Consistent(NewNlbPlatform("nlb-abc")))
	assert.True(t, PlatformByName("alicloud-vpc").Consistent(NewVpcPlatform("vpc-abc")))
	assert.True(t, PlatformByName("alicloud-waf-instance").Consistent(NewWafInstancePlatform("waf-abc")))
	assert.True(t, PlatformByName("alicloud-cloud-firewall").Consistent(NewCloudFirewallPlatform("1234567890")))
	assert.True(t, PlatformByName("alicloud-oss-bucket").Consistent(NewOssBucketPlatform("audit-logs")))
	assert.True(t, PlatformByName("alicloud-rds-instance").Consistent(NewRdsInstancePlatform("rm-abc")))
	assert.True(t, PlatformByName("alicloud-slb-loadbalancer").Consistent(NewSlbPlatform("lb-abc")))
	assert.True(t, PlatformByName("alicloud-redis-instance").Consistent(NewRedisInstancePlatform("r-abc")))
	assert.True(t, PlatformByName("alicloud-mongodb-instance").Consistent(NewMongodbInstancePlatform("dds-abc")))
	assert.True(t, PlatformByName("alicloud-polardb-cluster").Consistent(NewPolardbClusterPlatform("pc-abc")))
	assert.True(t, PlatformByName("alicloud-fc-function").Consistent(NewFcFunctionPlatform("cn-hangzhou", "handler")))
	assert.True(t, PlatformByName("alicloud-acr-instance").Consistent(NewAcrInstancePlatform("cri-abc")))
	assert.True(t, PlatformByName("alicloud-elasticsearch-instance").Consistent(NewEsInstancePlatform("es-cn-abc")))
}

// TestAlicloudIdentifiers pins the stable platform-id formats used for asset
// deduplication; changing them would orphan previously-scanned assets.
func TestAlicloudIdentifiers(t *testing.T) {
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/account/1234567890", NewAccountIdentifier("1234567890"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/ack/cluster/c-abc", NewAckClusterIdentifier("c-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/alb/loadbalancer/alb-abc", NewAlbIdentifier("alb-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/nlb/loadbalancer/nlb-abc", NewNlbIdentifier("nlb-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/vpc/network/vpc-abc", NewVpcIdentifier("vpc-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/waf/instance/waf-abc", NewWafInstanceIdentifier("waf-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/cloudfirewall/1234567890", NewCloudFirewallIdentifier("1234567890"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/oss/bucket/audit-logs", NewOssBucketIdentifier("audit-logs"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/rds/instance/rm-abc", NewRdsInstanceIdentifier("rm-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/slb/loadbalancer/lb-abc", NewSlbIdentifier("lb-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/redis/instance/r-abc", NewRedisInstanceIdentifier("r-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/mongodb/instance/dds-abc", NewMongodbInstanceIdentifier("dds-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/polardb/cluster/pc-abc", NewPolardbClusterIdentifier("pc-abc"))

	// Function Compute names repeat across regions, so the region is part of the
	// identity: two functions named "handler" in different regions must not
	// collapse into one asset.
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/fc/function/cn-hangzhou/handler",
		NewFcFunctionIdentifier("cn-hangzhou", "handler"))
	assert.NotEqual(t,
		NewFcFunctionIdentifier("cn-hangzhou", "handler"),
		NewFcFunctionIdentifier("ap-southeast-1", "handler"))

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/acr/instance/cri-abc", NewAcrInstanceIdentifier("cri-abc"))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/alicloud/elasticsearch/instance/es-cn-abc", NewEsInstanceIdentifier("es-cn-abc"))
}
