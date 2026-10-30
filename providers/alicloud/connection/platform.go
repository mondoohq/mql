// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	// Scope options that pin a discovered child connection to a single object.
	OptionClusterID         = "cluster-id"
	OptionAlbID             = "alb-id"
	OptionNlbID             = "nlb-id"
	OptionVpcID             = "vpc-id"
	OptionWafInstanceID     = "waf-instance-id"
	OptionCloudFirewall     = "cloud-firewall"
	OptionOssBucket         = "oss-bucket"
	OptionRdsInstanceID     = "rds-instance-id"
	OptionSlbID             = "slb-id"
	OptionRedisInstanceID   = "redis-instance-id"
	OptionMongodbInstanceID = "mongodb-instance-id"
	OptionPolardbClusterID  = "polardb-cluster-id"
	OptionFcFunctionName    = "fc-function-name"
	OptionAcrInstanceID     = "acr-instance-id"
	OptionEsInstanceID      = "es-instance-id"
)

const (
	platformIDAccount       = "//platformid.api.mondoo.app/runtime/alicloud/account/"
	platformIDAckCluster    = "//platformid.api.mondoo.app/runtime/alicloud/ack/cluster/"
	platformIDAlb           = "//platformid.api.mondoo.app/runtime/alicloud/alb/loadbalancer/"
	platformIDNlb           = "//platformid.api.mondoo.app/runtime/alicloud/nlb/loadbalancer/"
	platformIDVpc           = "//platformid.api.mondoo.app/runtime/alicloud/vpc/network/"
	platformIDWafInstance   = "//platformid.api.mondoo.app/runtime/alicloud/waf/instance/"
	platformIDCloudFirewall = "//platformid.api.mondoo.app/runtime/alicloud/cloudfirewall/"
	platformIDOssBucket     = "//platformid.api.mondoo.app/runtime/alicloud/oss/bucket/"
	platformIDRdsInstance   = "//platformid.api.mondoo.app/runtime/alicloud/rds/instance/"
	platformIDSlb           = "//platformid.api.mondoo.app/runtime/alicloud/slb/loadbalancer/"
	platformIDRedisInstance = "//platformid.api.mondoo.app/runtime/alicloud/redis/instance/"
	platformIDMongodb       = "//platformid.api.mondoo.app/runtime/alicloud/mongodb/instance/"
	platformIDPolardb       = "//platformid.api.mondoo.app/runtime/alicloud/polardb/cluster/"
	platformIDFcFunction    = "//platformid.api.mondoo.app/runtime/alicloud/fc/function/"
	platformIDAcrInstance   = "//platformid.api.mondoo.app/runtime/alicloud/acr/instance/"
	platformIDEsInstance    = "//platformid.api.mondoo.app/runtime/alicloud/elasticsearch/instance/"
)

// Platforms is the static catalog of platforms the alicloud provider emits: the
// account itself, and the per-object platforms produced by fine-grained asset
// discovery.
var Platforms = []*plugin.PlatformInfo{
	{Name: "alicloud-account", Title: "Alibaba Cloud account", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-ack-cluster", Title: "Alibaba Cloud ACK Cluster", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-alb-loadbalancer", Title: "Alibaba Cloud Application Load Balancer", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-nlb-loadbalancer", Title: "Alibaba Cloud Network Load Balancer", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-vpc", Title: "Alibaba Cloud VPC", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-waf-instance", Title: "Alibaba Cloud Web Application Firewall", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-cloud-firewall", Title: "Alibaba Cloud Cloud Firewall", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-oss-bucket", Title: "Alibaba Cloud OSS Bucket", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-rds-instance", Title: "Alibaba Cloud RDS Instance", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-slb-loadbalancer", Title: "Alibaba Cloud Classic Load Balancer", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-redis-instance", Title: "Alibaba Cloud ApsaraDB for Redis Instance", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-mongodb-instance", Title: "Alibaba Cloud ApsaraDB for MongoDB Instance", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-polardb-cluster", Title: "Alibaba Cloud PolarDB Cluster", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-fc-function", Title: "Alibaba Cloud Function Compute Function", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-acr-instance", Title: "Alibaba Cloud Container Registry Instance", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
	{Name: "alicloud-elasticsearch-instance", Title: "Alibaba Cloud Elasticsearch Cluster", Family: []string{"alicloud"}, Kind: []string{"api"}, Runtime: []string{"alicloud"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}

func newPlatform(name, title string, segments []string) *inventory.Platform {
	p := &inventory.Platform{}
	if title != "" {
		p.Title = title
	}
	p.TechnologyUrlSegments = segments
	PlatformByName(name).Apply(p)
	return p
}

// NewAccountPlatform returns the platform for an Alibaba Cloud account asset.
func NewAccountPlatform(accountID string) *inventory.Platform {
	return newPlatform("alicloud-account", "Alibaba Cloud account "+accountID,
		[]string{"technology=alicloud", "kind=account", "account=" + accountID})
}

// NewAckClusterPlatform returns the platform for a discovered ACK cluster asset.
func NewAckClusterPlatform(clusterID string) *inventory.Platform {
	return newPlatform("alicloud-ack-cluster", "",
		[]string{"technology=alicloud", "kind=ack-cluster", "cluster=" + clusterID})
}

// NewAlbPlatform returns the platform for a discovered ALB load balancer asset.
func NewAlbPlatform(lbID string) *inventory.Platform {
	return newPlatform("alicloud-alb-loadbalancer", "",
		[]string{"technology=alicloud", "kind=alb-loadbalancer", "loadbalancer=" + lbID})
}

// NewNlbPlatform returns the platform for a discovered NLB load balancer asset.
func NewNlbPlatform(lbID string) *inventory.Platform {
	return newPlatform("alicloud-nlb-loadbalancer", "",
		[]string{"technology=alicloud", "kind=nlb-loadbalancer", "loadbalancer=" + lbID})
}

// NewVpcPlatform returns the platform for a discovered VPC asset.
func NewVpcPlatform(vpcID string) *inventory.Platform {
	return newPlatform("alicloud-vpc", "",
		[]string{"technology=alicloud", "kind=vpc", "vpc=" + vpcID})
}

// NewWafInstancePlatform returns the platform for a discovered WAF instance asset.
func NewWafInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-waf-instance", "",
		[]string{"technology=alicloud", "kind=waf-instance", "instance=" + instanceID})
}

// NewCloudFirewallPlatform returns the platform for the account's Cloud Firewall asset.
func NewCloudFirewallPlatform(accountID string) *inventory.Platform {
	return newPlatform("alicloud-cloud-firewall", "",
		[]string{"technology=alicloud", "kind=cloud-firewall", "account=" + accountID})
}

// NewOssBucketPlatform returns the platform for a discovered OSS bucket asset.
func NewOssBucketPlatform(bucketName string) *inventory.Platform {
	return newPlatform("alicloud-oss-bucket", "",
		[]string{"technology=alicloud", "kind=oss-bucket", "bucket=" + bucketName})
}

// NewRdsInstancePlatform returns the platform for a discovered RDS instance asset.
func NewRdsInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-rds-instance", "",
		[]string{"technology=alicloud", "kind=rds-instance", "instance=" + instanceID})
}

// NewSlbPlatform returns the platform for a discovered CLB instance asset.
func NewSlbPlatform(lbID string) *inventory.Platform {
	return newPlatform("alicloud-slb-loadbalancer", "",
		[]string{"technology=alicloud", "kind=slb-loadbalancer", "loadbalancer=" + lbID})
}

// NewRedisInstancePlatform returns the platform for a discovered ApsaraDB for
// Redis instance asset.
func NewRedisInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-redis-instance", "",
		[]string{"technology=alicloud", "kind=redis-instance", "instance=" + instanceID})
}

// NewMongodbInstancePlatform returns the platform for a discovered ApsaraDB for
// MongoDB instance asset.
func NewMongodbInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-mongodb-instance", "",
		[]string{"technology=alicloud", "kind=mongodb-instance", "instance=" + instanceID})
}

// NewPolardbClusterPlatform returns the platform for a discovered PolarDB
// cluster asset.
func NewPolardbClusterPlatform(clusterID string) *inventory.Platform {
	return newPlatform("alicloud-polardb-cluster", "",
		[]string{"technology=alicloud", "kind=polardb-cluster", "cluster=" + clusterID})
}

// NewFcFunctionPlatform returns the platform for a discovered Function Compute
// function asset. Function names repeat across regions, so the region is part of
// the identity.
func NewFcFunctionPlatform(region, functionName string) *inventory.Platform {
	return newPlatform("alicloud-fc-function", "",
		[]string{"technology=alicloud", "kind=fc-function", "region=" + region, "function=" + functionName})
}

// NewAcrInstancePlatform returns the platform for a discovered Container
// Registry instance asset.
func NewAcrInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-acr-instance", "",
		[]string{"technology=alicloud", "kind=acr-instance", "instance=" + instanceID})
}

// NewEsInstancePlatform returns the platform for a discovered Elasticsearch
// cluster asset.
func NewEsInstancePlatform(instanceID string) *inventory.Platform {
	return newPlatform("alicloud-elasticsearch-instance", "",
		[]string{"technology=alicloud", "kind=elasticsearch-instance", "instance=" + instanceID})
}

func NewAccountIdentifier(accountID string) string       { return platformIDAccount + accountID }
func NewAckClusterIdentifier(clusterID string) string    { return platformIDAckCluster + clusterID }
func NewAlbIdentifier(lbID string) string                { return platformIDAlb + lbID }
func NewNlbIdentifier(lbID string) string                { return platformIDNlb + lbID }
func NewVpcIdentifier(vpcID string) string               { return platformIDVpc + vpcID }
func NewWafInstanceIdentifier(instanceID string) string  { return platformIDWafInstance + instanceID }
func NewCloudFirewallIdentifier(accountID string) string { return platformIDCloudFirewall + accountID }
func NewOssBucketIdentifier(bucketName string) string    { return platformIDOssBucket + bucketName }
func NewRdsInstanceIdentifier(instanceID string) string  { return platformIDRdsInstance + instanceID }
func NewSlbIdentifier(lbID string) string                { return platformIDSlb + lbID }

func NewRedisInstanceIdentifier(instanceID string) string {
	return platformIDRedisInstance + instanceID
}

func NewMongodbInstanceIdentifier(instanceID string) string {
	return platformIDMongodb + instanceID
}

func NewPolardbClusterIdentifier(clusterID string) string {
	return platformIDPolardb + clusterID
}

func NewAcrInstanceIdentifier(instanceID string) string {
	return platformIDAcrInstance + instanceID
}

func NewEsInstanceIdentifier(instanceID string) string {
	return platformIDEsInstance + instanceID
}

// NewFcFunctionIdentifier keys a function by region and name: Function Compute
// names are unique within a region, not across the account.
func NewFcFunctionIdentifier(region, functionName string) string {
	return platformIDFcFunction + region + "/" + functionName
}
