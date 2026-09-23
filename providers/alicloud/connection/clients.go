// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"

	actiontrailclient "github.com/alibabacloud-go/actiontrail-20200706/v3/client"
	albclient "github.com/alibabacloud-go/alb-20200616/v2/client"
	cbnclient "github.com/alibabacloud-go/cbn-20170912/v2/client"
	cloudfwclient "github.com/alibabacloud-go/cloudfw-20171207/v11/client"
	cloudssoclient "github.com/alibabacloud-go/cloudsso-20210515/client"
	configclient "github.com/alibabacloud-go/config-20200907/v4/client"
	crclient "github.com/alibabacloud-go/cr-20181201/v3/client"
	csclient "github.com/alibabacloud-go/cs-20151215/v8/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ddoscooclient "github.com/alibabacloud-go/ddoscoo-20200101/v5/client"
	ddsclient "github.com/alibabacloud-go/dds-20151201/v10/client"
	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	esclient "github.com/alibabacloud-go/elasticsearch-20170613/v6/client"
	essclient "github.com/alibabacloud-go/ess-20220222/v2/client"
	fcclient "github.com/alibabacloud-go/fc-20230330/v4/client"
	kmsclient "github.com/alibabacloud-go/kms-20160120/v4/client"
	nasclient "github.com/alibabacloud-go/nas-20170626/v4/client"
	nlbclient "github.com/alibabacloud-go/nlb-20220430/v4/client"
	polardbclient "github.com/alibabacloud-go/polardb-20170801/v9/client"
	rkvclient "github.com/alibabacloud-go/r-kvstore-20150101/v7/client"
	ramclient "github.com/alibabacloud-go/ram-20150501/v2/client"
	rdsclient "github.com/alibabacloud-go/rds-20140815/v16/client"
	rmclient "github.com/alibabacloud-go/resourcemanager-20200331/v3/client"
	sasclient "github.com/alibabacloud-go/sas-20181203/v10/client"
	slbclient "github.com/alibabacloud-go/slb-20140515/v4/client"
	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	stsclient "github.com/alibabacloud-go/sts-20150401/v2/client"
	tea "github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	wafclient "github.com/alibabacloud-go/waf-openapi-20211001/v7/client"
	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	osscred "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	credential "github.com/aliyun/credentials-go/credentials"
)

// endpoint builds the public Alibaba Cloud service endpoint for a region. A few
// services do not follow the usual <service>.<region>.aliyuncs.com layout: RAM,
// ActionTrail, Resource Management, and Cloud Enterprise Network (cbn) are
// global (region-less), Cloud Config is a center service reached through
// cn-shanghai, and Log Service (SLS) puts the region ahead of a fixed log host.
func endpoint(service, region string) string {
	switch service {
	case "ram", "actiontrail", "resourcemanager", "cbn":
		return service + ".aliyuncs.com"
	case "config":
		// Cloud Config is a center service; cn-shanghai serves the China and
		// international-Alibaba partition.
		return "config.cn-shanghai.aliyuncs.com"
	case "sls":
		return region + ".log.aliyuncs.com"
	}
	return fmt.Sprintf("%s.%s.aliyuncs.com", service, region)
}

// config assembles the shared OpenAPI config for a service client. Every
// Darabonba-generated client accepts *openapi.Config (an alias of
// models.Config), so one builder serves them all.
func (c *AlicloudConnection) config(service, region string) *openapi.Config {
	ep := endpoint(service, region)
	return &openapi.Config{
		Credential: c.cred,
		RegionId:   &region,
		Endpoint:   &ep,
	}
}

// cachedClient returns the client stored under key, or builds and stores it via
// build. Access is serialized so concurrent field resolution shares one client.
func (c *AlicloudConnection) cachedClient(key string, build func() (any, error)) (any, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if client, ok := c.clients[key]; ok {
		return client, nil
	}
	client, err := build()
	if err != nil {
		return nil, err
	}
	c.clients[key] = client
	return client, nil
}

// CenClient returns the Cloud Enterprise Network client. CEN is a global
// service, so one client is cached for the whole account.
func (c *AlicloudConnection) CenClient() (*cbnclient.Client, error) {
	client, err := c.cachedClient("cbn", func() (any, error) {
		return cbnclient.NewClient(c.config("cbn", c.region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*cbnclient.Client), nil
}

// SasClient returns a Security Center client for one of the two center regions.
// Security Center answers only in the center that owns the account, so callers
// probe both.
func (c *AlicloudConnection) SasClient(region string) (*sasclient.Client, error) {
	client, err := c.cachedClient("sas/"+region, func() (any, error) {
		return sasclient.NewClient(c.config("sas", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*sasclient.Client), nil
}

// CloudSsoClient returns a CloudSSO client for one of the two service regions.
// CloudSSO directories are hosted per-region, so callers probe both regions
// rather than assuming which one an account uses.
func (c *AlicloudConnection) CloudSsoClient(region string) (*cloudssoclient.Client, error) {
	client, err := c.cachedClient("cloudsso/"+region, func() (any, error) {
		return cloudssoclient.NewClient(c.config("cloudsso", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*cloudssoclient.Client), nil
}

// EssClient returns an Auto Scaling client for a region.
func (c *AlicloudConnection) EssClient(region string) (*essclient.Client, error) {
	client, err := c.cachedClient("ess/"+region, func() (any, error) {
		return essclient.NewClient(c.config("ess", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*essclient.Client), nil
}

func (c *AlicloudConnection) EcsClient(region string) (*ecsclient.Client, error) {
	client, err := c.cachedClient("ecs/"+region, func() (any, error) {
		return ecsclient.NewClient(c.config("ecs", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*ecsclient.Client), nil
}

func (c *AlicloudConnection) VpcClient(region string) (*vpcclient.Client, error) {
	client, err := c.cachedClient("vpc/"+region, func() (any, error) {
		return vpcclient.NewClient(c.config("vpc", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*vpcclient.Client), nil
}

// RamClient returns the global RAM client. RAM has no regional endpoints, so the
// client is cached under a single key.
func (c *AlicloudConnection) RamClient() (*ramclient.Client, error) {
	client, err := c.cachedClient("ram", func() (any, error) {
		return ramclient.NewClient(c.config("ram", c.region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*ramclient.Client), nil
}

func (c *AlicloudConnection) SlbClient(region string) (*slbclient.Client, error) {
	client, err := c.cachedClient("slb/"+region, func() (any, error) {
		return slbclient.NewClient(c.config("slb", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*slbclient.Client), nil
}

// CrClient returns the Container Registry client. The service's endpoint prefix
// is cr.
func (c *AlicloudConnection) CrClient(region string) (*crclient.Client, error) {
	client, err := c.cachedClient("cr/"+region, func() (any, error) {
		return crclient.NewClient(c.config("cr", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*crclient.Client), nil
}

// ElasticsearchClient returns the Elasticsearch client. The service's endpoint
// prefix is elasticsearch.
func (c *AlicloudConnection) ElasticsearchClient(region string) (*esclient.Client, error) {
	client, err := c.cachedClient("elasticsearch/"+region, func() (any, error) {
		return esclient.NewClient(c.config("elasticsearch", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*esclient.Client), nil
}

func (c *AlicloudConnection) StsClient(region string) (*stsclient.Client, error) {
	client, err := c.cachedClient("sts/"+region, func() (any, error) {
		return stsclient.NewClient(c.config("sts", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*stsclient.Client), nil
}

func (c *AlicloudConnection) RdsClient(region string) (*rdsclient.Client, error) {
	client, err := c.cachedClient("rds/"+region, func() (any, error) {
		return rdsclient.NewClient(c.config("rds", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*rdsclient.Client), nil
}

// RedisClient returns the ApsaraDB for Redis (Tair) client. The service's
// endpoint prefix is r-kvstore.
func (c *AlicloudConnection) RedisClient(region string) (*rkvclient.Client, error) {
	client, err := c.cachedClient("r-kvstore/"+region, func() (any, error) {
		return rkvclient.NewClient(c.config("r-kvstore", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*rkvclient.Client), nil
}

// MongoDBClient returns the ApsaraDB for MongoDB (dds) client. The service's
// endpoint prefix is mongodb.
func (c *AlicloudConnection) MongoDBClient(region string) (*ddsclient.Client, error) {
	client, err := c.cachedClient("mongodb/"+region, func() (any, error) {
		return ddsclient.NewClient(c.config("mongodb", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*ddsclient.Client), nil
}

func (c *AlicloudConnection) PolarDBClient(region string) (*polardbclient.Client, error) {
	client, err := c.cachedClient("polardb/"+region, func() (any, error) {
		return polardbclient.NewClient(c.config("polardb", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*polardbclient.Client), nil
}

// darabonbaOssCredentials adapts the Darabonba credential every other service
// client uses to the credential provider type the OSS SDK expects.
//
// It exists because those two SDKs resolve credentials independently. Without
// the adapter OSS can only see a static access key, so the two credential
// sources that never produce one, the shared credentials file and an ECS
// instance RAM role, reach every service except OSS. The failure is silent and
// misleading: OSS reports "access key id or access key secret is empty" on an
// account whose credentials are working everywhere else.
type darabonbaOssCredentials struct {
	cred credential.Credential
}

// GetCredentials resolves the current credential on every call rather than
// caching it, so a session token that the Darabonba credential refreshes (an
// assumed RAM role, an instance role) stays valid for OSS too.
func (p *darabonbaOssCredentials) GetCredentials(ctx context.Context) (osscred.Credentials, error) {
	model, err := p.cred.GetCredential()
	if err != nil {
		return osscred.Credentials{}, err
	}
	if model == nil {
		return osscred.Credentials{}, errors.New("alicloud: no credential available for OSS")
	}
	return osscred.Credentials{
		AccessKeyID:     tea.StringValue(model.AccessKeyId),
		AccessKeySecret: tea.StringValue(model.AccessKeySecret),
		SecurityToken:   tea.StringValue(model.SecurityToken),
	}, nil
}

// OssClient returns an Object Storage Service client for a region. OSS ships its
// own SDK with its own credential provider type, so the shared Darabonba
// credential is adapted rather than rebuilt, which keeps all four documented
// auth methods working for OSS exactly as they do for every other service.
func (c *AlicloudConnection) OssClient(region string) (*oss.Client, error) {
	client, err := c.cachedClient("oss/"+region, func() (any, error) {
		cfg := oss.LoadDefaultConfig().
			WithRegion(region).
			WithCredentialsProvider(&darabonbaOssCredentials{cred: c.cred})
		return oss.NewClient(cfg), nil
	})
	if err != nil {
		return nil, err
	}
	return client.(*oss.Client), nil
}

// CsClient returns a Container Service for Kubernetes (ACK) client for a region.
func (c *AlicloudConnection) CsClient(region string) (*csclient.Client, error) {
	client, err := c.cachedClient("cs/"+region, func() (any, error) {
		return csclient.NewClient(c.config("cs", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*csclient.Client), nil
}

// AlbClient returns an Application Load Balancer (ALB) client for a region.
func (c *AlicloudConnection) AlbClient(region string) (*albclient.Client, error) {
	client, err := c.cachedClient("alb/"+region, func() (any, error) {
		return albclient.NewClient(c.config("alb", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*albclient.Client), nil
}

// NlbClient returns a Network Load Balancer (NLB) client for a region.
func (c *AlicloudConnection) NlbClient(region string) (*nlbclient.Client, error) {
	client, err := c.cachedClient("nlb/"+region, func() (any, error) {
		return nlbclient.NewClient(c.config("nlb", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*nlbclient.Client), nil
}

// FcClient returns a Function Compute (FC 3.0) client for a region. FC 3.0
// resolves its regional endpoint (fcv3.<region>.aliyuncs.com, or <region>.fc for
// finance/edge regions) from RegionId via its own EndpointMap, so the endpoint
// is left unset rather than hard-coded.
func (c *AlicloudConnection) FcClient(region string) (*fcclient.Client, error) {
	client, err := c.cachedClient("fc/"+region, func() (any, error) {
		return fcclient.NewClient(&openapi.Config{
			Credential: c.cred,
			RegionId:   &region,
		})
	})
	if err != nil {
		return nil, err
	}
	return client.(*fcclient.Client), nil
}

// NasClient returns a NAS (Apsara File Storage) client for a region.
func (c *AlicloudConnection) NasClient(region string) (*nasclient.Client, error) {
	client, err := c.cachedClient("nas/"+region, func() (any, error) {
		return nasclient.NewClient(c.config("nas", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*nasclient.Client), nil
}

// WafClient returns a WAF 3.0 client for a center region (cn-hangzhou for the
// China center, ap-southeast-1 for the international center).
func (c *AlicloudConnection) WafClient(region string) (*wafclient.Client, error) {
	client, err := c.cachedClient("waf/"+region, func() (any, error) {
		return wafclient.NewClient(c.config("wafopenapi", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*wafclient.Client), nil
}

// CloudfwClient returns a Cloud Firewall client for a center region (cn-hangzhou
// for China, ap-southeast-1 for international).
func (c *AlicloudConnection) CloudfwClient(region string) (*cloudfwclient.Client, error) {
	client, err := c.cachedClient("cloudfw/"+region, func() (any, error) {
		return cloudfwclient.NewClient(c.config("cloudfw", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*cloudfwclient.Client), nil
}

// DdoscooClient returns an Anti-DDoS Pro/Premium client for a center region
// (cn-hangzhou for Anti-DDoS Pro, ap-southeast-1 for Anti-DDoS Premium).
func (c *AlicloudConnection) DdoscooClient(region string) (*ddoscooclient.Client, error) {
	client, err := c.cachedClient("ddoscoo/"+region, func() (any, error) {
		return ddoscooclient.NewClient(c.config("ddoscoo", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*ddoscooclient.Client), nil
}

// KmsClient returns a Key Management Service client for a region.
func (c *AlicloudConnection) KmsClient(region string) (*kmsclient.Client, error) {
	client, err := c.cachedClient("kms/"+region, func() (any, error) {
		return kmsclient.NewClient(c.config("kms", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*kmsclient.Client), nil
}

// ActionTrailClient returns the global ActionTrail client. ActionTrail is a
// center service, so a single client sees trails across all regions.
func (c *AlicloudConnection) ActionTrailClient() (*actiontrailclient.Client, error) {
	client, err := c.cachedClient("actiontrail", func() (any, error) {
		return actiontrailclient.NewClient(c.config("actiontrail", c.region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*actiontrailclient.Client), nil
}

// SlsClient returns a Log Service (SLS) client for a region. The client's
// endpoint is <region>.log.aliyuncs.com; per-project calls take the project as
// a method argument and the SLS gateway prepends it to the host at request time.
func (c *AlicloudConnection) SlsClient(region string) (*slsclient.Client, error) {
	client, err := c.cachedClient("sls/"+region, func() (any, error) {
		return slsclient.NewClient(c.config("sls", region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*slsclient.Client), nil
}

// ConfigClient returns the Cloud Config client. Cloud Config is a center
// service reached through the cn-shanghai endpoint, so one client is cached.
func (c *AlicloudConnection) ConfigClient() (*configclient.Client, error) {
	client, err := c.cachedClient("config", func() (any, error) {
		return configclient.NewClient(c.config("config", c.region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*configclient.Client), nil
}

// ResourceManagerClient returns the global Resource Management client backing
// the Resource Directory resources. It is a center service, so one client is
// cached for the whole account.
func (c *AlicloudConnection) ResourceManagerClient() (*rmclient.Client, error) {
	client, err := c.cachedClient("resourcemanager", func() (any, error) {
		return rmclient.NewClient(c.config("resourcemanager", c.region))
	})
	if err != nil {
		return nil, err
	}
	return client.(*rmclient.Client), nil
}

// GetRegions returns the region IDs to scan. When the caller pinned a region
// filter, that list is returned verbatim; otherwise every region enabled on the
// account is enumerated via the ECS DescribeRegions API.
func (c *AlicloudConnection) GetRegions() ([]string, error) {
	if len(c.regionFilter) > 0 {
		return c.Filters.General.applyRegionFilters(c.regionFilter), nil
	}

	client, err := c.EcsClient(c.region)
	if err != nil {
		return nil, err
	}

	resp, err := client.DescribeRegions(&ecsclient.DescribeRegionsRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Regions == nil {
		return nil, errors.New("alicloud: empty region list returned by DescribeRegions")
	}

	regions := make([]string, 0, len(resp.Body.Regions.Region))
	for _, r := range resp.Body.Regions.Region {
		if r != nil && r.RegionId != nil {
			regions = append(regions, *r.RegionId)
		}
	}
	return c.Filters.General.applyRegionFilters(regions), nil
}

// Identify looks up the account (UID) the credential belongs to via the STS
// GetCallerIdentity API and caches it on the connection.
func (c *AlicloudConnection) Identify() (string, error) {
	if c.accountID != "" {
		return c.accountID, nil
	}

	client, err := c.StsClient(c.region)
	if err != nil {
		return "", err
	}

	resp, err := client.GetCallerIdentity()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Body == nil || resp.Body.AccountId == nil {
		return "", errors.New("alicloud: empty caller identity returned by STS")
	}

	c.accountID = *resp.Body.AccountId
	return c.accountID, nil
}
