// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func testRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func TestHealthCheckProtocol(t *testing.T) {
	tests := []struct {
		name     string
		hcType   route53types.HealthCheckType
		expected string
	}{
		{"HTTP", route53types.HealthCheckTypeHttp, "HTTP"},
		{"HTTP_STR_MATCH", route53types.HealthCheckTypeHttpStrMatch, "HTTP"},
		{"HTTPS", route53types.HealthCheckTypeHttps, "HTTPS"},
		{"HTTPS_STR_MATCH", route53types.HealthCheckTypeHttpsStrMatch, "HTTPS"},
		{"TCP", route53types.HealthCheckTypeTcp, "TCP"},
		{"CALCULATED returns empty", route53types.HealthCheckTypeCalculated, ""},
		{"CLOUDWATCH_METRIC returns empty", route53types.HealthCheckTypeCloudwatchMetric, ""},
		{"RECOVERY_CONTROL returns empty", route53types.HealthCheckTypeRecoveryControl, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, healthCheckProtocol(tt.hcType))
		})
	}
}

func TestHostedZoneIdToArn(t *testing.T) {
	t.Run("nil returns empty string", func(t *testing.T) {
		assert.Equal(t, "", hostedZoneIdToArn(nil))
	})

	t.Run("plain zone ID", func(t *testing.T) {
		assert.Equal(t,
			"arn:aws:route53:::hostedzone/Z1234567890",
			hostedZoneIdToArn(aws.String("Z1234567890")),
		)
	})

	t.Run("strips /hostedzone/ prefix", func(t *testing.T) {
		assert.Equal(t,
			"arn:aws:route53:::hostedzone/Z1234567890",
			hostedZoneIdToArn(aws.String("/hostedzone/Z1234567890")),
		)
	})
}

func TestHealthCheckIdToArn(t *testing.T) {
	t.Run("nil returns empty string", func(t *testing.T) {
		assert.Equal(t, "", healthCheckIdToArn(nil))
	})

	t.Run("returns ARN with health check ID", func(t *testing.T) {
		assert.Equal(t,
			"arn:aws:route53:::healthcheck/abcdef-1234",
			healthCheckIdToArn(aws.String("abcdef-1234")),
		)
	})
}

func TestNewMqlAwsRoute53Record(t *testing.T) {
	runtime := testRuntime()

	t.Run("basic A record", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("example.com."),
			Type: route53types.RRTypeA,
			TTL:  aws.Int64(300),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("192.0.2.1")},
				{Value: aws.String("192.0.2.2")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.Equal(t, "example.com.", record.Name.Data)
		assert.Equal(t, "A", record.Type.Data)
		assert.Equal(t, int64(300), record.Ttl.Data)
		assert.Equal(t, "/hostedzone/Z123", record.cacheHostedZoneId)
		assert.False(t, record.IsAlias.Data)
		assert.Empty(t, record.AliasTargetDnsName.Data)
		assert.Equal(t, []any{"192.0.2.1", "192.0.2.2"}, record.resourceRecordsCache)
		assert.Nil(t, record.aliasTargetCache)
		assert.Nil(t, record.geoLocationCache)
		assert.Nil(t, record.geoProximityLocationCache)
		assert.Nil(t, record.cidrRoutingConfigCache)
	})

	t.Run("alias record", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("www.example.com."),
			Type: route53types.RRTypeA,
			AliasTarget: &route53types.AliasTarget{
				DNSName:              aws.String("d123.cloudfront.net"),
				HostedZoneId:         aws.String("Z2FDTNDATAQYW2"),
				EvaluateTargetHealth: true,
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.True(t, record.IsAlias.Data)
		assert.Equal(t, "d123.cloudfront.net", record.AliasTargetDnsName.Data)
		assert.Equal(t, "Z2FDTNDATAQYW2", record.AliasTargetHostedZoneId.Data)
		assert.True(t, record.AliasEvaluateTargetHealth.Data)
		assert.Equal(t, map[string]any{
			"dnsName":              "d123.cloudfront.net",
			"hostedZoneId":         "Z2FDTNDATAQYW2",
			"evaluateTargetHealth": true,
		}, record.aliasTargetCache)
	})

	t.Run("weighted routing record", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name:          aws.String("api.example.com."),
			Type:          route53types.RRTypeA,
			TTL:           aws.Int64(60),
			SetIdentifier: aws.String("us-east-1"),
			Weight:        aws.Int64(70),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("10.0.0.1")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.Equal(t, "us-east-1", record.SetIdentifier.Data)
		assert.Equal(t, int64(70), record.Weight.Data)
	})

	t.Run("geolocation record", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("geo.example.com."),
			Type: route53types.RRTypeA,
			TTL:  aws.Int64(300),
			GeoLocation: &route53types.GeoLocation{
				ContinentCode: aws.String("EU"),
				CountryCode:   aws.String("DE"),
			},
			SetIdentifier: aws.String("europe-de"),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("10.0.0.1")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"continentCode":   "EU",
			"countryCode":     "DE",
			"subdivisionCode": "",
		}, record.geoLocationCache)
	})

	t.Run("geoproximity record with bias", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("prox.example.com."),
			Type: route53types.RRTypeA,
			TTL:  aws.Int64(300),
			GeoProximityLocation: &route53types.GeoProximityLocation{
				AWSRegion: aws.String("us-west-2"),
				Bias:      aws.Int32(50),
			},
			SetIdentifier: aws.String("us-west-bias"),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("10.0.0.1")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		require.NotNil(t, record.geoProximityLocationCache)
		assert.Equal(t, "us-west-2", record.geoProximityLocationCache["awsRegion"])
		assert.Equal(t, int64(50), record.geoProximityLocationCache["bias"])
	})

	t.Run("CIDR routing record", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("cidr.example.com."),
			Type: route53types.RRTypeA,
			TTL:  aws.Int64(300),
			CidrRoutingConfig: &route53types.CidrRoutingConfig{
				CollectionId: aws.String("col-123"),
				LocationName: aws.String("us-east-1"),
			},
			SetIdentifier: aws.String("cidr-us-east"),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("10.0.0.1")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"collectionId": "col-123",
			"locationName": "us-east-1",
		}, record.cidrRoutingConfigCache)
	})

	t.Run("nil optional fields default to zero values", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name: aws.String("minimal.example.com."),
			Type: route53types.RRTypeCname,
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("target.example.com.")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "/hostedzone/Z123", rrs)
		require.NoError(t, err)

		assert.Equal(t, int64(0), record.Ttl.Data)
		assert.Equal(t, int64(0), record.Weight.Data)
		assert.False(t, record.MultiValueAnswer.Data)
		assert.Empty(t, record.HealthCheckId.Data)
	})

	t.Run("record ID format", func(t *testing.T) {
		rrs := route53types.ResourceRecordSet{
			Name:          aws.String("id.example.com."),
			Type:          route53types.RRTypeA,
			SetIdentifier: aws.String("set-1"),
			ResourceRecords: []route53types.ResourceRecord{
				{Value: aws.String("10.0.0.1")},
			},
		}

		record, err := newMqlAwsRoute53Record(runtime, "Z123", rrs)
		require.NoError(t, err)

		id, err := record.id()
		require.NoError(t, err)
		assert.Equal(t, "Z123//id.example.com.//A//set-1", id)
	})
}

func TestNewMqlAwsRoute53HealthCheck(t *testing.T) {
	runtime := testRuntime()

	t.Run("HTTP health check with all fields", func(t *testing.T) {
		hc := route53types.HealthCheck{
			Id:              aws.String("hc-12345"),
			CallerReference: aws.String("ref-abc"),
			HealthCheckConfig: &route53types.HealthCheckConfig{
				Type:                     route53types.HealthCheckTypeHttp,
				IPAddress:                aws.String("192.0.2.1"),
				FullyQualifiedDomainName: aws.String("example.com"),
				Port:                     aws.Int32(80),
				ResourcePath:             aws.String("/health"),
				SearchString:             aws.String("OK"),
				RequestInterval:          aws.Int32(30),
				FailureThreshold:         aws.Int32(3),
				MeasureLatency:           aws.Bool(true),
				EnableSNI:                aws.Bool(false),
				HealthThreshold:          aws.Int32(0),
				Inverted:                 aws.Bool(false),
				Disabled:                 aws.Bool(false),
				Regions: []route53types.HealthCheckRegion{
					route53types.HealthCheckRegionUsEast1,
					route53types.HealthCheckRegionEuWest1,
				},
			},
		}
		tags := map[string]any{"Name": "test-hc"}

		mqlHc, err := newMqlAwsRoute53HealthCheck(runtime, hc, tags)
		require.NoError(t, err)

		assert.Equal(t, "hc-12345", mqlHc.Id.Data)
		assert.Equal(t, "arn:aws:route53:::healthcheck/hc-12345", mqlHc.Arn.Data)
		assert.Equal(t, "HTTP", mqlHc.Type.Data)
		assert.Equal(t, "HTTP", mqlHc.Protocol.Data)
		assert.Equal(t, "192.0.2.1", mqlHc.IpAddress.Data)
		assert.Equal(t, "example.com", mqlHc.FullyQualifiedDomainName.Data)
		assert.Equal(t, int64(80), mqlHc.Port.Data)
		assert.Equal(t, "/health", mqlHc.ResourcePath.Data)
		assert.Equal(t, "OK", mqlHc.SearchString.Data)
		assert.Equal(t, int64(30), mqlHc.RequestInterval.Data)
		assert.Equal(t, int64(3), mqlHc.FailureThreshold.Data)
		assert.True(t, mqlHc.MeasureLatency.Data)
		assert.False(t, mqlHc.EnableSNI.Data)
		assert.Equal(t, "ref-abc", mqlHc.CallerReference.Data)
		assert.Equal(t, []any{"us-east-1", "eu-west-1"}, mqlHc.regionsCache)
		assert.Empty(t, mqlHc.childHealthChecksCache)
		assert.Nil(t, mqlHc.cloudWatchAlarmConfigCache)
	})

	t.Run("CALCULATED health check with children", func(t *testing.T) {
		hc := route53types.HealthCheck{
			Id:              aws.String("hc-calc"),
			CallerReference: aws.String("ref-calc"),
			HealthCheckConfig: &route53types.HealthCheckConfig{
				Type:              route53types.HealthCheckTypeCalculated,
				HealthThreshold:   aws.Int32(2),
				ChildHealthChecks: []string{"hc-child1", "hc-child2", "hc-child3"},
			},
		}

		mqlHc, err := newMqlAwsRoute53HealthCheck(runtime, hc, map[string]any{})
		require.NoError(t, err)

		assert.Equal(t, "CALCULATED", mqlHc.Type.Data)
		assert.Equal(t, "", mqlHc.Protocol.Data)
		assert.Equal(t, int64(2), mqlHc.HealthThreshold.Data)
		assert.Equal(t, []any{"hc-child1", "hc-child2", "hc-child3"}, mqlHc.childHealthChecksCache)
	})

	t.Run("health check with CloudWatch alarm", func(t *testing.T) {
		hc := route53types.HealthCheck{
			Id:              aws.String("hc-cw"),
			CallerReference: aws.String("ref-cw"),
			HealthCheckConfig: &route53types.HealthCheckConfig{
				Type: route53types.HealthCheckTypeCloudwatchMetric,
			},
			CloudWatchAlarmConfiguration: &route53types.CloudWatchAlarmConfiguration{
				ComparisonOperator: route53types.ComparisonOperatorGreaterThanThreshold,
				MetricName:         aws.String("HealthCheckStatus"),
				Namespace:          aws.String("AWS/Route53"),
				Statistic:          route53types.StatisticAverage,
				EvaluationPeriods:  aws.Int32(1),
				Period:             aws.Int32(60),
				Threshold:          aws.Float64(0.5),
				Dimensions: []route53types.Dimension{
					{Name: aws.String("HealthCheckId"), Value: aws.String("hc-cw")},
				},
			},
		}

		mqlHc, err := newMqlAwsRoute53HealthCheck(runtime, hc, map[string]any{})
		require.NoError(t, err)

		require.NotNil(t, mqlHc.cloudWatchAlarmConfigCache)
		assert.Equal(t, "GreaterThanThreshold", mqlHc.cloudWatchAlarmConfigCache["comparisonOperator"])
		assert.Equal(t, "HealthCheckStatus", mqlHc.cloudWatchAlarmConfigCache["metricName"])
		assert.Equal(t, "AWS/Route53", mqlHc.cloudWatchAlarmConfigCache["namespace"])
		assert.Equal(t, "Average", mqlHc.cloudWatchAlarmConfigCache["statistic"])
		assert.Equal(t, int64(1), mqlHc.cloudWatchAlarmConfigCache["evaluationPeriods"])
		assert.Equal(t, int64(60), mqlHc.cloudWatchAlarmConfigCache["period"])
		assert.Equal(t, 0.5, mqlHc.cloudWatchAlarmConfigCache["threshold"])

		dims := mqlHc.cloudWatchAlarmConfigCache["dimensions"].([]any)
		require.Len(t, dims, 1)
		dim := dims[0].(map[string]any)
		assert.Equal(t, "HealthCheckId", dim["name"])
		assert.Equal(t, "hc-cw", dim["value"])
	})

	t.Run("nil HealthCheckConfig returns error", func(t *testing.T) {
		hc := route53types.HealthCheck{
			Id:                aws.String("hc-nil"),
			HealthCheckConfig: nil,
		}

		_, err := newMqlAwsRoute53HealthCheck(runtime, hc, map[string]any{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "health check config is nil")
	})

	t.Run("nil optional pointer fields default to zero", func(t *testing.T) {
		hc := route53types.HealthCheck{
			Id:              aws.String("hc-minimal"),
			CallerReference: aws.String("ref-min"),
			HealthCheckConfig: &route53types.HealthCheckConfig{
				Type: route53types.HealthCheckTypeHttp,
			},
		}

		mqlHc, err := newMqlAwsRoute53HealthCheck(runtime, hc, map[string]any{})
		require.NoError(t, err)

		assert.Equal(t, int64(0), mqlHc.Port.Data)
		assert.Equal(t, int64(0), mqlHc.RequestInterval.Data)
		assert.Equal(t, int64(0), mqlHc.FailureThreshold.Data)
		assert.Equal(t, int64(0), mqlHc.HealthThreshold.Data)
		assert.False(t, mqlHc.MeasureLatency.Data)
		assert.False(t, mqlHc.EnableSNI.Data)
		assert.False(t, mqlHc.Inverted.Data)
		assert.False(t, mqlHc.Disabled.Data)
		assert.Empty(t, mqlHc.regionsCache)
		assert.Empty(t, mqlHc.childHealthChecksCache)
	})
}

func TestNormalizeAliasDNSName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"my-alb-123.us-east-1.elb.amazonaws.com.", "my-alb-123.us-east-1.elb.amazonaws.com"},
		{"dualstack.my-alb-123.us-east-1.elb.amazonaws.com.", "my-alb-123.us-east-1.elb.amazonaws.com"},
		{"MY-ALB-123.US-EAST-1.ELB.AMAZONAWS.COM", "my-alb-123.us-east-1.elb.amazonaws.com"},
		{"d111111abcdef8.cloudfront.net", "d111111abcdef8.cloudfront.net"},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeAliasDNSName(c.in), "normalizeAliasDNSName(%q)", c.in)
	}
}

// TestRecordAliasTargetNullState covers the branches of the alias-target
// resolvers that return before any resource enumeration: an empty alias target,
// and a CloudFront resolver short-circuiting when the alias hosted zone is not
// the fixed CloudFront zone. These are the branches reachable without a live
// connection.
func TestRecordAliasTargetNullState(t *testing.T) {
	t.Run("aliasLoadBalancer is null when alias target DNS name is empty", func(t *testing.T) {
		record := &mqlAwsRoute53Record{}
		result, err := record.aliasLoadBalancer()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, record.AliasLoadBalancer.IsNull())
		assert.True(t, record.AliasLoadBalancer.IsSet())
	})

	t.Run("aliasCloudFrontDistribution is null when alias hosted zone is not CloudFront", func(t *testing.T) {
		record := &mqlAwsRoute53Record{}
		record.AliasTargetHostedZoneId = plugin.TValue[string]{Data: "Z35SXDOTRQ7X7K", State: plugin.StateIsSet}
		record.AliasTargetDnsName = plugin.TValue[string]{Data: "dualstack.my-alb.us-east-1.elb.amazonaws.com", State: plugin.StateIsSet}
		result, err := record.aliasCloudFrontDistribution()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, record.AliasCloudFrontDistribution.IsNull())
		assert.True(t, record.AliasCloudFrontDistribution.IsSet())
	})

	t.Run("aliasCloudFrontDistribution is null when CloudFront zone but no DNS name", func(t *testing.T) {
		record := &mqlAwsRoute53Record{}
		record.AliasTargetHostedZoneId = plugin.TValue[string]{Data: cloudFrontAliasHostedZoneID, State: plugin.StateIsSet}
		result, err := record.aliasCloudFrontDistribution()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, record.AliasCloudFrontDistribution.IsNull())
		assert.True(t, record.AliasCloudFrontDistribution.IsSet())
	})
}

func lbWithDNSName(dnsName string) *mqlAwsElbLoadbalancer {
	lb := &mqlAwsElbLoadbalancer{}
	lb.DnsName = plugin.TValue[string]{Data: dnsName, State: plugin.StateIsSet}
	return lb
}

// TestBuildLoadBalancerDNSIndex verifies the alias-target DNS index that backs
// aws.route53.record.aliasLoadBalancer(): it must key every load balancer by its
// normalized DNS name and include classic load balancers, not just v2 ones (a
// Route 53 alias record can point at either).
func TestBuildLoadBalancerDNSIndex(t *testing.T) {
	v2 := lbWithDNSName("my-alb-123.us-east-1.elb.amazonaws.com")
	classic := lbWithDNSName("my-classic-elb-456.us-east-1.elb.amazonaws.com")
	blank := lbWithDNSName("")

	idx, err := buildLoadBalancerDNSIndex([]any{v2, blank}, []any{classic})
	require.NoError(t, err)

	// A v2 load balancer alias target (Route 53 prepends "dualstack." and a
	// trailing dot) resolves through the normalized key.
	assert.Same(t, v2, idx[normalizeAliasDNSName("dualstack.my-alb-123.us-east-1.elb.amazonaws.com.")])
	// The classic load balancer is indexed too — the regression this guards.
	assert.Same(t, classic, idx[normalizeAliasDNSName("my-classic-elb-456.us-east-1.elb.amazonaws.com")])
	// Load balancers with no DNS name are skipped rather than keyed under "".
	_, hasBlank := idx[""]
	assert.False(t, hasBlank)
	assert.Len(t, idx, 2)
}
