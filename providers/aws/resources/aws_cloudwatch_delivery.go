// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// CloudWatch Logs vended log delivery: delivery sources name the resource that
// vends logs, delivery destinations the log group, bucket, or stream that
// receives them, and deliveries pair one source with one destination.

func (a *mqlAwsCloudwatch) logDeliverySources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "cloudwatchlogs", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.CloudwatchLogs(region)
		res := []any{}
		paginator := cloudwatchlogs.NewDescribeDeliverySourcesPaginator(svc, &cloudwatchlogs.DescribeDeliverySourcesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, s := range page.DeliverySources {
				mqlSource, err := CreateResource(a.MqlRuntime, ResourceAwsCloudwatchLogDeliverySource, map[string]*llx.RawData{
					"__id":          llx.StringDataPtr(s.Arn),
					"arn":           llx.StringDataPtr(s.Arn),
					"name":          llx.StringDataPtr(s.Name),
					"region":        llx.StringData(region),
					"logType":       llx.StringDataPtr(s.LogType),
					"service":       llx.StringDataPtr(s.Service),
					"resourceArns":  llx.ArrayData(toInterfaceArr(s.ResourceArns), types.String),
					"status":        llx.StringData(string(s.Status)),
					"statusReason":  llx.StringData(string(s.StatusReason)),
					"configuration": llx.MapData(toInterfaceMap(s.DeliverySourceConfiguration), types.String),
					"tags":          llx.MapData(toInterfaceMap(s.Tags), types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSource)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsCloudwatch) logDeliveries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "cloudwatchlogs", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.CloudwatchLogs(region)
		res := []any{}
		paginator := cloudwatchlogs.NewDescribeDeliveriesPaginator(svc, &cloudwatchlogs.DescribeDeliveriesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, d := range page.Deliveries {
				id := convert.ToValue(d.Arn)
				if id == "" {
					id = "aws.cloudwatch.logDelivery/" + region + "/" + convert.ToValue(d.Id)
				}
				var suffixPath string
				var hiveCompatible bool
				if d.S3DeliveryConfiguration != nil {
					suffixPath = convert.ToValue(d.S3DeliveryConfiguration.SuffixPath)
					hiveCompatible = convert.ToValue(d.S3DeliveryConfiguration.EnableHiveCompatiblePath)
				}
				mqlDelivery, err := CreateResource(a.MqlRuntime, ResourceAwsCloudwatchLogDelivery, map[string]*llx.RawData{
					"__id":                       llx.StringData(id),
					"id":                         llx.StringDataPtr(d.Id),
					"arn":                        llx.StringDataPtr(d.Arn),
					"region":                     llx.StringData(region),
					"deliverySourceName":         llx.StringDataPtr(d.DeliverySourceName),
					"deliveryDestinationType":    llx.StringData(string(d.DeliveryDestinationType)),
					"recordFields":               llx.ArrayData(toInterfaceArr(d.RecordFields), types.String),
					"fieldDelimiter":             llx.StringDataPtr(d.FieldDelimiter),
					"s3SuffixPath":               llx.StringData(suffixPath),
					"s3EnableHiveCompatiblePath": llx.BoolData(hiveCompatible),
					"tags":                       llx.MapData(toInterfaceMap(d.Tags), types.String),
				})
				if err != nil {
					return nil, err
				}
				mqlDelivery.(*mqlAwsCloudwatchLogDelivery).deliveryDestinationArn = convert.ToValue(d.DeliveryDestinationArn)
				res = append(res, mqlDelivery)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsCloudwatch) logDeliveryDestinations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "cloudwatchlogs", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.CloudwatchLogs(region)
		res := []any{}
		paginator := cloudwatchlogs.NewDescribeDeliveryDestinationsPaginator(svc, &cloudwatchlogs.DescribeDeliveryDestinationsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, d := range page.DeliveryDestinations {
				var destinationArn string
				if d.DeliveryDestinationConfiguration != nil {
					destinationArn = convert.ToValue(d.DeliveryDestinationConfiguration.DestinationResourceArn)
				}
				mqlDestination, err := CreateResource(a.MqlRuntime, ResourceAwsCloudwatchLogDeliveryDestination, map[string]*llx.RawData{
					"__id":                    llx.StringDataPtr(d.Arn),
					"arn":                     llx.StringDataPtr(d.Arn),
					"name":                    llx.StringDataPtr(d.Name),
					"region":                  llx.StringData(region),
					"deliveryDestinationType": llx.StringData(string(d.DeliveryDestinationType)),
					"destinationResourceArn":  llx.StringData(destinationArn),
					"outputFormat":            llx.StringData(string(d.OutputFormat)),
					"tags":                    llx.MapData(toInterfaceMap(d.Tags), types.String),
				})
				if err != nil {
					return nil, err
				}
				mqlDestination.(*mqlAwsCloudwatchLogDeliveryDestination).roleArn = convert.ToValue(d.RoleArn)
				res = append(res, mqlDestination)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsCloudwatchLogDeliverySource) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudwatchLogDelivery) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudwatchLogDeliveryDestination) id() (string, error) {
	return a.__id, nil
}

// cloudwatchSingleton returns the shared aws.cloudwatch resource, whose
// delivery lists are fetched once per scan and reused by every lookup below.
func cloudwatchSingleton(runtime *plugin.Runtime) (*mqlAwsCloudwatch, error) {
	obj, err := CreateResource(runtime, ResourceAwsCloudwatch, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsCloudwatch), nil
}

// deliverySourceKey identifies a delivery source: names are unique per region.
func deliverySourceKey(region, name string) string {
	return region + "/" + name
}

// filterLogDeliveries returns the deliveries whose source is one of sources,
// keyed by deliverySourceKey.
func filterLogDeliveries(deliveries []any, sources map[string]struct{}) []any {
	res := []any{}
	for _, raw := range deliveries {
		d, ok := raw.(*mqlAwsCloudwatchLogDelivery)
		if !ok {
			continue
		}
		if _, ok := sources[deliverySourceKey(d.Region.Data, d.DeliverySourceName.Data)]; ok {
			res = append(res, d)
		}
	}
	return res
}

// logDeliveriesForResource returns the deliveries whose delivery source names
// resourceArn among its resource ARNs.
func logDeliveriesForResource(runtime *plugin.Runtime, resourceArn string) ([]any, error) {
	if resourceArn == "" {
		return []any{}, nil
	}
	cw, err := cloudwatchSingleton(runtime)
	if err != nil {
		return nil, err
	}
	sources := cw.GetLogDeliverySources()
	if sources.Error != nil {
		return nil, sources.Error
	}
	matching := map[string]struct{}{}
	for _, raw := range sources.Data {
		s, ok := raw.(*mqlAwsCloudwatchLogDeliverySource)
		if !ok {
			continue
		}
		if slices.Contains(s.ResourceArns.Data, any(resourceArn)) {
			matching[deliverySourceKey(s.Region.Data, s.Name.Data)] = struct{}{}
		}
	}
	if len(matching) == 0 {
		return []any{}, nil
	}
	deliveries := cw.GetLogDeliveries()
	if deliveries.Error != nil {
		return nil, deliveries.Error
	}
	return filterLogDeliveries(deliveries.Data, matching), nil
}

func (a *mqlAwsCloudwatchLogDeliverySource) deliveries() ([]any, error) {
	cw, err := cloudwatchSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	deliveries := cw.GetLogDeliveries()
	if deliveries.Error != nil {
		return nil, deliveries.Error
	}
	return filterLogDeliveries(deliveries.Data, map[string]struct{}{
		deliverySourceKey(a.Region.Data, a.Name.Data): {},
	}), nil
}

func (a *mqlAwsCloudwatchLogDelivery) deliverySource() (*mqlAwsCloudwatchLogDeliverySource, error) {
	cw, err := cloudwatchSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	sources := cw.GetLogDeliverySources()
	if sources.Error != nil {
		return nil, sources.Error
	}
	for _, raw := range sources.Data {
		s, ok := raw.(*mqlAwsCloudwatchLogDeliverySource)
		if ok && s.Region.Data == a.Region.Data && s.Name.Data == a.DeliverySourceName.Data {
			return s, nil
		}
	}
	a.DeliverySource.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsCloudwatchLogDelivery) deliveryDestination() (*mqlAwsCloudwatchLogDeliveryDestination, error) {
	cw, err := cloudwatchSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	destinations := cw.GetLogDeliveryDestinations()
	if destinations.Error != nil {
		return nil, destinations.Error
	}
	for _, raw := range destinations.Data {
		d, ok := raw.(*mqlAwsCloudwatchLogDeliveryDestination)
		if ok && a.deliveryDestinationArn != "" && d.Arn.Data == a.deliveryDestinationArn {
			return d, nil
		}
	}
	a.DeliveryDestination.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsCloudfrontDistribution) logDeliveries() ([]any, error) {
	return logDeliveriesForResource(a.MqlRuntime, a.Arn.Data)
}

func (a *mqlAwsBedrockKnowledgeBase) logDeliveries() ([]any, error) {
	kbArn := a.GetArn()
	if kbArn.Error != nil {
		return nil, kbArn.Error
	}
	return logDeliveriesForResource(a.MqlRuntime, kbArn.Data)
}

// mqlAwsCloudwatchLogDeliveryDestinationInternal keeps the role ARN that
// role() resolves.
type mqlAwsCloudwatchLogDeliveryDestinationInternal struct {
	roleArn string
}

func (a *mqlAwsCloudwatchLogDeliveryDestination) role() (*mqlAwsIamRole, error) {
	if a.roleArn == "" {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
		"arn": llx.StringData(a.roleArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// mqlAwsCloudwatchLogDeliveryInternal keeps the destination ARN that
// deliveryDestination() resolves.
type mqlAwsCloudwatchLogDeliveryInternal struct {
	deliveryDestinationArn string
}
