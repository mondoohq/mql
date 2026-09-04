// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudwatch) id() (string, error) {
	return "aws.cloudwatch", nil
}

func (a *mqlAwsCloudwatch) metrics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getMetrics(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getMetrics(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Cloudwatch(region)
			ctx := context.Background()

			res := []any{}
			params := &cloudwatch.ListMetricsInput{}
			paginator := cloudwatch.NewListMetricsPaginator(svc, params)
			for paginator.HasMorePages() {
				metrics, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, metric := range metrics.Metrics {
					dimensions := []any{}
					for _, d := range metric.Dimensions {
						mqlDimension, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metricdimension",
							map[string]*llx.RawData{
								"name":  llx.StringDataPtr(d.Name),
								"value": llx.StringDataPtr(d.Value),
							})
						if err != nil {
							return nil, err
						}
						dimensions = append(dimensions, mqlDimension)
					}

					mqlMetric, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metric",
						map[string]*llx.RawData{
							"__id": llx.StringData(cloudwatchMetricID(
								region, convert.ToValue(metric.Namespace), convert.ToValue(metric.MetricName), metric.Dimensions)),
							"name":       llx.StringDataPtr(metric.MetricName),
							"namespace":  llx.StringDataPtr(metric.Namespace),
							"region":     llx.StringData(region),
							"dimensions": llx.ArrayData(dimensions, types.Resource("aws.cloudwatch.metricdimension")),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlMetric)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchMetricdimension) id() (string, error) {
	name := a.Name.Data
	val := a.Value.Data

	return name + "/" + val, nil
}

// metricStatisticsCacheKey identifies one statistics series. A CloudWatch metric
// is identified by its namespace, name AND dimensions: AWS/EC2 CPUUtilization
// exists once per instance, distinguished only by the InstanceId dimension. A
// key without them collapses every instance's series onto one cache entry, so
// the first one fetched answers for all of them.
//
// Dimensions are sorted, because the key has to be the same for the same series
// no matter what order the API returned them in.
func metricStatisticsCacheKey(namespace, name, region, label string, dimensions []any) string {
	key := namespace + "/" + name + "/" + region + "/" + label

	pairs := make([]string, 0, len(dimensions))
	for _, d := range dimensions {
		dimension, ok := d.(*mqlAwsCloudwatchMetricdimension)
		if !ok {
			continue
		}
		pairs = append(pairs, dimension.Name.Data+"="+dimension.Value.Data)
	}
	if len(pairs) == 0 {
		return key
	}
	sort.Strings(pairs)
	return key + "/" + strings.Join(pairs, ",")
}

// id covers the init path only, which resolves the undimensioned aggregate for
// a namespace and metric name. The dimensioned series built by
// aws.cloudwatch.metric.statistics passes its own __id, since this resource has
// no dimensions field to read them back from.
func (a *mqlAwsCloudwatchMetricstatistics) id() (string, error) {
	return metricStatisticsCacheKey(a.Namespace.Data, a.Name.Data, a.Region.Data, a.Label.Data, nil), nil
}

// allow the user to query for a specific namespace metric in a specific region
func initAwsCloudwatchMetric(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	namespaceRaw := args["namespace"]
	if namespaceRaw == nil {
		return args, nil, nil
	}

	namespace, ok := namespaceRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	regionRaw := args["region"]
	if regionRaw == nil {
		return args, nil, nil
	}

	region, ok := regionRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudwatch(region)

	ctx := context.Background()

	params := &cloudwatch.ListMetricsInput{
		Namespace:  &namespace,
		MetricName: &name,
	}
	metrics, err := svc.ListMetrics(ctx, params)
	if err != nil {
		return args, nil, err
	}
	if len(metrics.Metrics) == 0 {
		return nil, nil, errors.New("no metrics found")
	}
	if len(metrics.Metrics) > 1 {
		return nil, nil, errors.New("more than one metric found for " + namespace + " " + name + " in region " + region)
	}
	dimensions := []any{}

	metric := metrics.Metrics[0]
	for _, d := range metric.Dimensions {
		mqlDimension, err := CreateResource(runtime, "aws.cloudwatch.metricdimension",
			map[string]*llx.RawData{
				"name":  llx.StringDataPtr(d.Name),
				"value": llx.StringDataPtr(d.Value),
			})
		if err != nil {
			return args, nil, err
		}
		dimensions = append(dimensions, mqlDimension)
	}

	args["name"] = llx.StringData(name)
	args["namespace"] = llx.StringData(namespace)
	args["region"] = llx.StringData(region)
	args["dimensions"] = llx.ArrayData(dimensions, types.Resource("aws.cloudwatch.metricdimension"))

	return args, nil, nil
}

func (a *mqlAwsCloudwatchMetric) dimensions() ([]any, error) {
	name := a.Name.Data
	namespace := a.Namespace.Data
	regionVal := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudwatch(regionVal)
	ctx := context.Background()

	params := &cloudwatch.ListMetricsInput{
		Namespace:  &namespace,
		MetricName: &name,
	}
	metrics, err := svc.ListMetrics(ctx, params)
	if err != nil {
		return nil, err
	}
	if len(metrics.Metrics) == 0 {
		return nil, nil
	}
	if len(metrics.Metrics) > 1 {
		return nil, errors.New("more than one metric found for " + namespace + " " + name + " in region " + regionVal)
	}
	dimensions := []any{}

	metric := metrics.Metrics[0]
	for _, d := range metric.Dimensions {
		mqlDimension, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metricdimension",
			map[string]*llx.RawData{
				"name":  llx.StringDataPtr(d.Name),
				"value": llx.StringDataPtr(d.Value),
			})
		if err != nil {
			return nil, err
		}
		dimensions = append(dimensions, mqlDimension)
	}
	return dimensions, nil
}

// allow the user to query for a specific namespace metric in a specific region
func initAwsCloudwatchMetricstatistics(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	namespaceRaw := args["namespace"]
	if namespaceRaw == nil {
		return args, nil, nil
	}

	namespace, ok := namespaceRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	regionRaw := args["region"]
	if regionRaw == nil {
		return args, nil, nil
	}

	region, ok := regionRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudwatch(region)
	ctx := context.Background()

	now := time.Now()
	dayAgo := time.Now().Add(-24 * time.Hour)
	params := &cloudwatch.GetMetricStatisticsInput{
		MetricName: &name,
		Namespace:  &namespace,
		StartTime:  &dayAgo,
		EndTime:    &now,
		Period:     aws.Int32(3600),
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticSum, cloudwatchtypes.StatisticAverage, cloudwatchtypes.StatisticMaximum, cloudwatchtypes.StatisticMinimum},
	}
	// no pagination required
	statsResp, err := svc.GetMetricStatistics(ctx, params)
	if err != nil {
		return args, nil, err
	}
	// Every datapoint here used to be created with no id of any kind, so all 24
	// hours of them shared one empty cache key and resolved to the first.
	statsKey := metricStatisticsCacheKey(namespace, name, region, convert.ToValue(statsResp.Label), nil)

	datapoints := []any{}
	for _, datapoint := range statsResp.Datapoints {
		mqlDatapoint, err := CreateResource(runtime, "aws.cloudwatch.metric.datapoint",
			map[string]*llx.RawData{
				"__id":      llx.StringData(datapointCacheKey(statsKey, datapoint)),
				"id":        llx.StringData(formatDatapointId(datapoint)),
				"timestamp": llx.TimeDataPtr(datapoint.Timestamp),
				"maximum":   llx.FloatData(convert.ToValue(datapoint.Maximum)),
				"minimum":   llx.FloatData(convert.ToValue(datapoint.Minimum)),
				"average":   llx.FloatData(convert.ToValue(datapoint.Average)),
				"sum":       llx.FloatData(convert.ToValue(datapoint.Sum)),
				"unit":      llx.StringData(string(datapoint.Unit)),
			})
		if err != nil {
			return args, nil, err
		}
		datapoints = append(datapoints, mqlDatapoint)
	}

	args["label"] = llx.StringDataPtr(statsResp.Label)
	args["datapoints"] = llx.ArrayData(datapoints, types.Resource("aws.cloudwatch.metric.datapoint"))
	args["name"] = llx.StringData(name)
	args["namespace"] = llx.StringData(namespace)
	args["region"] = llx.StringData(region)
	return args, nil, nil
}

func (a *mqlAwsCloudwatchMetric) statistics() (*mqlAwsCloudwatchMetricstatistics, error) {
	metricName := a.Name.Data
	namespace := a.Namespace.Data
	dimensions := a.Dimensions.Data
	regionVal := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudwatch(regionVal)
	ctx := context.Background()

	now := time.Now()
	dayAgo := time.Now().Add(-24 * time.Hour)
	typedDimensions := make([]cloudwatchtypes.Dimension, len(dimensions))
	for i, d := range dimensions {
		dimension := d.(*mqlAwsCloudwatchMetricdimension)
		name := dimension.Name.Data
		val := dimension.Value.Data

		typedDimensions[i].Name = &name
		typedDimensions[i].Value = &val
	}
	params := &cloudwatch.GetMetricStatisticsInput{
		MetricName: &metricName,
		Namespace:  &namespace,
		Dimensions: typedDimensions,
		StartTime:  &dayAgo,
		EndTime:    &now,
		Period:     aws.Int32(3600),
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticSum, cloudwatchtypes.StatisticAverage, cloudwatchtypes.StatisticMaximum, cloudwatchtypes.StatisticMinimum},
	}
	// no pagination required
	statsResp, err := svc.GetMetricStatistics(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, "could not gather AWS CloudWatch stats")
	}
	statsKey := metricStatisticsCacheKey(namespace, metricName, regionVal, convert.ToValue(statsResp.Label), dimensions)

	datapoints := []any{}
	for _, datapoint := range statsResp.Datapoints {
		mqlDatapoint, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metric.datapoint",
			map[string]*llx.RawData{
				"__id":      llx.StringData(datapointCacheKey(statsKey, datapoint)),
				"id":        llx.StringData(formatDatapointId(datapoint)),
				"timestamp": llx.TimeDataPtr(datapoint.Timestamp),
				"maximum":   llx.FloatData(convert.ToValue(datapoint.Maximum)),
				"minimum":   llx.FloatData(convert.ToValue(datapoint.Minimum)),
				"average":   llx.FloatData(convert.ToValue(datapoint.Average)),
				"sum":       llx.FloatData(convert.ToValue(datapoint.Sum)),
				"unit":      llx.StringData(string(datapoint.Unit)),
			})
		if err != nil {
			return nil, err
		}
		datapoints = append(datapoints, mqlDatapoint)
	}
	mqlStat, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metricstatistics",
		map[string]*llx.RawData{
			"__id":       llx.StringData(statsKey),
			"label":      llx.StringDataPtr(statsResp.Label),
			"datapoints": llx.ArrayData(datapoints, types.Resource("aws.cloudwatch.metric.datapoint")),
			"name":       llx.StringData(metricName),
			"namespace":  llx.StringData(namespace),
			"region":     llx.StringData(regionVal),
		})
	if err != nil {
		return nil, err
	}

	return mqlStat.(*mqlAwsCloudwatchMetricstatistics), nil
}

func (a *mqlAwsCloudwatchMetricDatapoint) id() (string, error) {
	return a.Id.Data, nil
}

// datapointCacheKey identifies a datapoint within its series. formatDatapointId
// hashes the datapoint's own values, which is not enough on its own: two
// instances idling at the same value in the same hour hash identically, so the
// series has to be part of the key. The public id field keeps the hash.
func datapointCacheKey(statisticsKey string, d cloudwatchtypes.Datapoint) string {
	ts := ""
	if d.Timestamp != nil {
		ts = strconv.FormatInt(d.Timestamp.UnixNano(), 10)
	}
	return statisticsKey + "/datapoint/" + ts + "/" + formatDatapointId(d)
}

func formatDatapointId(d cloudwatchtypes.Datapoint) string {
	byteConfig, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write(byteConfig)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (a *mqlAwsCloudwatchMetric) alarms() ([]any, error) {
	metricName := a.Name.Data
	namespace := a.Namespace.Data
	regionVal := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudwatch(regionVal)
	ctx := context.Background()

	params := &cloudwatch.DescribeAlarmsForMetricInput{
		MetricName: &metricName,
		Namespace:  &namespace,
	}
	// no pagination required
	alarmsResp, err := svc.DescribeAlarmsForMetric(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, "could not gather AWS CloudWatch alarms")
	}
	res := []any{}
	for _, alarm := range alarmsResp.MetricAlarms {
		mqlAlarm, err := NewResource(a.MqlRuntime, "aws.cloudwatch.metricsalarm",
			map[string]*llx.RawData{"arn": llx.StringData(convert.ToValue(alarm.AlarmArn))})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlarm)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) alarms() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAlarms(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getAlarms(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Cloudwatch(region)
			ctx := context.Background()

			res := []any{}
			params := &cloudwatch.DescribeAlarmsInput{}
			paginator := cloudwatch.NewDescribeAlarmsPaginator(svc, params)
			for paginator.HasMorePages() {
				alarms, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, alarm := range alarms.MetricAlarms {
					actions := []any{}
					for _, action := range alarm.AlarmActions {
						mqlAlarmAction, err := NewResource(a.MqlRuntime, "aws.sns.topic",
							map[string]*llx.RawData{
								"arn":    llx.StringData(action),
								"region": llx.StringData(region),
							})
						if err != nil {
							return nil, err
						}
						actions = append(actions, mqlAlarmAction)
					}
					insuffActions := []any{}
					for _, action := range alarm.InsufficientDataActions {
						mqlInsuffAction, err := NewResource(a.MqlRuntime, "aws.sns.topic",
							map[string]*llx.RawData{
								"arn":    llx.StringData(action),
								"region": llx.StringData(region),
							})
						if err != nil {
							return nil, err
						}
						insuffActions = append(insuffActions, mqlInsuffAction)
					}

					okActions := []any{}
					for _, action := range alarm.OKActions {
						mqlokAction, err := NewResource(a.MqlRuntime, "aws.sns.topic",
							map[string]*llx.RawData{
								"arn":    llx.StringData(action),
								"region": llx.StringData(region),
							})
						if err != nil {
							return nil, err
						}
						okActions = append(okActions, mqlokAction)
					}

					dimensions := []any{}
					for _, d := range alarm.Dimensions {
						mqlDimension, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metricdimension",
							map[string]*llx.RawData{
								"name":  llx.StringDataPtr(d.Name),
								"value": llx.StringDataPtr(d.Value),
							})
						if err != nil {
							return nil, err
						}
						dimensions = append(dimensions, mqlDimension)
					}

					threshold := llx.NilData
					if alarm.Threshold != nil {
						threshold = llx.FloatData(*alarm.Threshold)
					}

					mqlAlarm, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metricsalarm",
						map[string]*llx.RawData{
							"arn":                         llx.StringDataPtr(alarm.AlarmArn),
							"metricName":                  llx.StringDataPtr(alarm.MetricName),
							"metricNamespace":             llx.StringDataPtr(alarm.Namespace),
							"region":                      llx.StringData(region),
							"state":                       llx.StringData(string(alarm.StateValue)),
							"stateReason":                 llx.StringDataPtr(alarm.StateReason),
							"stateReasonData":             llx.StringDataPtr(alarm.StateReasonData),
							"insufficientDataActions":     llx.ArrayData(insuffActions, types.Resource("aws.sns.topic")),
							"okActions":                   llx.ArrayData(okActions, types.Resource("aws.sns.topic")),
							"name":                        llx.StringDataPtr(alarm.AlarmName),
							"actions":                     llx.ArrayData(actions, types.Resource("aws.sns.topic")),
							"actionsEnabled":              llx.BoolDataPtr(alarm.ActionsEnabled),
							"comparisonOperator":          llx.StringData(string(alarm.ComparisonOperator)),
							"threshold":                   threshold,
							"thresholdMetricId":           llx.StringDataPtr(alarm.ThresholdMetricId),
							"evaluationPeriods":           llx.IntDataPtr(alarm.EvaluationPeriods),
							"datapointsToAlarm":           llx.IntDataPtr(alarm.DatapointsToAlarm),
							"period":                      llx.IntDataPtr(alarm.Period),
							"statistic":                   llx.StringData(string(alarm.Statistic)),
							"extendedStatistic":           llx.StringDataPtr(alarm.ExtendedStatistic),
							"treatMissingData":            llx.StringDataPtr(alarm.TreatMissingData),
							"unit":                        llx.StringData(string(alarm.Unit)),
							"alarmDescription":            llx.StringDataPtr(alarm.AlarmDescription),
							"dimensions":                  llx.ArrayData(dimensions, types.Resource("aws.cloudwatch.metricdimension")),
							"alarmConfigurationUpdatedAt": llx.TimeDataPtr(alarm.AlarmConfigurationUpdatedTimestamp),
							"stateUpdatedAt":              llx.TimeDataPtr(alarm.StateUpdatedTimestamp),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAlarm)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatch) logGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLogGroups(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getLogGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudwatch>getLogGroups>calling aws with region %s", region)

			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()

			params := &cloudwatchlogs.DescribeLogGroupsInput{}
			paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(svc, params)
			res := []any{}
			for paginator.HasMorePages() {
				logGroups, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather AWS CloudWatch log groups")
				}
				for _, loggroup := range logGroups.LogGroups {
					// Only fetch tags eagerly when tag-based filters are configured
					var groupTags map[string]string
					if conn.Filters.General.HasTags() {
						tagsResp, err := svc.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: loggroup.LogGroupArn})
						if err == nil {
							groupTags = tagsResp.Tags
							if conn.Filters.General.IsFilteredOutByTags(groupTags) {
								log.Debug().Interface("log_group", loggroup.LogGroupName).Interface("tags", groupTags).Msg("excluding log group due to tag filters")
								continue
							}
						} else {
							log.Warn().Err(err).Interface("log_group", loggroup.LogGroupName).Msg("could not get tags for log group")
						}
					}

					lg, err := buildLogGroupResource(a.MqlRuntime, region, loggroup)
					if err != nil {
						return nil, err
					}
					if groupTags != nil {
						lg.cacheTags = groupTags
						lg.tagsFetched = true
					}
					res = append(res, lg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// buildLogGroupResource maps an SDK log group into an aws.cloudwatch.loggroup
// resource. Shared by the list path and the targeted init lookup.
func buildLogGroupResource(runtime *plugin.Runtime, region string, loggroup cloudwatchlogstypes.LogGroup) (*mqlAwsCloudwatchLoggroup, error) {
	args := make(map[string]*llx.RawData)
	args["arn"] = llx.StringDataPtr(loggroup.Arn)
	args["name"] = llx.StringDataPtr(loggroup.LogGroupName)
	args["region"] = llx.StringData(region)
	// CloudWatch signals "never expire" by returning no retention at all.
	// Defaulting that to 0 made the strongest retention read as the weakest, so
	// `retentionInDays >= 365` excluded exactly the groups that keep their logs
	// forever. Null is the honest reading, and neverExpires is what a filter
	// can assert on directly.
	args["retentionInDays"] = llx.IntDataPtr(loggroup.RetentionInDays)
	args["neverExpires"] = llx.BoolData(loggroup.RetentionInDays == nil)
	args["createdAt"] = llx.TimeDataPtr(int64MillisToTime(loggroup.CreationTime))
	args["dataProtectionStatus"] = llx.StringData(string(loggroup.DataProtectionStatus))
	args["deletionProtectionEnabled"] = llx.BoolDataPtr(loggroup.DeletionProtectionEnabled)
	args["logGroupClass"] = llx.StringData(string(loggroup.LogGroupClass))
	args["storedBytes"] = llx.IntDataDefault(loggroup.StoredBytes, 0)

	inherited := make([]any, 0, len(loggroup.InheritedProperties))
	for _, ip := range loggroup.InheritedProperties {
		inherited = append(inherited, string(ip))
	}
	args["inheritedProperties"] = llx.ArrayData(inherited, types.String)

	// add kms key if there is one
	if loggroup.KmsKeyId != nil {
		mqlKeyResource, err := NewResource(runtime, ResourceAwsKmsKey,
			map[string]*llx.RawData{
				"arn": llx.StringDataPtr(loggroup.KmsKeyId),
			})
		if err != nil {
			args["kmsKey"] = llx.NilData
		} else {
			mqlKey := mqlKeyResource.(*mqlAwsKmsKey)
			args["kmsKey"] = llx.ResourceData(mqlKey, mqlKey.MqlName())
		}
	} else {
		args["kmsKey"] = llx.NilData
	}

	mqlLogGroup, err := CreateResource(runtime, ResourceAwsCloudwatchLoggroup, args)
	if err != nil {
		return nil, err
	}
	return mqlLogGroup.(*mqlAwsCloudwatchLoggroup), nil
}

func initAwsCloudwatchLoggroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformCloudwatchLoggroup); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch cloudwatch log group")
	}

	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsCloudwatchLoggroup, arnVal); cached != nil {
		return args, cached, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	// Targeted lookup: derive the region + group name from the ARN and fetch
	// just this one log group (by name prefix) instead of describing every log
	// group in every region. Only attempt this for log groups owned by the
	// account we're connected to; cross-account references fall through to the
	// scan + placeholder path below.
	region := ""
	name := ""
	sameAccount := true
	if parsed, parseErr := arn.Parse(arnVal); parseErr == nil {
		region = parsed.Region
		name = strings.TrimSuffix(strings.TrimPrefix(parsed.Resource, "log-group:"), ":*")
		sameAccount = parsed.AccountID == "" || parsed.AccountID == conn.AccountId()
	}
	if args["region"] != nil {
		if r, ok := args["region"].Value.(string); ok && r != "" {
			region = r
		}
	}
	if region != "" && name != "" && sameAccount {
		svc := conn.CloudwatchLogs(region)
		// DescribeLogGroups only filters by name *prefix*, so other groups can
		// share this group's prefix and the exact match may land on a later
		// page. Paginate and match exactly; on access-denied fall through to the
		// scan + placeholder path below.
		paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(svc, &cloudwatchlogs.DescribeLogGroupsInput{
			LogGroupNamePrefix: &name,
		})
		for paginator.HasMorePages() {
			out, err := paginator.NextPage(context.Background())
			if err != nil {
				if Is400AccessDeniedError(err) {
					break
				}
				return nil, nil, err
			}
			for i := range out.LogGroups {
				if convert.ToValue(out.LogGroups[i].LogGroupName) == name {
					lg, err := buildLogGroupResource(runtime, region, out.LogGroups[i])
					if err != nil {
						return nil, nil, err
					}
					return args, lg, nil
				}
			}
		}
	}

	// Fallback: scan all log groups (e.g. cross-account references or when the
	// ARN carries no usable region).
	obj, err := CreateResource(runtime, "aws.cloudwatch", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cloudwatch := obj.(*mqlAwsCloudwatch)
	rawResources := cloudwatch.GetLogGroups()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	// CloudWatch's DescribeLogGroups returns ARNs with a trailing ":*" suffix;
	// other AWS services (e.g. EventBridge Pipes LogConfiguration) return the
	// bare ARN without it. Compare both with and without the suffix so init
	// resolves correctly regardless of which form the caller passes.
	arnNoStar := strings.TrimSuffix(arnVal, ":*")
	for _, rawResource := range rawResources.Data {
		logGroup := rawResource.(*mqlAwsCloudwatchLoggroup)
		mqlLgArn := logGroup.Arn.Data

		if mqlLgArn == arnVal || strings.TrimSuffix(mqlLgArn, ":*") == arnNoStar {
			return args, logGroup, nil
		}
	}

	// If the log group is in a different account (e.g., organizational trail referencing
	// a log group in the management account), create a placeholder resource with basic
	// info extracted from the ARN instead of failing.
	if parsedArn, parseErr := arn.Parse(arnVal); parseErr == nil && parsedArn.AccountID != conn.AccountId() {
		log.Warn().Str("arn", arnVal).Str("currentAccount", conn.AccountId()).Str("logGroupAccount", parsedArn.AccountID).Msg("cross-account CloudWatch log group reference")
		grpRegion, groupName := parseLogGroupArn(arnVal)
		if grpRegion == "" || groupName == "" {
			return nil, nil, errors.New("cloudwatch log group does not exist")
		}
		args["name"] = llx.StringData(groupName)
		args["region"] = llx.StringData(grpRegion)
		// Nothing about this group was read, so neither field has a value to
		// report. -1 was a second sentinel for the same field, which arithmetic
		// accepts as silently as 0 did.
		args["retentionInDays"] = llx.NilData
		args["neverExpires"] = llx.NilData
		args["storedBytes"] = llx.NilData
		args["dataProtectionStatus"] = llx.StringData("")
		args["deletionProtectionEnabled"] = llx.BoolData(false)
		args["logGroupClass"] = llx.StringData("")
		args["inheritedProperties"] = llx.ArrayData([]any{}, types.String)
		return args, nil, nil
	}

	return nil, nil, errors.New("cloudwatch log group does not exist")
}

type mqlAwsCloudwatchLoggroupInternal struct {
	cacheTags   map[string]string
	tagsFetched bool
	tagsLock    sync.Mutex
}

func (a *mqlAwsCloudwatchLoggroup) tags() (map[string]any, error) {
	if a.tagsFetched {
		return toInterfaceMap(a.cacheTags), nil
	}
	a.tagsLock.Lock()
	defer a.tagsLock.Unlock()
	if a.tagsFetched {
		return toInterfaceMap(a.cacheTags), nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudwatchLogs(a.Region.Data)
	ctx := context.Background()

	// CloudWatch Logs stores the log-group ARN with a trailing ":*" wildcard,
	// which ListTagsForResource rejects as an invalid resourceArn. Strip it.
	arnVal := strings.TrimSuffix(a.Arn.Data, ":*")
	tagsResp, err := svc.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: &arnVal})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.tagsFetched = true
			return nil, nil
		}
		return nil, err
	}
	a.cacheTags = tagsResp.Tags
	a.tagsFetched = true
	return toInterfaceMap(tagsResp.Tags), nil
}

func (a *mqlAwsCloudwatchLoggroup) kmsKey() (*mqlAwsKmsKey, error) {
	// Return the key resolved at creation time when present; only mark the field
	// null (with an explicit state) when no key was set — e.g. the cross-account
	// placeholder path that never populates kmsKey. Unconditionally nulling here
	// would drop the KMS key on log groups that actually have one.
	if a.KmsKey.Data == nil {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return a.KmsKey.Data, nil
}

func (a *mqlAwsCloudwatchLoggroup) id() (string, error) {
	return a.Arn.Data, nil
}

// parseLogGroupArn extracts the region and group name from a CloudWatch log group ARN.
// ARN format: arn:aws:logs:<region>:<account>:log-group:<name>:*
// Group names may contain colons, so we rejoin parts 6..n-1 (stripping trailing "*").
func parseLogGroupArn(arnValue string) (region string, groupName string) {
	parts := strings.Split(arnValue, ":")
	if len(parts) < 8 {
		return "", ""
	}
	region = parts[3]
	// Rejoin parts 6 through second-to-last to handle names with colons
	groupName = strings.Join(parts[6:len(parts)-1], ":")
	return
}

func (a *mqlAwsCloudwatchLoggroup) metricsFilters() ([]any, error) {
	arnValue := a.Arn.Data

	region, groupName := parseLogGroupArn(arnValue)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudwatchLogs(region)
	ctx := context.Background()

	params := &cloudwatchlogs.DescribeMetricFiltersInput{LogGroupName: &groupName}
	paginator := cloudwatchlogs.NewDescribeMetricFiltersPaginator(svc, params)
	metricFilters := []any{}
	for paginator.HasMorePages() {
		metricsResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather log metric filters")
		}
		for _, m := range metricsResp.MetricFilters {
			mqlCloudwatchMetrics := []any{}
			transformations := make([]any, 0, len(m.MetricTransformations))
			for _, mt := range m.MetricTransformations {
				mqlAwsMetric, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.metric",
					map[string]*llx.RawData{
						"name":      llx.StringDataPtr(mt.MetricName),
						"namespace": llx.StringDataPtr(mt.MetricNamespace),
						"region":    llx.StringData(region),
					})
				if err != nil {
					return nil, err
				}
				mqlCloudwatchMetrics = append(mqlCloudwatchMetrics, mqlAwsMetric)

				dims := map[string]any{}
				for dk, dv := range mt.Dimensions {
					dims[dk] = dv
				}
				transformation := map[string]any{
					"metricName":      convert.ToValue(mt.MetricName),
					"metricNamespace": convert.ToValue(mt.MetricNamespace),
					"metricValue":     convert.ToValue(mt.MetricValue),
					"dimensions":      dims,
					"unit":            string(mt.Unit),
				}
				if mt.DefaultValue != nil {
					transformation["defaultValue"] = *mt.DefaultValue
				}
				transformations = append(transformations, transformation)
			}
			mqlAwsLogGroupMetricFilters, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.loggroup.metricsfilter",
				map[string]*llx.RawData{
					"id":                     llx.StringData(groupName + "/" + region + "/" + convert.ToValue(m.FilterName)),
					"filterName":             llx.StringDataPtr(m.FilterName),
					"filterPattern":          llx.StringDataPtr(m.FilterPattern),
					"logGroupName":           llx.StringData(groupName),
					"metrics":                llx.ArrayData(mqlCloudwatchMetrics, types.Resource("aws.cloudwatch.metric")),
					"metricTransformations":  llx.ArrayData(transformations, types.Dict),
					"applyOnTransformedLogs": llx.BoolData(m.ApplyOnTransformedLogs),
					"createdAt":              llx.TimeDataPtr(int64MillisToTime(m.CreationTime)),
				})
			if err != nil {
				return nil, err
			}
			metricFilters = append(metricFilters, mqlAwsLogGroupMetricFilters)
		}
	}
	return metricFilters, nil
}

func (a *mqlAwsCloudwatchLoggroupMetricsfilter) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAwsCloudwatchMetricsalarmInternal struct {
	lazyTags
}

func (a *mqlAwsCloudwatchMetricsalarm) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudwatchMetricsalarm) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		alarmArn := a.Arn.Data

		svc := conn.Cloudwatch(a.Region.Data)
		resp, err := svc.ListTagsForResource(context.Background(), &cloudwatch.ListTagsForResourceInput{
			ResourceARN: &alarmArn,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return tagsToMap(resp.Tags,
			func(t cloudwatchtypes.Tag) *string { return t.Key },
			func(t cloudwatchtypes.Tag) *string { return t.Value }), nil
	})
}

// cloudwatchMetricID builds the cache key for a CloudWatch metric. ListMetrics
// returns one entry per (Namespace, MetricName, Dimensions) tuple, so the
// dimensions are part of the metric's identity: without them every
// AWS/EC2 CPUUtilization metric in a region collapses onto one resource and
// each instance reports the first instance's dimensions and statistics.
// Dimensions are sorted so the key is stable regardless of API ordering.
func cloudwatchMetricID(region, namespace, name string, dimensions []cloudwatchtypes.Dimension) string {
	pairs := make([]string, 0, len(dimensions))
	for _, d := range dimensions {
		pairs = append(pairs, convert.ToValue(d.Name)+"="+convert.ToValue(d.Value))
	}
	sort.Strings(pairs)

	id := region + "/" + namespace + "/" + name
	if len(pairs) > 0 {
		id += "/" + strings.Join(pairs, ",")
	}
	return id
}

func (a *mqlAwsCloudwatchMetric) id() (string, error) {
	// Dimensions are resources rather than raw values here, so the collection
	// path passes an explicit "__id" built by cloudwatchMetricID (which wins
	// over this method). This remains as the codegen-required fallback.
	region := a.Region.Data
	namespace := a.Namespace.Data
	name := a.Name.Data
	return region + "/" + namespace + "/" + name, nil
}

func int64MillisToTime(ms *int64) *time.Time {
	if ms == nil {
		return nil
	}
	t := time.UnixMilli(*ms)
	return &t
}

func (a *mqlAwsCloudwatchLoggroup) subscriptionFilters() ([]any, error) {
	arnValue := a.Arn.Data

	region, groupName := parseLogGroupArn(arnValue)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudwatchLogs(region)
	ctx := context.Background()

	params := &cloudwatchlogs.DescribeSubscriptionFiltersInput{LogGroupName: &groupName}
	paginator := cloudwatchlogs.NewDescribeSubscriptionFiltersPaginator(svc, params)
	res := []any{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(err, "could not gather subscription filters")
		}
		for _, sf := range page.SubscriptionFilters {
			mqlSF, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.loggroup.subscriptionfilter",
				map[string]*llx.RawData{
					"id":                     llx.StringData(groupName + "/" + region + "/" + convert.ToValue(sf.FilterName)),
					"filterName":             llx.StringDataPtr(sf.FilterName),
					"filterPattern":          llx.StringDataPtr(sf.FilterPattern),
					"destinationArn":         llx.StringDataPtr(sf.DestinationArn),
					"distribution":           llx.StringData(string(sf.Distribution)),
					"applyOnTransformedLogs": llx.BoolData(sf.ApplyOnTransformedLogs),
					"createdAt":              llx.TimeDataPtr(int64MillisToTime(sf.CreationTime)),
					"region":                 llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			mqlSF.(*mqlAwsCloudwatchLoggroupSubscriptionfilter).cacheRoleArn = convert.ToValue(sf.RoleArn)
			res = append(res, mqlSF)
		}
	}
	return res, nil
}

func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) iamRole() (*mqlAwsIamRole, error) {
	arnVal := a.cacheRoleArn
	if arnVal == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// destinationResource resolves the subscription filter's destination ARN to a
// typed resource, but only when the ARN belongs to wantService. A filter has
// exactly one destination, so the accessors for the other services resolve to
// null.
func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) destinationResource(wantService, resourceName string) (plugin.Resource, bool, error) {
	arnVal := a.DestinationArn.Data
	if arnVal == "" {
		return nil, false, nil
	}
	parsed, err := arn.Parse(arnVal)
	if err != nil {
		log.Warn().Str("arn", arnVal).Err(err).Msg("could not parse subscription filter destination ARN")
		return nil, false, nil
	}
	if parsed.Service != wantService {
		return nil, false, nil
	}
	res, err := NewResource(a.MqlRuntime, resourceName,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}

func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	res, ok, err := a.destinationResource("lambda", "aws.lambda.function")
	if err != nil || !ok {
		a.LambdaFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) kinesisStream() (*mqlAwsKinesisStream, error) {
	res, ok, err := a.destinationResource("kinesis", "aws.kinesis.stream")
	if err != nil || !ok {
		a.KinesisStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, err
	}
	return res.(*mqlAwsKinesisStream), nil
}

func (a *mqlAwsCloudwatchLoggroupSubscriptionfilter) firehoseDeliveryStream() (*mqlAwsKinesisFirehoseDeliveryStream, error) {
	res, ok, err := a.destinationResource("firehose", "aws.kinesis.firehoseDeliveryStream")
	if err != nil || !ok {
		a.FirehoseDeliveryStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, err
	}
	return res.(*mqlAwsKinesisFirehoseDeliveryStream), nil
}

func (a *mqlAwsCloudwatchLoggroup) logStreams() ([]any, error) {
	arnValue := a.Arn.Data

	region, groupName := parseLogGroupArn(arnValue)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudwatchLogs(region)
	ctx := context.Background()

	params := &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: &groupName}
	paginator := cloudwatchlogs.NewDescribeLogStreamsPaginator(svc, params)
	res := []any{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(err, "could not gather log streams")
		}
		for _, ls := range page.LogStreams {
			mqlLS, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.loggroup.logstream",
				map[string]*llx.RawData{
					"__id":                llx.StringData(region + "/" + groupName + "/" + convert.ToValue(ls.LogStreamName)),
					"arn":                 llx.StringDataPtr(ls.Arn),
					"name":                llx.StringDataPtr(ls.LogStreamName),
					"createdAt":           llx.TimeDataPtr(int64MillisToTime(ls.CreationTime)),
					"firstEventTimestamp": llx.TimeDataPtr(int64MillisToTime(ls.FirstEventTimestamp)),
					"lastEventTimestamp":  llx.TimeDataPtr(int64MillisToTime(ls.LastEventTimestamp)),
					"lastIngestionTime":   llx.TimeDataPtr(int64MillisToTime(ls.LastIngestionTime)),
					"region":              llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlLS)
		}
	}
	return res, nil
}

// id is the fallback identity for a log stream built without an explicit key.
// It cannot qualify the stream by its log group, because a log stream resource
// carries no reference to one and a cache field would be assigned only after
// CreateResource has already computed the key. The lister therefore passes a
// group-qualified __id directly, which is what actually keys these: Lambda
// names every stream YYYY/MM/DD/[$LATEST]<hex>, so the same stream name in two
// function log groups is routine, and region plus name alone merged them into
// a single row.
func (a *mqlAwsCloudwatchLoggroupLogstream) id() (string, error) {
	// Use a composite ID instead of the ARN, since the ARN can be nil for some
	// streams.
	return a.Region.Data + "/" + a.Name.Data, nil
}

func (a *mqlAwsCloudwatch) resourcePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getResourcePolicies(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getResourcePolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()

			res := []any{}
			var nextToken *string
			for {
				resp, err := svc.DescribeResourcePolicies(ctx, &cloudwatchlogs.DescribeResourcePoliciesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, rp := range resp.ResourcePolicies {
					mqlRP, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.resourcepolicy",
						map[string]*llx.RawData{
							"policyName":      llx.StringDataPtr(rp.PolicyName),
							"policyDocument":  llx.StringDataPtr(rp.PolicyDocument),
							"lastUpdatedTime": llx.TimeDataPtr(int64MillisToTime(rp.LastUpdatedTime)),
							"scope":           llx.StringData(string(rp.PolicyScope)),
							"resourceArn":     llx.StringDataPtr(rp.ResourceArn),
							"region":          llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRP)
				}
				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchResourcepolicy) id() (string, error) {
	return a.Region.Data + "/" + a.PolicyName.Data, nil
}

func initAwsCloudwatchMetricsalarm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch AWS CloudWatch metrics alarm")
	}

	// load all cloudwatch metrics alarm
	obj, err := CreateResource(runtime, "aws.cloudwatch", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	aws := obj.(*mqlAwsCloudwatch)

	rawResources := aws.GetAlarms()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		alarm := rawResource.(*mqlAwsCloudwatchMetricsalarm)
		if alarm.Arn.Data == arnVal {
			return args, alarm, nil
		}
	}
	return nil, nil, errors.New("cloudwatch alarm does not exist")
}

type mqlAwsCloudwatchLoggroupSubscriptionfilterInternal struct {
	cacheRoleArn string
}
