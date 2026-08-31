// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsSns) id() (string, error) {
	return "aws.sns", nil
}

func (a *mqlAwsSnsTopic) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSnsSubscription) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSns) topics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTopics(conn), 5)
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

// initAwsSnsTopic resolves a single SNS topic. Topics are keyed by ARN, and
// every topic API call needs the region that ARN carries, so the region is
// always derived from it. When the resource is requested for a discovered
// asset (aws-sns-topic platform) no args are passed and the ARN comes from the
// connection's asset identifier.
func initAwsSnsTopic(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSnsTopic); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch sns topic")
	}
	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'arn' in aws.sns.topic initialization, it must be a string")
	}
	parsedArn, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}

	args["region"] = llx.StringData(parsedArn.Region)
	return args, nil, nil
}

func (a *mqlAwsSns) getTopics(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sns(region)
			ctx := context.Background()
			res := []any{}

			params := &sns.ListTopicsInput{}
			paginator := sns.NewListTopicsPaginator(svc, params)
			for paginator.HasMorePages() {
				topics, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				// Pre-fetch tags in parallel when tag-based filters are configured.
				// SNS has no batch tags endpoint, so this turns a sequential
				// per-topic call into bounded concurrent calls.
				var tagsByArn map[string]map[string]string
				if conn.Filters.General.HasTags() {
					arns := make([]string, 0, len(topics.Topics))
					for _, topic := range topics.Topics {
						if topic.TopicArn != nil {
							arns = append(arns, *topic.TopicArn)
						}
					}
					tagsByArn = fetchTagsConcurrently(ctx, arns, func(ctx context.Context, topicArn string) (map[string]string, error) {
						tags, err := getSNSTags(ctx, svc, &topicArn)
						if err != nil {
							return nil, err
						}
						return mapStringInterfaceToStringString(tags), nil
					})
				}

				for _, topic := range topics.Topics {
					args := map[string]*llx.RawData{
						"__id":   llx.StringDataPtr(topic.TopicArn),
						"arn":    llx.StringDataPtr(topic.TopicArn),
						"region": llx.StringData(region),
					}
					if conn.Filters.General.HasTags() {
						tags, fetched := tagsByArn[convert.ToValue(topic.TopicArn)]
						if conn.Filters.General.IsFilteredOutByTags(tags) {
							log.Debug().Interface("topic", topic.TopicArn).Msg("excluding sns topic due to filters")
							continue
						}
						// Seed the tags we already paid for; discovery reads them
						// back immediately and would otherwise re-fetch. Only seed
						// a tag set we actually read - publishing an empty map for
						// a topic whose ListTagsForResource call failed would
						// report "no tags" as fact. Leaving it unset keeps the
						// field lazy.
						if fetched {
							args["tags"] = llx.MapData(stringMapToAny(tags), mqltypes.String)
						}
					}

					mqlTopic, err := CreateResource(a.MqlRuntime, "aws.sns.topic", args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTopic)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSnsTopicInternal struct {
	fetched   bool
	topicAtts map[string]string
	lock      sync.Mutex
}

func (a *mqlAwsSnsTopic) fetchTopicAttributes() (map[string]string, error) {
	if a.fetched {
		return a.topicAtts, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.topicAtts, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sns(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: &arn})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.topicAtts = resp.Attributes
	return a.topicAtts, nil
}

// cachedFifoTopic reports whether the topic is FIFO, but only when the topic
// attributes have already been read. known is false when nothing has been
// fetched yet, so callers can decide whether the answer is worth an API call.
func (a *mqlAwsSnsTopic) cachedFifoTopic() (isFifo bool, known bool) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if !a.fetched {
		return false, false
	}
	return a.topicAtts["FifoTopic"] == "true", true
}

func (a *mqlAwsSnsTopic) attributes() (any, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(atts)
}

// SNS omits SignatureVersion and TracingConfig from GetTopicAttributes unless
// the topic was explicitly configured with them, and the value in force on such
// a topic is the documented service default: signature version 1, and
// PassThrough tracing. Reporting the default rather than "" is a deliberate
// departure from reporting only what was read: these are settings the service
// applies to the topic right now, not evidence we failed to gather. Reporting
// "" would put every never-configured topic outside the enum the field
// documents, so `signatureVersion == "1"` would miss the majority of SigV1
// topics.
const (
	snsDefaultSignatureVersion = "1"
	snsDefaultTracingConfig    = "PassThrough"
)

// snsAttributeOrDefault returns the attribute SNS reported, or the service
// default in force when SNS omitted it.
func snsAttributeOrDefault(atts map[string]string, name string, def string) string {
	if v := atts[name]; v != "" {
		return v
	}
	return def
}

func (a *mqlAwsSnsTopic) signatureVersion() (string, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return "", err
	}
	return snsAttributeOrDefault(atts, "SignatureVersion", snsDefaultSignatureVersion), nil
}

func (a *mqlAwsSnsTopic) owner() (string, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return "", err
	}
	return atts["Owner"], nil
}

func (a *mqlAwsSnsTopic) kmsMasterKey() (*mqlAwsKmsKey, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return nil, err
	}
	keyId := atts["KmsMasterKeyId"]
	if keyId != "" {
		mqlKeyResource, err := NewResource(a.MqlRuntime, "aws.kms.key",
			map[string]*llx.RawData{
				"arn":    llx.StringData(keyId),
				"region": llx.StringData(a.Region.Data),
			},
		)
		if err != nil {
			return nil, err
		}
		return mqlKeyResource.(*mqlAwsKmsKey), nil
	}
	a.KmsMasterKey.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsSnsTopic) policy() (any, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return nil, err
	}
	val, ok := atts["Policy"]
	if !ok || val == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return convert.JsonToDict(result)
}

func (a *mqlAwsSnsTopic) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Sns(region)
	ctx := context.Background()

	return getSNSTags(ctx, svc, &arn)
}

func getSNSTags(ctx context.Context, svc *sns.Client, arn *string) (map[string]any, error) {
	resp, err := svc.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{ResourceArn: arn})
	var respErr *http.ResponseError
	if err != nil {
		if errors.As(err, &respErr) {
			if respErr.HTTPStatusCode() == 404 || respErr.HTTPStatusCode() == 400 { // some sns topics do not support tags..
				return nil, nil
			}
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, t := range resp.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsSnsTopic) subscriptions() ([]any, error) {
	arnValue := a.Arn.Data
	regionVal := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Sns(regionVal)
	ctx := context.Background()

	mqlSubs := []any{}
	params := &sns.ListSubscriptionsByTopicInput{TopicArn: &arnValue}
	paginator := sns.NewListSubscriptionsByTopicPaginator(svc, params)
	for paginator.HasMorePages() {
		subsByTopic, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range subsByTopic.Subscriptions {
			// Pending subscriptions have ARN "PendingConfirmation" which is not unique.
			// Synthesize a stable __id from topic ARN + protocol + endpoint.
			subId := convert.ToValue(sub.SubscriptionArn)
			if !arn.IsARN(subId) {
				subId = arnValue + "/" + convert.ToValue(sub.Protocol) + "/" + convert.ToValue(sub.Endpoint)
			}
			mqlSub, err := CreateResource(a.MqlRuntime, "aws.sns.subscription",
				map[string]*llx.RawData{
					"__id":     llx.StringData(subId),
					"arn":      llx.StringDataPtr(sub.SubscriptionArn),
					"protocol": llx.StringDataPtr(sub.Protocol),
					"endpoint": llx.StringDataPtr(sub.Endpoint),
					"owner":    llx.StringDataPtr(sub.Owner),
					"region":   llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			mqlSub.(*mqlAwsSnsSubscription).cacheTopicArn = sub.TopicArn
			mqlSubs = append(mqlSubs, mqlSub)
		}
	}
	return mqlSubs, nil
}

// Internal caching for subscription attributes
type mqlAwsSnsSubscriptionInternal struct {
	cacheTopicArn *string
	fetched       bool
	// unconfirmed marks a subscription whose ARN is the literal
	// "PendingConfirmation" placeholder. SNS has no attributes to give for
	// one, so attrs stays nil and every attribute-backed field reads null.
	unconfirmed bool
	attrs       map[string]string
	lock        sync.Mutex
}

func (a *mqlAwsSnsSubscription) topic() (*mqlAwsSnsTopic, error) {
	if a.cacheTopicArn == nil || *a.cacheTopicArn == "" {
		a.Topic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheTopicArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsSnsSubscription) fetchAttributes() (map[string]string, error) {
	if a.fetched {
		return a.attrs, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.attrs, nil
	}

	arnVal := a.Arn.Data

	// Unconfirmed subscriptions have ARN set to "PendingConfirmation" which is
	// not a valid ARN. GetSubscriptionAttributes will reject it, so no
	// attribute was ever read for this subscription. Return no attributes
	// rather than a synthesized map: fabricating one would report
	// confirmationWasAuthenticated as a measured false ("not authenticated")
	// when the truth is that the subscription is not yet confirmed.
	if !arn.IsARN(arnVal) {
		a.fetched = true
		a.unconfirmed = true
		a.attrs = nil
		return nil, nil
	}

	regionVal := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sns(regionVal)
	ctx := context.Background()

	resp, err := svc.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{
		SubscriptionArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}

	a.fetched = true
	a.attrs = resp.Attributes
	return a.attrs, nil
}

// isUnconfirmed reports whether the subscription is still awaiting
// confirmation, in which case SNS holds no attributes for it and every
// attribute-backed field must read null rather than a zero value.
func (a *mqlAwsSnsSubscription) isUnconfirmed() bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.unconfirmed
}

func (a *mqlAwsSnsSubscription) attributes() (any, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	if a.isUnconfirmed() {
		a.Attributes.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.JsonToDict(attrs)
}

func (a *mqlAwsSnsSubscription) rawMessageDelivery() (bool, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return false, err
	}
	if a.isUnconfirmed() {
		a.RawMessageDelivery.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return attrs["RawMessageDelivery"] == "true", nil
}

func (a *mqlAwsSnsSubscription) filterPolicy() (any, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	val, ok := attrs["FilterPolicy"]
	if !ok || val == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return convert.JsonToDict(result)
}

func (a *mqlAwsSnsSubscription) filterPolicyScope() (string, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return "", err
	}
	if a.isUnconfirmed() {
		a.FilterPolicyScope.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return attrs["FilterPolicyScope"], nil
}

func (a *mqlAwsSnsSubscription) redrivePolicy() (any, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	val, ok := attrs["RedrivePolicy"]
	if !ok || val == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return convert.JsonToDict(result)
}

func (a *mqlAwsSnsSubscription) confirmationWasAuthenticated() (bool, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return false, err
	}
	if a.isUnconfirmed() {
		// Not "the confirmation was unauthenticated": there has been no
		// confirmation to authenticate yet.
		a.ConfirmationWasAuthenticated.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return attrs["ConfirmationWasAuthenticated"] == "true", nil
}

func (a *mqlAwsSnsSubscription) deliveryPolicy() (any, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	val, ok := attrs["DeliveryPolicy"]
	if !ok || val == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return convert.JsonToDict(result)
}

func (a *mqlAwsSnsSubscription) pendingConfirmation() (bool, error) {
	attrs, err := a.fetchAttributes()
	if err != nil {
		return false, err
	}
	// A "PendingConfirmation" placeholder ARN is itself the answer: the
	// subscription exists and is unconfirmed. This one stays a measured true.
	if a.isUnconfirmed() {
		return true, nil
	}
	return attrs["PendingConfirmation"] == "true", nil
}

func (a *mqlAwsSnsTopic) fifoTopic() (bool, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return false, err
	}
	return atts["FifoTopic"] == "true", nil
}

func (a *mqlAwsSnsTopic) contentBasedDeduplication() (bool, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return false, err
	}
	return atts["ContentBasedDeduplication"] == "true", nil
}

func (a *mqlAwsSnsTopic) tracingConfig() (string, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return "", err
	}
	return snsAttributeOrDefault(atts, "TracingConfig", snsDefaultTracingConfig), nil
}

func (a *mqlAwsSnsTopic) displayName() (string, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return "", err
	}
	return atts["DisplayName"], nil
}

func (a *mqlAwsSnsTopic) deliveryPolicy() (any, error) {
	atts, err := a.fetchTopicAttributes()
	if err != nil {
		return nil, err
	}
	val, ok := atts["DeliveryPolicy"]
	if !ok || val == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return convert.JsonToDict(result)
}

// isSnsOperationUnsupported reports whether SNS answered that the operation
// does not apply to this topic. SNS rejects GetDataProtectionPolicy on a FIFO
// topic with a 400 InvalidAction ("Operation (GetDataProtectionPolicy) is not
// supported on FIFO topics"), which says the field does not exist for that
// topic rather than that the read failed.
//
// Deliberately narrow: it matches the InvalidAction code alone and never a
// denial or a throttle, so an AccessDenied still surfaces as an error instead
// of becoming a silent null.
func isSnsOperationUnsupported(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "InvalidAction"
}

func (a *mqlAwsSnsTopic) dataProtectionPolicy() (any, error) {
	// FIFO topics have no data protection policy, and SNS rejects the call
	// rather than answering it. When the topic attributes are already in hand
	// the FIFO answer is free, so skip a call that can only fail.
	if isFifo, known := a.cachedFifoTopic(); known && isFifo {
		a.DataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sns(a.Region.Data)
	ctx := context.Background()
	arnVal := a.Arn.Data

	resp, err := svc.GetDataProtectionPolicy(ctx, &sns.GetDataProtectionPolicyInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.DataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		if isSnsOperationUnsupported(err) {
			a.DataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.DataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if resp.DataProtectionPolicy == nil || *resp.DataProtectionPolicy == "" {
		a.DataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	var policy map[string]any
	if err := json.Unmarshal([]byte(*resp.DataProtectionPolicy), &policy); err != nil {
		return nil, err
	}
	return convert.JsonToDict(policy)
}
