// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsSqs) id() (string, error) {
	return "aws.sqs", nil
}

func (a *mqlAwsSqsQueue) id() (string, error) {
	return a.Url.Data, nil
}

// sqsQueueName returns the queue name carried by an SQS queue URL, which is
// always its last path segment. For
// "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue" that is
// "MyQueue".
func sqsQueueName(queueURL string) string {
	if i := strings.LastIndex(queueURL, "/"); i >= 0 {
		return queueURL[i+1:]
	}
	return queueURL
}

// regionFromSqsQueueURL returns the region encoded in an SQS queue URL host.
// It covers the standard "sqs.<region>.amazonaws.com" host, its FIPS
// "sqs-fips.<region>.amazonaws.com" variant, and the legacy
// "<region>.queue.amazonaws.com" host. It returns "" when the host carries no
// region, such as the region-less legacy "queue.amazonaws.com".
func regionFromSqsQueueURL(queueURL string) string {
	u, err := url.Parse(queueURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) < 3 {
		return ""
	}
	switch {
	case parts[0] == "sqs" || parts[0] == "sqs-fips":
		return parts[1]
	case parts[1] == "queue":
		return parts[0]
	}
	return ""
}

// resolvedSqsQueueByArn returns the queue this ARN names out of the account's
// queue list, or nil.
//
// It deliberately reads the list only when it is *already* resolved rather than
// calling GetQueues: for a one-off query against a single queue, listing every
// queue in every region costs more than the GetQueueUrl it would save. During a
// scan the list is always resolved, because discovery walks it to build the
// queue assets in the first place.
//
// The queue name and owning account are the URL's path, whatever form the
// hostname takes (sqs.<region>., sqs-fips.<region>., <region>.queue.), so
// matching on the path plus the region the hostname implies does not assume a
// commercial endpoint.
func resolvedSqsQueueByArn(runtime *plugin.Runtime, queueArn arn.ARN) *mqlAwsSqsQueue {
	obj, err := CreateResource(runtime, ResourceAwsSqs, map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	sqsRes, ok := obj.(*mqlAwsSqs)
	if !ok || !sqsRes.Queues.IsSet() || sqsRes.Queues.Error != nil {
		return nil
	}

	wantPath := "/" + queueArn.AccountID + "/" + queueArn.Resource
	for _, raw := range sqsRes.Queues.Data {
		q, ok := raw.(*mqlAwsSqsQueue)
		if !ok || !q.Url.IsSet() {
			continue
		}
		u, err := url.Parse(q.Url.Data)
		if err != nil || u.Path != wantPath {
			continue
		}
		if regionFromSqsQueueURL(q.Url.Data) != queueArn.Region {
			continue
		}
		return q
	}
	return nil
}

// initAwsSqsQueue resolves a single SQS queue. Queues are keyed by their URL,
// which is also what every queue API call takes. A queue requested by ARN
// alone (from a discovered aws-sqs-queue asset, or from another resource that
// only holds the ARN) is resolved through GetQueueUrl using the queue name and
// owner account the ARN carries.
func initAwsSqsQueue(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSqsQueue); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	// A URL already identifies the queue, so only the region it implies is
	// still missing.
	if args["url"] != nil {
		if args["region"] == nil {
			queueURL, ok := args["url"].Value.(string)
			if !ok {
				return nil, nil, fmt.Errorf("wrong type for 'url' in aws.sqs.queue initialization, it must be a string")
			}
			region := regionFromSqsQueueURL(queueURL)
			if region == "" {
				return nil, nil, fmt.Errorf("unable to determine region from sqs queue url %q", queueURL)
			}
			args["region"] = llx.StringData(region)
		}
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, fmt.Errorf("arn or url required to fetch sqs queue")
	}
	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("wrong type for 'arn' in aws.sqs.queue initialization, it must be a string")
	}
	parsedArn, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}

	// This resource keys its __id on the queue URL, which is the very thing
	// GetQueueUrl is called to resolve, so the ARN cannot be a cache key the
	// way it is for the ARN-keyed resources. Match the already-resolved list
	// instead, which during a scan has been walked by discovery already.
	if q := resolvedSqsQueueByArn(runtime, parsedArn); q != nil {
		return args, q, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Sqs(parsedArn.Region)
	resp, err := svc.GetQueueUrl(context.Background(), &sqs.GetQueueUrlInput{
		QueueName:              aws.String(parsedArn.Resource),
		QueueOwnerAWSAccountId: aws.String(parsedArn.AccountID),
	})
	if err != nil {
		return nil, nil, err
	}
	// Returning here without a URL would leave the resource with an empty
	// __id, so treat a missing URL as a lookup failure.
	if resp.QueueUrl == nil || *resp.QueueUrl == "" {
		return nil, nil, fmt.Errorf("aws.sqs.queue with arn %q not found", arnVal)
	}

	args["url"] = llx.StringDataPtr(resp.QueueUrl)
	args["region"] = llx.StringData(parsedArn.Region)
	return args, nil, nil
}

func (a *mqlAwsSqs) queues() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getQueues(conn), 5)
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

func (a *mqlAwsSqs) getQueues(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sqs(region)
			ctx := context.Background()
			res := []any{}

			// MaxResults is required to get a NextToken back: "Token value is
			// null if there are no additional results to request, or if you did
			// not set MaxResults in the request." Without it the paginator stops
			// after one page and every queue past the first 1000 in a region is
			// invisible -- to aws.sqs.queues and to discovery, so those queues
			// never become assets at all.
			params := &sqs.ListQueuesInput{MaxResults: aws.Int32(1000)}
			paginator := sqs.NewListQueuesPaginator(svc, params)
			for paginator.HasMorePages() {
				qs, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				// Pre-fetch tags in parallel when tag-based filters are configured.
				// SQS has no batch tags endpoint, so this turns a sequential
				// per-queue call into bounded concurrent calls.
				var tagsByUrl map[string]map[string]string
				if conn.Filters.General.HasTags() {
					tagsByUrl = fetchTagsConcurrently(ctx, qs.QueueUrls, func(ctx context.Context, queueUrl string) (map[string]string, error) {
						resp, err := svc.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: aws.String(queueUrl)})
						if err != nil {
							return nil, err
						}
						return resp.Tags, nil
					})
				}

				for _, q := range qs.QueueUrls {
					args := map[string]*llx.RawData{
						"url":    llx.StringData(q),
						"region": llx.StringData(region),
					}
					if conn.Filters.General.HasTags() {
						tags, fetched := tagsByUrl[q]
						if conn.Filters.General.IsFilteredOutByTags(tags) {
							log.Debug().Str("queue", q).Msg("excluding sqs queue due to filters")
							continue
						}
						// Seed the tags we already paid for; discovery reads them
						// back immediately and would otherwise re-fetch. Only seed
						// a tag set we actually read - publishing an empty map for
						// a queue whose ListQueueTags call failed would report "no
						// tags" as fact. Leaving it unset keeps the field lazy.
						if fetched {
							args["tags"] = llx.MapData(stringMapToAny(tags), mqltypes.String)
						}
					}

					mqlQueue, err := CreateResource(a.MqlRuntime, "aws.sqs.queue", args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlQueue)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSqsQueueInternal struct {
	fetched   bool
	queueAtts map[string]string
	lock      sync.Mutex
}

func (a *mqlAwsSqsQueue) fetchAttributes() (map[string]string, error) {
	if a.fetched {
		return a.queueAtts, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.queueAtts, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Sqs(a.Region.Data)
	desc, err := svc.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(a.Url.Data), AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll}})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.queueAtts = desc.Attributes
	return desc.Attributes, nil
}

func (a *mqlAwsSqsQueue) kmsKey() (*mqlAwsKmsKey, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	if atts["KmsMasterKeyId"] == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	id := atts["KmsMasterKeyId"]
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		kmsKeyRefArgs(a.Region.Data, conn.AccountId(), id))
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSqsQueue) deadLetterQueue() (*mqlAwsSqsQueue, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	c := atts["RedrivePolicy"]
	if c == "" {
		a.DeadLetterQueue.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	var r redrivePolicy
	err = json.Unmarshal([]byte(c), &r)
	if err != nil {
		return nil, err
	}
	parsedArn, err := arn.Parse(r.DeadLetterTargetArn)
	if err != nil {
		return nil, err
	}
	// "https://sqs.us-east-1.amazonaws.com/921877552404/Test-Preslav-Queue"
	url := fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", a.Region.Data, parsedArn.AccountID, parsedArn.Resource)
	q, err := NewResource(a.MqlRuntime, "aws.sqs.queue",
		map[string]*llx.RawData{
			"arn":    llx.StringData(r.DeadLetterTargetArn),
			"url":    llx.StringData(url),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return q.(*mqlAwsSqsQueue), nil
}

func (a *mqlAwsSqsQueue) arn() (string, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return "", err
	}
	return atts["QueueArn"], nil
}

func (a *mqlAwsSqsQueue) createdAt() (*time.Time, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	i, err := strconv.ParseInt(atts["CreatedTimestamp"], 10, 64)
	if err != nil {
		return nil, err
	}
	t := time.Unix(i, 0)
	return &t, nil
}

func (a *mqlAwsSqsQueue) deliveryDelaySeconds() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(atts["DelaySeconds"])
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

func (a *mqlAwsSqsQueue) lastModified() (*time.Time, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	i, err := strconv.ParseInt(atts["LastModifiedTimestamp"], 10, 64)
	if err != nil {
		return nil, err
	}
	t := time.Unix(i, 0)
	return &t, nil
}

type redrivePolicy struct {
	DeadLetterTargetArn string `json:"deadLetterTargetArn,omitempty"`
	// Kept raw so an absent key stays absent. A queue with no redrive policy
	// has no maxReceiveCount at all, which is not the same as a count of 0.
	// The raw form also absorbs the quoted-number spelling the console has
	// historically written.
	MaxReceiveCount json.RawMessage `json:"maxReceiveCount,omitempty"`
}

// parseRedriveMaxReceiveCount returns the per-message receive-attempt count a
// queue's RedrivePolicy attribute sets before a message is moved to the
// dead-letter queue.
//
// ok is false when the queue carries no redrive policy, or carries one without
// a maxReceiveCount: that queue has no receive-attempt limit, so a count of 0
// would report a limit that was never configured.
func parseRedriveMaxReceiveCount(redrivePolicyAttr string) (int64, bool, error) {
	if redrivePolicyAttr == "" {
		return 0, false, nil
	}
	var r redrivePolicy
	if err := json.Unmarshal([]byte(redrivePolicyAttr), &r); err != nil {
		return 0, false, err
	}
	raw := strings.TrimSpace(string(r.MaxReceiveCount))
	if raw == "" || raw == "null" {
		return 0, false, nil
	}
	count, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid maxReceiveCount %s in sqs redrive policy: %w", raw, err)
	}
	return count, true, nil
}

func (a *mqlAwsSqsQueue) maxReceiveCount() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	count, ok, err := parseRedriveMaxReceiveCount(atts["RedrivePolicy"])
	if err != nil {
		return 0, err
	}
	if !ok {
		a.MaxReceiveCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return count, nil
}

func (a *mqlAwsSqsQueue) maximumMessageSize() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(atts["MaximumMessageSize"])
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

func (a *mqlAwsSqsQueue) messageRetentionPeriodSeconds() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(atts["MessageRetentionPeriod"])
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

func (a *mqlAwsSqsQueue) receiveMessageWaitTimeSeconds() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(atts["ReceiveMessageWaitTimeSeconds"])
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

// sqsManagedSseEnabled reports the SqsManagedSseEnabled attribute, which
// covers SQS-managed server-side encryption (SSE-SQS) only. A queue encrypted
// with a customer-managed KMS key reports false here and names its key through
// kmsKey, so this is not an "is the queue encrypted" answer on its own.
func (a *mqlAwsSqsQueue) sqsManagedSseEnabled() (bool, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(atts["SqsManagedSseEnabled"])
}

func (a *mqlAwsSqsQueue) queueType() (string, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return "", err
	}
	if atts["FifoQueue"] == "true" {
		return "fifo", nil
	}
	return "standard", nil
}

func (a *mqlAwsSqsQueue) visibilityTimeoutSeconds() (int64, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(atts["VisibilityTimeout"])
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

func (a *mqlAwsSqsQueue) deduplicationScope() (string, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return "", err
	}
	return atts["DeduplicationScope"], nil
}

func (a *mqlAwsSqsQueue) fifoThroughputLimit() (string, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return "", err
	}
	return atts["FifoThroughputLimit"], nil
}

func (a *mqlAwsSqsQueue) policy() (any, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	policyStr := atts["Policy"]
	if policyStr == "" {
		return nil, nil
	}
	var policy any
	if err := json.Unmarshal([]byte(policyStr), &policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func (a *mqlAwsSqsQueue) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Sqs(a.Region.Data)

	resp, err := svc.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: aws.String(a.Url.Data)})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsSqsQueue) contentBasedDeduplication() (bool, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return false, err
	}
	if atts["ContentBasedDeduplication"] == "" {
		return false, nil
	}
	return strconv.ParseBool(atts["ContentBasedDeduplication"])
}

func (a *mqlAwsSqsQueue) redriveAllowPolicy() (any, error) {
	atts, err := a.fetchAttributes()
	if err != nil {
		return nil, err
	}
	policyStr := atts["RedriveAllowPolicy"]
	if policyStr == "" {
		return nil, nil
	}
	var policy map[string]any
	if err := json.Unmarshal([]byte(policyStr), &policy); err != nil {
		return nil, err
	}
	return convert.JsonToDict(policy)
}
