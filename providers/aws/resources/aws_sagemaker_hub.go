// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// Content types to enumerate when listing everything inside a hub.
var hubContentTypesToList = []smtypes.HubContentType{
	smtypes.HubContentTypeModel,
	smtypes.HubContentTypeNotebook,
	smtypes.HubContentTypeModelReference,
}

// ---- Init for hub cross-reference ----

func initAwsSagemakerHub(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker hub")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetHubs()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			h := rawResource.(*mqlAwsSagemakerHub)
			if h.Arn.Data == arnVal {
				return args, h, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.hub with arn %q not found", arnVal)
}

// ---- Hubs ----

func (a *mqlAwsSagemaker) hubs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getHubs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getHubs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				out, err := svc.ListHubs(ctx, &sagemaker.ListHubsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, h := range out.HubSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, h.HubArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlHub, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHub,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(h.HubArn),
							"name":           llx.StringDataPtr(h.HubName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(h.HubStatus)),
							"createdAt":      llx.TimeDataPtr(h.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(h.LastModifiedTime),
							"displayName":    llx.StringDataPtr(h.HubDisplayName),
							"description":    llx.StringDataPtr(h.HubDescription),
						})
					if err != nil {
						return nil, err
					}
					m := mqlHub.(*mqlAwsSagemakerHub)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlHub)
				}

				if out.NextToken == nil || *out.NextToken == "" {
					break
				}
				nextToken = out.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerHubInternal struct {
	sagemakerTagsCache
	detailsLock         sync.Mutex
	detailsFetched      bool
	cacheFailureReason  string
	cacheSearchKeywords []any
	cacheS3OutputPath   string
}

func (a *mqlAwsSagemakerHub) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerHub) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerHub) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeHub(ctx, &sagemaker.DescribeHubInput{HubName: &name})
	if err != nil {
		return err
	}
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheSearchKeywords = make([]any, 0, len(resp.HubSearchKeywords))
	for _, kw := range resp.HubSearchKeywords {
		a.cacheSearchKeywords = append(a.cacheSearchKeywords, kw)
	}
	if resp.S3StorageConfig != nil {
		a.cacheS3OutputPath = convert.ToValue(resp.S3StorageConfig.S3OutputPath)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerHub) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerHub) searchKeywords() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheSearchKeywords, nil
}

func (a *mqlAwsSagemakerHub) s3OutputPath() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheS3OutputPath, nil
}

func (a *mqlAwsSagemakerHub) contents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	hubName := a.Name.Data
	region := a.Region.Data

	res := []any{}
	for _, ct := range hubContentTypesToList {
		var nextToken *string
		for {
			out, err := svc.ListHubContents(ctx, &sagemaker.ListHubContentsInput{
				HubName:        &hubName,
				HubContentType: ct,
				NextToken:      nextToken,
			})
			if err != nil {
				return nil, classifyAwsError(err, "sagemaker:ListHubContents")
			}

			for _, c := range out.HubContentSummaries {
				var eagerTags map[string]any
				if conn.Filters.General.HasTags() {
					tags, err := getSagemakerTags(ctx, svc, c.HubContentArn)
					if err != nil {
						return nil, err
					}
					if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
						continue
					}
					eagerTags = tags
				}

				mqlContent, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHubContent,
					map[string]*llx.RawData{
						"arn":                          llx.StringDataPtr(c.HubContentArn),
						"name":                         llx.StringDataPtr(c.HubContentName),
						"region":                       llx.StringData(region),
						"hubName":                      llx.StringData(hubName),
						"contentType":                  llx.StringData(string(c.HubContentType)),
						"status":                       llx.StringData(string(c.HubContentStatus)),
						"contentVersion":               llx.StringDataPtr(c.HubContentVersion),
						"documentSchemaVersion":        llx.StringDataPtr(c.DocumentSchemaVersion),
						"createdAt":                    llx.TimeDataPtr(c.CreationTime),
						"displayName":                  llx.StringDataPtr(c.HubContentDisplayName),
						"description":                  llx.StringDataPtr(c.HubContentDescription),
						"sageMakerPublicHubContentArn": llx.StringDataPtr(c.SageMakerPublicHubContentArn),
						"supportStatus":                llx.StringData(string(c.SupportStatus)),
					})
				if err != nil {
					return nil, err
				}
				m := mqlContent.(*mqlAwsSagemakerHubContent)
				if eagerTags != nil {
					m.cacheTags = eagerTags
					m.tagsFetched = true
				}
				res = append(res, mqlContent)
			}

			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			nextToken = out.NextToken
		}
	}
	return res, nil
}

// ---- Hub content ----

type mqlAwsSagemakerHubContentInternal struct {
	sagemakerTagsCache
	detailsLock         sync.Mutex
	detailsFetched      bool
	cacheSearchKeywords []any
	cacheDocument       string
	cacheMarkdown       string
	cacheFailureReason  string
}

func (a *mqlAwsSagemakerHubContent) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerHubContent) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerHubContent) hub() (*mqlAwsSagemakerHub, error) {
	hubName := a.HubName.Data
	if hubName == "" {
		a.Hub.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	hubArn := "arn:aws:sagemaker:" + a.Region.Data + ":" + conn.AccountId() + ":hub/" + hubName
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.hub",
		map[string]*llx.RawData{"arn": llx.StringData(hubArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerHub), nil
}

func (a *mqlAwsSagemakerHubContent) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	hubName := a.HubName.Data
	name := a.Name.Data
	contentVersion := a.ContentVersion.Data
	contentType := smtypes.HubContentType(a.ContentType.Data)

	input := &sagemaker.DescribeHubContentInput{
		HubName:        &hubName,
		HubContentName: &name,
		HubContentType: contentType,
	}
	if contentVersion != "" {
		input.HubContentVersion = &contentVersion
	}
	resp, err := svc.DescribeHubContent(ctx, input)
	if err != nil {
		return err
	}
	a.cacheDocument = convert.ToValue(resp.HubContentDocument)
	a.cacheMarkdown = convert.ToValue(resp.HubContentMarkdown)
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheSearchKeywords = make([]any, 0, len(resp.HubContentSearchKeywords))
	for _, kw := range resp.HubContentSearchKeywords {
		a.cacheSearchKeywords = append(a.cacheSearchKeywords, kw)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerHubContent) document() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheDocument, nil
}

func (a *mqlAwsSagemakerHubContent) markdown() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheMarkdown, nil
}

func (a *mqlAwsSagemakerHubContent) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerHubContent) searchKeywords() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheSearchKeywords, nil
}
