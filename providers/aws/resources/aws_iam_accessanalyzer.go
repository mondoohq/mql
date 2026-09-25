// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsIamAccessAnalyzerAnalyzer) id() (string, error) {
	return a.Arn.Data, nil
}

// mqlAwsIamAccessAnalyzerFindingInternal caches the unused-access detail of a
// finding. ListFindingsV2 returns a summary without it, so the detail costs one
// GetFindingV2 call per finding and is shared by the four fields that read it.
type mqlAwsIamAccessAnalyzerFindingInternal struct {
	unusedFetched               atomic.Bool
	unusedLock                  sync.Mutex
	cacheUnusedLastAccessed     *time.Time
	cacheUnusedServiceNamespace string
	cacheUnusedActions          []any
	cacheUnusedAccessKeyId      string
}

// fetchUnusedAccessDetails resolves the unused-access detail of the finding.
// Findings of any other type carry no such detail, so they resolve to empty
// values without an API call.
func (a *mqlAwsIamAccessAnalyzerFinding) fetchUnusedAccessDetails() error {
	if a.unusedFetched.Load() {
		return nil
	}
	a.unusedLock.Lock()
	defer a.unusedLock.Unlock()
	if a.unusedFetched.Load() {
		return nil
	}

	if !strings.HasPrefix(a.Type.Data, "Unused") {
		a.unusedFetched.Store(true)
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AccessAnalyzer(a.Region.Data)
	finding, err := svc.GetFindingV2(context.Background(), &accessanalyzer.GetFindingV2Input{
		AnalyzerArn: aws.String(a.AnalyzerArn.Data),
		Id:          aws.String(a.Id.Data),
	})
	if err != nil {
		return classifyAwsError(err, "access-analyzer:GetFindingV2")
	}

	detail := parseUnusedAccessDetails(finding.FindingDetails)
	a.cacheUnusedLastAccessed = detail.lastAccessed
	a.cacheUnusedServiceNamespace = detail.serviceNamespace
	a.cacheUnusedActions = detail.actions
	a.cacheUnusedAccessKeyId = detail.accessKeyId

	a.unusedFetched.Store(true)
	return nil
}

// unusedAccessDetail holds the unused-access values carried by a finding.
type unusedAccessDetail struct {
	lastAccessed     *time.Time
	serviceNamespace string
	actions          []any
	accessKeyId      string
}

// parseUnusedAccessDetails picks the unused-access member out of a finding
// detail union. The external-access and internal-access members carry no
// unused-access data and are skipped.
func parseUnusedAccessDetails(details []aatypes.FindingDetails) unusedAccessDetail {
	var res unusedAccessDetail
	for _, detail := range details {
		switch typed := detail.(type) {
		case *aatypes.FindingDetailsMemberUnusedPermissionDetails:
			res.lastAccessed = typed.Value.LastAccessed
			res.serviceNamespace = convert.ToValue(typed.Value.ServiceNamespace)
			for _, action := range typed.Value.Actions {
				res.actions = append(res.actions, convert.ToValue(action.Action))
			}
		case *aatypes.FindingDetailsMemberUnusedIamRoleDetails:
			res.lastAccessed = typed.Value.LastAccessed
		case *aatypes.FindingDetailsMemberUnusedIamUserAccessKeyDetails:
			res.lastAccessed = typed.Value.LastAccessed
			res.accessKeyId = convert.ToValue(typed.Value.AccessKeyId)
		case *aatypes.FindingDetailsMemberUnusedIamUserPasswordDetails:
			res.lastAccessed = typed.Value.LastAccessed
		}
	}
	return res
}

func (a *mqlAwsIamAccessAnalyzerFinding) lastAccessedAt() (*time.Time, error) {
	if err := a.fetchUnusedAccessDetails(); err != nil {
		return nil, err
	}
	return a.cacheUnusedLastAccessed, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) unusedServiceNamespace() (string, error) {
	if err := a.fetchUnusedAccessDetails(); err != nil {
		return "", err
	}
	return a.cacheUnusedServiceNamespace, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) unusedActions() ([]any, error) {
	if err := a.fetchUnusedAccessDetails(); err != nil {
		return nil, err
	}
	if a.cacheUnusedActions == nil {
		return []any{}, nil
	}
	return a.cacheUnusedActions, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) unusedAccessKeyId() (string, error) {
	if err := a.fetchUnusedAccessDetails(); err != nil {
		return "", err
	}
	return a.cacheUnusedAccessKeyId, nil
}

func (a *mqlAwsIamAccessAnalyzer) analyzers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAnalyzers(conn), 5)
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

func (a *mqlAwsIamAccessAnalyzer) getAnalyzers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.AccessAnalyzer(region)
			res := []any{}

			// we need to iterate over all the analyzers types in the account
			analyzerTypes := []aatypes.Type{aatypes.TypeAccount, aatypes.TypeOrganization, aatypes.TypeAccountUnusedAccess, aatypes.TypeOrganizationUnusedAccess, aatypes.TypeAccountInternalAccess, aatypes.TypeOrganizationInternalAccess}
			for _, analyzerType := range analyzerTypes {
				ctx := context.Background()

				// query all the analyzers in the account / region
				params := &accessanalyzer.ListAnalyzersInput{Type: analyzerType}
				paginator := accessanalyzer.NewListAnalyzersPaginator(svc, params)
				for paginator.HasMorePages() {
					analyzers, err := paginator.NextPage(ctx)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Msg("error accessing region for AWS API")
							return res, nil
						}
						log.Error().Err(err).Str("region", region).Msg("error listing analyzers")
						return nil, err
					}
					for _, analyzer := range analyzers.Analyzers {
						mqlAnalyzer, err := CreateResource(a.MqlRuntime, "aws.iam.accessAnalyzer.analyzer",
							map[string]*llx.RawData{
								"arn":                    llx.StringDataPtr(analyzer.Arn),
								"name":                   llx.StringDataPtr(analyzer.Name),
								"status":                 llx.StringData(string(analyzer.Status)),
								"type":                   llx.StringData(string(analyzer.Type)),
								"region":                 llx.StringData(region),
								"tags":                   llx.MapData(toInterfaceMap(analyzer.Tags), types.String),
								"createdAt":              llx.TimeDataPtr(analyzer.CreatedAt),
								"lastResourceAnalyzed":   llx.StringDataPtr(analyzer.LastResourceAnalyzed),
								"lastResourceAnalyzedAt": llx.TimeDataPtr(analyzer.LastResourceAnalyzedAt),
							})
						if err != nil {
							return nil, err
						}
						res = append(res, mqlAnalyzer)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsIamAccessAnalyzer) getAnalyzerMap() (map[string][]string, error) {
	analyzerMap := map[string][]string{}
	analyzerList := a.GetAnalyzers()
	if analyzerList.Error != nil {
		return nil, analyzerList.Error
	}
	for _, analyzer := range analyzerList.Data {
		analyzerInstance, ok := analyzer.(*mqlAwsIamAccessAnalyzerAnalyzer)
		if !ok {
			return nil, errors.New("error casting to analyzer instance")
		}
		region := analyzerInstance.GetRegion().Data
		if analyzerMap[region] == nil {
			analyzerMap[region] = []string{}
		}
		analyzerMap[region] = append(analyzerMap[region], analyzerInstance.GetArn().Data)
	}
	return analyzerMap, nil
}

func (a *mqlAwsIamAccessAnalyzer) findings() ([]any, error) {
	return a.listFindingsWithStatus("ACTIVE")
}

func (a *mqlAwsIamAccessAnalyzer) archivedFindings() ([]any, error) {
	return a.listFindingsWithStatus("ARCHIVED")
}

func (a *mqlAwsIamAccessAnalyzer) listFindingsWithStatus(status string) ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	analyzerMap, err := a.getAnalyzerMap()
	if err != nil {
		return nil, err
	}

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.listFindings(conn, analyzerMap, status), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		results := poolOfJobs.Jobs[i].Result.([]any)
		res = append(res, results...)
	}
	return res, nil
}

func (a *mqlAwsIamAccessAnalyzer) listFindings(conn *connection.AwsConnection, analyzerMap map[string][]string, status string) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.AccessAnalyzer(region)
			res := []any{}

			analyzerList := analyzerMap[region]
			for _, analyzerArn := range analyzerList {
				ctx := context.Background()

				params := &accessanalyzer.ListFindingsV2Input{
					AnalyzerArn: aws.String(analyzerArn),
					Filter: map[string]aatypes.Criterion{
						"status": {
							Eq: []string{status},
						},
					},
				}
				paginator := accessanalyzer.NewListFindingsV2Paginator(svc, params)
				for paginator.HasMorePages() {
					findings, err := paginator.NextPage(ctx)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Msg("error accessing region for AWS API")
							return res, nil
						}
						log.Error().Err(err).Str("region", region).Msg("error listing findings")
						return nil, err
					}
					for _, finding := range findings.Findings {
						mqlFinding, err := CreateResource(a.MqlRuntime, "aws.iam.accessAnalyzer.finding",
							map[string]*llx.RawData{
								"__id":                 llx.StringDataPtr(finding.Id),
								"id":                   llx.StringDataPtr(finding.Id),
								"error":                llx.StringDataPtr(finding.Error),
								"resourceArn":          llx.StringDataPtr(finding.Resource),
								"resourceOwnerAccount": llx.StringDataPtr(finding.ResourceOwnerAccount),
								"resourceType":         llx.StringData(string(finding.ResourceType)),
								"status":               llx.StringData(string(finding.Status)),
								"type":                 llx.StringData(string(finding.FindingType)),
								"createdAt":            llx.TimeDataPtr(finding.CreatedAt),
								"updatedAt":            llx.TimeDataPtr(finding.UpdatedAt),
								"analyzedAt":           llx.TimeDataPtr(finding.AnalyzedAt),
								"region":               llx.StringData(region),
								"analyzerArn":          llx.StringData(analyzerArn),
							})
						if err != nil {
							return nil, err
						}
						res = append(res, mqlFinding)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// archiveRules returns the rules that archive matching findings as they are
// created. Only external- and internal-access analyzers support archive rules;
// the unused-access analyzer types reject the call, so those resolve to an
// empty list rather than failing the scan.
func (a *mqlAwsIamAccessAnalyzerAnalyzer) archiveRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AccessAnalyzer(a.Region.Data)
	ctx := context.Background()
	analyzerName := a.Name.Data
	analyzerArn := a.Arn.Data

	res := []any{}
	paginator := accessanalyzer.NewListArchiveRulesPaginator(svc, &accessanalyzer.ListArchiveRulesInput{
		AnalyzerName: aws.String(analyzerName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			var notFound *aatypes.ResourceNotFoundException
			if errors.As(err, &notFound) {
				return res, nil
			}
			// An unused-access analyzer rejects ListArchiveRules with a
			// ValidationException, which is expected and means the analyzer has
			// no archive rules rather than that the call failed. Log the message
			// so a genuine schema or argument problem is still visible instead of
			// being silently flattened into an empty list.
			var validation *aatypes.ValidationException
			if errors.As(err, &validation) {
				log.Debug().Err(err).Str("analyzer", analyzerName).Str("region", a.Region.Data).
					Msg("archive rules are not available for this analyzer")
				return res, nil
			}
			return nil, classifyAwsError(err, "access-analyzer:ListArchiveRules")
		}
		for _, rule := range page.ArchiveRules {
			filter, err := archiveRuleFilterToDict(rule.Filter)
			if err != nil {
				return nil, err
			}
			mqlRule, err := CreateResource(a.MqlRuntime, "aws.iam.accessAnalyzer.archiveRule",
				map[string]*llx.RawData{
					// Rule names are unique only within one analyzer.
					"__id":        llx.StringData(analyzerArn + "/archiveRule/" + convert.ToValue(rule.RuleName)),
					"name":        llx.StringDataPtr(rule.RuleName),
					"analyzerArn": llx.StringData(analyzerArn),
					"region":      llx.StringData(a.Region.Data),
					"filter":      llx.MapData(filter, types.Dict),
					"createdAt":   llx.TimeDataPtr(rule.CreatedAt),
					"updatedAt":   llx.TimeDataPtr(rule.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

// archiveRuleFilterToDict converts an archive rule's criteria into a dict per
// finding property. Each criterion keeps only the comparisons it actually sets,
// so an absent comparison does not read as an empty match list.
func archiveRuleFilterToDict(filter map[string]aatypes.Criterion) (map[string]any, error) {
	res := make(map[string]any, len(filter))
	for key, criterion := range filter {
		entry := map[string]any{}
		if len(criterion.Eq) > 0 {
			entry["Eq"] = convert.SliceAnyToInterface(criterion.Eq)
		}
		if len(criterion.Neq) > 0 {
			entry["Neq"] = convert.SliceAnyToInterface(criterion.Neq)
		}
		if len(criterion.Contains) > 0 {
			entry["Contains"] = convert.SliceAnyToInterface(criterion.Contains)
		}
		if criterion.Exists != nil {
			entry["Exists"] = *criterion.Exists
		}
		res[key] = entry
	}
	return res, nil
}

func (a *mqlAwsIamAccessAnalyzerArchiveRule) id() (string, error) {
	return a.__id, nil
}
