// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
//
// The external-access detail is cached the same way, once per finding, from the
// per-analyzer memo on aws.iam.accessAnalyzer (see detailsForAnalyzer).
type mqlAwsIamAccessAnalyzerFindingInternal struct {
	unusedFetched               atomic.Bool
	unusedLock                  sync.Mutex
	unusedErr                   error
	cacheUnusedLastAccessed     *time.Time
	cacheUnusedServiceNamespace string
	cacheUnusedActions          []any
	cacheUnusedAccessKeyId      string

	externalOnce     sync.Once
	cacheExternal    externalAccessDetail
	cacheExternalOK  bool
	cacheExternalErr error
}

// mqlAwsIamAccessAnalyzerInternal holds the external-access details of each
// analyzer's findings, keyed by analyzer ARN. There is one aws.iam.accessAnalyzer
// resource per scan, so every finding of the scan shares these memos.
type mqlAwsIamAccessAnalyzerInternal struct {
	detailMemos sync.Map // analyzer ARN -> *externalDetailMemo

	// refusedLock guards externalRefused: the regions whose external-access
	// findings listing was refused, with the refusal. Set while
	// externalAccessFindings() computes, so it is complete once
	// GetExternalAccessFindings returns.
	refusedLock     sync.Mutex
	externalRefused map[string]error
}

// externalRefusedRegion returns the refusal that kept region's external-access
// findings from the list, or nil.
func (a *mqlAwsIamAccessAnalyzer) externalRefusedRegion(region string) error {
	a.refusedLock.Lock()
	defer a.refusedLock.Unlock()
	return a.externalRefused[region]
}

// fetchUnusedAccessDetails resolves the unused-access detail of the finding.
// Findings of any other type carry no such detail, so they resolve to empty
// values without an API call.
//
// A refused GetFindingV2 is cached: with structured errors it is returned as
// Forbidden by every field that reads the detail, without them the fields read
// empty as they always did.
func (a *mqlAwsIamAccessAnalyzerFinding) fetchUnusedAccessDetails() error {
	if a.unusedFetched.Load() {
		return a.unusedErr
	}
	a.unusedLock.Lock()
	defer a.unusedLock.Unlock()
	if a.unusedFetched.Load() {
		return a.unusedErr
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
		if Is400AccessDeniedError(err) {
			if plugin.StructuredErrors() {
				a.unusedErr = llx.Forbidden(err, llx.WithPermissions(permGetFinding))
			} else {
				log.Warn().Str("finding", a.Id.Data).Str("region", a.Region.Data).
					Msg("no permission to read access analyzer finding detail")
			}
			a.unusedFetched.Store(true)
			return a.unusedErr
		}
		return err
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

// IAM actions named by the refusals of this file. ListFindingsV2 and
// GetFindingV2 are authorized by the same actions as their v1 operations.
const (
	permListFindings = "access-analyzer:ListFindings"
	permGetFinding   = "access-analyzer:GetFinding"
)

// externalAccessDetail is the decoded external-access member of a finding: who
// outside the zone of trust has access, to what, and how.
type externalAccessDetail struct {
	principal   map[string]any
	isPublic    *bool
	actions     []any
	condition   map[string]any
	sources     []any // dicts
	rcpRestrict string
}

// newExternalAccessDetail builds the detail from the fields the v1
// FindingSummary and the v2 ExternalAccessDetails share.
func newExternalAccessDetail(principal map[string]string, isPublic *bool, action []string,
	condition map[string]string, sources []aatypes.FindingSource, rcp aatypes.ResourceControlPolicyRestriction,
) externalAccessDetail {
	res := externalAccessDetail{
		principal:   make(map[string]any, len(principal)),
		isPublic:    isPublic,
		actions:     make([]any, 0, len(action)),
		condition:   make(map[string]any, len(condition)),
		sources:     make([]any, 0, len(sources)),
		rcpRestrict: string(rcp),
	}
	for k, v := range principal {
		res.principal[k] = v
	}
	for _, act := range action {
		res.actions = append(res.actions, act)
	}
	for k, v := range condition {
		res.condition[k] = v
	}
	for _, src := range sources {
		entry := map[string]any{"type": string(src.Type)}
		if src.Detail != nil {
			if src.Detail.AccessPointArn != nil {
				entry["accessPointArn"] = *src.Detail.AccessPointArn
			}
			if src.Detail.AccessPointAccount != nil {
				entry["accessPointAccount"] = *src.Detail.AccessPointAccount
			}
		}
		res.sources = append(res.sources, entry)
	}
	return res
}

// decodeFindingSummaryV1 reads the external-access detail out of a ListFindings
// summary. ListFindings serves external-access analyzers only, so every summary
// it returns describes external access.
func decodeFindingSummaryV1(s aatypes.FindingSummary) externalAccessDetail {
	return newExternalAccessDetail(s.Principal, s.IsPublic, s.Action, s.Condition, s.Sources, s.ResourceControlPolicyRestriction)
}

// decodeExternalAccessDetails picks the external-access member out of a
// GetFindingV2 detail union. It reports false when the finding carries none.
func decodeExternalAccessDetails(details []aatypes.FindingDetails) (externalAccessDetail, bool) {
	for _, detail := range details {
		if typed, ok := detail.(*aatypes.FindingDetailsMemberExternalAccessDetails); ok {
			v := typed.Value
			return newExternalAccessDetail(v.Principal, v.IsPublic, v.Action, v.Condition, v.Sources, v.ResourceControlPolicyRestriction), true
		}
	}
	return externalAccessDetail{}, false
}

// externalDetailMemo holds one analyzer's external-access details, filled by
// one paged ListFindings pass.
type externalDetailMemo struct {
	once sync.Once
	byID map[string]externalAccessDetail
	err  error
}

// detailsForAnalyzer returns the external-access details of every finding of
// the analyzer, keyed by finding id. The first call per analyzer lists them
// with ListFindings, whose summary carries the detail that the ListFindingsV2
// summary lacks; later calls read the memo. A refusal is cached as Forbidden.
func (a *mqlAwsIamAccessAnalyzer) detailsForAnalyzer(region, analyzerArn string) (map[string]externalAccessDetail, error) {
	v, _ := a.detailMemos.LoadOrStore(analyzerArn, &externalDetailMemo{})
	memo := v.(*externalDetailMemo)
	memo.once.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.AccessAnalyzer(region)
		ctx := context.Background()
		byID := map[string]externalAccessDetail{}
		paginator := accessanalyzer.NewListFindingsPaginator(svc, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: aws.String(analyzerArn),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					memo.err = llx.Forbidden(err, llx.WithPermissions(permListFindings))
				} else {
					memo.err = err
				}
				return
			}
			for _, summary := range page.Findings {
				if summary.Id == nil {
					continue
				}
				byID[*summary.Id] = decodeFindingSummaryV1(summary)
			}
		}
		memo.byID = byID
	})
	return memo.byID, memo.err
}

// accessAnalyzerRoot returns the scan's aws.iam.accessAnalyzer resource.
func accessAnalyzerRoot(runtime *plugin.Runtime) (*mqlAwsIamAccessAnalyzer, error) {
	obj, err := CreateResource(runtime, ResourceAwsIamAccessAnalyzer, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsIamAccessAnalyzer), nil
}

// fetchExternalAccessDetail resolves the external-access detail of the finding.
// Findings of any other type carry none and report false without an API call.
// The detail comes from the analyzer's memo; a finding the memo does not hold
// (created after the memo was filled) reads it with GetFindingV2.
func (a *mqlAwsIamAccessAnalyzerFinding) fetchExternalAccessDetail() (externalAccessDetail, bool, error) {
	a.externalOnce.Do(func() {
		if a.Type.Data != string(aatypes.FindingTypeExternalAccess) {
			return
		}
		root, err := accessAnalyzerRoot(a.MqlRuntime)
		if err != nil {
			a.cacheExternalErr = err
			return
		}
		byID, err := root.detailsForAnalyzer(a.Region.Data, a.AnalyzerArn.Data)
		if err != nil {
			a.cacheExternalErr = err
			return
		}
		if d, ok := byID[a.Id.Data]; ok {
			a.cacheExternal, a.cacheExternalOK = d, true
			return
		}

		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.AccessAnalyzer(a.Region.Data)
		finding, err := svc.GetFindingV2(context.Background(), &accessanalyzer.GetFindingV2Input{
			AnalyzerArn: aws.String(a.AnalyzerArn.Data),
			Id:          aws.String(a.Id.Data),
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.cacheExternalErr = llx.Forbidden(err, llx.WithPermissions(permGetFinding))
			} else {
				a.cacheExternalErr = err
			}
			return
		}
		a.cacheExternal, a.cacheExternalOK = decodeExternalAccessDetails(finding.FindingDetails)
	})
	return a.cacheExternal, a.cacheExternalOK, a.cacheExternalErr
}

func (a *mqlAwsIamAccessAnalyzerFinding) principal() (map[string]any, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Principal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.principal, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) isPublic() (bool, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return false, err
	}
	if !ok || d.isPublic == nil {
		a.IsPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *d.isPublic, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) actions() ([]any, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}
	return d.actions, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) condition() (map[string]any, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Condition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.condition, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) sources() ([]any, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}
	return d.sources, nil
}

func (a *mqlAwsIamAccessAnalyzerFinding) resourceControlPolicyRestriction() (string, error) {
	d, ok, err := a.fetchExternalAccessDetail()
	if err != nil {
		return "", err
	}
	if !ok {
		a.ResourceControlPolicyRestriction.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return d.rcpRestrict, nil
}

// analyzer resolves the finding's analyzer against the already-listed
// analyzers, so it costs no API call of its own.
func (a *mqlAwsIamAccessAnalyzerFinding) analyzer() (*mqlAwsIamAccessAnalyzerAnalyzer, error) {
	if a.AnalyzerArn.Data == "" {
		a.Analyzer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := accessAnalyzerRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	analyzers := root.GetAnalyzers()
	if analyzers.Error != nil {
		return nil, analyzers.Error
	}
	for _, x := range analyzers.Data {
		if analyzer, ok := x.(*mqlAwsIamAccessAnalyzerAnalyzer); ok && analyzer.Arn.Data == a.AnalyzerArn.Data {
			return analyzer, nil
		}
	}
	a.Analyzer.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
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
								"unusedAccessAge":        llx.IntDataPtr(unusedAccessAge(analyzer.Configuration)),
								"unusedAccessExclusions": llx.ArrayData(unusedAccessExclusions(analyzer.Configuration), types.Dict),
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
						mqlFinding, err := a.newFinding(finding, region, analyzerArn)
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

// newFinding creates the aws.iam.accessAnalyzer.finding resource of a
// ListFindingsV2 summary. The finding id is the cache key, so a finding listed
// by two lists is one resource.
func (a *mqlAwsIamAccessAnalyzer) newFinding(finding aatypes.FindingSummaryV2, region, analyzerArn string) (plugin.Resource, error) {
	return CreateResource(a.MqlRuntime, "aws.iam.accessAnalyzer.finding",
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
}

// externalAccessAnalyzerTypes are the analyzer types that report external
// access. Their findings are of type ExternalAccess.
var externalAccessAnalyzerTypes = []string{string(aatypes.TypeAccount), string(aatypes.TypeOrganization)}

var errNoExternalAccessAnalyzer = errors.New("no external-access analyzer is active")

// activeAnalyzersByRegion returns the ARNs of the ACTIVE analyzers whose type is
// in analyzerTypes, grouped by region, from the cached analyzer list.
func (a *mqlAwsIamAccessAnalyzer) activeAnalyzersByRegion(analyzerTypes []string) (map[string][]string, error) {
	analyzers := a.GetAnalyzers()
	if analyzers.Error != nil {
		return nil, analyzers.Error
	}
	res := map[string][]string{}
	for _, x := range analyzers.Data {
		analyzer, ok := x.(*mqlAwsIamAccessAnalyzerAnalyzer)
		if !ok {
			return nil, errors.New("error casting to analyzer instance")
		}
		if analyzer.Status.Data != string(aatypes.AnalyzerStatusActive) || !slices.Contains(analyzerTypes, analyzer.Type.Data) {
			continue
		}
		res[analyzer.Region.Data] = append(res[analyzer.Region.Data], analyzer.Arn.Data)
	}
	return res, nil
}

// externalAccessRegions returns the regions with an ACTIVE ACCOUNT or
// ORGANIZATION analyzer.
func (a *mqlAwsIamAccessAnalyzer) externalAccessRegions() (map[string]bool, error) {
	byRegion, err := a.activeAnalyzersByRegion(externalAccessAnalyzerTypes)
	if err != nil {
		return nil, err
	}
	res := make(map[string]bool, len(byRegion))
	for region := range byRegion {
		res[region] = true
	}
	return res, nil
}

func (a *mqlAwsIamAccessAnalyzer) externalAccessFindings() ([]any, error) {
	res, refused, err := a.listFindingsOfTypes(string(aatypes.FindingStatusActive), externalAccessAnalyzerTypes,
		string(aatypes.FindingTypeExternalAccess), errNoExternalAccessAnalyzer)
	a.refusedLock.Lock()
	a.externalRefused = refused
	a.refusedLock.Unlock()
	return res, err
}

// regionFindings is what one region's listing contributes: its findings, and
// the refusal that kept it from contributing all of them.
type regionFindings struct {
	region   string
	findings []any
	refused  error
}

// listFindingsOfTypes lists the findings with status of the ACTIVE analyzers
// whose type is in analyzerTypes, keeping those of findingType (empty: any).
// It returns NotApplicable (with noAnalyzer) when no such analyzer is active and
// Forbidden when every region's call was refused. A refusal in some regions is
// logged, the other regions' findings are returned, and refused names the
// regions whose list is incomplete, so a caller does not read a refused region
// as one with nothing to report.
func (a *mqlAwsIamAccessAnalyzer) listFindingsOfTypes(status string, analyzerTypes []string, findingType string, noAnalyzer error) (list []any, refused map[string]error, err error) {
	byRegion, err := a.activeAnalyzersByRegion(analyzerTypes)
	if err != nil {
		return nil, nil, err
	}
	if len(byRegion) == 0 {
		return nil, nil, llx.NotApplicable(noAnalyzer)
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	tasks := make([]*jobpool.Job, 0, len(byRegion))
	for region, analyzerArns := range byRegion {
		tasks = append(tasks, jobpool.NewJob(func() (jobpool.JobResult, error) {
			svc := conn.AccessAnalyzer(region)
			ctx := context.Background()
			res := regionFindings{region: region, findings: []any{}}
			for _, analyzerArn := range analyzerArns {
				paginator := accessanalyzer.NewListFindingsV2Paginator(svc, &accessanalyzer.ListFindingsV2Input{
					AnalyzerArn: aws.String(analyzerArn),
					Filter:      map[string]aatypes.Criterion{"status": {Eq: []string{status}}},
				})
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("analyzer", analyzerArn).
								Msg("no permission to list access analyzer findings")
							// Keep what the region's other analyzers returned.
							res.refused = err
							return res, nil
						}
						return nil, err
					}
					for _, finding := range page.Findings {
						if findingType != "" && string(finding.FindingType) != findingType {
							continue
						}
						mqlFinding, err := a.newFinding(finding, region, analyzerArn)
						if err != nil {
							return nil, err
						}
						res.findings = append(res.findings, mqlFinding)
					}
				}
			}
			return res, nil
		}))
	}
	pool := jobpool.CreatePool(tasks, 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, nil, pool.GetErrors()
	}

	res := []any{}
	refused = map[string]error{}
	for i := range pool.Jobs {
		rf := pool.Jobs[i].Result.(regionFindings)
		res = append(res, rf.findings...)
		if rf.refused != nil {
			refused[rf.region] = rf.refused
		}
	}
	if len(refused) == len(byRegion) {
		// Every region refused: report the alphabetically first one, so the
		// error does not depend on which job finished last.
		regions := slices.Sorted(maps.Keys(refused))
		return nil, refused, llx.Forbidden(refused[regions[0]], llx.WithPermissions(permListFindings))
	}
	return res, refused, nil
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
			if Is400AccessDeniedError(err) {
				log.Warn().Str("analyzer", analyzerName).Str("region", a.Region.Data).
					Msg("no permission to list access analyzer archive rules")
				return res, nil
			}
			if _, ok := errors.AsType[*aatypes.ResourceNotFoundException](err); ok {
				return res, nil
			}
			// An unused-access analyzer rejects ListArchiveRules with a
			// ValidationException, which is expected and means the analyzer has
			// no archive rules rather than that the call failed. Log the message
			// so a genuine schema or argument problem is still visible instead of
			// being silently flattened into an empty list.
			if _, ok := errors.AsType[*aatypes.ValidationException](err); ok {
				log.Debug().Err(err).Str("analyzer", analyzerName).Str("region", a.Region.Data).
					Msg("archive rules are not available for this analyzer")
				return res, nil
			}
			return nil, err
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
