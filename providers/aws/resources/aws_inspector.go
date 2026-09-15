// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"

	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	llxtypes "go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsInspector) id() (string, error) {
	return "aws.inspector", nil
}

// id identifies one coverage row. Inspector reports a resource once per scan
// type, so an instance covered by both PACKAGE and NETWORK produces two rows
// that differ only in scanType - without it they collapsed into one and the
// second scan type became invisible. The region is part of it too, since
// resource ids like an ECR repository name are only unique within one.
func (a *mqlAwsInspectorCoverage) id() (string, error) {
	return a.AccountId.Data + "/" + a.Region.Data + "/" + a.ResourceId.Data + "/" + a.ScanType.Data, nil
}

func (a *mqlAwsInspector) coverages() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCoverage(conn), 5)
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

func (a *mqlAwsInspector) getCoverage(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Inspector(region)
			ctx := context.Background()
			res := []any{}

			params := &inspector2.ListCoverageInput{}
			paginator := inspector2.NewListCoveragePaginator(svc, params)
			for paginator.HasMorePages() {
				coverages, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, coverage := range coverages.CoveredResources {
					if coverage.AccountId == nil || coverage.ResourceId == nil {
						continue
					}
					var statusReason, statusCode string
					if coverage.ScanStatus != nil {
						statusReason = string(coverage.ScanStatus.Reason)
						statusCode = string(coverage.ScanStatus.StatusCode)
					}
					mqlCoverage, err := CreateResource(a.MqlRuntime, "aws.inspector.coverage",
						map[string]*llx.RawData{
							"accountId":     llx.StringDataPtr(coverage.AccountId),
							"resourceId":    llx.StringDataPtr(coverage.ResourceId),
							"resourceType":  llx.StringData(string(coverage.ResourceType)),
							"lastScannedAt": llx.TimeDataPtr(coverage.LastScannedAt),
							"statusReason":  llx.StringData(statusReason),
							"statusCode":    llx.StringData(statusCode),
							"scanType":      llx.StringData(string(coverage.ScanType)),
							"scanMode":      llx.StringData(string(coverage.ScanMode)),
							// Inspector can cover resources hosted outside AWS, so the
							// provider fields identify where the resource actually lives.
							"provider":          llx.StringData(string(coverage.Provider)),
							"providerAccountId": llx.StringDataPtr(coverage.ProviderAccountId),
							"providerOrgId":     llx.StringDataPtr(coverage.ProviderOrgId),
							"providerPartition": llx.StringDataPtr(coverage.ProviderPartition),
							"providerRegion":    llx.StringDataPtr(coverage.ProviderRegion),
							"region":            llx.StringData(region),
						},
					)
					if err != nil {
						return nil, err
					}
					mqlCoverage.(*mqlAwsInspectorCoverage).cacheCoverage = &coverage
					res = append(res, mqlCoverage)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsInspectorCoverageInternal struct {
	cacheCoverage *types.CoveredResource
}

type mqlAwsInspectorCoverageInstanceInternal struct {
	cacheAmiId string
}

// id is a fallback only. The coverage that owns this instance passes an
// explicit __id, because an instance is a one-to-one detail of a coverage row
// and has nothing of its own that identifies it: the previous key concatenated
// the tag map, which is neither unique (two instances tagged alike collide) nor
// stable (Go randomizes map iteration, so the same instance could key
// differently between two runs of the same scan).
func (a *mqlAwsInspectorCoverageInstance) id() (string, error) {
	return a.Region.Data, nil
}

func (a *mqlAwsInspectorCoverage) ec2Instance() (*mqlAwsInspectorCoverageInstance, error) {
	if a.cacheCoverage != nil && a.cacheCoverage.ResourceMetadata != nil && a.cacheCoverage.ResourceMetadata.Ec2 != nil {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		args := map[string]*llx.RawData{
			"__id":     llx.StringData(a.MqlID() + "/ec2Instance"),
			"platform": llx.StringData(string(a.cacheCoverage.ResourceMetadata.Ec2.Platform)),
			"tags":     llx.MapData(toInterfaceMap(a.cacheCoverage.ResourceMetadata.Ec2.Tags), llxtypes.String),
			"region":   llx.StringData(a.Region.Data),
		}
		image, err := NewResource(a.MqlRuntime, "aws.ec2.image", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(imageArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(a.cacheCoverage.ResourceMetadata.Ec2.AmiId))),
		})
		if err == nil {
			args["image"] = llx.ResourceData(image, "aws.ec2.image")
		}
		mqlEc2Instance, err := CreateResource(a.MqlRuntime, "aws.inspector.coverage.instance", args)
		if err == nil {
			if a.cacheCoverage.ResourceMetadata.Ec2.AmiId != nil {
				mqlEc2Instance.(*mqlAwsInspectorCoverageInstance).cacheAmiId = *a.cacheCoverage.ResourceMetadata.Ec2.AmiId
			}
			return mqlEc2Instance.(*mqlAwsInspectorCoverageInstance), err
		}
	}
	a.Ec2Instance.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func listMapConversion(m []string) map[string]any {
	newMap := make(map[string]any)
	for _, k := range m {
		newMap[k] = ""
	}
	return newMap
}

// id is a fallback only, for the same reason as the instance above: the owning
// coverage passes an explicit __id, and an image tag list is neither a unique
// nor a stably ordered identity.
func (a *mqlAwsInspectorCoverageImage) id() (string, error) {
	return a.Region.Data, nil
}

func (a *mqlAwsInspectorCoverage) ecrImage() (*mqlAwsInspectorCoverageImage, error) {
	if a.cacheCoverage != nil && a.cacheCoverage.ResourceMetadata != nil && a.cacheCoverage.ResourceMetadata.EcrImage != nil {
		mqlEcr, err := CreateResource(a.MqlRuntime, "aws.inspector.coverage.image", map[string]*llx.RawData{
			"__id":          llx.StringData(a.MqlID() + "/ecrImage"),
			"tags":          llx.MapData(listMapConversion(a.cacheCoverage.ResourceMetadata.EcrImage.Tags), llxtypes.String),
			"imagePulledAt": llx.TimeDataPtr(a.cacheCoverage.ResourceMetadata.EcrImage.ImagePulledAt),
			"region":        llx.StringData(a.Region.Data),
		})
		if err == nil {
			return mqlEcr.(*mqlAwsInspectorCoverageImage), err
		}
	}
	a.EcrImage.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsInspectorCoverageRepository) id() (string, error) {
	return a.Region.Data + "/" + a.Name.Data, nil
}

func (a *mqlAwsInspectorCoverage) ecrRepo() (*mqlAwsInspectorCoverageRepository, error) {
	if a.cacheCoverage != nil && a.cacheCoverage.ResourceMetadata != nil && a.cacheCoverage.ResourceMetadata.EcrRepository != nil {
		mqlEcr, err := CreateResource(a.MqlRuntime, "aws.inspector.coverage.repository", map[string]*llx.RawData{
			"__id":          llx.StringData(a.MqlID() + "/ecrRepo"),
			"name":          llx.StringDataPtr(a.cacheCoverage.ResourceMetadata.EcrRepository.Name),
			"scanFrequency": llx.StringData(string(a.cacheCoverage.ResourceMetadata.EcrRepository.ScanFrequency)),
			"region":        llx.StringData(a.Region.Data),
		})
		if err == nil {
			return mqlEcr.(*mqlAwsInspectorCoverageRepository), err
		}
	}
	a.EcrRepo.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsInspectorCoverage) lambda() (*mqlAwsLambdaFunction, error) {
	if a.cacheCoverage != nil && a.cacheCoverage.ResourceMetadata != nil && a.cacheCoverage.ResourceMetadata.LambdaFunction != nil {
		l, err := NewResource(a.MqlRuntime, "aws.lambda.function",
			map[string]*llx.RawData{
				"name":   llx.StringDataPtr(a.cacheCoverage.ResourceMetadata.LambdaFunction.FunctionName),
				"region": llx.StringData(a.Region.Data),
			})
		if err == nil {
			return l.(*mqlAwsLambdaFunction), nil
		}
	}
	a.Lambda.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ============================================================
// Inspector Account Status & Configuration
// ============================================================

func (a *mqlAwsInspectorAccountStatus) id() (string, error) {
	return a.AccountId.Data + "/" + a.Region.Data, nil
}

func (a *mqlAwsInspectorConfiguration) id() (string, error) {
	return "aws.inspector.configuration/" + a.Region.Data, nil
}

func inspectorStateStatus(s *types.State) string {
	if s == nil {
		return ""
	}
	return string(s.Status)
}

func (a *mqlAwsInspector) accountStatuses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAccountStatuses(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsInspector) getAccountStatuses(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Inspector(region)
			ctx := context.Background()
			res := []any{}

			// with no account IDs, BatchGetAccountStatus returns the status of
			// the requesting account
			resp, err := svc.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}
			for i := range resp.Accounts {
				acct := resp.Accounts[i]
				rs := acct.ResourceState
				if rs == nil {
					rs = &types.ResourceState{}
				}
				// AccountId is a required field on the API response, but fall
				// back to the connection account so the __id stays unique even
				// if it ever comes back empty
				accountID := convert.ToValue(acct.AccountId)
				if accountID == "" {
					accountID = conn.AccountId()
				}
				mqlStatus, err := CreateResource(a.MqlRuntime, "aws.inspector.accountStatus",
					map[string]*llx.RawData{
						"accountId":            llx.StringData(accountID),
						"status":               llx.StringData(inspectorStateStatus(acct.State)),
						"ec2Status":            llx.StringData(inspectorStateStatus(rs.Ec2)),
						"ecrStatus":            llx.StringData(inspectorStateStatus(rs.Ecr)),
						"lambdaStatus":         llx.StringData(inspectorStateStatus(rs.Lambda)),
						"lambdaCodeStatus":     llx.StringData(inspectorStateStatus(rs.LambdaCode)),
						"codeRepositoryStatus": llx.StringData(inspectorStateStatus(rs.CodeRepository)),
						"region":               llx.StringData(region),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlStatus)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsInspector) configurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConfigurations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsInspector) getConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Inspector(region)
			ctx := context.Background()
			res := []any{}

			resp, err := svc.GetConfiguration(ctx, &inspector2.GetConfigurationInput{})
			if err != nil {
				// GetConfiguration returns ResourceNotFoundException ("No
				// CustomerRecord exists") in regions where Inspector was never
				// enabled; treat that as no configuration rather than an error
				var notFound *types.ResourceNotFoundException
				if errors.As(err, &notFound) {
					return res, nil
				}
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			args := map[string]*llx.RawData{
				"region":                    llx.StringData(region),
				"ecrRescanDuration":         llx.StringData(""),
				"ecrPullDateRescanDuration": llx.StringData(""),
				"ecrPullDateRescanMode":     llx.StringData(""),
				"ecrRescanDurationStatus":   llx.StringData(""),
				"ecrRescanUpdatedAt":        llx.TimeDataPtr(nil),
				"ec2ScanMode":               llx.StringData(""),
				"ec2ScanModeStatus":         llx.StringData(""),
			}
			if resp.EcrConfiguration != nil && resp.EcrConfiguration.RescanDurationState != nil {
				rds := resp.EcrConfiguration.RescanDurationState
				args["ecrRescanDuration"] = llx.StringData(string(rds.RescanDuration))
				args["ecrPullDateRescanDuration"] = llx.StringData(string(rds.PullDateRescanDuration))
				args["ecrPullDateRescanMode"] = llx.StringData(string(rds.PullDateRescanMode))
				args["ecrRescanDurationStatus"] = llx.StringData(string(rds.Status))
				args["ecrRescanUpdatedAt"] = llx.TimeDataPtr(rds.UpdatedAt)
			}
			if resp.Ec2Configuration != nil && resp.Ec2Configuration.ScanModeState != nil {
				sms := resp.Ec2Configuration.ScanModeState
				args["ec2ScanMode"] = llx.StringData(string(sms.ScanMode))
				args["ec2ScanModeStatus"] = llx.StringData(string(sms.ScanModeStatus))
			}
			mqlConfig, err := CreateResource(a.MqlRuntime, "aws.inspector.configuration", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConfig)
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// ============================================================
// Inspector Findings
// ============================================================

type mqlAwsInspectorFindingInternal struct {
	cacheFinding *types.Finding
}

func (a *mqlAwsInspectorFinding) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsInspector) findings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFindings(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsInspector) getFindings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Inspector(region)
			ctx := context.Background()
			res := []any{}

			paginator := inspector2.NewListFindingsPaginator(svc, &inspector2.ListFindingsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Findings {
					finding := page.Findings[i]
					if finding.FindingArn == nil {
						continue
					}

					var inspectorScore float64
					if finding.InspectorScore != nil {
						inspectorScore = *finding.InspectorScore
					}

					mqlFinding, err := CreateResource(a.MqlRuntime, "aws.inspector.finding",
						map[string]*llx.RawData{
							"arn":              llx.StringDataPtr(finding.FindingArn),
							"accountId":        llx.StringDataPtr(finding.AwsAccountId),
							"title":            llx.StringDataPtr(finding.Title),
							"description":      llx.StringDataPtr(finding.Description),
							"severity":         llx.StringData(string(finding.Severity)),
							"status":           llx.StringData(string(finding.Status)),
							"type":             llx.StringData(string(finding.Type)),
							"firstObservedAt":  llx.TimeDataPtr(finding.FirstObservedAt),
							"lastObservedAt":   llx.TimeDataPtr(finding.LastObservedAt),
							"updatedAt":        llx.TimeDataPtr(finding.UpdatedAt),
							"inspectorScore":   llx.FloatData(inspectorScore),
							"exploitAvailable": llx.StringData(string(finding.ExploitAvailable)),
							"fixAvailable":     llx.StringData(string(finding.FixAvailable)),
							"region":           llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					mqlFinding.(*mqlAwsInspectorFinding).cacheFinding = &finding
					res = append(res, mqlFinding)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsInspectorFinding) remediation() (string, error) {
	if a.cacheFinding != nil && a.cacheFinding.Remediation != nil && a.cacheFinding.Remediation.Recommendation != nil {
		return convert.ToValue(a.cacheFinding.Remediation.Recommendation.Text), nil
	}
	return "", nil
}

func (a *mqlAwsInspectorFinding) remediationUrl() (string, error) {
	if a.cacheFinding != nil && a.cacheFinding.Remediation != nil && a.cacheFinding.Remediation.Recommendation != nil {
		return convert.ToValue(a.cacheFinding.Remediation.Recommendation.Url), nil
	}
	return "", nil
}

func (a *mqlAwsInspectorFinding) packageVulnerability() (*mqlAwsInspectorFindingPackageVulnerability, error) {
	if a.cacheFinding == nil || a.cacheFinding.PackageVulnerabilityDetails == nil {
		a.PackageVulnerability.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	pvd := a.cacheFinding.PackageVulnerabilityDetails

	findingArn := a.Arn.Data

	cvssScores := make([]any, 0, len(pvd.Cvss))
	for _, c := range pvd.Cvss {
		mqlCvss, err := CreateResource(a.MqlRuntime, "aws.inspector.finding.packageVulnerability.cvssScore",
			map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("%s/cvss/%s/%s/%.1f", findingArn, convert.ToValue(c.Source), convert.ToValue(c.Version), derefFloat64(c.BaseScore))),
				"baseScore":     llx.FloatData(derefFloat64(c.BaseScore)),
				"scoringVector": llx.StringDataPtr(c.ScoringVector),
				"source":        llx.StringDataPtr(c.Source),
				"version":       llx.StringDataPtr(c.Version),
			})
		if err != nil {
			return nil, err
		}
		cvssScores = append(cvssScores, mqlCvss)
	}

	vulnPkgs := make([]any, 0, len(pvd.VulnerablePackages))
	for i := range pvd.VulnerablePackages {
		pkg := pvd.VulnerablePackages[i]
		mqlPkg, err := CreateResource(a.MqlRuntime, "aws.inspector.finding.vulnerablePackage",
			map[string]*llx.RawData{
				"__id":           llx.StringData(fmt.Sprintf("%s/pkg/%s/%s/%s", findingArn, convert.ToValue(pkg.Name), convert.ToValue(pkg.Version), convert.ToValue(pkg.Arch))),
				"name":           llx.StringDataPtr(pkg.Name),
				"version":        llx.StringDataPtr(pkg.Version),
				"arch":           llx.StringDataPtr(pkg.Arch),
				"epoch":          llx.IntData(int64(pkg.Epoch)),
				"packageManager": llx.StringData(string(pkg.PackageManager)),
				"filePath":       llx.StringDataPtr(pkg.FilePath),
				"fixedInVersion": llx.StringDataPtr(pkg.FixedInVersion),
				"remediation":    llx.StringDataPtr(pkg.Remediation),
				"release":        llx.StringDataPtr(pkg.Release),
			})
		if err != nil {
			return nil, err
		}
		vulnPkgs = append(vulnPkgs, mqlPkg)
	}

	mqlPvd, err := CreateResource(a.MqlRuntime, "aws.inspector.finding.packageVulnerability",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(findingArn + "/packageVulnerability"),
			"vulnerabilityId":        llx.StringDataPtr(pvd.VulnerabilityId),
			"source":                 llx.StringDataPtr(pvd.Source),
			"sourceUrl":              llx.StringDataPtr(pvd.SourceUrl),
			"vendorSeverity":         llx.StringDataPtr(pvd.VendorSeverity),
			"vendorCreatedAt":        llx.TimeDataPtr(pvd.VendorCreatedAt),
			"vendorUpdatedAt":        llx.TimeDataPtr(pvd.VendorUpdatedAt),
			"cvssScores":             llx.ArrayData(cvssScores, llxtypes.Resource("aws.inspector.finding.packageVulnerability.cvssScore")),
			"referenceUrls":          llx.ArrayData(llx.TArr2Raw(pvd.ReferenceUrls), "string"),
			"relatedVulnerabilities": llx.ArrayData(llx.TArr2Raw(pvd.RelatedVulnerabilities), "string"),
			"vulnerablePackages":     llx.ArrayData(vulnPkgs, "aws.inspector.finding.vulnerablePackage"),
		})
	if err != nil {
		return nil, err
	}
	return mqlPvd.(*mqlAwsInspectorFindingPackageVulnerability), nil
}

func (a *mqlAwsInspectorFindingPackageVulnerability) id() (string, error) {
	return a.VulnerabilityId.Data + "/" + a.Source.Data, nil
}

func (a *mqlAwsInspectorFindingPackageVulnerabilityCvssScore) id() (string, error) {
	return fmt.Sprintf("%s/%s/%.1f", a.Source.Data, a.Version.Data, a.BaseScore.Data), nil
}

func derefFloat64(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func (a *mqlAwsInspectorFindingVulnerablePackage) id() (string, error) {
	return a.Name.Data + "/" + a.Version.Data + "/" + a.Arch.Data, nil
}

func (a *mqlAwsInspectorFinding) networkReachability() (*mqlAwsInspectorFindingNetworkReachability, error) {
	if a.cacheFinding == nil || a.cacheFinding.NetworkReachabilityDetails == nil {
		a.NetworkReachability.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	nrd := a.cacheFinding.NetworkReachabilityDetails

	var portStart, portEnd int64
	if nrd.OpenPortRange != nil {
		portStart = int64(convert.ToValue(nrd.OpenPortRange.Begin))
		portEnd = int64(convert.ToValue(nrd.OpenPortRange.End))
	}

	var networkPath []any
	if nrd.NetworkPath != nil {
		path, err := convert.JsonToDictSlice(nrd.NetworkPath.Steps)
		if err != nil {
			return nil, err
		}
		networkPath = path
	}

	findingArn := a.Arn.Data
	mqlNr, err := CreateResource(a.MqlRuntime, "aws.inspector.finding.networkReachability",
		map[string]*llx.RawData{
			"__id":          llx.StringData(findingArn + "/networkReachability"),
			"protocol":      llx.StringData(string(nrd.Protocol)),
			"openPortStart": llx.IntData(portStart),
			"openPortEnd":   llx.IntData(portEnd),
			"networkPath":   llx.ArrayData(networkPath, "dict"),
		})
	if err != nil {
		return nil, err
	}
	return mqlNr.(*mqlAwsInspectorFindingNetworkReachability), nil
}

func (a *mqlAwsInspectorFindingNetworkReachability) id() (string, error) {
	return fmt.Sprintf("%s/%d/%d", a.Protocol.Data, a.OpenPortStart.Data, a.OpenPortEnd.Data), nil
}

func (a *mqlAwsInspectorFinding) codeVulnerability() (*mqlAwsInspectorFindingCodeVulnerability, error) {
	if a.cacheFinding == nil || a.cacheFinding.CodeVulnerabilityDetails == nil {
		a.CodeVulnerability.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	cvd := a.cacheFinding.CodeVulnerabilityDetails

	filePath, err := convert.JsonToDict(cvd.FilePath)
	if err != nil {
		return nil, err
	}

	findingArn := a.Arn.Data
	mqlCv, err := CreateResource(a.MqlRuntime, "aws.inspector.finding.codeVulnerability",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(findingArn + "/codeVulnerability"),
			"cwes":                 llx.ArrayData(llx.TArr2Raw(cvd.Cwes), "string"),
			"detectorId":           llx.StringDataPtr(cvd.DetectorId),
			"detectorName":         llx.StringDataPtr(cvd.DetectorName),
			"detectorTags":         llx.ArrayData(llx.TArr2Raw(cvd.DetectorTags), "string"),
			"filePath":             llx.DictData(filePath),
			"referenceUrls":        llx.ArrayData(llx.TArr2Raw(cvd.ReferenceUrls), "string"),
			"ruleId":               llx.StringDataPtr(cvd.RuleId),
			"sourceLambdaLayerArn": llx.StringDataPtr(cvd.SourceLambdaLayerArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlCv.(*mqlAwsInspectorFindingCodeVulnerability), nil
}

func (a *mqlAwsInspectorFindingCodeVulnerability) id() (string, error) {
	return a.DetectorId.Data + "/" + a.RuleId.Data, nil
}
