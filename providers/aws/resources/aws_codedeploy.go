// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

const (
	codeDeployApplicationPattern     = "arn:aws:codedeploy:%s:%s:application:%s"
	codeDeployDeploymentGroupPattern = "arn:aws:codedeploy:%s:%s:deploymentgroup:%s/%s"
	// Deployments don't have a standard ARN, so we'll use their ID.
)

func (c *mqlAwsCodedeploy) id() (string, error) {
	return "aws.codedeploy", nil
}

func (c *mqlAwsCodedeploy) applications() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(c.getApplicationResources(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	for _, job := range poolOfJobs.Jobs {
		if job.Result != nil {
			res = append(res, job.Result.([]any)...)
		}
	}
	return res, nil
}

func (c *mqlAwsCodedeploy) getApplicationResources(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		reg := region // Capture range variable
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("codedeploy>getApplicationResources>calling aws with region %s", reg)
			svc := conn.CodeDeploy(reg)
			ctx := context.Background()
			appResources := []any{}

			params := &codedeploy.ListApplicationsInput{}
			paginator := codedeploy.NewListApplicationsPaginator(svc, params)
			for paginator.HasMorePages() {
				output, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", reg).Msg("error accessing CodeDeploy applications in region")
						return appResources, nil // Skip region on access denied
					}
					return nil, errors.Wrapf(err, "could not list CodeDeploy applications in region %s", reg)
				}

				if len(output.Applications) > 0 {
					batchGetInput := &codedeploy.BatchGetApplicationsInput{ApplicationNames: output.Applications}
					appInfos, err := svc.BatchGetApplications(ctx, batchGetInput)
					if err != nil {
						return nil, errors.Wrapf(err, "could not batch get CodeDeploy application details in region %s", reg)
					}

					for _, appInfo := range appInfos.ApplicationsInfo {
						arn := fmt.Sprintf(codeDeployApplicationPattern, reg, conn.AccountId(), aws.ToString(appInfo.ApplicationName))
						args := map[string]*llx.RawData{
							"__id":            llx.StringData(arn),
							"applicationName": llx.StringDataPtr(appInfo.ApplicationName),
							"applicationId":   llx.StringDataPtr(appInfo.ApplicationId),
							"arn":             llx.StringData(arn),
							"computePlatform": llx.StringData(string(appInfo.ComputePlatform)),
							"createdAt":       llx.TimeDataPtr(appInfo.CreateTime),
							"linkedToGitHub":  llx.BoolData(appInfo.LinkedToGitHub),
							"region":          llx.StringData(reg),
						}
						mqlApp, err := CreateResource(c.MqlRuntime, "aws.codedeploy.application", args)
						if err != nil {
							return nil, err
						}
						appResources = append(appResources, mqlApp)
					}
				}
			}
			return jobpool.JobResult(appResources), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCodedeployApplication) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCodedeployApplication) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CodeDeploy(a.Region.Data)
	ctx := context.Background()

	output, err := svc.ListTagsForResource(ctx, &codedeploy.ListTagsForResourceInput{ResourceArn: aws.String(a.Arn.Data)})
	if err != nil {
		return nil, errors.Wrapf(err, "could not list tags for CodeDeploy application %s", a.Arn.Data)
	}

	tagsMap := make(map[string]any)
	for _, tag := range output.Tags {
		tagsMap[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tagsMap, nil
}

func (a *mqlAwsCodedeployApplication) deploymentGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CodeDeploy(a.Region.Data)
	ctx := context.Background()
	dgResources := []any{}

	params := &codedeploy.ListDeploymentGroupsInput{
		ApplicationName: aws.String(a.ApplicationName.Data),
	}
	paginator := codedeploy.NewListDeploymentGroupsPaginator(svc, params)
	for paginator.HasMorePages() {
		listOutput, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "could not list deployment groups for application %s", a.ApplicationName.Data)
		}

		if len(listOutput.DeploymentGroups) > 0 {
			batchGetInput := &codedeploy.BatchGetDeploymentGroupsInput{
				ApplicationName:      aws.String(a.ApplicationName.Data),
				DeploymentGroupNames: listOutput.DeploymentGroups,
			}
			batchGetOutput, err := svc.BatchGetDeploymentGroups(ctx, batchGetInput)
			if err != nil {
				return nil, errors.Wrapf(err, "could not batch get deployment group details for application %s", a.ApplicationName.Data)
			}

			for _, dgInfo := range batchGetOutput.DeploymentGroupsInfo {
				arn := fmt.Sprintf(codeDeployDeploymentGroupPattern,
					a.Region.Data, conn.AccountId(), aws.ToString(dgInfo.ApplicationName), aws.ToString(dgInfo.DeploymentGroupName),
				)
				args := map[string]*llx.RawData{
					"__id":                llx.StringData(arn),
					"applicationName":     llx.StringDataPtr(dgInfo.ApplicationName),
					"arn":                 llx.StringData(arn),
					"deploymentGroupId":   llx.StringDataPtr(dgInfo.DeploymentGroupId),
					"deploymentGroupName": llx.StringDataPtr(dgInfo.DeploymentGroupName),
					"computePlatform":     llx.StringData(string(dgInfo.ComputePlatform)),
					"region":              llx.StringData(a.Region.Data),
				}

				mqlDg, err := CreateResource(a.MqlRuntime, "aws.codedeploy.deploymentGroup", args)
				if err != nil {
					return nil, err
				}
				mqlDg.(*mqlAwsCodedeployDeploymentGroup).cacheServiceRoleArn = convert.ToValue(dgInfo.ServiceRoleArn)
				// Store dgInfo in an internal struct if more fields are needed for resolver methods
				mqlDg.(*mqlAwsCodedeployDeploymentGroup).sdkData = dgInfo

				dgResources = append(dgResources, mqlDg)
			}
		}
	}
	return dgResources, nil
}

func (a *mqlAwsCodedeployApplication) deployments() ([]any, error) {
	groups, err := a.deploymentGroups()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, g := range groups {
		group := g.(*mqlAwsCodedeployDeploymentGroup)
		deployments, err := group.deployments()
		if err != nil {
			return res, err
		}

		res = append(res, deployments...)
	}
	return res, nil
}

type mqlAwsCodedeployDeploymentGroupInternal struct {
	cacheServiceRoleArn string
	sdkData             codedeploytypes.DeploymentGroupInfo // Store fetched data
}

func (dg *mqlAwsCodedeployDeploymentGroup) id() (string, error) {
	return dg.Arn.Data, nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) serviceRole() (*mqlAwsIamRole, error) {
	arnVal := dg.cacheServiceRoleArn
	if arnVal == "" {
		dg.ServiceRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(dg.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) targetRevision() (any, error) {
	if dg.sdkData.TargetRevision == nil {
		return nil, nil
	}
	return convert.JsonToDict(dg.sdkData.TargetRevision)
}

func (dg *mqlAwsCodedeployDeploymentGroup) tags() (map[string]any, error) {
	conn := dg.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CodeDeploy(dg.Region.Data)
	ctx := context.Background()

	output, err := svc.ListTagsForResource(ctx, &codedeploy.ListTagsForResourceInput{ResourceArn: aws.String(dg.Arn.Data)})
	if err != nil {
		return nil, errors.Wrapf(err, "could not list tags for CodeDeploy deployment group %s", dg.Arn.Data)
	}

	tagsMap := make(map[string]any)
	for _, tag := range output.Tags {
		tagsMap[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tagsMap, nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) deployments() ([]any, error) {
	return listDeployments(dg.MqlRuntime, dg.Region.Data, &dg.ApplicationName.Data, &dg.DeploymentGroupName.Data)
}

func (dg *mqlAwsCodedeployDeploymentGroup) autoScalingGroups() ([]any, error) {
	asgResources := []any{}
	if dg.sdkData.AutoScalingGroups == nil {
		return asgResources, nil
	}
	for _, asg := range dg.sdkData.AutoScalingGroups {
		if asg.Name == nil {
			continue
		}
		// This assumes ASGs are in the same region as the CodeDeploy deployment group
		// ARN construction for ASGs is a bit different, usually fetched via name
		// We'd need a way to link to an existing aws.autoscaling.group resource.
		// For now, returning basic info. A full resource link would require aws.autoscaling.group to be an init-able resource by name+region.
		asgRes, err := NewResource(dg.MqlRuntime, ResourceAwsAutoscalingGroup, map[string]*llx.RawData{
			"name":   llx.StringData(*asg.Name),
			"region": llx.StringData(dg.Region.Data),
			// ARN might need to be constructed or looked up if not directly available
		})
		if err != nil {
			log.Error().Err(err).Msgf("could not create resource for ASG %s", *asg.Name)
			continue
		}
		asgResources = append(asgResources, asgRes)
	}
	return asgResources, nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) ec2TagFilters() ([]any, error) {
	return convert.JsonToDictSlice(dg.sdkData.Ec2TagFilters)
}

func (dg *mqlAwsCodedeployDeploymentGroup) onPremisesInstanceTagFilters() ([]any, error) {
	return convert.JsonToDictSlice(dg.sdkData.OnPremisesInstanceTagFilters)
}

func (dg *mqlAwsCodedeployDeploymentGroup) lastSuccessfulDeployment() (*mqlAwsCodedeployDeployment, error) {
	if dg.sdkData.LastSuccessfulDeployment == nil || dg.sdkData.LastSuccessfulDeployment.DeploymentId == nil {
		dg.LastSuccessfulDeployment = plugin.TValue[*mqlAwsCodedeployDeployment]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	dep, err := getDeploymentResource(dg.MqlRuntime, dg.Region.Data, &dg.ApplicationName.Data, &dg.DeploymentGroupName.Data, dg.sdkData.LastSuccessfulDeployment.DeploymentId)
	if err != nil {
		return nil, err
	}
	if dep == nil {
		// The group still names a deployment that CodeDeploy no longer holds.
		// Returning a typed nil with no error would leave the field set and
		// not null, and serializing it calls MqlID on the nil receiver.
		dg.LastSuccessfulDeployment = plugin.TValue[*mqlAwsCodedeployDeployment]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return dep, nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) lastAttemptedDeployment() (*mqlAwsCodedeployDeployment, error) {
	if dg.sdkData.LastAttemptedDeployment == nil || dg.sdkData.LastAttemptedDeployment.DeploymentId == nil {
		dg.LastAttemptedDeployment = plugin.TValue[*mqlAwsCodedeployDeployment]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	dep, err := getDeploymentResource(dg.MqlRuntime, dg.Region.Data, &dg.ApplicationName.Data, &dg.DeploymentGroupName.Data, dg.sdkData.LastAttemptedDeployment.DeploymentId)
	if err != nil {
		return nil, err
	}
	if dep == nil {
		// The group still names a deployment that CodeDeploy no longer holds.
		// Returning a typed nil with no error would leave the field set and
		// not null, and serializing it calls MqlID on the nil receiver.
		dg.LastAttemptedDeployment = plugin.TValue[*mqlAwsCodedeployDeployment]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return dep, nil
}

func (dg *mqlAwsCodedeployDeploymentGroup) deploymentStyle() (any, error) {
	if dg.sdkData.DeploymentStyle == nil {
		return nil, nil
	}
	return convert.JsonToDict(dg.sdkData.DeploymentStyle)
}

func (dg *mqlAwsCodedeployDeploymentGroup) blueGreenDeploymentConfiguration() (any, error) {
	if dg.sdkData.BlueGreenDeploymentConfiguration == nil {
		return nil, nil
	}
	return convert.JsonToDict(dg.sdkData.BlueGreenDeploymentConfiguration)
}

func (dg *mqlAwsCodedeployDeploymentGroup) loadBalancerInfo() (any, error) {
	if dg.sdkData.LoadBalancerInfo == nil {
		return nil, nil
	}
	return convert.JsonToDict(dg.sdkData.LoadBalancerInfo)
}

func (d *mqlAwsCodedeployDeployment) id() (string, error) {
	return d.Arn.Data, nil
}

type mqlAwsCodedeployDeploymentInternal struct {
	sdkData codedeploytypes.DeploymentInfo // Store fetched data
}

func (d *mqlAwsCodedeployDeployment) targetInstances() (any, error) {
	if d.sdkData.TargetInstances == nil {
		return nil, nil
	}
	return convert.JsonToDict(d.sdkData.TargetInstances)
}

func (d *mqlAwsCodedeployDeployment) revision() (any, error) {
	if d.sdkData.Revision == nil {
		return nil, nil
	}
	return convert.JsonToDict(d.sdkData.Revision)
}

func (d *mqlAwsCodedeployDeployment) errorInformation() (any, error) {
	if d.sdkData.ErrorInformation == nil {
		return nil, nil
	}
	return convert.JsonToDict(d.sdkData.ErrorInformation)
}

func (d *mqlAwsCodedeployDeployment) deploymentOverview() (any, error) {
	if d.sdkData.DeploymentOverview == nil {
		return nil, nil
	}
	return convert.JsonToDict(d.sdkData.DeploymentOverview)
}

func (d *mqlAwsCodedeployDeployment) isRollback() (bool, error) {
	if d.sdkData.RollbackInfo == nil {
		return false, nil // Default to false if RollbackInfo is not present
	}
	return d.sdkData.RollbackInfo.RollbackDeploymentId != nil, nil
}

func (d *mqlAwsCodedeployDeployment) rollbackInfo() (any, error) {
	if d.sdkData.RollbackInfo == nil {
		return nil, nil
	}
	return convert.JsonToDict(d.sdkData.RollbackInfo)
}

// Helper function to list deployments
func listDeployments(runtime *plugin.Runtime, region string, appName, dgName *string) ([]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.CodeDeploy(region)
	ctx := context.Background()
	depResources := []any{}

	params := &codedeploy.ListDeploymentsInput{
		ApplicationName:     appName,
		DeploymentGroupName: dgName,
		// Potentially filter by IncludeOnlyStatuses for active ones if desired
		// IncludeOnlyStatuses: []codedeploytypes.DeploymentStatus{DeploymentStatusInProgress, DeploymentStatusQueued, DeploymentStatusReady}
	}
	paginator := codedeploy.NewListDeploymentsPaginator(svc, params)
	for paginator.HasMorePages() {
		listOutput, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "could not list deployments for app %s, group %s", aws.ToString(appName), aws.ToString(dgName))
		}

		if len(listOutput.Deployments) > 0 {
			batchGetInput := &codedeploy.BatchGetDeploymentsInput{DeploymentIds: listOutput.Deployments}
			batchGetOutput, err := svc.BatchGetDeployments(ctx, batchGetInput)
			if err != nil {
				return nil, errors.Wrapf(err, "could not batch get deployment details")
			}

			for _, depInfo := range batchGetOutput.DeploymentsInfo {
				// Construct a synthetic ARN or use deploymentId for uniqueness
				syntheticArn := fmt.Sprintf(
					"arn:aws:codedeploy:%s:%s:deployment/%s/%s/%s",
					region, conn.AccountId(), aws.ToString(depInfo.ApplicationName),
					aws.ToString(depInfo.DeploymentGroupName), aws.ToString(depInfo.DeploymentId),
				)

				args := map[string]*llx.RawData{
					"__id":                          llx.StringData(syntheticArn),
					"applicationName":               llx.StringDataPtr(depInfo.ApplicationName),
					"deploymentId":                  llx.StringDataPtr(depInfo.DeploymentId),
					"arn":                           llx.StringData(syntheticArn), // Or just depInfo.DeploymentId
					"status":                        llx.StringData(string(depInfo.Status)),
					"deploymentGroupName":           llx.StringDataPtr(depInfo.DeploymentGroupName),
					"deploymentConfigName":          llx.StringDataPtr(depInfo.DeploymentConfigName),
					"deploymentMode":                codeDeployDeploymentMode(depInfo.DeploymentMode),
					"createdAt":                     llx.TimeDataPtr(depInfo.CreateTime),
					"completedAt":                   llx.TimeDataPtr(depInfo.CompleteTime),
					"description":                   llx.StringDataPtr(depInfo.Description),
					"creator":                       llx.StringData(string(depInfo.Creator)),
					"ignoreApplicationStopFailures": llx.BoolData(depInfo.IgnoreApplicationStopFailures),
					"region":                        llx.StringData(region),
				}
				mqlDep, err := CreateResource(runtime, "aws.codedeploy.deployment", args)
				if err != nil {
					return nil, err
				}
				mqlDep.(*mqlAwsCodedeployDeployment).sdkData = depInfo
				depResources = append(depResources, mqlDep)
			}
		}
	}
	return depResources, nil
}

// codeDeployDeploymentMode publishes DeploymentInfo.DeploymentMode.
//
// The SDK types the mode as a value rather than a pointer, so a deployment
// that recorded no mode arrives as the empty string. AWS documents that state
// as "no value was recorded either way" and explicitly not as STANDARD, so it
// reports null: an empty string would read as a mode of "", and STANDARD would
// claim the deployment downloaded a fresh revision when nothing says it did.
func codeDeployDeploymentMode(mode codedeploytypes.DeploymentMode) *llx.RawData {
	if mode == "" {
		return llx.StringDataPtr(nil)
	}
	s := string(mode)
	return llx.StringDataPtr(&s)
}

// Helper function to get a single deployment resource
func getDeploymentResource(runtime *plugin.Runtime, region string, appName, dgName, depID *string) (*mqlAwsCodedeployDeployment, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.CodeDeploy(region)
	ctx := context.Background()

	getInput := &codedeploy.GetDeploymentInput{DeploymentId: depID}
	getOutput, err := svc.GetDeployment(ctx, getInput)
	if err != nil {
		// If it's a NotFound error, it's not an issue, just means the deployment doesn't exist or isn't accessible.
		var depNotExists *codedeploytypes.DeploymentDoesNotExistException
		if errors.As(err, &depNotExists) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "could not get deployment details for ID %s", aws.ToString(depID))
	}

	if getOutput.DeploymentInfo == nil {
		return nil, nil // Deployment info not found
	}
	depInfo := getOutput.DeploymentInfo
	syntheticArn := fmt.Sprintf("arn:aws:codedeploy:%s:%s:deployment/%s/%s/%s",
		region, conn.AccountId(), aws.ToString(depInfo.ApplicationName), aws.ToString(depInfo.DeploymentGroupName), aws.ToString(depInfo.DeploymentId))

	args := map[string]*llx.RawData{
		"__id":                          llx.StringData(syntheticArn),
		"applicationName":               llx.StringDataPtr(depInfo.ApplicationName),
		"deploymentId":                  llx.StringDataPtr(depInfo.DeploymentId),
		"arn":                           llx.StringData(syntheticArn),
		"status":                        llx.StringData(string(depInfo.Status)),
		"deploymentGroupName":           llx.StringDataPtr(depInfo.DeploymentGroupName),
		"deploymentConfigName":          llx.StringDataPtr(depInfo.DeploymentConfigName),
		"deploymentMode":                codeDeployDeploymentMode(depInfo.DeploymentMode),
		"createdAt":                     llx.TimeDataPtr(depInfo.CreateTime),
		"completedAt":                   llx.TimeDataPtr(depInfo.CompleteTime),
		"description":                   llx.StringDataPtr(depInfo.Description),
		"creator":                       llx.StringData(string(depInfo.Creator)),
		"ignoreApplicationStopFailures": llx.BoolData(depInfo.IgnoreApplicationStopFailures),
		"region":                        llx.StringData(region),
	}
	mqlDep, err := CreateResource(runtime, "aws.codedeploy.deployment", args)
	if err != nil {
		return nil, err
	}
	mqlDep.(*mqlAwsCodedeployDeployment).sdkData = *depInfo
	return mqlDep.(*mqlAwsCodedeployDeployment), nil
}

func initAwsCodedeployApplication(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch CodeDeploy application")
	}

	obj, err := CreateResource(runtime, "aws.codedeploy", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cd := obj.(*mqlAwsCodedeploy)
	rawResources := cd.GetApplications()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	for _, r := range rawResources.Data {
		app := r.(*mqlAwsCodedeployApplication)
		if app.Arn.Data == arnVal {
			return args, app, nil
		}
	}
	return nil, nil, errors.New("codedeploy application does not exist")
}
