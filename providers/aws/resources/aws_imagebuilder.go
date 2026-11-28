// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
	ibtypes "github.com/aws/aws-sdk-go-v2/service/imagebuilder/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsImagebuilder) id() (string, error) {
	return "aws.imagebuilder", nil
}

// --- cleanup script detection ---

// imagebuilderSkipCleanupRe matches the flag files that skip one section of
// the Image Builder cleanup script, for example skip_cleanup_ssh_files.
var imagebuilderSkipCleanupRe = regexp.MustCompile(`skip_cleanup_[a-z0-9_]+`)

// imagebuilderPerformCleanupFile is the flag file the cleanup script requires
// to run; a recipe that overrides user data must create it.
const imagebuilderPerformCleanupFile = "perform_cleanup"

// imagebuilderSkippedCleanupSections returns the skip_cleanup_* file names a
// script or component document mentions, in order of first appearance.
func imagebuilderSkippedCleanupSections(text string) []string {
	res := []string{}
	for _, m := range imagebuilderSkipCleanupRe.FindAllString(text, -1) {
		if !slices.Contains(res, m) {
			res = append(res, m)
		}
	}
	return res
}

// imagebuilderCleanupScriptDisabled reports whether a recipe's user data
// override keeps the cleanup script from running: an override replaces the
// user data that creates the perform_cleanup file, so the script runs only
// when the override creates that file itself.
func imagebuilderCleanupScriptDisabled(userDataOverride string) bool {
	if strings.TrimSpace(userDataOverride) == "" {
		return false
	}
	return !strings.Contains(userDataOverride, imagebuilderPerformCleanupFile)
}

// imagebuilderDecodeUserData decodes a base64 user data override. A value that
// is not valid base64 is returned as is.
func imagebuilderDecodeUserData(v *string) string {
	raw := convert.ToValue(v)
	if raw == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	return string(decoded)
}

// --- distribution configurations ---

// imagebuilderLaunchPermissionPublic reports whether a launch permission
// grants every AWS account the right to launch the AMI.
func imagebuilderLaunchPermissionPublic(lp *ibtypes.LaunchPermissionConfiguration) bool {
	if lp == nil {
		return false
	}
	for _, g := range lp.UserGroups {
		if strings.EqualFold(g, "all") {
			return true
		}
	}
	return false
}

func (a *mqlAwsImagebuilder) distributionConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "imagebuilder", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.ImageBuilder(region)
		res := []any{}
		paginator := imagebuilder.NewListDistributionConfigurationsPaginator(svc, &imagebuilder.ListDistributionConfigurationsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, d := range page.DistributionConfigurationSummaryList {
				mqlDist, err := CreateResource(a.MqlRuntime, ResourceAwsImagebuilderDistributionConfiguration, map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(d.Arn),
					"arn":         llx.StringDataPtr(d.Arn),
					"name":        llx.StringDataPtr(d.Name),
					"region":      llx.StringData(region),
					"description": llx.StringDataPtr(d.Description),
					"createdAt":   llx.TimeDataPtr(parseAwsTimestampPtr(d.DateCreated)),
					"updatedAt":   llx.TimeDataPtr(parseAwsTimestampPtr(d.DateUpdated)),
					"tags":        llx.MapData(toInterfaceMap(d.Tags), types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlDist)
			}
		}
		return res, nil
	})
}

type mqlAwsImagebuilderDistributionConfigurationInternal struct {
	lock    sync.Mutex
	fetched bool
	detail  *ibtypes.DistributionConfiguration
}

func (a *mqlAwsImagebuilderDistributionConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

// imagebuilderRegionFromArn returns the region of an Image Builder ARN.
func imagebuilderRegionFromArn(resourceArn string) (string, error) {
	parsed, err := arn.Parse(resourceArn)
	if err != nil {
		return "", err
	}
	if parsed.Service != "imagebuilder" || parsed.Region == "" {
		return "", fmt.Errorf("not an Image Builder ARN: %q", resourceArn)
	}
	return parsed.Region, nil
}

// initAwsImagebuilderDistributionConfiguration resolves a distribution
// configuration from its ARN, for the reference an image pipeline holds.
func initAwsImagebuilderDistributionConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws imagebuilder distribution configuration")
	}
	if cached := cachedArgByArn(runtime, ResourceAwsImagebuilderDistributionConfiguration, args); cached != nil {
		return args, cached, nil
	}
	distArn, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	region, err := imagebuilderRegionFromArn(distArn)
	if err != nil {
		return nil, nil, err
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.ImageBuilder(region)
	out, err := svc.GetDistributionConfiguration(context.Background(), &imagebuilder.GetDistributionConfigurationInput{
		DistributionConfigurationArn: &distArn,
	})
	if err != nil {
		return nil, nil, err
	}
	d := out.DistributionConfiguration
	if d == nil {
		return nil, nil, fmt.Errorf("aws.imagebuilder.distributionConfiguration with arn %q not found", distArn)
	}
	args["__id"] = llx.StringData(distArn)
	args["arn"] = llx.StringData(distArn)
	args["name"] = llx.StringDataPtr(d.Name)
	args["region"] = llx.StringData(region)
	args["description"] = llx.StringDataPtr(d.Description)
	args["createdAt"] = llx.TimeDataPtr(parseAwsTimestampPtr(d.DateCreated))
	args["updatedAt"] = llx.TimeDataPtr(parseAwsTimestampPtr(d.DateUpdated))
	args["tags"] = llx.MapData(toInterfaceMap(d.Tags), types.String)
	res, err := CreateResource(runtime, ResourceAwsImagebuilderDistributionConfiguration, args)
	if err != nil {
		return nil, nil, err
	}
	mqlDist := res.(*mqlAwsImagebuilderDistributionConfiguration)
	mqlDist.lock.Lock()
	mqlDist.detail = d
	mqlDist.fetched = true
	mqlDist.lock.Unlock()
	return args, res, nil
}

func (a *mqlAwsImagebuilderDistributionConfiguration) fetchDetail() (*ibtypes.DistributionConfiguration, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	distArn := a.Arn.Data
	svc := conn.ImageBuilder(a.Region.Data)
	out, err := svc.GetDistributionConfiguration(context.Background(), &imagebuilder.GetDistributionConfigurationInput{
		DistributionConfigurationArn: &distArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) && plugin.StructuredErrors() {
			return nil, llx.Forbidden(err, llx.WithPermissions("imagebuilder:GetDistributionConfiguration"))
		}
		return nil, err
	}
	a.detail = out.DistributionConfiguration
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsImagebuilderDistributionConfiguration) distributions() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if detail == nil {
		return res, nil
	}
	for _, d := range detail.Distributions {
		region := convert.ToValue(d.Region)
		var (
			amiName, amiDescription, amiKmsKeyId string
			amiTags                              map[string]string
			targetAccountIds                     []string
			lp                                   *ibtypes.LaunchPermissionConfiguration
		)
		if ami := d.AmiDistributionConfiguration; ami != nil {
			amiName = convert.ToValue(ami.Name)
			amiDescription = convert.ToValue(ami.Description)
			amiKmsKeyId = convert.ToValue(ami.KmsKeyId)
			amiTags = ami.AmiTags
			targetAccountIds = ami.TargetAccountIds
			lp = ami.LaunchPermission
		}
		var userGroups, userIds, orgArns, ouArns []string
		if lp != nil {
			userGroups, userIds, orgArns, ouArns = lp.UserGroups, lp.UserIds, lp.OrganizationArns, lp.OrganizationalUnitArns
		}
		mqlDistribution, err := CreateResource(a.MqlRuntime, ResourceAwsImagebuilderDistributionConfigurationDistribution, map[string]*llx.RawData{
			"__id":                                   llx.StringData(a.Arn.Data + "/distribution/" + region),
			"region":                                 llx.StringData(region),
			"amiName":                                llx.StringData(amiName),
			"amiDescription":                         llx.StringData(amiDescription),
			"amiKmsKeyId":                            llx.StringData(amiKmsKeyId),
			"amiTags":                                llx.MapData(toInterfaceMap(amiTags), types.String),
			"targetAccountIds":                       llx.ArrayData(toInterfaceArr(targetAccountIds), types.String),
			"launchPermissionUserGroups":             llx.ArrayData(toInterfaceArr(userGroups), types.String),
			"launchPermissionUserIds":                llx.ArrayData(toInterfaceArr(userIds), types.String),
			"launchPermissionOrganizationArns":       llx.ArrayData(toInterfaceArr(orgArns), types.String),
			"launchPermissionOrganizationalUnitArns": llx.ArrayData(toInterfaceArr(ouArns), types.String),
			"public":                                 llx.BoolData(imagebuilderLaunchPermissionPublic(lp)),
			"licenseConfigurationArns":               llx.ArrayData(toInterfaceArr(d.LicenseConfigurationArns), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDistribution)
	}
	return res, nil
}

func (a *mqlAwsImagebuilderDistributionConfiguration) public() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail == nil {
		return false, nil
	}
	for _, d := range detail.Distributions {
		if d.AmiDistributionConfiguration != nil && imagebuilderLaunchPermissionPublic(d.AmiDistributionConfiguration.LaunchPermission) {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsImagebuilderDistributionConfigurationDistribution) id() (string, error) {
	return a.__id, nil
}

// --- components ---

func (a *mqlAwsImagebuilder) components() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "imagebuilder", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.ImageBuilder(region)
		res := []any{}
		paginator := imagebuilder.NewListComponentsPaginator(svc, &imagebuilder.ListComponentsInput{
			Owner: ibtypes.OwnershipSelf,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, c := range page.ComponentVersionList {
				mqlComponent, err := fetchImagebuilderComponent(ctx, a.MqlRuntime, region, convert.ToValue(c.Arn))
				if err != nil {
					return nil, err
				}
				res = append(res, mqlComponent)
			}
		}
		return res, nil
	})
}

// fetchImagebuilderComponent reads one component version with its document.
// componentArn may name a build version or a semantic version, including
// x.x.x wildcards, which resolve to the latest matching version.
func fetchImagebuilderComponent(ctx context.Context, runtime *plugin.Runtime, region, componentArn string) (*mqlAwsImagebuilderComponent, error) {
	if cached := cachedByArn(runtime, ResourceAwsImagebuilderComponent, componentArn); cached != nil {
		return cached.(*mqlAwsImagebuilderComponent), nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.ImageBuilder(region)
	out, err := svc.GetComponent(ctx, &imagebuilder.GetComponentInput{
		ComponentBuildVersionArn: &componentArn,
	})
	if err != nil {
		return nil, err
	}
	c := out.Component
	if c == nil {
		return nil, fmt.Errorf("aws.imagebuilder.component with arn %q not found", componentArn)
	}
	data := convert.ToValue(c.Data)
	res, err := CreateResource(runtime, ResourceAwsImagebuilderComponent, map[string]*llx.RawData{
		"__id":                   llx.StringDataPtr(c.Arn),
		"arn":                    llx.StringDataPtr(c.Arn),
		"name":                   llx.StringDataPtr(c.Name),
		"version":                llx.StringDataPtr(c.Version),
		"region":                 llx.StringData(region),
		"description":            llx.StringDataPtr(c.Description),
		"changeDescription":      llx.StringDataPtr(c.ChangeDescription),
		"platform":               llx.StringData(string(c.Platform)),
		"type":                   llx.StringData(string(c.Type)),
		"owner":                  llx.StringDataPtr(c.Owner),
		"supportedOsVersions":    llx.ArrayData(toInterfaceArr(c.SupportedOsVersions), types.String),
		"encrypted":              llx.BoolData(convert.ToValue(c.Encrypted)),
		"kmsKeyId":               llx.StringDataPtr(c.KmsKeyId),
		"data":                   llx.StringData(data),
		"skippedCleanupSections": llx.ArrayData(toInterfaceArr(imagebuilderSkippedCleanupSections(data)), types.String),
		"createdAt":              llx.TimeDataPtr(parseAwsTimestampPtr(c.DateCreated)),
		"tags":                   llx.MapData(toInterfaceMap(c.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsImagebuilderComponent), nil
}

func (a *mqlAwsImagebuilderComponent) id() (string, error) {
	return a.Arn.Data, nil
}

// --- image recipes ---

func (a *mqlAwsImagebuilder) imageRecipes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "imagebuilder", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.ImageBuilder(region)
		res := []any{}
		paginator := imagebuilder.NewListImageRecipesPaginator(svc, &imagebuilder.ListImageRecipesInput{
			Owner: ibtypes.OwnershipSelf,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, r := range page.ImageRecipeSummaryList {
				mqlRecipe, err := fetchImagebuilderImageRecipe(ctx, a.MqlRuntime, region, convert.ToValue(r.Arn))
				if err != nil {
					return nil, err
				}
				res = append(res, mqlRecipe)
			}
		}
		return res, nil
	})
}

func fetchImagebuilderImageRecipe(ctx context.Context, runtime *plugin.Runtime, region, recipeArn string) (*mqlAwsImagebuilderImageRecipe, error) {
	if cached := cachedByArn(runtime, ResourceAwsImagebuilderImageRecipe, recipeArn); cached != nil {
		return cached.(*mqlAwsImagebuilderImageRecipe), nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.ImageBuilder(region)
	out, err := svc.GetImageRecipe(ctx, &imagebuilder.GetImageRecipeInput{
		ImageRecipeArn: &recipeArn,
	})
	if err != nil {
		return nil, err
	}
	r := out.ImageRecipe
	if r == nil {
		return nil, fmt.Errorf("aws.imagebuilder.imageRecipe with arn %q not found", recipeArn)
	}
	args, err := imagebuilderImageRecipeArgs(region, r)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAwsImagebuilderImageRecipe, args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsImagebuilderImageRecipe), nil
}

func imagebuilderImageRecipeArgs(region string, r *ibtypes.ImageRecipe) (map[string]*llx.RawData, error) {
	components := make([]any, 0, len(r.Components))
	for _, c := range r.Components {
		params := make([]any, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			params = append(params, map[string]any{
				"name":  convert.ToValue(p.Name),
				"value": toInterfaceArr(p.Value),
			})
		}
		components = append(components, map[string]any{
			"componentArn": convert.ToValue(c.ComponentArn),
			"parameters":   params,
		})
	}
	var userData string
	var ssmUninstall bool
	if aic := r.AdditionalInstanceConfiguration; aic != nil {
		userData = imagebuilderDecodeUserData(aic.UserDataOverride)
		if aic.SystemsManagerAgent != nil {
			ssmUninstall = convert.ToValue(aic.SystemsManagerAgent.UninstallAfterBuild)
		}
	}
	return map[string]*llx.RawData{
		"__id":                        llx.StringDataPtr(r.Arn),
		"arn":                         llx.StringDataPtr(r.Arn),
		"name":                        llx.StringDataPtr(r.Name),
		"version":                     llx.StringDataPtr(r.Version),
		"region":                      llx.StringData(region),
		"description":                 llx.StringDataPtr(r.Description),
		"platform":                    llx.StringData(string(r.Platform)),
		"owner":                       llx.StringDataPtr(r.Owner),
		"parentImage":                 llx.StringDataPtr(r.ParentImage),
		"workingDirectory":            llx.StringDataPtr(r.WorkingDirectory),
		"components":                  llx.ArrayData(components, types.Dict),
		"userDataOverride":            llx.StringData(userData),
		"ssmAgentUninstallAfterBuild": llx.BoolData(ssmUninstall),
		"cleanupScriptDisabled":       llx.BoolData(imagebuilderCleanupScriptDisabled(userData)),
		"createdAt":                   llx.TimeDataPtr(parseAwsTimestampPtr(r.DateCreated)),
		"tags":                        llx.MapData(toInterfaceMap(r.Tags), types.String),
	}, nil
}

// initAwsImagebuilderImageRecipe resolves an image recipe from its ARN, for
// the reference an image pipeline holds.
func initAwsImagebuilderImageRecipe(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws imagebuilder image recipe")
	}
	if cached := cachedArgByArn(runtime, ResourceAwsImagebuilderImageRecipe, args); cached != nil {
		return args, cached, nil
	}
	recipeArn, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	region, err := imagebuilderRegionFromArn(recipeArn)
	if err != nil {
		return nil, nil, err
	}
	res, err := fetchImagebuilderImageRecipe(context.Background(), runtime, region, recipeArn)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsImagebuilderImageRecipe) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsImagebuilderImageRecipe) componentDetails() ([]any, error) {
	res := []any{}
	for _, raw := range a.Components.Data {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		componentArn, _ := c["componentArn"].(string)
		if componentArn == "" {
			continue
		}
		mqlComponent, err := fetchImagebuilderComponent(context.Background(), a.MqlRuntime, a.Region.Data, componentArn)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlComponent)
	}
	return res, nil
}

func (a *mqlAwsImagebuilderImageRecipe) skippedCleanupSections() ([]any, error) {
	sections := imagebuilderSkippedCleanupSections(a.UserDataOverride.Data)
	components := a.GetComponentDetails()
	if components.Error != nil {
		return nil, components.Error
	}
	for _, raw := range components.Data {
		c, ok := raw.(*mqlAwsImagebuilderComponent)
		if !ok {
			continue
		}
		for _, s := range c.SkippedCleanupSections.Data {
			if str, ok := s.(string); ok && !slices.Contains(sections, str) {
				sections = append(sections, str)
			}
		}
	}
	return toInterfaceArr(sections), nil
}

func (a *mqlAwsImagebuilderImageRecipe) cleanupBypassed() (bool, error) {
	if a.CleanupScriptDisabled.Data {
		return true, nil
	}
	sections := a.GetSkippedCleanupSections()
	if sections.Error != nil {
		return false, sections.Error
	}
	return len(sections.Data) > 0, nil
}

// --- image pipelines ---

func (a *mqlAwsImagebuilder) imagePipelines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "imagebuilder", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.ImageBuilder(region)
		res := []any{}
		paginator := imagebuilder.NewListImagePipelinesPaginator(svc, &imagebuilder.ListImagePipelinesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for i := range page.ImagePipelineList {
				mqlPipeline, err := newMqlImagebuilderImagePipeline(a.MqlRuntime, region, &page.ImagePipelineList[i])
				if err != nil {
					return nil, err
				}
				res = append(res, mqlPipeline)
			}
		}
		return res, nil
	})
}

func newMqlImagebuilderImagePipeline(runtime *plugin.Runtime, region string, p *ibtypes.ImagePipeline) (plugin.Resource, error) {
	var testsEnabled, scanningEnabled bool
	if p.ImageTestsConfiguration != nil {
		testsEnabled = convert.ToValue(p.ImageTestsConfiguration.ImageTestsEnabled)
	} else {
		// Image Builder runs image tests unless they are turned off.
		testsEnabled = true
	}
	if p.ImageScanningConfiguration != nil {
		scanningEnabled = convert.ToValue(p.ImageScanningConfiguration.ImageScanningEnabled)
	}
	schedule := llx.NilData
	if s := p.Schedule; s != nil {
		schedule = llx.DictData(map[string]any{
			"scheduleExpression":              convert.ToValue(s.ScheduleExpression),
			"timezone":                        convert.ToValue(s.Timezone),
			"pipelineExecutionStartCondition": string(s.PipelineExecutionStartCondition),
		})
	}
	workflows := make([]any, 0, len(p.Workflows))
	for _, w := range p.Workflows {
		params := make([]any, 0, len(w.Parameters))
		for _, wp := range w.Parameters {
			params = append(params, map[string]any{
				"name":  convert.ToValue(wp.Name),
				"value": toInterfaceArr(wp.Value),
			})
		}
		workflows = append(workflows, map[string]any{
			"workflowArn":   convert.ToValue(w.WorkflowArn),
			"onFailure":     string(w.OnFailure),
			"parallelGroup": convert.ToValue(w.ParallelGroup),
			"parameters":    params,
		})
	}
	res, err := CreateResource(runtime, ResourceAwsImagebuilderImagePipeline, map[string]*llx.RawData{
		"__id":                           llx.StringDataPtr(p.Arn),
		"arn":                            llx.StringDataPtr(p.Arn),
		"name":                           llx.StringDataPtr(p.Name),
		"region":                         llx.StringData(region),
		"description":                    llx.StringDataPtr(p.Description),
		"platform":                       llx.StringData(string(p.Platform)),
		"status":                         llx.StringData(string(p.Status)),
		"containerRecipeArn":             llx.StringDataPtr(p.ContainerRecipeArn),
		"infrastructureConfigurationArn": llx.StringDataPtr(p.InfrastructureConfigurationArn),
		"enhancedImageMetadataEnabled":   llx.BoolData(convert.ToValue(p.EnhancedImageMetadataEnabled)),
		"imageTestsEnabled":              llx.BoolData(testsEnabled),
		"imageScanningEnabled":           llx.BoolData(scanningEnabled),
		"schedule":                       schedule,
		"workflows":                      llx.ArrayData(workflows, types.Dict),
		"lastRunStatus":                  llx.StringData(string(p.LastRunStatus)),
		"consecutiveFailures":            llx.IntDataDefault(p.ConsecutiveFailures, 0),
		"createdAt":                      llx.TimeDataPtr(parseAwsTimestampPtr(p.DateCreated)),
		"updatedAt":                      llx.TimeDataPtr(parseAwsTimestampPtr(p.DateUpdated)),
		"lastRunAt":                      llx.TimeDataPtr(parseAwsTimestampPtr(p.DateLastRun)),
		"nextRunAt":                      llx.TimeDataPtr(parseAwsTimestampPtr(p.DateNextRun)),
		"tags":                           llx.MapData(toInterfaceMap(p.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	pipeline := res.(*mqlAwsImagebuilderImagePipeline)
	pipeline.imageRecipeArn = convert.ToValue(p.ImageRecipeArn)
	pipeline.distributionConfigurationArn = convert.ToValue(p.DistributionConfigurationArn)
	pipeline.executionRoleArn = convert.ToValue(p.ExecutionRole)
	return pipeline, nil
}

// mqlAwsImagebuilderImagePipelineInternal keeps the ARNs that the typed
// accessors resolve.
type mqlAwsImagebuilderImagePipelineInternal struct {
	imageRecipeArn               string
	distributionConfigurationArn string
	executionRoleArn             string
}

func (a *mqlAwsImagebuilderImagePipeline) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsImagebuilderImagePipeline) imageRecipe() (*mqlAwsImagebuilderImageRecipe, error) {
	if a.imageRecipeArn == "" {
		a.ImageRecipe.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsImagebuilderImageRecipe, map[string]*llx.RawData{
		"arn": llx.StringData(a.imageRecipeArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsImagebuilderImageRecipe), nil
}

func (a *mqlAwsImagebuilderImagePipeline) distributionConfiguration() (*mqlAwsImagebuilderDistributionConfiguration, error) {
	if a.distributionConfigurationArn == "" {
		a.DistributionConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsImagebuilderDistributionConfiguration, map[string]*llx.RawData{
		"arn": llx.StringData(a.distributionConfigurationArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsImagebuilderDistributionConfiguration), nil
}

func (a *mqlAwsImagebuilderImagePipeline) executionRole() (*mqlAwsIamRole, error) {
	if a.executionRoleArn == "" {
		a.ExecutionRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
		"arn": llx.StringData(a.executionRoleArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsImagebuilderImagePipeline) cleanupBypassed() (bool, error) {
	recipe := a.GetImageRecipe()
	if recipe.Error != nil {
		return false, recipe.Error
	}
	if recipe.Data == nil {
		a.CleanupBypassed.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	bypassed := recipe.Data.GetCleanupBypassed()
	return bypassed.Data, bypassed.Error
}
