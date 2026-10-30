// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strings"

	fcclient "github.com/alibabacloud-go/fc-20230330/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ramRoleNameFromArn extracts the role name from a RAM role ARN of the form
// acs:ram::<account>:role/<name>, returning "" when the ARN has no role segment.
func ramRoleNameFromArn(arn string) string {
	const marker = "role/"
	_, after, ok := strings.CutLast(arn, marker)
	if !ok {
		return ""
	}
	return after
}

func (r *mqlAlicloudFc) id() (string, error) {
	return "alicloud.fc", nil
}

func (r *mqlAlicloudFc) functions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.FcClient(region)
		if err != nil {
			return nil, err
		}

		var nextToken *string
		firstPage := true
		for {
			resp, err := client.ListFunctions(&fcclient.ListFunctionsRequest{
				Limit:     tea.Int32(100),
				NextToken: nextToken,
			})
			if err != nil {
				if firstPage {
					// the region may not have FC enabled or the credential may
					// lack access there; skip it rather than failing the scan
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}
			for _, fn := range resp.Body.Functions {
				if fn == nil || fn.FunctionName == nil {
					continue
				}
				mqlFn, err := newFcFunction(r.MqlRuntime, region, fn)
				if err != nil {
					return nil, err
				}
				// ListFunctions returns tags inline, so the filter costs nothing
				// beyond the listing already made
				if filteredOutByTags(conn, mqlFn.Tags.Data) {
					continue
				}
				res = append(res, mqlFn)
			}
			if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
				break
			}
			nextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// mqlAlicloudFcFunctionInternal caches the identifiers for the typed
// cross-references.
type mqlAlicloudFcFunctionInternal struct {
	region               string
	functionName         string
	cacheRoleArn         string
	cacheVpcId           string
	cacheVswitchIds      []string
	cacheSecurityGroupId string
	cacheLogProjectName  string
}

// newFcFunction builds a fully populated alicloud.fc.function from an FC Function
// record (the same type returned by ListFunctions and GetFunction).
func newFcFunction(runtime *plugin.Runtime, region string, fn *fcclient.Function) (*mqlAlicloudFcFunction, error) {
	functionName := tea.StringValue(fn.FunctionName)

	env := map[string]any{}
	for k, v := range fn.EnvironmentVariables {
		env[k] = tea.StringValue(v)
	}

	tags := map[string]any{}
	for _, t := range fn.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	vpcId, securityGroupId := "", ""
	var vswitchIds []string
	if fn.VpcConfig != nil {
		vpcId = tea.StringValue(fn.VpcConfig.VpcId)
		securityGroupId = tea.StringValue(fn.VpcConfig.SecurityGroupId)
		vswitchIds = strPtrsToStrings(fn.VpcConfig.VSwitchIds)
	}

	logProject, logStore := "", ""
	if fn.LogConfig != nil {
		logProject = tea.StringValue(fn.LogConfig.Project)
		logStore = tea.StringValue(fn.LogConfig.Logstore)
	}

	containerImage := ""
	if fn.CustomContainerConfig != nil {
		containerImage = tea.StringValue(fn.CustomContainerConfig.Image)
	}

	resource, err := CreateResource(runtime, "alicloud.fc.function", map[string]*llx.RawData{
		"__id":                 llx.StringData(region + "/" + functionName),
		"regionId":             llx.StringData(region),
		"functionName":         llx.StringData(functionName),
		"functionId":           llx.StringDataPtr(fn.FunctionId),
		"arn":                  llx.StringDataPtr(fn.FunctionArn),
		"description":          llx.StringDataPtr(fn.Description),
		"runtime":              llx.StringDataPtr(fn.Runtime),
		"handler":              llx.StringDataPtr(fn.Handler),
		"timeout":              llx.IntData(int64(tea.Int32Value(fn.Timeout))),
		"memorySize":           llx.IntData(int64(tea.Int32Value(fn.MemorySize))),
		"diskSize":             llx.IntData(int64(tea.Int32Value(fn.DiskSize))),
		"cpu":                  llx.FloatData(float64(tea.Float32Value(fn.Cpu))),
		"state":                llx.StringDataPtr(fn.State),
		"stateReason":          llx.StringDataPtr(fn.StateReason),
		"codeSize":             llx.IntData(tea.Int64Value(fn.CodeSize)),
		"codeChecksum":         llx.StringDataPtr(fn.CodeChecksum),
		"createdTime":          llx.TimeDataPtr(alicloudParseTime(fn.CreatedTime)),
		"lastModifiedTime":     llx.TimeDataPtr(alicloudParseTime(fn.LastModifiedTime)),
		"internetAccess":       llx.BoolDataPtr(fn.InternetAccess),
		"instanceConcurrency":  llx.IntData(int64(tea.Int32Value(fn.InstanceConcurrency))),
		"resourceGroupId":      llx.StringDataPtr(fn.ResourceGroupId),
		"environmentVariables": llx.MapData(env, types.String),
		"customContainerImage": llx.StringData(containerImage),
		"logStore":             llx.StringData(logStore),
		"tags":                 llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlFn := resource.(*mqlAlicloudFcFunction)
	mqlFn.region = region
	mqlFn.functionName = functionName
	mqlFn.cacheRoleArn = tea.StringValue(fn.Role)
	mqlFn.cacheVpcId = vpcId
	mqlFn.cacheVswitchIds = vswitchIds
	mqlFn.cacheSecurityGroupId = securityGroupId
	mqlFn.cacheLogProjectName = logProject
	return mqlFn, nil
}

// initAlicloudFcFunction resolves a function by name within a region, reusing an
// already-listed function from the resource cache and otherwise fetching it via
// GetFunction.
func initAlicloudFcFunction(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered function asset, resolve the function the asset is scoped to
	args = scopedInitArgs(runtime, args, connection.OptionFcFunctionName, "functionName")

	functionName, err := requiredStringArg(args, "functionName", "alicloud.fc.function")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.fc.function")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.fc.function\x00" + region + "/" + functionName); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.FcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetFunction(new(functionName), &fcclient.GetFunctionRequest{})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.FunctionName == nil {
		return nil, nil, fmt.Errorf("alicloud.fc.function %q not found in region %q", functionName, region)
	}
	res, err := newFcFunction(runtime, region, resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudFcFunction) id() (string, error) {
	// Read the public fields (always set by SetAllData) rather than the
	// Internal cache fields, which are empty on the init fast-path — otherwise
	// __id is "/" and every such function collides in the cache.
	return r.RegionId.Data + "/" + r.FunctionName.Data, nil
}

func (r *mqlAlicloudFcFunction) executionRole() (*mqlAlicloudRamRole, error) {
	roleName := ramRoleNameFromArn(r.cacheRoleArn)
	if roleName == "" {
		r.ExecutionRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRamRole(r.MqlRuntime, roleName)
}

func (r *mqlAlicloudFcFunction) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}

func (r *mqlAlicloudFcFunction) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVswitchIds {
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if vsw != nil {
			res = append(res, vsw)
		}
	}
	return res, nil
}

func (r *mqlAlicloudFcFunction) securityGroup() (*mqlAlicloudEcsSecuritygroup, error) {
	if r.cacheSecurityGroupId == "" {
		r.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEcsSecuritygroup(r.MqlRuntime, r.region, r.cacheSecurityGroupId)
}

func (r *mqlAlicloudFcFunction) logProject() (*mqlAlicloudLogProject, error) {
	if r.cacheLogProjectName == "" {
		r.LogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveLogProject(r.MqlRuntime, r.region, r.cacheLogProjectName)
}

func (r *mqlAlicloudFcFunction) triggers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.FcClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.ListTriggers(new(r.functionName), &fcclient.ListTriggersRequest{
			Limit:     tea.Int32(100),
			NextToken: nextToken,
		})
		if err != nil {
			// the function exists (it was listed), so an error listing its
			// triggers is a real failure, not a missing-service case
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, t := range resp.Body.Triggers {
			if t == nil || t.TriggerName == nil {
				continue
			}
			mqlTrigger, err := newFcTrigger(r.MqlRuntime, r.region, r.functionName, t)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTrigger)
		}
		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}
	return res, nil
}

// mqlAlicloudFcTriggerInternal caches the region and invocation role ARN for the
// typed invocationRole() reference.
type mqlAlicloudFcTriggerInternal struct {
	region             string
	cacheInvocationArn string
}

func newFcTrigger(runtime *plugin.Runtime, region, functionName string, t *fcclient.Trigger) (*mqlAlicloudFcTrigger, error) {
	triggerName := tea.StringValue(t.TriggerName)

	httpUrlInternet, httpUrlIntranet := "", ""
	if t.HttpTrigger != nil {
		httpUrlInternet = tea.StringValue(t.HttpTrigger.UrlInternet)
		httpUrlIntranet = tea.StringValue(t.HttpTrigger.UrlIntranet)
	}

	var triggerConfig any
	if t.TriggerConfig != nil && *t.TriggerConfig != "" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(*t.TriggerConfig), &parsed); err == nil {
			triggerConfig = parsed
		}
	}

	resource, err := CreateResource(runtime, "alicloud.fc.trigger", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + functionName + "/" + triggerName),
		"regionId":         llx.StringData(region),
		"functionName":     llx.StringData(functionName),
		"triggerName":      llx.StringData(triggerName),
		"triggerId":        llx.StringDataPtr(t.TriggerId),
		"type":             llx.StringDataPtr(t.TriggerType),
		"sourceArn":        llx.StringDataPtr(t.SourceArn),
		"targetArn":        llx.StringDataPtr(t.TargetArn),
		"qualifier":        llx.StringDataPtr(t.Qualifier),
		"status":           llx.StringDataPtr(t.Status),
		"description":      llx.StringDataPtr(t.Description),
		"createdTime":      llx.TimeDataPtr(alicloudParseTime(t.CreatedTime)),
		"lastModifiedTime": llx.TimeDataPtr(alicloudParseTime(t.LastModifiedTime)),
		"httpUrlInternet":  llx.StringData(httpUrlInternet),
		"httpUrlIntranet":  llx.StringData(httpUrlIntranet),
		"triggerConfig":    llx.DictData(triggerConfig),
	})
	if err != nil {
		return nil, err
	}
	mqlTrigger := resource.(*mqlAlicloudFcTrigger)
	mqlTrigger.region = region
	mqlTrigger.cacheInvocationArn = tea.StringValue(t.InvocationRole)
	return mqlTrigger, nil
}

// function resolves the function the trigger belongs to. A trigger cannot
// outlive its function, so a failure to read it is a real error. The function is
// already in the resource cache whenever the trigger was reached through it,
// which the function init consults before calling the API.
func (r *mqlAlicloudFcTrigger) function() (*mqlAlicloudFcFunction, error) {
	name := r.FunctionName.Data
	if name == "" {
		r.Function.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.fc.function", map[string]*llx.RawData{
		"functionName": llx.StringData(name),
		"regionId":     llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudFcFunction), nil
}

func (r *mqlAlicloudFcTrigger) id() (string, error) {
	return r.RegionId.Data + "/" + r.FunctionName.Data + "/" + r.TriggerName.Data, nil
}

func (r *mqlAlicloudFcTrigger) internetInvocable() (bool, error) {
	return r.HttpUrlInternet.Data != "", nil
}

func (r *mqlAlicloudFcTrigger) invocationRole() (*mqlAlicloudRamRole, error) {
	roleName := ramRoleNameFromArn(r.cacheInvocationArn)
	if roleName == "" {
		r.InvocationRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRamRole(r.MqlRuntime, roleName)
}
