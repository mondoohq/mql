// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	essclient "github.com/alibabacloud-go/ess-20220222/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// essPageSize is the per-request item count for the page-numbered Auto Scaling
// APIs, which cap a page at 50.
const essPageSize int32 = 50

func (r *mqlAlicloudEss) id() (string, error) {
	return "alicloud.ess", nil
}

// mqlAlicloudEssScalingGroupInternal caches the identifiers the group's typed
// references resolve from, none of which are exposed as fields of their own.
type mqlAlicloudEssScalingGroupInternal struct {
	cacheVpcID                        string
	cacheVswitchIDs                   []string
	cacheActiveScalingConfigurationID string
}

// mqlAlicloudEssScalingConfigurationInternal caches the identifiers the
// configuration's typed references resolve from.
type mqlAlicloudEssScalingConfigurationInternal struct {
	cacheScalingGroupID     string
	cacheRamRoleName        string
	cacheSecurityGroupIDs   []any
	cacheImageID            string
	cacheKeyPairName        string
	cacheSystemDiskKmsKeyID string
}

func (r *mqlAlicloudEssScalingGroup) id() (string, error) {
	return r.RegionId.Data + "/" + r.ScalingGroupId.Data, nil
}

func (r *mqlAlicloudEssScalingConfiguration) id() (string, error) {
	return r.RegionId.Data + "/" + r.ScalingConfigurationId.Data, nil
}

func (r *mqlAlicloudEss) scalingGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		groups, err := essScalingGroupsInRegion(r.MqlRuntime, conn, region)
		if err != nil {
			// a region may be un-activated or access-denied; skip it rather
			// than failing the whole scan
			log.Debug().Err(err).Str("region", region).
				Msg("alicloud: could not list scaling groups")
			continue
		}
		res = append(res, groups...)
	}
	return res, nil
}

// essScalingGroupsInRegion lists every scaling group in one region.
func essScalingGroupsInRegion(runtime *plugin.Runtime, conn *connection.AlicloudConnection, region string) ([]any, error) {
	client, err := conn.EssClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	for {
		resp, err := client.DescribeScalingGroups(&essclient.DescribeScalingGroupsRequest{
			RegionId:   new(region),
			PageNumber: new(pageNumber),
			PageSize:   new(essPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, g := range resp.Body.ScalingGroups {
			if g == nil || g.ScalingGroupId == nil {
				continue
			}
			group, err := newEssScalingGroup(runtime, region, g)
			if err != nil {
				return nil, err
			}
			res = append(res, group)
		}

		if !essHasMorePages(pageNumber, len(resp.Body.ScalingGroups), resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// essHasMorePages reports whether another page remains. The Auto Scaling APIs
// report a total count, but a short page also ends the walk so a stale or
// missing total cannot spin the loop.
func essHasMorePages(pageNumber int32, pageLen int, totalCount *int32) bool {
	if pageLen == 0 || int32(pageLen) < essPageSize {
		return false
	}
	if totalCount == nil {
		return true
	}
	return pageNumber*essPageSize < *totalCount
}

func newEssScalingGroup(runtime *plugin.Runtime, region string, g *essclient.DescribeScalingGroupsResponseBodyScalingGroups) (*mqlAlicloudEssScalingGroup, error) {
	resource, err := CreateResource(runtime, "alicloud.ess.scalingGroup", map[string]*llx.RawData{
		"__id":                    llx.StringData(region + "/" + tea.StringValue(g.ScalingGroupId)),
		"scalingGroupId":          llx.StringDataPtr(g.ScalingGroupId),
		"name":                    llx.StringDataPtr(g.ScalingGroupName),
		"regionId":                llx.StringData(region),
		"lifecycleState":          llx.StringDataPtr(g.LifecycleState),
		"groupType":               llx.StringDataPtr(g.GroupType),
		"minSize":                 llx.IntDataPtr(g.MinSize),
		"maxSize":                 llx.IntDataPtr(g.MaxSize),
		"desiredCapacity":         llx.IntDataPtr(g.DesiredCapacity),
		"totalCapacity":           llx.IntDataPtr(g.TotalCapacity),
		"activeCapacity":          llx.IntDataPtr(g.ActiveCapacity),
		"defaultCooldown":         llx.IntDataPtr(g.DefaultCooldown),
		"healthCheckType":         llx.StringDataPtr(g.HealthCheckType),
		"multiAZPolicy":           llx.StringDataPtr(g.MultiAZPolicy),
		"scalingPolicy":           llx.StringDataPtr(g.ScalingPolicy),
		"groupDeletionProtection": llx.BoolDataPtr(g.GroupDeletionProtection),
		"suspendedProcesses":      llx.ArrayData(llx.TArr2Raw(strPtrSliceToStrings(g.SuspendedProcesses)), types.String),
		"systemSuspended":         llx.BoolDataPtr(g.SystemSuspended),
		"maxInstanceLifetime":     llx.IntDataPtr(g.MaxInstanceLifetime),
		"resourceGroupId":         llx.StringDataPtr(g.ResourceGroupId),
		"launchTemplateId":        llx.StringDataPtr(g.LaunchTemplateId),
		"launchTemplateVersion":   llx.StringDataPtr(g.LaunchTemplateVersion),
		"creationTime":            llx.TimeDataPtr(parseEcsTime(g.CreationTime)),
		"modificationTime":        llx.TimeDataPtr(parseEcsTime(g.ModificationTime)),
	})
	if err != nil {
		return nil, err
	}

	group := resource.(*mqlAlicloudEssScalingGroup)
	group.cacheVpcID = tea.StringValue(g.VpcId)
	group.cacheActiveScalingConfigurationID = tea.StringValue(g.ActiveScalingConfigurationId)
	group.cacheVswitchIDs = essGroupVswitchIDs(g)
	return group, nil
}

// essGroupVswitchIDs collects the group's vSwitches. VSwitchIds supersedes the
// singular VSwitchId when both are set, so the singular one is only used as a
// fallback.
func essGroupVswitchIDs(g *essclient.DescribeScalingGroupsResponseBodyScalingGroups) []string {
	if ids := strPtrSliceToStrings(g.VSwitchIds); len(ids) > 0 {
		return ids
	}
	if id := tea.StringValue(g.VSwitchId); id != "" {
		return []string{id}
	}
	return nil
}

// strPtrSliceToStrings dereferences an SDK string-pointer slice, dropping nil
// and empty entries. convert.SliceStrPtrToStr panics on a nil element, so it
// is not usable on SDK data.
func strPtrSliceToStrings(in []*string) []string {
	res := make([]string, 0, len(in))
	for _, s := range in {
		if s == nil || *s == "" {
			continue
		}
		res = append(res, *s)
	}
	return res
}

func initAlicloudEssScalingGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	scalingGroupID, err := requiredStringArg(args, "scalingGroupId", "alicloud.ess.scalingGroup")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.ess.scalingGroup")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.ess.scalingGroup\x00" + region + "/" + scalingGroupID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EssClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeScalingGroups(&essclient.DescribeScalingGroupsRequest{
		RegionId:        new(region),
		ScalingGroupIds: []*string{new(scalingGroupID)},
		PageSize:        new(essPageSize),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, nil, fmt.Errorf("alicloud.ess.scalingGroup %q not found in region %q", scalingGroupID, region)
	}

	for _, g := range resp.Body.ScalingGroups {
		if g == nil || tea.StringValue(g.ScalingGroupId) != scalingGroupID {
			continue
		}
		group, err := newEssScalingGroup(runtime, region, g)
		if err != nil {
			return nil, nil, err
		}
		return nil, group, nil
	}
	return nil, nil, fmt.Errorf("alicloud.ess.scalingGroup %q not found in region %q", scalingGroupID, region)
}

func (r *mqlAlicloudEssScalingGroup) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, r.cacheVpcID)
}

func (r *mqlAlicloudEssScalingGroup) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVswitchIDs {
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, id)
		if err != nil {
			log.Debug().Err(err).Str("vswitch", id).Str("region", r.RegionId.Data).
				Msg("alicloud: could not resolve vSwitch")
			continue
		}
		if vsw == nil {
			continue
		}
		res = append(res, vsw)
	}
	return res, nil
}

func (r *mqlAlicloudEssScalingGroup) activeScalingConfiguration() (*mqlAlicloudEssScalingConfiguration, error) {
	if r.cacheActiveScalingConfigurationID == "" {
		r.ActiveScalingConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEssScalingConfiguration(r.MqlRuntime, r.RegionId.Data, r.cacheActiveScalingConfigurationID)
}

func (r *mqlAlicloudEssScalingGroup) scalingConfigurations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	return essScalingConfigurationsInRegion(r.MqlRuntime, conn, r.RegionId.Data, r.ScalingGroupId.Data)
}

func (r *mqlAlicloudEss) scalingConfigurations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		configs, err := essScalingConfigurationsInRegion(r.MqlRuntime, conn, region, "")
		if err != nil {
			log.Debug().Err(err).Str("region", region).
				Msg("alicloud: could not list scaling configurations")
			continue
		}
		res = append(res, configs...)
	}
	return res, nil
}

// essScalingConfigurationsInRegion lists the scaling configurations in one
// region, narrowed to a single scaling group when scalingGroupID is set.
func essScalingConfigurationsInRegion(runtime *plugin.Runtime, conn *connection.AlicloudConnection, region, scalingGroupID string) ([]any, error) {
	client, err := conn.EssClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	for {
		req := &essclient.DescribeScalingConfigurationsRequest{
			RegionId:   new(region),
			PageNumber: new(pageNumber),
			PageSize:   new(essPageSize),
		}
		if scalingGroupID != "" {
			req.ScalingGroupId = new(scalingGroupID)
		}
		resp, err := client.DescribeScalingConfigurations(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, c := range resp.Body.ScalingConfigurations {
			if c == nil || c.ScalingConfigurationId == nil {
				continue
			}
			config, err := newEssScalingConfiguration(runtime, region, c)
			if err != nil {
				return nil, err
			}
			res = append(res, config)
		}

		if !essHasMorePages(pageNumber, len(resp.Body.ScalingConfigurations), resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func newEssScalingConfiguration(runtime *plugin.Runtime, region string, c *essclient.DescribeScalingConfigurationsResponseBodyScalingConfigurations) (*mqlAlicloudEssScalingConfiguration, error) {
	confidentialComputing := ""
	if c.SecurityOptions != nil {
		confidentialComputing = tea.StringValue(c.SecurityOptions.ConfidentialComputingMode)
	}

	resource, err := CreateResource(runtime, "alicloud.ess.scalingConfiguration", map[string]*llx.RawData{
		"__id":                        llx.StringData(region + "/" + tea.StringValue(c.ScalingConfigurationId)),
		"scalingConfigurationId":      llx.StringDataPtr(c.ScalingConfigurationId),
		"name":                        llx.StringDataPtr(c.ScalingConfigurationName),
		"regionId":                    llx.StringData(region),
		"lifecycleState":              llx.StringDataPtr(c.LifecycleState),
		"instanceType":                llx.StringDataPtr(c.InstanceType),
		"userData":                    llx.StringData(decodeUserData(tea.StringValue(c.UserData))),
		"imageOwnerAlias":             llx.StringDataPtr(c.ImageOwnerAlias),
		"metadataHttpTokens":          llx.StringDataPtr(c.HttpTokens),
		"metadataEndpointEnabled":     llx.BoolData(!strings.EqualFold(tea.StringValue(c.HttpEndpoint), "disabled")),
		"passwordInherit":             llx.BoolDataPtr(c.PasswordInherit),
		"passwordSet":                 llx.BoolDataPtr(c.PasswordSetted),
		"securityEnhancementStrategy": llx.StringDataPtr(c.SecurityEnhancementStrategy),
		"internetMaxBandwidthIn":      llx.IntDataPtr(c.InternetMaxBandwidthIn),
		"internetMaxBandwidthOut":     llx.IntDataPtr(c.InternetMaxBandwidthOut),
		"systemDiskEncrypted":         llx.BoolDataPtr(c.SystemDiskEncrypted),
		"systemDiskCategory":          llx.StringDataPtr(c.SystemDiskCategory),
		"systemDiskSize":              llx.IntDataPtr(c.SystemDiskSize),
		"deletionProtection":          llx.BoolDataPtr(c.DeletionProtection),
		"spotStrategy":                llx.StringDataPtr(c.SpotStrategy),
		"tenancy":                     llx.StringDataPtr(c.Tenancy),
		"confidentialComputingMode":   llx.StringData(confidentialComputing),
		"creationTime":                llx.TimeDataPtr(parseEcsTime(c.CreationTime)),
	})
	if err != nil {
		return nil, err
	}

	config := resource.(*mqlAlicloudEssScalingConfiguration)
	config.cacheScalingGroupID = tea.StringValue(c.ScalingGroupId)
	config.cacheRamRoleName = tea.StringValue(c.RamRoleName)
	config.cacheImageID = tea.StringValue(c.ImageId)
	config.cacheKeyPairName = tea.StringValue(c.KeyPairName)
	config.cacheSystemDiskKmsKeyID = tea.StringValue(c.SystemDiskKMSKeyId)
	config.cacheSecurityGroupIDs = essConfigSecurityGroupIDs(c)
	return config, nil
}

// essConfigSecurityGroupIDs collects the configuration's security groups.
// SecurityGroupIds supersedes the singular SecurityGroupId when both are set,
// so the singular one is only used as a fallback.
func essConfigSecurityGroupIDs(c *essclient.DescribeScalingConfigurationsResponseBodyScalingConfigurations) []any {
	res := []any{}
	for _, id := range strPtrSliceToStrings(c.SecurityGroupIds) {
		res = append(res, id)
	}
	if len(res) > 0 {
		return res
	}
	if id := tea.StringValue(c.SecurityGroupId); id != "" {
		res = append(res, id)
	}
	return res
}

// resolveEssScalingConfiguration returns the typed scaling configuration for an
// id within a region, or (nil, nil) when configID is empty.
func resolveEssScalingConfiguration(runtime *plugin.Runtime, region, configID string) (*mqlAlicloudEssScalingConfiguration, error) {
	if configID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.ess.scalingConfiguration", map[string]*llx.RawData{
		"scalingConfigurationId": llx.StringData(configID),
		"regionId":               llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudEssScalingConfiguration), nil
}

func initAlicloudEssScalingConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	configID, err := requiredStringArg(args, "scalingConfigurationId", "alicloud.ess.scalingConfiguration")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.ess.scalingConfiguration")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.ess.scalingConfiguration\x00" + region + "/" + configID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EssClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeScalingConfigurations(&essclient.DescribeScalingConfigurationsRequest{
		RegionId:                new(region),
		ScalingConfigurationIds: []*string{new(configID)},
		PageSize:                new(essPageSize),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, nil, fmt.Errorf("alicloud.ess.scalingConfiguration %q not found in region %q", configID, region)
	}

	for _, c := range resp.Body.ScalingConfigurations {
		if c == nil || tea.StringValue(c.ScalingConfigurationId) != configID {
			continue
		}
		config, err := newEssScalingConfiguration(runtime, region, c)
		if err != nil {
			return nil, nil, err
		}
		return nil, config, nil
	}
	return nil, nil, fmt.Errorf("alicloud.ess.scalingConfiguration %q not found in region %q", configID, region)
}

func (r *mqlAlicloudEssScalingConfiguration) scalingGroup() (*mqlAlicloudEssScalingGroup, error) {
	if r.cacheScalingGroupID == "" {
		r.ScalingGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.ess.scalingGroup", map[string]*llx.RawData{
		"scalingGroupId": llx.StringData(r.cacheScalingGroupID),
		"regionId":       llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudEssScalingGroup), nil
}

func (r *mqlAlicloudEssScalingConfiguration) ramRole() (*mqlAlicloudRamRole, error) {
	if r.cacheRamRoleName == "" {
		r.RamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRamRole(r.MqlRuntime, r.cacheRamRoleName)
}

func (r *mqlAlicloudEssScalingConfiguration) securityGroups() ([]any, error) {
	return resolveEcsSecuritygroups(r.MqlRuntime, r.RegionId.Data, r.cacheSecurityGroupIDs)
}

// The three references below resolve to null rather than failing when the
// target has gone. A scaling configuration is a long-lived template that
// routinely outlives the image, key pair, or key it names, and a group that
// can no longer launch is itself worth reporting, so one dangling reference
// must not fail a query over every configuration in the account. This is a
// deliberate departure from alicloud.ecs.instance, where the same references
// point at resources that exist for as long as the instance does.

func (r *mqlAlicloudEssScalingConfiguration) image() (*mqlAlicloudEcsImage, error) {
	if r.cacheImageID == "" {
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	image, err := resolveEcsImage(r.MqlRuntime, r.RegionId.Data, r.cacheImageID)
	if err != nil || image == nil {
		log.Debug().Err(err).Str("image", r.cacheImageID).Str("region", r.RegionId.Data).
			Msg("alicloud: could not resolve scaling configuration image")
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return image, nil
}

func (r *mqlAlicloudEssScalingConfiguration) keyPair() (*mqlAlicloudEcsKeypair, error) {
	if r.cacheKeyPairName == "" {
		r.KeyPair.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	keyPair, err := resolveEcsKeypair(r.MqlRuntime, r.RegionId.Data, r.cacheKeyPairName)
	if err != nil || keyPair == nil {
		log.Debug().Err(err).Str("keyPair", r.cacheKeyPairName).Str("region", r.RegionId.Data).
			Msg("alicloud: could not resolve scaling configuration key pair")
		r.KeyPair.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return keyPair, nil
}

func (r *mqlAlicloudEssScalingConfiguration) systemDiskKmsKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheSystemDiskKmsKeyID == "" {
		r.SystemDiskKmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, r.RegionId.Data, r.cacheSystemDiskKmsKeyID)
	if err != nil || key == nil {
		log.Debug().Err(err).Str("kmsKey", r.cacheSystemDiskKmsKeyID).Str("region", r.RegionId.Data).
			Msg("alicloud: could not resolve scaling configuration system disk key")
		r.SystemDiskKmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}
