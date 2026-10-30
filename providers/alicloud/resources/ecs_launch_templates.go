// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ecsLaunchTemplatePageSize is the page size used for the launch template and
// launch template version listings.
const ecsLaunchTemplatePageSize = 50

// ecsImdsV2Required reports whether a metadata-service configuration demands a
// session token. Only "required" does; "optional" still answers the token-less
// IMDSv1 request that a server-side request forgery against the workload can
// reach, and an absent value reads as not required rather than claiming a
// control that may not be in place.
func ecsImdsV2Required(httpTokens *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(httpTokens)), "required")
}

// ecsDiskEncrypted reads the Encrypted member of a launch template disk, which
// the API returns as the string "true" or "false" rather than as a boolean. An
// absent or unparseable value reads as unencrypted, so an unread setting never
// reports encryption nobody confirmed.
func ecsDiskEncrypted(encrypted *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(encrypted)), "true")
}

// mqlAlicloudEcsLaunchTemplateInternal caches the region the template was
// listed from, which the version listing needs.
type mqlAlicloudEcsLaunchTemplateInternal struct {
	region string
}

func (r *mqlAlicloudEcsLaunchTemplate) id() (string, error) {
	return r.RegionId.Data + "/" + r.LaunchTemplateId.Data, nil
}

func (r *mqlAlicloudEcsLaunchTemplateVersion) id() (string, error) {
	return fmt.Sprintf("%s/%s/%d", r.RegionId.Data, r.LaunchTemplateId.Data, r.VersionNumber.Data), nil
}

func (r *mqlAlicloudEcsLaunchTemplate) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// launchTemplates enumerates the account's instance launch templates across
// every scanned region.
func (r *mqlAlicloudEcs) launchTemplates() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.EcsClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeLaunchTemplates(&ecsclient.DescribeLaunchTemplatesRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   tea.Int32(ecsLaunchTemplatePageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list ECS launch templates")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.LaunchTemplateSets == nil {
				break
			}
			items := resp.Body.LaunchTemplateSets.LaunchTemplateSet
			for _, tmpl := range items {
				if tmpl == nil || tmpl.LaunchTemplateId == nil {
					continue
				}
				tags := map[string]any{}
				if tmpl.Tags != nil {
					for _, t := range tmpl.Tags.Tag {
						if t == nil || t.TagKey == nil {
							continue
						}
						tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
					}
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.ecs.launchTemplate", map[string]*llx.RawData{
					"__id":                 llx.StringData(region + "/" + tea.StringValue(tmpl.LaunchTemplateId)),
					"regionId":             llx.StringData(region),
					"launchTemplateId":     llx.StringDataPtr(tmpl.LaunchTemplateId),
					"launchTemplateName":   llx.StringDataPtr(tmpl.LaunchTemplateName),
					"createdBy":            llx.StringDataPtr(tmpl.CreatedBy),
					"defaultVersionNumber": llx.IntData(tea.Int64Value(tmpl.DefaultVersionNumber)),
					"latestVersionNumber":  llx.IntData(tea.Int64Value(tmpl.LatestVersionNumber)),
					"createTime":           llx.TimeDataPtr(parseEcsTime(tmpl.CreateTime)),
					"modifiedTime":         llx.TimeDataPtr(parseEcsTime(tmpl.ModifiedTime)),
					"resourceGroupId":      llx.StringDataPtr(tmpl.ResourceGroupId),
					"tags":                 llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				mqlTemplate := resource.(*mqlAlicloudEcsLaunchTemplate)
				mqlTemplate.region = region
				res = append(res, mqlTemplate)
			}
			// count what actually arrived: the server may cap PageSize below the
			// requested value, and multiplying the requested size by the page
			// number would then overstate progress and stop early, dropping
			// templates without any sign that the walk was short
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// versions lists the template's versions, each carrying the instance shape it
// launches.
func (r *mqlAlicloudEcsLaunchTemplate) versions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EcsClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int32(0)
	for {
		resp, err := client.DescribeLaunchTemplateVersions(&ecsclient.DescribeLaunchTemplateVersionsRequest{
			RegionId:         new(r.region),
			LaunchTemplateId: new(r.LaunchTemplateId.Data),
			PageNumber:       new(pageNumber),
			PageSize:         tea.Int32(ecsLaunchTemplatePageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.LaunchTemplateVersionSets == nil {
			break
		}
		items := resp.Body.LaunchTemplateVersionSets.LaunchTemplateVersionSet
		for _, version := range items {
			if version == nil || version.VersionNumber == nil {
				continue
			}
			mqlVersion, err := newEcsLaunchTemplateVersion(r.MqlRuntime, r.region, version)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVersion)
		}
		// see the note in launchTemplates: the requested page size is not a
		// reliable measure of how many records have been seen
		collected += int32(len(items))
		if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// defaultVersion returns the version launched when a launch names none. It
// scans the already-fetched version list rather than issuing a second call.
func (r *mqlAlicloudEcsLaunchTemplate) defaultVersion() (*mqlAlicloudEcsLaunchTemplateVersion, error) {
	versions := r.GetVersions()
	if versions.Error != nil {
		log.Debug().Err(versions.Error).Str("template", r.LaunchTemplateId.Data).
			Msg("alicloud> could not read launch template versions")
		r.DefaultVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range versions.Data {
		version, ok := entry.(*mqlAlicloudEcsLaunchTemplateVersion)
		if ok && version.IsDefault.Data {
			return version, nil
		}
	}
	r.DefaultVersion.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// mqlAlicloudEcsLaunchTemplateVersionInternal caches the identifiers the
// version's typed references resolve, none of which are exposed as fields of
// their own.
type mqlAlicloudEcsLaunchTemplateVersionInternal struct {
	cacheImageID   string
	cacheRamRole   string
	cacheVpcID     string
	cacheVswitchID string
}

// newEcsLaunchTemplateVersion maps one launch template version into a resource,
// flattening the nested launch data the API returns.
func newEcsLaunchTemplateVersion(runtime *plugin.Runtime, region string, v *ecsclient.DescribeLaunchTemplateVersionsResponseBodyLaunchTemplateVersionSetsLaunchTemplateVersionSet) (*mqlAlicloudEcsLaunchTemplateVersion, error) {
	templateID := tea.StringValue(v.LaunchTemplateId)
	versionNumber := tea.Int64Value(v.VersionNumber)

	var (
		data                                                      = v.LaunchTemplateData
		securityGroupIDs                                          []string
		instanceType, imageID, imageOwnerAlias, zoneId            *string
		keyPairName, securityStrategy, spotStrategy, httpEndpoint *string
		httpTokens, userData, vpcID, vswitchID, ramRoleName       *string
		passwordInherit, deletionProtection                       *bool
		hopLimit, bandwidthIn, bandwidthOut                       *int32
		systemDiskCategory, systemDiskKmsKeyID, systemDiskEnc     *string
		systemDiskDeleteWithInstance                              *bool
	)
	if data != nil {
		instanceType, imageID, imageOwnerAlias, zoneId = data.InstanceType, data.ImageId, data.ImageOwnerAlias, data.ZoneId
		keyPairName, securityStrategy = data.KeyPairName, data.SecurityEnhancementStrategy
		spotStrategy, httpEndpoint, httpTokens = data.SpotStrategy, data.HttpEndpoint, data.HttpTokens
		userData, vpcID, vswitchID, ramRoleName = data.UserData, data.VpcId, data.VSwitchId, data.RamRoleName
		passwordInherit, deletionProtection = data.PasswordInherit, data.DeletionProtection
		hopLimit = data.HttpPutResponseHopLimit
		bandwidthIn, bandwidthOut = data.InternetMaxBandwidthIn, data.InternetMaxBandwidthOut

		// the API carries the security groups in two shapes: a single id on an
		// older template, and a repeated list on a newer one
		if single := tea.StringValue(data.SecurityGroupId); single != "" {
			securityGroupIDs = append(securityGroupIDs, single)
		}
		if data.SecurityGroupIds != nil {
			securityGroupIDs = append(securityGroupIDs, strPtrsToStrings(data.SecurityGroupIds.SecurityGroupId)...)
		}
		if disk := data.SystemDisk; disk != nil {
			systemDiskCategory, systemDiskKmsKeyID = disk.Category, disk.KMSKeyId
			systemDiskEnc = disk.Encrypted
			systemDiskDeleteWithInstance = disk.DeleteWithInstance
		}
	}

	resource, err := CreateResource(runtime, "alicloud.ecs.launchTemplate.version", map[string]*llx.RawData{
		"__id":                         llx.StringData(fmt.Sprintf("%s/%s/%d", region, templateID, versionNumber)),
		"regionId":                     llx.StringData(region),
		"launchTemplateId":             llx.StringData(templateID),
		"versionNumber":                llx.IntData(versionNumber),
		"versionDescription":           llx.StringDataPtr(v.VersionDescription),
		"isDefault":                    llx.BoolData(tea.BoolValue(v.DefaultVersion)),
		"createdBy":                    llx.StringDataPtr(v.CreatedBy),
		"createTime":                   llx.TimeDataPtr(parseEcsTime(v.CreateTime)),
		"instanceType":                 llx.StringDataPtr(instanceType),
		"imageId":                      llx.StringDataPtr(imageID),
		"imageOwnerAlias":              llx.StringDataPtr(imageOwnerAlias),
		"zoneId":                       llx.StringDataPtr(zoneId),
		"keyPairName":                  llx.StringDataPtr(keyPairName),
		"passwordInherit":              llx.BoolData(tea.BoolValue(passwordInherit)),
		"securityEnhancementStrategy":  llx.StringDataPtr(securityStrategy),
		"securityGroupIds":             llx.ArrayData(strsToAny(securityGroupIDs), types.String),
		"userData":                     llx.StringData(decodeUserData(tea.StringValue(userData))),
		"httpEndpoint":                 llx.StringDataPtr(httpEndpoint),
		"httpTokens":                   llx.StringDataPtr(httpTokens),
		"imdsV2Required":               llx.BoolData(ecsImdsV2Required(httpTokens)),
		"httpPutResponseHopLimit":      llx.IntData(int64(tea.Int32Value(hopLimit))),
		"internetMaxBandwidthIn":       llx.IntData(int64(tea.Int32Value(bandwidthIn))),
		"internetMaxBandwidthOut":      llx.IntData(int64(tea.Int32Value(bandwidthOut))),
		"deletionProtection":           llx.BoolData(tea.BoolValue(deletionProtection)),
		"spotStrategy":                 llx.StringDataPtr(spotStrategy),
		"systemDiskCategory":           llx.StringDataPtr(systemDiskCategory),
		"systemDiskEncrypted":          llx.BoolData(ecsDiskEncrypted(systemDiskEnc)),
		"systemDiskKmsKeyId":           llx.StringDataPtr(systemDiskKmsKeyID),
		"systemDiskDeleteWithInstance": llx.BoolData(tea.BoolValue(systemDiskDeleteWithInstance)),
	})
	if err != nil {
		return nil, err
	}
	mqlVersion := resource.(*mqlAlicloudEcsLaunchTemplateVersion)
	mqlVersion.cacheImageID = tea.StringValue(imageID)
	mqlVersion.cacheRamRole = tea.StringValue(ramRoleName)
	mqlVersion.cacheVpcID = tea.StringValue(vpcID)
	mqlVersion.cacheVswitchID = tea.StringValue(vswitchID)
	return mqlVersion, nil
}

// The four references below resolve to null rather than failing when the target
// has gone. A launch template is long-lived and routinely outlives the image,
// role, or network it names, and a template that can no longer launch is itself
// worth reporting, so one dangling reference must not fail a query over every
// template in the account.

func (r *mqlAlicloudEcsLaunchTemplateVersion) image() (*mqlAlicloudEcsImage, error) {
	if r.cacheImageID == "" {
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	image, err := resolveEcsImage(r.MqlRuntime, r.RegionId.Data, r.cacheImageID)
	if err != nil || image == nil {
		log.Debug().Err(err).Str("image", r.cacheImageID).
			Msg("alicloud> could not resolve launch template image")
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return image, nil
}

func (r *mqlAlicloudEcsLaunchTemplateVersion) ramRole() (*mqlAlicloudRamRole, error) {
	if r.cacheRamRole == "" {
		r.RamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := resolveRamRole(r.MqlRuntime, r.cacheRamRole)
	if err != nil || role == nil {
		log.Debug().Err(err).Str("role", r.cacheRamRole).
			Msg("alicloud> could not resolve launch template RAM role")
		r.RamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

func (r *mqlAlicloudEcsLaunchTemplateVersion) securityGroups() ([]any, error) {
	return resolveEcsSecuritygroups(r.MqlRuntime, r.RegionId.Data, r.SecurityGroupIds.Data)
}

func (r *mqlAlicloudEcsLaunchTemplateVersion) vpc() (*mqlAlicloudVpcNetwork, error) {
	return cloudfwResolveVpc(r.MqlRuntime, r.RegionId.Data, r.cacheVpcID, &r.Vpc)
}

func (r *mqlAlicloudEcsLaunchTemplateVersion) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vswitch, err := resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, r.cacheVswitchID)
	if err != nil || vswitch == nil {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return vswitch, nil
}

// launchTemplate resolves the template a scaling group launches from, by
// scanning alicloud.ecs.launchTemplates, which is fetched once for the scan.
// Null for a group that launches from a scaling configuration instead.
func (r *mqlAlicloudEssScalingGroup) launchTemplate() (*mqlAlicloudEcsLaunchTemplate, error) {
	wanted := r.LaunchTemplateId.Data
	if wanted == "" {
		r.LaunchTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ecs, err := CreateResource(r.MqlRuntime, "alicloud.ecs", map[string]*llx.RawData{})
	if err != nil {
		r.LaunchTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	templates := ecs.(*mqlAlicloudEcs).GetLaunchTemplates()
	if templates.Error != nil {
		log.Debug().Err(templates.Error).Msg("alicloud> could not resolve a scaling group launch template")
		r.LaunchTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range templates.Data {
		template, ok := entry.(*mqlAlicloudEcsLaunchTemplate)
		if ok && template.LaunchTemplateId.Data == wanted {
			return template, nil
		}
	}
	r.LaunchTemplate.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
