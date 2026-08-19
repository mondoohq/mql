// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsWorkspaces) id() (string, error) {
	return "aws.workspaces", nil
}

// ---- Directories ----

func (a *mqlAwsWorkspaces) directories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDirectories(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsWorkspaces) getDirectories(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspaces>getDirectories>calling aws with region %s", region)
			svc := conn.Workspaces(region)
			ctx := context.Background()
			res := []any{}

			paginator := workspaces.NewDescribeWorkspaceDirectoriesPaginator(svc, &workspaces.DescribeWorkspaceDirectoriesInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces directories API")
						return res, nil
					}
					return nil, err
				}

				for _, dir := range resp.Directories {
					mqlDir, err := newMqlAwsWorkspacesDirectory(a.MqlRuntime, region, dir)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDir)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsWorkspacesDirectory(runtime *plugin.Runtime, region string, dir workspacestypes.WorkspaceDirectory) (*mqlAwsWorkspacesDirectory, error) {
	workspaceAccessProps, err := convert.JsonToDict(dir.WorkspaceAccessProperties)
	if err != nil {
		return nil, err
	}
	defaultCreationProps, err := convert.JsonToDict(dir.WorkspaceCreationProperties)
	if err != nil {
		return nil, err
	}
	certBasedAuthProps, err := convert.JsonToDict(dir.CertificateBasedAuthProperties)
	if err != nil {
		return nil, err
	}
	selfservicePerms, err := convert.JsonToDict(dir.SelfservicePermissions)
	if err != nil {
		return nil, err
	}

	directoryId := ""
	if dir.DirectoryId != nil {
		directoryId = *dir.DirectoryId
	}

	resource, err := CreateResource(runtime, "aws.workspaces.directory",
		map[string]*llx.RawData{
			"__id":                           llx.StringData("aws.workspaces.directory/" + region + "/" + directoryId),
			"directoryId":                    llx.StringDataPtr(dir.DirectoryId),
			"directoryName":                  llx.StringDataPtr(dir.DirectoryName),
			"directoryType":                  llx.StringData(string(dir.DirectoryType)),
			"alias":                          llx.StringDataPtr(dir.Alias),
			"state":                          llx.StringData(string(dir.State)),
			"dnsIpAddresses":                 llx.ArrayData(toInterfaceArr(dir.DnsIpAddresses), types.String),
			"endpointEncryptionMode":         llx.StringData(string(dir.EndpointEncryptionMode)),
			"workspaceAccessProperties":      llx.MapData(workspaceAccessProps, types.Any),
			"defaultCreationProperties":      llx.MapData(defaultCreationProps, types.Any),
			"certificateBasedAuthProperties": llx.MapData(certBasedAuthProps, types.Any),
			"ipGroupIds":                     llx.ArrayData(toInterfaceArr(dir.IpGroupIds), types.String),
			"selfservicePermissions":         llx.MapData(selfservicePerms, types.Any),
			"iamRoleId":                      llx.StringDataPtr(dir.IamRoleId),
			"subnetIds":                      llx.ArrayData(toInterfaceArr(dir.SubnetIds), types.String),
			"region":                         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkspacesDirectory), nil
}

func (a *mqlAwsWorkspacesDirectory) id() (string, error) {
	return "aws.workspaces.directory/" + a.Region.Data + "/" + a.DirectoryId.Data, nil
}

const (
	workspacesWorkspaceArnPattern = "arn:aws:workspaces:%s:%s:workspace/%s"
	workspacesDirectoryArnPattern = "arn:aws:workspaces:%s:%s:directory/%s"
	workspacesIpGroupArnPattern   = "arn:aws:workspaces:%s:%s:workspaceipgroup/%s"
)

func (a *mqlAwsWorkspacesDirectory) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(workspacesDirectoryArnPattern, a.Region.Data, conn.AccountId(), a.DirectoryId.Data), nil
}

type mqlAwsWorkspacesDirectoryInternal struct {
	clientPropsFetched atomic.Bool
	clientProps        *workspacestypes.ClientProperties
	clientPropsLock    sync.Mutex
}

// fetchClientProperties loads the directory's client properties once and shares
// the result across clientExperiencePolicy, clientReconnectEnabled, and
// clientLogUploadEnabled, which all come from the same call.
func (a *mqlAwsWorkspacesDirectory) fetchClientProperties() (*workspacestypes.ClientProperties, error) {
	if a.clientPropsFetched.Load() {
		return a.clientProps, nil
	}
	a.clientPropsLock.Lock()
	defer a.clientPropsLock.Unlock()
	if a.clientPropsFetched.Load() {
		return a.clientProps, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Workspaces(a.Region.Data)
	resp, err := svc.DescribeClientProperties(context.Background(), &workspaces.DescribeClientPropertiesInput{
		ResourceIds: []string{a.DirectoryId.Data},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.clientPropsFetched.Store(true)
			return nil, nil
		}
		return nil, err
	}
	for _, r := range resp.ClientPropertiesList {
		if r.ClientProperties != nil {
			a.clientProps = r.ClientProperties
			break
		}
	}
	a.clientPropsFetched.Store(true)
	return a.clientProps, nil
}

func (a *mqlAwsWorkspacesDirectory) clientExperiencePolicy() (string, error) {
	props, err := a.fetchClientProperties()
	if err != nil || props == nil {
		return "", err
	}
	return convert.ToValue(props.ClientExperiencePolicy), nil
}

func (a *mqlAwsWorkspacesDirectory) clientReconnectEnabled() (bool, error) {
	props, err := a.fetchClientProperties()
	if err != nil || props == nil {
		return false, err
	}
	return props.ReconnectEnabled == workspacestypes.ReconnectEnumEnabled, nil
}

func (a *mqlAwsWorkspacesDirectory) clientLogUploadEnabled() (bool, error) {
	props, err := a.fetchClientProperties()
	if err != nil || props == nil {
		return false, err
	}
	return props.LogUploadEnabled == workspacestypes.LogUploadEnumEnabled, nil
}

func (a *mqlAwsWorkspacesDirectory) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Workspaces(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeTags(ctx, &workspaces.DescribeTagsInput{
		ResourceId: &a.DirectoryId.Data,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, tag := range resp.TagList {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags, nil
}

// ---- Instances ----

func (a *mqlAwsWorkspaces) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsWorkspaces) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspaces>getInstances>calling aws with region %s", region)
			svc := conn.Workspaces(region)
			ctx := context.Background()
			res := []any{}

			paginator := workspaces.NewDescribeWorkspacesPaginator(svc, &workspaces.DescribeWorkspacesInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces instances API")
						return res, nil
					}
					return nil, err
				}

				for _, ws := range resp.Workspaces {
					mqlWs, err := newMqlAwsWorkspacesWorkspace(a.MqlRuntime, region, ws)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlWs)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsWorkspacesWorkspace(runtime *plugin.Runtime, region string, ws workspacestypes.Workspace) (*mqlAwsWorkspacesWorkspace, error) {
	workspaceId := ""
	if ws.WorkspaceId != nil {
		workspaceId = *ws.WorkspaceId
	}

	// WorkspaceProperties is absent on some responses, and nested
	// virtualization is only reported for the WorkSpace types that support
	// it. Leaving the pointer nil keeps the field null in both cases: a
	// false would claim we looked and the feature was switched off.
	var nestedVirtualizationEnabled *bool
	if ws.WorkspaceProperties != nil {
		nestedVirtualizationEnabled = ws.WorkspaceProperties.NestedVirtualizationEnabled
	}

	resource, err := CreateResource(runtime, "aws.workspaces.workspace",
		map[string]*llx.RawData{
			"__id":                        llx.StringData("aws.workspaces.workspace/" + region + "/" + workspaceId),
			"workspaceId":                 llx.StringDataPtr(ws.WorkspaceId),
			"directoryId":                 llx.StringDataPtr(ws.DirectoryId),
			"userName":                    llx.StringDataPtr(ws.UserName),
			"ipAddress":                   llx.StringDataPtr(ws.IpAddress),
			"computerName":                llx.StringDataPtr(ws.ComputerName),
			"bundleId":                    llx.StringDataPtr(ws.BundleId),
			"subnetId":                    llx.StringDataPtr(ws.SubnetId),
			"state":                       llx.StringData(string(ws.State)),
			"rootVolumeEncryptionEnabled": llx.BoolDataPtr(ws.RootVolumeEncryptionEnabled),
			"userVolumeEncryptionEnabled": llx.BoolDataPtr(ws.UserVolumeEncryptionEnabled),
			"nestedVirtualizationEnabled": llx.BoolDataPtr(nestedVirtualizationEnabled),
			"volumeEncryptionKey":         llx.StringDataPtr(ws.VolumeEncryptionKey),
			"errorCode":                   llx.StringDataPtr(ws.ErrorCode),
			"errorMessage":                llx.StringDataPtr(ws.ErrorMessage),
			"region":                      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkspacesWorkspace), nil
}

type mqlAwsWorkspacesWorkspaceInternal struct {
	connStatusFetched bool
	connStatusLock    sync.Mutex
}

func (a *mqlAwsWorkspacesWorkspace) id() (string, error) {
	return "aws.workspaces.workspace/" + a.Region.Data + "/" + a.WorkspaceId.Data, nil
}

func (a *mqlAwsWorkspacesWorkspace) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(workspacesWorkspaceArnPattern, a.Region.Data, conn.AccountId(), a.WorkspaceId.Data), nil
}

func (a *mqlAwsWorkspacesWorkspace) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Workspaces(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeTags(ctx, &workspaces.DescribeTagsInput{
		ResourceId: &a.WorkspaceId.Data,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, tag := range resp.TagList {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsWorkspacesWorkspace) fetchConnectionStatus() error {
	if a.connStatusFetched {
		return nil
	}
	a.connStatusLock.Lock()
	defer a.connStatusLock.Unlock()
	if a.connStatusFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Workspaces(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeWorkspacesConnectionStatus(ctx, &workspaces.DescribeWorkspacesConnectionStatusInput{
		WorkspaceIds: []string{a.WorkspaceId.Data},
	})
	if err != nil {
		return err
	}

	var connState string
	var checkTimestamp *time.Time
	var lastUserTimestamp *time.Time
	if len(resp.WorkspacesConnectionStatus) > 0 {
		status := resp.WorkspacesConnectionStatus[0]
		connState = string(status.ConnectionState)
		checkTimestamp = status.ConnectionStateCheckTimestamp
		lastUserTimestamp = status.LastKnownUserConnectionTimestamp
	}

	a.ConnectionState = plugin.TValue[string]{Data: connState, State: plugin.StateIsSet}
	a.ConnectionStateCheckTimestamp = plugin.TValue[*time.Time]{Data: checkTimestamp, State: plugin.StateIsSet}
	a.LastKnownUserConnectionTimestamp = plugin.TValue[*time.Time]{Data: lastUserTimestamp, State: plugin.StateIsSet}
	a.connStatusFetched = true
	return nil
}

func (a *mqlAwsWorkspacesWorkspace) connectionState() (string, error) {
	return "", a.fetchConnectionStatus()
}

func (a *mqlAwsWorkspacesWorkspace) connectionStateCheckTimestamp() (*time.Time, error) {
	return nil, a.fetchConnectionStatus()
}

func (a *mqlAwsWorkspacesWorkspace) lastKnownUserConnectionTimestamp() (*time.Time, error) {
	return nil, a.fetchConnectionStatus()
}

func (a *mqlAwsWorkspacesWorkspace) securityGroups() ([]any, error) {
	ipAddress := a.IpAddress.Data
	if ipAddress == "" {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	sgIdSet := map[string]struct{}{}
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(svc, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("addresses.private-ip-address"), Values: []string{ipAddress}},
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ni := range page.NetworkInterfaces {
			for _, sg := range ni.Groups {
				if sg.GroupId != nil {
					sgIdSet[*sg.GroupId] = struct{}{}
				}
			}
		}
	}

	region := a.Region.Data
	sgs := make([]any, 0, len(sgIdSet))
	for sgId := range sgIdSet {
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{
				"id":     llx.StringData(sgId),
				"region": llx.StringData(region),
			})
		if err != nil {
			return nil, err
		}
		sgs = append(sgs, mqlSg)
	}
	return sgs, nil
}

// ---- Images ----

func (a *mqlAwsWorkspaces) images() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getImages(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsWorkspaces) getImages(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspaces>getImages>calling aws with region %s", region)
			svc := conn.Workspaces(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeWorkspaceImages(ctx, &workspaces.DescribeWorkspaceImagesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces images API")
						return res, nil
					}
					return nil, err
				}

				for _, img := range resp.Images {
					mqlImg, err := newMqlAwsWorkspacesImage(a.MqlRuntime, region, img)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlImg)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsWorkspacesImage(runtime *plugin.Runtime, region string, img workspacestypes.WorkspaceImage) (*mqlAwsWorkspacesImage, error) {
	operatingSystem, err := convert.JsonToDict(img.OperatingSystem)
	if err != nil {
		return nil, err
	}

	imageId := ""
	if img.ImageId != nil {
		imageId = *img.ImageId
	}

	resource, err := CreateResource(runtime, "aws.workspaces.image",
		map[string]*llx.RawData{
			"__id":            llx.StringData("aws.workspaces.image/" + region + "/" + imageId),
			"imageId":         llx.StringDataPtr(img.ImageId),
			"name":            llx.StringDataPtr(img.Name),
			"description":     llx.StringDataPtr(img.Description),
			"operatingSystem": llx.MapData(operatingSystem, types.Any),
			"state":           llx.StringData(string(img.State)),
			"created":         llx.TimeDataPtr(img.Created),
			"ownerAccountId":  llx.StringDataPtr(img.OwnerAccountId),
			"region":          llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkspacesImage), nil
}

func (a *mqlAwsWorkspacesImage) id() (string, error) {
	return "aws.workspaces.image/" + a.Region.Data + "/" + a.ImageId.Data, nil
}

// ---- Bundles ----

func (a *mqlAwsWorkspaces) bundles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getBundles(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsWorkspaces) getBundles(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspaces>getBundles>calling aws with region %s", region)
			svc := conn.Workspaces(region)
			ctx := context.Background()
			res := []any{}

			paginator := workspaces.NewDescribeWorkspaceBundlesPaginator(svc, &workspaces.DescribeWorkspaceBundlesInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces bundles API")
						return res, nil
					}
					return nil, err
				}

				for _, bundle := range resp.Bundles {
					mqlBundle, err := newMqlAwsWorkspacesBundle(a.MqlRuntime, region, bundle)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlBundle)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsWorkspacesBundle(runtime *plugin.Runtime, region string, bundle workspacestypes.WorkspaceBundle) (*mqlAwsWorkspacesBundle, error) {
	computeType, err := convert.JsonToDict(bundle.ComputeType)
	if err != nil {
		return nil, err
	}
	userStorage, err := convert.JsonToDict(bundle.UserStorage)
	if err != nil {
		return nil, err
	}
	rootStorage, err := convert.JsonToDict(bundle.RootStorage)
	if err != nil {
		return nil, err
	}

	bundleId := ""
	if bundle.BundleId != nil {
		bundleId = *bundle.BundleId
	}

	resource, err := CreateResource(runtime, "aws.workspaces.bundle",
		map[string]*llx.RawData{
			"__id":            llx.StringData("aws.workspaces.bundle/" + region + "/" + bundleId),
			"bundleId":        llx.StringDataPtr(bundle.BundleId),
			"name":            llx.StringDataPtr(bundle.Name),
			"description":     llx.StringDataPtr(bundle.Description),
			"owner":           llx.StringDataPtr(bundle.Owner),
			"computeType":     llx.MapData(computeType, types.Any),
			"userStorage":     llx.MapData(userStorage, types.Any),
			"rootStorage":     llx.MapData(rootStorage, types.Any),
			"state":           llx.StringData(string(bundle.State)),
			"bundleType":      llx.StringData(string(bundle.BundleType)),
			"imageId":         llx.StringDataPtr(bundle.ImageId),
			"creationTime":    llx.TimeDataPtr(bundle.CreationTime),
			"lastUpdatedTime": llx.TimeDataPtr(bundle.LastUpdatedTime),
			"region":          llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkspacesBundle), nil
}

func (a *mqlAwsWorkspacesBundle) id() (string, error) {
	return "aws.workspaces.bundle/" + a.Region.Data + "/" + a.BundleId.Data, nil
}

// errWorkspacesBundleUnresolved marks a bundle reference that names no readable
// bundle. Returning it beats handing back a half-populated resource: a resource
// built from the reference args alone leaves every other field *unset*, and an
// unset field encodes to a primitive with no type, which llx logs as malformed
// before coercing it to null (see plugin.TValue.ToDataRes and
// llx.Primitive.RawData). Callers that would rather have a null bundle than an
// error convert it back at the accessor.
var errWorkspacesBundleUnresolved = errors.New("aws workspaces bundle unresolved")

// parseWorkspacesBundleRef reads the region and bundle ID a bundle reference was
// created with. Both are required: DescribeWorkspaceBundles with neither a
// bundle ID nor an owner answers with every bundle the account owns, so falling
// through on a partial reference would bind an arbitrary bundle.
func parseWorkspacesBundleRef(args map[string]*llx.RawData) (string, string, error) {
	var region, bundleId string
	if r := args["region"]; r != nil {
		if s, ok := r.Value.(string); ok {
			region = s
		}
	}
	if b := args["bundleId"]; b != nil {
		if s, ok := b.Value.(string); ok {
			bundleId = s
		}
	}
	if region == "" || bundleId == "" {
		return "", "", errors.New("bundleId + region required to fetch aws workspaces bundle")
	}
	return region, bundleId, nil
}

// initAwsWorkspacesBundle fetches a single bundle by ID.
//
// Filtering by bundle ID reaches AMAZON-provided bundles as well as
// account-owned ones, which an unfiltered DescribeWorkspaceBundles does not:
// AWS answers that with the caller's own bundles unless an owner is named.
func initAwsWorkspacesBundle(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	region, bundleId, err := parseWorkspacesBundleRef(args)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Workspaces(region)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := svc.DescribeWorkspaceBundles(ctx, &workspaces.DescribeWorkspaceBundlesInput{
		BundleIds: []string{bundleId},
	})
	if err != nil {
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces bundles API")
			return nil, nil, fmt.Errorf("%w: %q in %s is not readable", errWorkspacesBundleUnresolved, bundleId, region)
		}
		return nil, nil, err
	}
	// a bundle deleted after the WorkSpace was built no longer resolves
	if len(resp.Bundles) == 0 {
		return nil, nil, fmt.Errorf("%w: %q not found in %s", errWorkspacesBundleUnresolved, bundleId, region)
	}

	mqlBundle, err := newMqlAwsWorkspacesBundle(runtime, region, resp.Bundles[0])
	if err != nil {
		return nil, nil, err
	}
	return args, mqlBundle, nil
}

// ---- IP Groups ----

func (a *mqlAwsWorkspaces) ipGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getIpGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsWorkspaces) getIpGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspaces>getIpGroups>calling aws with region %s", region)
			svc := conn.Workspaces(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeIpGroups(ctx, &workspaces.DescribeIpGroupsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces IP groups API")
						return res, nil
					}
					return nil, err
				}

				for _, group := range resp.Result {
					mqlGroup, err := newMqlAwsWorkspacesIpGroup(a.MqlRuntime, region, group)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlGroup)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsWorkspacesIpGroup(runtime *plugin.Runtime, region string, group workspacestypes.WorkspacesIpGroup) (*mqlAwsWorkspacesIpGroup, error) {
	userRules, err := convert.JsonToDictSlice(group.UserRules)
	if err != nil {
		return nil, err
	}

	groupId := ""
	if group.GroupId != nil {
		groupId = *group.GroupId
	}

	resource, err := CreateResource(runtime, "aws.workspaces.ipGroup",
		map[string]*llx.RawData{
			"__id":      llx.StringData("aws.workspaces.ipGroup/" + region + "/" + groupId),
			"groupId":   llx.StringDataPtr(group.GroupId),
			"groupName": llx.StringDataPtr(group.GroupName),
			"groupDesc": llx.StringDataPtr(group.GroupDesc),
			"userRules": llx.ArrayData(userRules, types.Dict),
			"region":    llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkspacesIpGroup), nil
}

func (a *mqlAwsWorkspacesIpGroup) id() (string, error) {
	return "aws.workspaces.ipGroup/" + a.Region.Data + "/" + a.GroupId.Data, nil
}

func (a *mqlAwsWorkspacesIpGroup) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(workspacesIpGroupArnPattern, a.Region.Data, conn.AccountId(), a.GroupId.Data), nil
}

func (a *mqlAwsWorkspacesDirectory) subnets() ([]any, error) {
	subnetIds := a.SubnetIds.Data
	if len(subnetIds) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	res := []any{}
	for _, idAny := range subnetIds {
		id, ok := idAny.(string)
		if !ok || id == "" {
			continue
		}
		subnetArn := fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), id)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsWorkspacesWorkspace) bundle() (*mqlAwsWorkspacesBundle, error) {
	bundleId := a.BundleId.Data
	if bundleId == "" {
		a.Bundle.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.workspaces.bundle", map[string]*llx.RawData{
		"bundleId": llx.StringData(bundleId),
		"region":   llx.StringData(a.Region.Data),
	})
	if err != nil {
		// a bundle that names nothing readable is this WorkSpace having no
		// bundle to report, not a failure: one deleted or unreadable bundle
		// must not take down a fleet-wide query
		if errors.Is(err, errWorkspacesBundleUnresolved) {
			log.Debug().Str("bundleId", bundleId).Str("region", a.Region.Data).Msg("workspaces>bundle>unresolved")
			a.Bundle.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlAwsWorkspacesBundle), nil
}

func (a *mqlAwsWorkspacesWorkspace) subnet() (*mqlAwsVpcSubnet, error) {
	subnetId := a.SubnetId.Data
	if subnetId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	subnetArn := fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), subnetId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcSubnet), nil
}
