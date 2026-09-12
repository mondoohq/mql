// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/smithy-go/transport/http"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

func (a *mqlAwsEfsFilesystem) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEfs) filesystems() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "elasticfilesystem", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("efs>getFilesystems>calling aws with region %s", region)

		svc := conn.Efs(region)
		res := []any{}

		params := &efs.DescribeFileSystemsInput{}
		paginator := efs.NewDescribeFileSystemsPaginator(svc, params)
		for paginator.HasMorePages() {
			describeFileSystemsRes, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, fs := range describeFileSystemsRes.FileSystems {
				if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(efsTagsToMap(fs.Tags))) {
					log.Debug().Interface("filesystem", fs.FileSystemArn).Msg("skipping efs filesystem due to filters")
					continue
				}

				mqlFilesystem, err := buildEfsFilesystemResource(a.MqlRuntime, region, fs)
				if err != nil {
					return nil, err
				}

				res = append(res, mqlFilesystem)
			}
		}
		return res, nil
	})
}

type mqlAwsEfsFilesystemInternal struct {
	cacheKmsKeyID             *string
	cacheFileSystemProtection *efstypes.FileSystemProtectionDescription

	backupPolicyOnce sync.Once
	backupPolicyResp *efs.DescribeBackupPolicyOutput
	backupPolicyErr  error
}

// fetchBackupPolicy reads the file system's backup policy once and hands it to
// both fields derived from it. A 404 means the file system has no backup
// policy, which reads the same way as DISABLED; any other error (403, 5xx,
// ...) propagates, because a null status would let a backup check pass on a
// file system nobody could read.
func (a *mqlAwsEfsFilesystem) fetchBackupPolicy() (*efs.DescribeBackupPolicyOutput, error) {
	a.backupPolicyOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Efs(a.Region.Data)
		id := a.Id.Data
		resp, err := svc.DescribeBackupPolicy(context.Background(), &efs.DescribeBackupPolicyInput{
			FileSystemId: &id,
		})
		if err != nil {
			var respErr *http.ResponseError
			if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
				return
			}
			a.backupPolicyErr = err
			return
		}
		a.backupPolicyResp = resp
	})
	return a.backupPolicyResp, a.backupPolicyErr
}

func buildEfsFilesystemResource(runtime *plugin.Runtime, region string, fs efstypes.FileSystemDescription) (*mqlAwsEfsFilesystem, error) {
	var sizeInBytes int64
	if fs.SizeInBytes != nil {
		sizeInBytes = fs.SizeInBytes.Value
	}

	// Provisioned throughput is only set when throughputMode is provisioned;
	// leave the field null otherwise instead of reporting a misleading 0.
	provisionedThroughput := llx.NilData
	if fs.ProvisionedThroughputInMibps != nil {
		provisionedThroughput = llx.FloatData(*fs.ProvisionedThroughputInMibps)
	}

	args := map[string]*llx.RawData{
		"id":                           llx.StringDataPtr(fs.FileSystemId),
		"arn":                          llx.StringDataPtr(fs.FileSystemArn),
		"name":                         llx.StringDataPtr(fs.Name),
		"encrypted":                    llx.BoolData(convert.ToValue(fs.Encrypted)),
		"ownerId":                      llx.StringDataPtr(fs.OwnerId),
		"region":                       llx.StringData(region),
		"availabilityZone":             llx.StringDataPtr(fs.AvailabilityZoneName),
		"availabilityZoneId":           llx.StringDataPtr(fs.AvailabilityZoneId),
		"creationToken":                llx.StringDataPtr(fs.CreationToken),
		"provisionedThroughputInMibps": provisionedThroughput,
		"createdAt":                    llx.TimeDataPtr(fs.CreationTime),
		"tags":                         llx.MapData(efsTagsToMap(fs.Tags), types.String),
		"performanceMode":              llx.StringData(string(fs.PerformanceMode)),
		"throughputMode":               llx.StringData(string(fs.ThroughputMode)),
		"sizeInBytes":                  llx.IntData(sizeInBytes),
		"lifecycleState":               llx.StringData(string(fs.LifeCycleState)),
	}
	mqlFilesystem, err := CreateResource(runtime, "aws.efs.filesystem", args)
	if err != nil {
		return nil, err
	}
	fsResource := mqlFilesystem.(*mqlAwsEfsFilesystem)
	fsResource.cacheKmsKeyID = fs.KmsKeyId
	fsResource.cacheFileSystemProtection = fs.FileSystemProtection
	return fsResource, nil
}

func (a *mqlAwsEfsFilesystem) kmsKey() (*mqlAwsKmsKey, error) {
	// add kms key if there is one
	if a.cacheKmsKeyID != nil {
		mqlKeyResource, err := NewResource(a.MqlRuntime, "aws.kms.key", map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyID),
		})
		// initAwsKmsKey returns (nil, err) on an unparseable ARN or a denied
		// DescribeKey; asserting on the nil interface would panic and, because
		// blocks run in goroutines, take down the whole scan.
		if err != nil {
			return nil, err
		}
		return mqlKeyResource.(*mqlAwsKmsKey), nil
	}
	a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull

	return nil, nil
}

func initAwsEfsFilesystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEfsFilesystem); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch efs filesystem")
	}

	arnVal := args["arn"].Value.(string)

	// Derive region + filesystem id for a single targeted DescribeFileSystems
	// call instead of listing every filesystem in every region.
	var region, fsId string
	if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "file-system/") {
		region = parsed.Region
		fsId = strings.TrimPrefix(parsed.Resource, "file-system/")
	}

	if cached := cachedByArn(runtime, ResourceAwsEfsFilesystem, arnVal); cached != nil {
		return args, cached, nil
	}

	if region != "" && fsId != "" {
		conn := runtime.Connection.(*connection.AwsConnection)
		svc := conn.Efs(region)
		resp, err := svc.DescribeFileSystems(context.Background(), &efs.DescribeFileSystemsInput{
			FileSystemId: &fsId,
		})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.FileSystems) > 0 {
			fs, err := buildEfsFilesystemResource(runtime, region, resp.FileSystems[0])
			if err != nil {
				return nil, nil, err
			}
			return args, fs, nil
		}
		return nil, nil, errors.New("efs filesystem does not exist")
	}

	// Fallback: scan the cached list when the ARN can't be parsed for a
	// targeted lookup.
	obj, err := CreateResource(runtime, "aws.efs", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	efs := obj.(*mqlAwsEfs)
	rawResources := efs.GetFilesystems()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	for _, rawResource := range rawResources.Data {
		fs := rawResource.(*mqlAwsEfsFilesystem)
		if fs.Arn.Data == arnVal {
			return args, fs, nil
		}
	}
	return nil, nil, errors.New("efs filesystem does not exist")
}

// backupPolicy is the deprecated dict view of automaticBackup. It emits only
// the documented shape, a `BackupPolicy` object carrying `Status`; serializing
// the whole SDK output would also publish its ResultMetadata, which describes
// the API call rather than the file system.
func (a *mqlAwsEfsFilesystem) backupPolicy() (any, error) {
	resp, err := a.fetchBackupPolicy()
	if err != nil || resp == nil || resp.BackupPolicy == nil {
		return nil, err
	}
	return map[string]any{
		"BackupPolicy": map[string]any{
			"Status": string(resp.BackupPolicy.Status),
		},
	}, nil
}

func (a *mqlAwsEfsFilesystem) automaticBackup() (*mqlAwsEfsBackupPolicy, error) {
	resp, err := a.fetchBackupPolicy()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.BackupPolicy == nil {
		a.AutomaticBackup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.efs.backupPolicy", map[string]*llx.RawData{
		"__id":   llx.StringData(a.Arn.Data + "/backupPolicy"),
		"status": llx.StringData(string(resp.BackupPolicy.Status)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsBackupPolicy), nil
}

func (a *mqlAwsEfsFilesystem) lifecycleConfiguration() (*mqlAwsEfsFilesystemLifecycleConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	region := a.Region.Data

	svc := conn.Efs(region)
	ctx := context.Background()

	resp, err := svc.DescribeLifecycleConfiguration(ctx, &efs.DescribeLifecycleConfigurationInput{
		FileSystemId: &id,
	})
	if err != nil {
		// A 404 establishes that the file system has no lifecycle
		// configuration. A denial establishes nothing, and null would make a
		// file system with no lifecycle policy and one nobody could check read
		// identically, so it propagates.
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.LifecycleConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if len(resp.LifecyclePolicies) == 0 {
		a.LifecycleConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// Aggregate all policies into a single lifecycle configuration
	var transitionToIA, transitionToArchive, transitionToPrimary string
	for _, p := range resp.LifecyclePolicies {
		if p.TransitionToIA != "" {
			transitionToIA = string(p.TransitionToIA)
		}
		if p.TransitionToArchive != "" {
			transitionToArchive = string(p.TransitionToArchive)
		}
		if p.TransitionToPrimaryStorageClass != "" {
			transitionToPrimary = string(p.TransitionToPrimaryStorageClass)
		}
	}

	configId := a.Arn.Data + "/lifecycleConfiguration"
	mqlConfig, err := CreateResource(a.MqlRuntime, "aws.efs.filesystem.lifecycleConfiguration",
		map[string]*llx.RawData{
			"__id":                            llx.StringData(configId),
			"transitionToIA":                  llx.StringData(transitionToIA),
			"transitionToArchive":             llx.StringData(transitionToArchive),
			"transitionToPrimaryStorageClass": llx.StringData(transitionToPrimary),
		})
	if err != nil {
		return nil, err
	}
	return mqlConfig.(*mqlAwsEfsFilesystemLifecycleConfiguration), nil
}

func (a *mqlAwsEfsFilesystemLifecycleConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEfsFilesystem) replicationConfiguration() (*mqlAwsEfsFilesystemReplicationConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	region := a.Region.Data

	svc := conn.Efs(region)
	ctx := context.Background()

	resp, err := svc.DescribeReplicationConfigurations(ctx, &efs.DescribeReplicationConfigurationsInput{
		FileSystemId: &id,
	})
	if err != nil {
		// ReplicationConfigurationNotFound (404) establishes that the file
		// system is not replicated. A denial does not, so an unreplicated file
		// system and one nobody could check must not read the same way.
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.ReplicationConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Replications) == 0 {
		a.ReplicationConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	repl := resp.Replications[0]

	// Build destination sub-resources
	destinations := make([]any, 0, len(repl.Destinations))
	for _, dest := range repl.Destinations {
		destId := convert.ToValue(repl.SourceFileSystemArn) + "/replication/" + convert.ToValue(dest.FileSystemId)
		mqlDest, err := CreateResource(a.MqlRuntime, "aws.efs.filesystem.replicationDestination",
			map[string]*llx.RawData{
				"__id":                    llx.StringData(destId),
				"region":                  llx.StringDataPtr(dest.Region),
				"status":                  llx.StringData(string(dest.Status)),
				"lastReplicatedTimestamp": llx.TimeDataPtr(dest.LastReplicatedTimestamp),
			})
		if err != nil {
			return nil, err
		}
		mqlDest.(*mqlAwsEfsFilesystemReplicationDestination).cacheFileSystemId = convert.ToValue(dest.FileSystemId)
		destinations = append(destinations, mqlDest)
	}

	replId := convert.ToValue(repl.SourceFileSystemArn) + "/replication"
	mqlRepl, err := CreateResource(a.MqlRuntime, "aws.efs.filesystem.replicationConfiguration",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(replId),
			"sourceFileSystemId":     llx.StringDataPtr(repl.SourceFileSystemId),
			"sourceFileSystemRegion": llx.StringDataPtr(repl.SourceFileSystemRegion),
			"creationTime":           llx.TimeDataPtr(repl.CreationTime),
			"destinations":           llx.ArrayData(destinations, types.Resource("aws.efs.filesystem.replicationDestination")),
		})
	if err != nil {
		return nil, err
	}
	mqlRepl.(*mqlAwsEfsFilesystemReplicationConfiguration).cacheSourceFileSystemArn = convert.ToValue(repl.SourceFileSystemArn)
	mqlRepl.(*mqlAwsEfsFilesystemReplicationConfiguration).cacheOriginalSourceFileSystemArn = convert.ToValue(repl.OriginalSourceFileSystemArn)
	return mqlRepl.(*mqlAwsEfsFilesystemReplicationConfiguration), nil
}

func (a *mqlAwsEfsFilesystemReplicationConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEfsFilesystemReplicationConfiguration) sourceFileSystem() (*mqlAwsEfsFilesystem, error) {
	arnVal := a.cacheSourceFileSystemArn
	if arnVal == "" {
		a.SourceFileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

func (a *mqlAwsEfsFilesystemReplicationConfiguration) originalSourceFileSystem() (*mqlAwsEfsFilesystem, error) {
	arnVal := a.cacheOriginalSourceFileSystemArn
	if arnVal == "" {
		a.OriginalSourceFileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

func (a *mqlAwsEfsFilesystemReplicationDestination) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEfsFilesystemReplicationDestination) fileSystem() (*mqlAwsEfsFilesystem, error) {
	fsId := a.cacheFileSystemId
	if fsId == "" {
		a.FileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(efsFilesystemArnPattern, a.Region.Data, conn.AccountId(), fsId)
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

func (a *mqlAwsEfsFilesystem) fileSystemProtection() (any, error) {
	if a.cacheFileSystemProtection == nil {
		return nil, nil
	}
	result := map[string]any{
		"replicationOverwriteProtection": string(a.cacheFileSystemProtection.ReplicationOverwriteProtection),
	}
	return result, nil
}

func (a *mqlAwsEfsFilesystem) protection() (*mqlAwsEfsFileSystemProtection, error) {
	if a.cacheFileSystemProtection == nil {
		a.Protection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.efs.fileSystemProtection", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.Arn.Data + "/fileSystemProtection"),
		"replicationOverwriteProtection": llx.StringData(string(a.cacheFileSystemProtection.ReplicationOverwriteProtection)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFileSystemProtection), nil
}

func efsTagsToMap(tags []efstypes.Tag) map[string]any {
	return tagsToMap(tags, func(t efstypes.Tag) *string { return t.Key }, func(t efstypes.Tag) *string { return t.Value })
}

func (a *mqlAwsEfsFilesystem) mountTargets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	region := a.Region.Data

	svc := conn.Efs(region)
	ctx := context.Background()

	res := []any{}
	params := &efs.DescribeMountTargetsInput{
		FileSystemId: &id,
	}
	paginator := efs.NewDescribeMountTargetsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// A denial truncates the list without saying so. Returning the
			// partial slice would let mountTargets.all(...) pass vacuously on a
			// file system whose mount targets nobody could enumerate, so the
			// failure propagates instead.
			return nil, err
		}

		for _, mt := range page.MountTargets {
			// A failed group read is carried on the mount target rather than
			// failing the whole list: one unreadable mount target must not
			// erase the rest, but its securityGroups field must not read as an
			// empty list either.
			sgRes, sgErr := svc.DescribeMountTargetSecurityGroups(ctx, &efs.DescribeMountTargetSecurityGroupsInput{
				MountTargetId: mt.MountTargetId,
			})
			if sgErr != nil {
				log.Warn().Str("mountTargetId", convert.ToValue(mt.MountTargetId)).Msg("error fetching security groups for mount target")
			}

			args := map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(mt.MountTargetId),
				"mountTargetId":    llx.StringDataPtr(mt.MountTargetId),
				"availabilityZone": llx.StringDataPtr(mt.AvailabilityZoneName),
				"ipAddress":        llx.StringDataPtr(mt.IpAddress),
				"lifecycleState":   llx.StringData(string(mt.LifeCycleState)),
				"region":           llx.StringData(region),
			}

			mqlMountTarget, err := CreateResource(a.MqlRuntime, ResourceAwsEfsMountTarget, args)
			if err != nil {
				return nil, err
			}
			mqlMountTarget.(*mqlAwsEfsMountTarget).cacheFileSystemId = convert.ToValue(mt.FileSystemId)
			mqlMountTarget.(*mqlAwsEfsMountTarget).cacheSubnetId = convert.ToValue(mt.SubnetId)
			mqlMountTarget.(*mqlAwsEfsMountTarget).cacheNetworkInterfaceId = convert.ToValue(mt.NetworkInterfaceId)

			// Cache the security group IDs, or the reason there are none.
			mqlMt := mqlMountTarget.(*mqlAwsEfsMountTarget)
			mqlMt.cacheSecurityGroupsErr = sgErr
			if sgErr == nil && sgRes != nil {
				mqlMt.cacheSecurityGroupIDs = sgRes.SecurityGroups
			}

			res = append(res, mqlMountTarget)
		}
	}

	return res, nil
}

func (a *mqlAwsEfsFilesystem) accessPoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	region := a.Region.Data

	svc := conn.Efs(region)
	ctx := context.Background()

	res := []any{}
	params := &efs.DescribeAccessPointsInput{
		FileSystemId: &id,
	}
	paginator := efs.NewDescribeAccessPointsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// As with mount targets, a truncated list presented as complete is
			// what makes an accessPoints.all(...) check pass on evidence that
			// was never read.
			return nil, err
		}

		for _, ap := range page.AccessPoints {
			// Convert POSIX user to dict
			var posixUser map[string]any
			if ap.PosixUser != nil {
				posixUser = map[string]any{
					"uid": convert.ToValue(ap.PosixUser.Uid),
					"gid": convert.ToValue(ap.PosixUser.Gid),
				}
				if len(ap.PosixUser.SecondaryGids) > 0 {
					secondaryGids := make([]any, len(ap.PosixUser.SecondaryGids))
					for i, gid := range ap.PosixUser.SecondaryGids {
						secondaryGids[i] = gid
					}
					posixUser["secondaryGids"] = secondaryGids
				}
			}

			// Convert root directory to dict
			var rootDirectory map[string]any
			if ap.RootDirectory != nil {
				rootDirectory = map[string]any{
					"path": convert.ToValue(ap.RootDirectory.Path),
				}
				if ap.RootDirectory.CreationInfo != nil {
					rootDirectory["creationInfo"] = map[string]any{
						"ownerUid":    convert.ToValue(ap.RootDirectory.CreationInfo.OwnerUid),
						"ownerGid":    convert.ToValue(ap.RootDirectory.CreationInfo.OwnerGid),
						"permissions": convert.ToValue(ap.RootDirectory.CreationInfo.Permissions),
					}
				}
			}

			// A nil PosixUser or RootDirectory is not "empty", it means the
			// access point enforces no identity or no root of its own, so the
			// reference stays null rather than reporting uid 0 and path "".
			mqlPosixUser, err := newMqlEfsPosixUser(a.MqlRuntime, convert.ToValue(ap.AccessPointArn), ap.PosixUser)
			if err != nil {
				return nil, err
			}
			mqlRootDirectory, err := newMqlEfsRootDirectory(a.MqlRuntime, convert.ToValue(ap.AccessPointArn), ap.RootDirectory)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(ap.AccessPointArn),
				"accessPointId":  llx.StringDataPtr(ap.AccessPointId),
				"arn":            llx.StringDataPtr(ap.AccessPointArn),
				"name":           llx.StringDataPtr(ap.Name),
				"lifecycleState": llx.StringData(string(ap.LifeCycleState)),
				"region":         llx.StringData(region),
				"tags":           llx.MapData(efsTagsToMap(ap.Tags), types.String),
				"posixIdentity":  mqlPosixUser,
				"root":           mqlRootDirectory,
			}

			// Set unconditionally: a key left out of the args map leaves the
			// field unset rather than null, and reading an unset field crosses
			// the plugin boundary with no type information.
			args["posixUser"] = llx.DictData(posixUser)
			args["rootDirectory"] = llx.DictData(rootDirectory)

			mqlAccessPoint, err := CreateResource(a.MqlRuntime, ResourceAwsEfsAccessPoint, args)
			if err != nil {
				return nil, err
			}
			mqlAccessPoint.(*mqlAwsEfsAccessPoint).cacheFileSystemId = convert.ToValue(ap.FileSystemId)

			res = append(res, mqlAccessPoint)
		}
	}

	return res, nil
}

// efsPolicyNotFound reports the answer EFS gives for a file system that
// carries no resource policy at all: PolicyNotFound, HTTP 404.
//
// It is a statement about the file system, not a failure to read one, which is
// why it is deliberately narrow. A denial (403) and a transport error both
// leave the policy unknown, and neither may be folded in here: the empty
// document they would produce is byte-identical to the one a file system with
// no policy produces, and isPublic, which is derived from it, would then report
// a file system open to the world as private.
func efsPolicyNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == 404
	}
	return false
}

// fileSystemPolicy returns the file system's resource policy document. The
// empty string means one thing only: the file system carries no policy. Any
// error other than the 404 that establishes that propagates, so that
// policyStatements and isPublic, both derived from this field, report an
// unreadable policy as unreadable rather than as absent.
func (a *mqlAwsEfsFilesystem) fileSystemPolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	region := a.Region.Data

	svc := conn.Efs(region)
	ctx := context.Background()

	policyRes, err := svc.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
		FileSystemId: &id,
	})
	if err != nil {
		if efsPolicyNotFound(err) {
			return "", nil
		}
		return "", err
	}

	if policyRes != nil && policyRes.Policy != nil {
		return *policyRes.Policy, nil
	}

	return "", nil
}

// Mount Target implementation
type mqlAwsEfsMountTargetInternal struct {
	cacheFileSystemId       string
	cacheSubnetId           string
	cacheNetworkInterfaceId string
	cacheSecurityGroupIDs   []string
	// cacheSecurityGroupsErr records why the group list could not be read, so
	// the accessor can report the refusal instead of an empty list.
	cacheSecurityGroupsErr error
}

// securityGroups returns the security groups attached to the mount target.
//
// EFS attaches at least one security group to every mount target, so an empty
// list is never a reading the API produced: it means the group list was not
// read. Reporting it as a list would make a
// mountTargets.all(securityGroups.none(...)) check pass on a mount target
// nobody could inspect, so an unread list is an error.
func (a *mqlAwsEfsMountTarget) securityGroups() ([]any, error) {
	if a.cacheSecurityGroupsErr != nil {
		return nil, fmt.Errorf("could not read security groups for EFS mount target %s: %w",
			a.MountTargetId.Data, a.cacheSecurityGroupsErr)
	}
	if len(a.cacheSecurityGroupIDs) == 0 {
		return nil, fmt.Errorf("no security groups were read for EFS mount target %s", a.MountTargetId.Data)
	}

	region := a.Region.Data

	res := []any{}
	for _, sgID := range a.cacheSecurityGroupIDs {
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup", map[string]*llx.RawData{
			"id":     llx.StringData(sgID),
			"region": llx.StringData(region),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}

	return res, nil
}

func (a *mqlAwsEfsMountTarget) subnet() (*mqlAwsVpcSubnet, error) {
	subnetId := a.cacheSubnetId
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

func (a *mqlAwsEfsMountTarget) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	eniId := a.cacheNetworkInterfaceId
	if eniId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{"id": llx.StringData(eniId), "region": llx.StringData(a.Region.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Networkinterface), nil
}

func (a *mqlAwsEfsMountTarget) fileSystem() (*mqlAwsEfsFilesystem, error) {
	fsId := a.cacheFileSystemId
	if fsId == "" {
		a.FileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(efsFilesystemArnPattern, a.Region.Data, conn.AccountId(), fsId)
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

func (a *mqlAwsEfsAccessPoint) fileSystem() (*mqlAwsEfsFilesystem, error) {
	fsId := a.cacheFileSystemId
	if fsId == "" {
		a.FileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(efsFilesystemArnPattern, a.Region.Data, conn.AccountId(), fsId)
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem",
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

type mqlAwsEfsFilesystemReplicationConfigurationInternal struct {
	cacheSourceFileSystemArn         string
	cacheOriginalSourceFileSystemArn string
}

type mqlAwsEfsFilesystemReplicationDestinationInternal struct {
	cacheFileSystemId string
}

type mqlAwsEfsAccessPointInternal struct {
	cacheFileSystemId string
}

// newMqlEfsPosixUser builds the POSIX identity an access point enforces. A nil
// PosixUser means the access point enforces no identity at all, which is
// reported as null rather than as uid 0, the identity that would make every
// client root.
func newMqlEfsPosixUser(runtime *plugin.Runtime, accessPointArn string, pu *efstypes.PosixUser) (*llx.RawData, error) {
	if pu == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.efs.posixUser", map[string]*llx.RawData{
		"__id":          llx.StringData(accessPointArn + "/posixUser"),
		"uid":           llx.IntDataPtr(pu.Uid),
		"gid":           llx.IntDataPtr(pu.Gid),
		"secondaryGids": llx.ArrayData(convert.SliceAnyToInterface(pu.SecondaryGids), types.Int),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "aws.efs.posixUser"), nil
}

// newMqlEfsRootDirectory builds the root an access point exposes. A nil
// RootDirectory means the access point does not restrict the root, which is
// reported as null rather than as the empty path.
func newMqlEfsRootDirectory(runtime *plugin.Runtime, accessPointArn string, rd *efstypes.RootDirectory) (*llx.RawData, error) {
	if rd == nil {
		return llx.NilData, nil
	}
	ownerUid, ownerGid := llx.NilData, llx.NilData
	permissions := llx.NilData
	if ci := rd.CreationInfo; ci != nil {
		ownerUid = llx.IntDataPtr(ci.OwnerUid)
		ownerGid = llx.IntDataPtr(ci.OwnerGid)
		permissions = llx.StringDataPtr(ci.Permissions)
	}
	res, err := CreateResource(runtime, "aws.efs.rootDirectory", map[string]*llx.RawData{
		"__id":        llx.StringData(accessPointArn + "/rootDirectory"),
		"path":        llx.StringDataPtr(rd.Path),
		"ownerUid":    ownerUid,
		"ownerGid":    ownerGid,
		"permissions": permissions,
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "aws.efs.rootDirectory"), nil
}
