// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	sgwtypes "github.com/aws/aws-sdk-go-v2/service/storagegateway/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// ========================
// aws.storagegateway
// ========================

func (a *mqlAwsStoragegateway) id() (string, error) {
	return ResourceAwsStoragegateway, nil
}

func (a *mqlAwsStoragegateway) gateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getGateways(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsStoragegateway) getGateways(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		regionVal := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("storagegateway>getGateways>calling aws with region %s", regionVal)

			svc := conn.StorageGateway(regionVal)
			ctx := context.Background()
			res := []any{}

			paginator := storagegateway.NewListGatewaysPaginator(svc, &storagegateway.ListGatewaysInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, gw := range page.Gateways {
					if gw.GatewayARN == nil {
						// ARN is the cache key; without it the resource can't be
						// addressed or de-duplicated, so skip it.
						continue
					}
					args := map[string]*llx.RawData{
						"__id":              llx.StringDataPtr(gw.GatewayARN),
						"arn":               llx.StringDataPtr(gw.GatewayARN),
						"id":                llx.StringDataPtr(gw.GatewayId),
						"name":              llx.StringDataPtr(gw.GatewayName),
						"type":              llx.StringDataPtr(gw.GatewayType),
						"operationalState":  llx.StringDataPtr(gw.GatewayOperationalState),
						"ec2InstanceId":     llx.StringDataPtr(gw.Ec2InstanceId),
						"ec2InstanceRegion": llx.StringDataPtr(gw.Ec2InstanceRegion),
						"hostEnvironment":   llx.StringData(string(gw.HostEnvironment)),
						"hostEnvironmentId": llx.StringDataPtr(gw.HostEnvironmentId),
						"softwareVersion":   llx.StringDataPtr(gw.SoftwareVersion),
						"deprecationDate":   llx.StringDataPtr(gw.DeprecationDate),
						"region":            llx.StringData(regionVal),
					}
					mqlGateway, err := CreateResource(a.MqlRuntime, ResourceAwsStoragegatewayGateway, args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlGateway)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// ========================
// aws.storagegateway.gateway
// ========================

type mqlAwsStoragegatewayGatewayInternal struct {
	fetched bool
	lock    sync.Mutex
	info    *storagegateway.DescribeGatewayInformationOutput
}

func (a *mqlAwsStoragegatewayGateway) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsStoragegatewayGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch storage gateway")
	}

	obj, err := CreateResource(runtime, ResourceAwsStoragegateway, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sgwService := obj.(*mqlAwsStoragegateway)
	rawResources := sgwService.GetGateways()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		gw := rawResource.(*mqlAwsStoragegatewayGateway)
		if gw.Arn.Data == arnVal {
			return args, gw, nil
		}
	}
	return nil, nil, errors.New("storage gateway does not exist")
}

// fetchInfo lazily loads the detailed gateway configuration via
// DescribeGatewayInformation and caches it. Multiple computed fields share it.
func (a *mqlAwsStoragegatewayGateway) fetchInfo() (*storagegateway.DescribeGatewayInformationOutput, error) {
	if a.fetched {
		return a.info, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.info, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.StorageGateway(a.Region.Data)
	arn := a.Arn.Data
	out, err := svc.DescribeGatewayInformation(context.Background(), &storagegateway.DescribeGatewayInformationInput{
		GatewayARN: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "storagegateway:DescribeGatewayInformation")
	}
	a.fetched = true
	a.info = out
	return out, nil
}

func (a *mqlAwsStoragegatewayGateway) endpointType() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.EndpointType), nil
}

func (a *mqlAwsStoragegatewayGateway) gatewayCapacity() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return string(info.GatewayCapacity), nil
}

func (a *mqlAwsStoragegatewayGateway) supportedGatewayCapacities() ([]any, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return nil, err
	}
	res := make([]any, 0, len(info.SupportedGatewayCapacities))
	for _, c := range info.SupportedGatewayCapacities {
		res = append(res, string(c))
	}
	return res, nil
}

func (a *mqlAwsStoragegatewayGateway) state() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.GatewayState), nil
}

func (a *mqlAwsStoragegatewayGateway) timezone() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.GatewayTimezone), nil
}

func (a *mqlAwsStoragegatewayGateway) lastSoftwareUpdate() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.LastSoftwareUpdate), nil
}

func (a *mqlAwsStoragegatewayGateway) nextUpdateAvailabilityDate() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.NextUpdateAvailabilityDate), nil
}

func (a *mqlAwsStoragegatewayGateway) softwareUpdatesEndDate() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.SoftwareUpdatesEndDate), nil
}

func (a *mqlAwsStoragegatewayGateway) cloudWatchLogGroupArn() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.CloudWatchLogGroupARN), nil
}

func (a *mqlAwsStoragegatewayGateway) vpcEndpoint() (string, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return "", err
	}
	return convert.ToValue(info.VPCEndpoint), nil
}

func (a *mqlAwsStoragegatewayGateway) networkInterfaces() ([]any, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return nil, err
	}
	res := make([]any, 0, len(info.GatewayNetworkInterfaces))
	for _, ni := range info.GatewayNetworkInterfaces {
		res = append(res, map[string]any{
			"ipv4Address": convert.ToValue(ni.Ipv4Address),
			"ipv6Address": convert.ToValue(ni.Ipv6Address),
			"macAddress":  convert.ToValue(ni.MacAddress),
		})
	}
	return res, nil
}

func (a *mqlAwsStoragegatewayGateway) tags() (map[string]any, error) {
	info, err := a.fetchInfo()
	if err != nil || info == nil {
		return nil, err
	}
	return storageGatewayTagsToMap(info.Tags), nil
}

func (a *mqlAwsStoragegatewayGateway) fileShares() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.StorageGateway(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	arn := a.Arn.Data
	paginator := storagegateway.NewListFileSharesPaginator(svc, &storagegateway.ListFileSharesInput{
		GatewayARN: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:ListFileShares")
		}

		for _, fs := range page.FileShareInfoList {
			args := map[string]*llx.RawData{
				"__id":       llx.StringDataPtr(fs.FileShareARN),
				"arn":        llx.StringDataPtr(fs.FileShareARN),
				"id":         llx.StringDataPtr(fs.FileShareId),
				"type":       llx.StringData(string(fs.FileShareType)),
				"status":     llx.StringDataPtr(fs.FileShareStatus),
				"gatewayArn": llx.StringDataPtr(fs.GatewayARN),
				"region":     llx.StringData(a.Region.Data),
			}
			mqlFileShare, err := CreateResource(a.MqlRuntime, ResourceAwsStoragegatewayFileShare, args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFileShare)
		}
	}
	return res, nil
}

func (a *mqlAwsStoragegatewayGateway) volumes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.StorageGateway(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	arn := a.Arn.Data
	paginator := storagegateway.NewListVolumesPaginator(svc, &storagegateway.ListVolumesInput{
		GatewayARN: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:ListVolumes")
		}

		for _, vol := range page.VolumeInfos {
			args := map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(vol.VolumeARN),
				"arn":              llx.StringDataPtr(vol.VolumeARN),
				"id":               llx.StringDataPtr(vol.VolumeId),
				"type":             llx.StringDataPtr(vol.VolumeType),
				"sizeInBytes":      llx.IntData(vol.VolumeSizeInBytes),
				"attachmentStatus": llx.StringDataPtr(vol.VolumeAttachmentStatus),
				"gatewayArn":       llx.StringDataPtr(vol.GatewayARN),
				"gatewayId":        llx.StringDataPtr(vol.GatewayId),
				"region":           llx.StringData(a.Region.Data),
			}
			mqlVolume, err := CreateResource(a.MqlRuntime, ResourceAwsStoragegatewayVolume, args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVolume)
		}
	}
	return res, nil
}

// ========================
// aws.storagegateway.fileShare
// ========================

type sgwFileShareDetail struct {
	name                string
	kmsEncrypted        bool
	encryptionType      string
	kmsKey              string
	defaultStorageClass string
	objectAcl           string
	readOnly            bool
	requesterPays       bool
	guessMimeType       bool
	locationArn         string
	bucketRegion        string
	auditDestinationArn string
	role                string
}

type mqlAwsStoragegatewayFileShareInternal struct {
	fetched bool
	lock    sync.Mutex
	detail  *sgwFileShareDetail
}

func (a *mqlAwsStoragegatewayFileShare) id() (string, error) {
	return a.Arn.Data, nil
}

// fetchDetail lazily loads the file-share configuration via
// DescribeNFSFileShares or DescribeSMBFileShares depending on the share type.
func (a *mqlAwsStoragegatewayFileShare) fetchDetail() (*sgwFileShareDetail, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.StorageGateway(a.Region.Data)
	ctx := context.Background()
	arns := []string{a.Arn.Data}

	var detail *sgwFileShareDetail
	switch strings.ToUpper(a.Type.Data) {
	case "SMB":
		out, err := svc.DescribeSMBFileShares(ctx, &storagegateway.DescribeSMBFileSharesInput{FileShareARNList: arns})
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:DescribeSMBFileShares")
		}
		if len(out.SMBFileShareInfoList) > 0 {
			s := out.SMBFileShareInfoList[0]
			detail = &sgwFileShareDetail{
				name:                convert.ToValue(s.FileShareName),
				kmsEncrypted:        s.KMSEncrypted,
				encryptionType:      string(s.EncryptionType),
				kmsKey:              convert.ToValue(s.KMSKey),
				defaultStorageClass: convert.ToValue(s.DefaultStorageClass),
				objectAcl:           string(s.ObjectACL),
				readOnly:            convert.ToValue(s.ReadOnly),
				requesterPays:       convert.ToValue(s.RequesterPays),
				guessMimeType:       convert.ToValue(s.GuessMIMETypeEnabled),
				locationArn:         convert.ToValue(s.LocationARN),
				bucketRegion:        convert.ToValue(s.BucketRegion),
				auditDestinationArn: convert.ToValue(s.AuditDestinationARN),
				role:                convert.ToValue(s.Role),
			}
		}
	case "NFS":
		out, err := svc.DescribeNFSFileShares(ctx, &storagegateway.DescribeNFSFileSharesInput{FileShareARNList: arns})
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:DescribeNFSFileShares")
		}
		if len(out.NFSFileShareInfoList) > 0 {
			s := out.NFSFileShareInfoList[0]
			detail = &sgwFileShareDetail{
				name:                convert.ToValue(s.FileShareName),
				kmsEncrypted:        s.KMSEncrypted,
				encryptionType:      string(s.EncryptionType),
				kmsKey:              convert.ToValue(s.KMSKey),
				defaultStorageClass: convert.ToValue(s.DefaultStorageClass),
				objectAcl:           string(s.ObjectACL),
				readOnly:            convert.ToValue(s.ReadOnly),
				requesterPays:       convert.ToValue(s.RequesterPays),
				guessMimeType:       convert.ToValue(s.GuessMIMETypeEnabled),
				locationArn:         convert.ToValue(s.LocationARN),
				bucketRegion:        convert.ToValue(s.BucketRegion),
				auditDestinationArn: convert.ToValue(s.AuditDestinationARN),
				role:                convert.ToValue(s.Role),
			}
		}
	}

	a.fetched = true
	a.detail = detail
	return detail, nil
}

func (a *mqlAwsStoragegatewayFileShare) name() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.name, nil
}

func (a *mqlAwsStoragegatewayFileShare) kmsEncrypted() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.kmsEncrypted, nil
}

func (a *mqlAwsStoragegatewayFileShare) encryptionType() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.encryptionType, nil
}

func (a *mqlAwsStoragegatewayFileShare) kmsKey() (*mqlAwsKmsKey, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || d.kmsKey == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringData(d.kmsKey)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsStoragegatewayFileShare) defaultStorageClass() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.defaultStorageClass, nil
}

func (a *mqlAwsStoragegatewayFileShare) objectAcl() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.objectAcl, nil
}

func (a *mqlAwsStoragegatewayFileShare) readOnly() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.readOnly, nil
}

func (a *mqlAwsStoragegatewayFileShare) requesterPays() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.requesterPays, nil
}

func (a *mqlAwsStoragegatewayFileShare) guessMimeTypeEnabled() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.guessMimeType, nil
}

func (a *mqlAwsStoragegatewayFileShare) locationArn() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.locationArn, nil
}

func (a *mqlAwsStoragegatewayFileShare) bucketRegion() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.bucketRegion, nil
}

func (a *mqlAwsStoragegatewayFileShare) auditDestinationArn() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.auditDestinationArn, nil
}

func (a *mqlAwsStoragegatewayFileShare) iamRole() (*mqlAwsIamRole, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || d.role == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(d.role)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

// ========================
// aws.storagegateway.volume
// ========================

type sgwVolumeDetail struct {
	status           string
	createdAt        *time.Time
	sourceSnapshotId string
	kmsKey           string
}

type mqlAwsStoragegatewayVolumeInternal struct {
	fetched bool
	lock    sync.Mutex
	detail  *sgwVolumeDetail
}

func (a *mqlAwsStoragegatewayVolume) id() (string, error) {
	return a.Arn.Data, nil
}

// fetchDetail lazily loads the volume configuration via
// DescribeCachediSCSIVolumes or DescribeStorediSCSIVolumes by volume type.
func (a *mqlAwsStoragegatewayVolume) fetchDetail() (*sgwVolumeDetail, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.StorageGateway(a.Region.Data)
	ctx := context.Background()
	arns := []string{a.Arn.Data}

	var detail *sgwVolumeDetail
	if strings.HasPrefix(strings.ToUpper(a.Type.Data), "STORED") {
		out, err := svc.DescribeStorediSCSIVolumes(ctx, &storagegateway.DescribeStorediSCSIVolumesInput{VolumeARNs: arns})
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:DescribeStorediSCSIVolumes")
		}
		if len(out.StorediSCSIVolumes) > 0 {
			v := out.StorediSCSIVolumes[0]
			detail = &sgwVolumeDetail{
				status:           convert.ToValue(v.VolumeStatus),
				createdAt:        v.CreatedDate,
				sourceSnapshotId: convert.ToValue(v.SourceSnapshotId),
				kmsKey:           convert.ToValue(v.KMSKey),
			}
		}
	} else {
		out, err := svc.DescribeCachediSCSIVolumes(ctx, &storagegateway.DescribeCachediSCSIVolumesInput{VolumeARNs: arns})
		if err != nil {
			return nil, classifyAwsError(err, "storagegateway:DescribeCachediSCSIVolumes")
		}
		if len(out.CachediSCSIVolumes) > 0 {
			v := out.CachediSCSIVolumes[0]
			detail = &sgwVolumeDetail{
				status:           convert.ToValue(v.VolumeStatus),
				createdAt:        v.CreatedDate,
				sourceSnapshotId: convert.ToValue(v.SourceSnapshotId),
				kmsKey:           convert.ToValue(v.KMSKey),
			}
		}
	}

	a.fetched = true
	a.detail = detail
	return detail, nil
}

func (a *mqlAwsStoragegatewayVolume) status() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.status, nil
}

func (a *mqlAwsStoragegatewayVolume) createdAt() (*time.Time, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return d.createdAt, nil
}

func (a *mqlAwsStoragegatewayVolume) sourceSnapshotId() (string, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.sourceSnapshotId, nil
}

// encrypted reports whether the volume is encrypted at rest. Storage Gateway
// volumes support only SSE-KMS, and the SDK's CachediSCSIVolume /
// StorediSCSIVolume types expose only KMSKey — there is no KMSEncrypted bool or
// EncryptionType field as there is on the file-share types. KMSKey is populated
// whenever the volume is KMS-encrypted, so its presence is the canonical signal.
func (a *mqlAwsStoragegatewayVolume) encrypted() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.kmsKey != "", nil
}

func (a *mqlAwsStoragegatewayVolume) kmsKey() (*mqlAwsKmsKey, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || d.kmsKey == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringData(d.kmsKey)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ========================
// Helper functions
// ========================

func storageGatewayTagsToMap(tags []sgwtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t sgwtypes.Tag) *string { return t.Key }, func(t sgwtypes.Tag) *string { return t.Value })
}
