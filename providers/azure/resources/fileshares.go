// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/fileshares/armfileshares"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionFileSharesServiceFileShareInternal struct {
	cacheSystemData          any
	cacheAllowedSubnetIds    []string
	cachePrivateEndpointConn []*armfileshares.PrivateEndpointConnection
}

type mqlAzureSubscriptionFileSharesServiceFileShareSnapshotInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionFileSharesService) id() (string, error) {
	return "azure.subscription.fileSharesService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionFileSharesService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShare) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionFileSharesServiceFileShare(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionFileSharesService,
		func(s *mqlAzureSubscriptionFileSharesService) *plugin.TValue[[]any] { return s.GetFileShares() },
		ResourceAzureSubscriptionFileSharesServiceFileShare)
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShareSnapshot) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShare) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShareSnapshot) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShare) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConn)
}

func (a *mqlAzureSubscriptionFileSharesService) fileShares() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armfileshares.NewClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, share := range page.Value {
			if share == nil {
				continue
			}
			mqlShare, err := createFileShareResource(a.MqlRuntime, share)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlShare)
		}
	}
	return res, nil
}

// fileShareAllowedSubnetIds lists the subnets a share admits when its public
// endpoint is restricted.
//
// An unrestricted share reports no subnets at all, which is not the same as
// admitting none: it leaves the endpoint open to whatever can reach it. The
// empty list is what the caller reads for that, so nil entries are dropped
// rather than becoming empty strings that would resolve to nothing.
func fileShareAllowedSubnetIds(access *armfileshares.PublicAccessProperties) []string {
	if access == nil {
		return nil
	}
	res := make([]string, 0, len(access.AllowedSubnets))
	for _, subnet := range access.AllowedSubnets {
		if subnet == nil || *subnet == "" {
			continue
		}
		res = append(res, *subnet)
	}
	return res
}

// fileShareNfsProtocol reads the two NFS protections off a share. A share that
// states neither reports both as empty rather than as disabled, so a check can
// tell an unset share from one configured without them.
func fileShareNfsProtocol(props *armfileshares.NfsProtocolProperties) (encryptionInTransitRequired string, rootSquash string) {
	if props == nil {
		return "", ""
	}
	return enumString(props.EncryptionInTransitRequired), enumString(props.RootSquash)
}

// fileShareSnapshotTime parses the snapshot timestamp.
//
// This resource provider reports it as a string where the classic share
// reports a time. Parsing it here keeps a retention query readable the same way
// across both kinds of share, instead of making one of them compare text.
//
// Azure writes seven fractional digits ("2026-03-15T08:12:34.0000000Z"). The
// RFC3339 layout carries no fractional part, but time.Parse accepts one after
// the seconds field regardless, so both that form and a bare
// "2026-03-15T08:12:34Z" parse, and the digits are kept rather than truncated.
//
// A value that will not parse reports as null rather than failing the listing:
// the resource provider is new and its timestamp format is not pinned by the
// SDK, and one unreadable timestamp should not take the share's other fields
// with it. The raw value is logged so the format can be chased if it happens.
func fileShareSnapshotTime(raw *string) *time.Time {
	if raw == nil || *raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		log.Warn().Str("snapshotTime", *raw).Msg("could not parse file share snapshot time, reporting it as null")
		return nil
	}
	return &parsed
}

func createFileShareResource(runtime *plugin.Runtime, share *armfileshares.FileShare) (*mqlAzureSubscriptionFileSharesServiceFileShare, error) {
	props := share.Properties
	if props == nil {
		props = &armfileshares.FileShareProperties{}
	}

	encryptionInTransitRequired, rootSquash := fileShareNfsProtocol(props.NfsProtocolProperties)

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionFileSharesServiceFileShare,
		map[string]*llx.RawData{
			"id":                          llx.StringDataPtr(share.ID),
			"name":                        llx.StringDataPtr(share.Name),
			"location":                    llx.StringDataPtr(share.Location),
			"type":                        llx.StringDataPtr(share.Type),
			"tags":                        llx.MapData(convert.PtrMapStrToInterface(share.Tags), types.String),
			"provisioningState":           llx.StringData(enumString(props.ProvisioningState)),
			"protocol":                    llx.StringData(enumString(props.Protocol)),
			"mountName":                   llx.StringDataPtr(props.MountName),
			"hostName":                    llx.StringDataPtr(props.HostName),
			"mediaTier":                   llx.StringData(enumString(props.MediaTier)),
			"redundancy":                  llx.StringData(enumString(props.Redundancy)),
			"publicNetworkAccess":         llx.StringData(enumString(props.PublicNetworkAccess)),
			"encryptionInTransitRequired": llx.StringData(encryptionInTransitRequired),
			"rootSquash":                  llx.StringData(rootSquash),
			// Carried through as pointers rather than dereferenced: a share
			// that reports no provisioning is not a share provisioned at
			// zero, and llx.IntDataPtr turns the nil into null.
			"provisionedStorageGiB":          llx.IntDataPtr(props.ProvisionedStorageGiB),
			"provisionedIoPerSec":            llx.IntDataPtr(props.ProvisionedIOPerSec),
			"provisionedThroughputMibPerSec": llx.IntDataPtr(props.ProvisionedThroughputMiBPerSec),
			"includedBurstIoPerSec":          llx.IntDataPtr(props.IncludedBurstIOPerSec),
			"maxBurstIoPerSecCredits":        llx.IntDataPtr(props.MaxBurstIOPerSecCredits),
		})
	if err != nil {
		return nil, err
	}

	mqlShare := resource.(*mqlAzureSubscriptionFileSharesServiceFileShare)
	mqlShare.cacheAllowedSubnetIds = fileShareAllowedSubnetIds(props.PublicAccessProperties)
	mqlShare.cachePrivateEndpointConn = props.PrivateEndpointConnections

	sysData, err := convert.JsonToDict(share.SystemData)
	if err != nil {
		return nil, err
	}
	mqlShare.cacheSystemData = sysData

	return mqlShare, nil
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShare) allowedSubnets() ([]any, error) {
	res := make([]any, 0, len(a.cacheAllowedSubnetIds))
	for _, id := range a.cacheAllowedSubnetIds {
		subnet, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, subnet)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionFileSharesServiceFileShare) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	shareName, err := parsed.Component("fileShares")
	if err != nil {
		return nil, err
	}

	client, err := armfileshares.NewFileShareSnapshotsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByFileSharePager(parsed.ResourceGroup, shareName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range page.Value {
			if snapshot == nil {
				continue
			}
			snapProps := snapshot.Properties
			if snapProps == nil {
				snapProps = &armfileshares.FileShareSnapshotProperties{}
			}

			mqlSnapshot, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionFileSharesServiceFileShareSnapshot,
				map[string]*llx.RawData{
					"id":           llx.StringDataPtr(snapshot.ID),
					"name":         llx.StringDataPtr(snapshot.Name),
					"type":         llx.StringDataPtr(snapshot.Type),
					"snapshotTime": llx.TimeDataPtr(fileShareSnapshotTime(snapProps.SnapshotTime)),
					"initiatorId":  llx.StringDataPtr(snapProps.InitiatorID),
					"metadata":     llx.MapData(convert.PtrMapStrToInterface(snapProps.Metadata), types.String),
				})
			if err != nil {
				return nil, err
			}

			sysData, err := convert.JsonToDict(snapshot.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSnapshot.(*mqlAzureSubscriptionFileSharesServiceFileShareSnapshot).cacheSystemData = sysData
			res = append(res, mqlSnapshot)
		}
	}
	return res, nil
}
