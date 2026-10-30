// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	datastream "cloud.google.com/go/datastream/apiv1"
	"cloud.google.com/go/datastream/apiv1/datastreampb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) datastream() (*mqlGcpProjectDatastreamService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.datastreamService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDatastreamService), nil
}

func initGcpProjectDatastreamService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectDatastreamService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/datastreamService", g.ProjectId.Data), nil
}

// =====================
// Stream
// =====================

func (g *mqlGcpProjectDatastreamServiceStream) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectDatastreamServiceStreamInternal struct {
	cacheKmsKey                 string
	cacheSourceProfileName      string
	cacheDestinationProfileName string
}

func (g *mqlGcpProjectDatastreamServiceStream) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKey == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKey)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectDatastreamServiceStream) source() (*mqlGcpProjectDatastreamServiceConnectionProfile, error) {
	return resolveDatastreamConnectionProfile(g.MqlRuntime, g.cacheSourceProfileName, &g.Source)
}

func (g *mqlGcpProjectDatastreamServiceStream) destination() (*mqlGcpProjectDatastreamServiceConnectionProfile, error) {
	return resolveDatastreamConnectionProfile(g.MqlRuntime, g.cacheDestinationProfileName, &g.Destination)
}

func resolveDatastreamConnectionProfile(runtime *plugin.Runtime, fullName string, slot *plugin.TValue[*mqlGcpProjectDatastreamServiceConnectionProfile]) (*mqlGcpProjectDatastreamServiceConnectionProfile, error) {
	if fullName == "" {
		slot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.datastreamService.connectionProfile",
		map[string]*llx.RawData{"name": llx.StringData(fullName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDatastreamServiceConnectionProfile), nil
}

func (g *mqlGcpProjectDatastreamService) streams() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListStreams(ctx, &datastreampb.ListStreamsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		stream, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		sourceProfileName := ""
		var sourceConfigDict map[string]any
		if stream.SourceConfig != nil {
			sourceProfileName = stream.SourceConfig.SourceConnectionProfile
			sourceConfigDict, err = protoToDict(stream.SourceConfig)
			if err != nil {
				return nil, err
			}
		}

		destProfileName := ""
		var destConfigDict map[string]any
		if stream.DestinationConfig != nil {
			destProfileName = stream.DestinationConfig.DestinationConnectionProfile
			destConfigDict, err = protoToDict(stream.DestinationConfig)
			if err != nil {
				return nil, err
			}
		}

		backfillStrategy := datastreamBackfillStrategy(stream)

		kmsKey := ""
		if stream.CustomerManagedEncryptionKey != nil {
			kmsKey = *stream.CustomerManagedEncryptionKey
		}

		errorRes, err := buildDatastreamStreamErrors(g.MqlRuntime, projectId, stream.Name, stream.Errors)
		if err != nil {
			return nil, err
		}

		var createTime, updateTime *llx.RawData
		if stream.CreateTime != nil {
			createTime = llx.TimeData(stream.CreateTime.AsTime())
		} else {
			createTime = llx.NilData
		}
		if stream.UpdateTime != nil {
			updateTime = llx.TimeData(stream.UpdateTime.AsTime())
		} else {
			updateTime = llx.NilData
		}

		mqlStream, err := CreateResource(g.MqlRuntime, "gcp.project.datastreamService.stream", map[string]*llx.RawData{
			"projectId":         llx.StringData(projectId),
			"name":              llx.StringData(stream.Name),
			"displayName":       llx.StringData(stream.DisplayName),
			"labels":            llx.MapData(convert.MapToInterfaceMap(stream.Labels), types.String),
			"state":             llx.StringData(stream.State.String()),
			"sourceConfig":      llx.DictData(sourceConfigDict),
			"destinationConfig": llx.DictData(destConfigDict),
			"backfillStrategy":  llx.StringData(backfillStrategy),
			"errors":            llx.ArrayData(errorRes, types.Resource("gcp.project.datastreamService.stream.error")),
			"satisfiesPzi":      llx.BoolDataPtr(stream.SatisfiesPzi),
			"satisfiesPzs":      llx.BoolDataPtr(stream.SatisfiesPzs),
			"createTime":        createTime,
			"updateTime":        updateTime,
		})
		if err != nil {
			return nil, err
		}
		mqlObj := mqlStream.(*mqlGcpProjectDatastreamServiceStream)
		mqlObj.cacheKmsKey = kmsKey
		mqlObj.cacheSourceProfileName = sourceProfileName
		mqlObj.cacheDestinationProfileName = destProfileName
		res = append(res, mqlObj)
	}

	return res, nil
}

func buildDatastreamStreamErrors(runtime *plugin.Runtime, projectId, streamName string, errs []*datastreampb.Error) ([]any, error) {
	res := make([]any, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var errorTime *llx.RawData
		if e.ErrorTime != nil {
			errorTime = llx.TimeData(e.ErrorTime.AsTime())
		} else {
			errorTime = llx.NilData
		}
		mqlErr, err := CreateResource(runtime, "gcp.project.datastreamService.stream.error", map[string]*llx.RawData{
			"projectId":  llx.StringData(projectId),
			"streamName": llx.StringData(streamName),
			"errorUuid":  llx.StringData(e.ErrorUuid),
			"reason":     llx.StringData(e.Reason),
			"message":    llx.StringData(e.Message),
			"errorTime":  errorTime,
			"details":    llx.MapData(convert.MapToInterfaceMap(e.Details), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlErr)
	}
	return res, nil
}

func (g *mqlGcpProjectDatastreamServiceStreamError) id() (string, error) {
	if g.StreamName.Error != nil {
		return "", g.StreamName.Error
	}
	if g.ErrorUuid.Error != nil {
		return "", g.ErrorUuid.Error
	}
	return fmt.Sprintf("%s/errors/%s", g.StreamName.Data, g.ErrorUuid.Data), nil
}

// =====================
// ConnectionProfile
// =====================

func (g *mqlGcpProjectDatastreamServiceConnectionProfile) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectDatastreamServiceConnectionProfileInternal struct {
	cacheGcsBucket             string
	cachePrivateConnectionName string
}

func (g *mqlGcpProjectDatastreamServiceConnectionProfile) bucket() (*mqlGcpProjectStorageServiceBucket, error) {
	if g.cacheGcsBucket == "" {
		g.Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.storageService.bucket",
		map[string]*llx.RawData{"name": llx.StringData(g.cacheGcsBucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}

func (g *mqlGcpProjectDatastreamServiceConnectionProfile) privateConnection() (*mqlGcpProjectDatastreamServicePrivateConnection, error) {
	if g.cachePrivateConnectionName == "" {
		g.PrivateConnection.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.datastreamService.privateConnection",
		map[string]*llx.RawData{"name": llx.StringData(g.cachePrivateConnectionName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDatastreamServicePrivateConnection), nil
}

func initGcpProjectDatastreamServiceConnectionProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args == nil {
		args = make(map[string]*llx.RawData)
	}

	// Resolve from the asset identifier when accessed as a discovered
	// gcp-datastream-connectionprofile asset (no explicit name arg).
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(fmt.Sprintf("projects/%s/locations/%s/connectionProfiles/%s", ids.project, ids.region, ids.name))
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.datastreamService.connectionProfile requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.datastreamService.connectionProfile requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, conn.ResourceID(), service_datastream); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Datastream API is not enabled on project " + conn.ResourceID())
	}

	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	cp, err := client.GetConnectionProfile(ctx, &datastreampb.GetConnectionProfileRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlConnectionProfileFromProto(runtime, conn.ResourceID(), cp)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (g *mqlGcpProjectDatastreamService) connectionProfiles() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListConnectionProfiles(ctx, &datastreampb.ListConnectionProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		cp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlCp, err := mqlConnectionProfileFromProto(g.MqlRuntime, projectId, cp)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCp)
	}

	return res, nil
}

func mqlConnectionProfileFromProto(runtime *plugin.Runtime, projectId string, cp *datastreampb.ConnectionProfile) (*mqlGcpProjectDatastreamServiceConnectionProfile, error) {
	profileType, profileDict, gcsBucket, err := datastreamProfileToDict(cp)
	if err != nil {
		return nil, err
	}
	connectivityType, connectivityDict, privateConnName, err := datastreamConnectivityToDict(cp)
	if err != nil {
		return nil, err
	}

	var createTime, updateTime *llx.RawData
	if cp.CreateTime != nil {
		createTime = llx.TimeData(cp.CreateTime.AsTime())
	} else {
		createTime = llx.NilData
	}
	if cp.UpdateTime != nil {
		updateTime = llx.TimeData(cp.UpdateTime.AsTime())
	} else {
		updateTime = llx.NilData
	}

	res, err := CreateResource(runtime, "gcp.project.datastreamService.connectionProfile", map[string]*llx.RawData{
		"projectId":        llx.StringData(projectId),
		"name":             llx.StringData(cp.Name),
		"displayName":      llx.StringData(cp.DisplayName),
		"labels":           llx.MapData(convert.MapToInterfaceMap(cp.Labels), types.String),
		"profileType":      llx.StringData(profileType),
		"profile":          llx.DictData(profileDict),
		"connectivityType": llx.StringData(connectivityType),
		"connectivity":     llx.DictData(connectivityDict),
		"satisfiesPzi":     llx.BoolDataPtr(cp.SatisfiesPzi),
		"satisfiesPzs":     llx.BoolDataPtr(cp.SatisfiesPzs),
		"createTime":       createTime,
		"updateTime":       updateTime,
	})
	if err != nil {
		return nil, err
	}
	mqlCp := res.(*mqlGcpProjectDatastreamServiceConnectionProfile)
	mqlCp.cacheGcsBucket = gcsBucket
	mqlCp.cachePrivateConnectionName = privateConnName
	return mqlCp, nil
}

// datastreamBackfillStrategy returns the backfill-strategy discriminator string
// for a Stream: "all", "none", or "" if the oneof is unset.
func datastreamBackfillStrategy(s *datastreampb.Stream) string {
	if s == nil {
		return ""
	}
	switch s.BackfillStrategy.(type) {
	case *datastreampb.Stream_BackfillAll:
		return "all"
	case *datastreampb.Stream_BackfillNone:
		return "none"
	}
	return ""
}

// datastreamProfileToDict resolves the profile oneof on a ConnectionProfile.
// Returns the profile type discriminator, a dict of the profile fields, and the GCS bucket name (empty string if not a GCS profile).
func datastreamProfileToDict(cp *datastreampb.ConnectionProfile) (string, map[string]any, string, error) {
	switch p := cp.Profile.(type) {
	case *datastreampb.ConnectionProfile_OracleProfile:
		d, err := protoToDict(p.OracleProfile)
		return "oracle", d, "", err
	case *datastreampb.ConnectionProfile_MysqlProfile:
		d, err := protoToDict(p.MysqlProfile)
		return "mysql", d, "", err
	case *datastreampb.ConnectionProfile_PostgresqlProfile:
		d, err := protoToDict(p.PostgresqlProfile)
		return "postgresql", d, "", err
	case *datastreampb.ConnectionProfile_SqlServerProfile:
		d, err := protoToDict(p.SqlServerProfile)
		return "sqlserver", d, "", err
	case *datastreampb.ConnectionProfile_MongodbProfile:
		d, err := protoToDict(p.MongodbProfile)
		return "mongodb", d, "", err
	case *datastreampb.ConnectionProfile_BigqueryProfile:
		d, err := protoToDict(p.BigqueryProfile)
		return "bigquery", d, "", err
	case *datastreampb.ConnectionProfile_GcsProfile:
		d, err := protoToDict(p.GcsProfile)
		bucket := ""
		if p.GcsProfile != nil {
			bucket = p.GcsProfile.Bucket
		}
		return "gcs", d, bucket, err
	case *datastreampb.ConnectionProfile_SalesforceProfile:
		d, err := protoToDict(p.SalesforceProfile)
		return "salesforce", d, "", err
	}
	return "", nil, "", nil
}

// datastreamConnectivityToDict resolves the connectivity oneof on a ConnectionProfile.
// Returns the connectivity type discriminator, a dict of the connectivity fields, and the resolved private-connection resource name (empty unless privateConnectivity).
func datastreamConnectivityToDict(cp *datastreampb.ConnectionProfile) (string, map[string]any, string, error) {
	switch c := cp.Connectivity.(type) {
	case *datastreampb.ConnectionProfile_StaticServiceIpConnectivity:
		d, err := protoToDict(c.StaticServiceIpConnectivity)
		return "staticServiceIp", d, "", err
	case *datastreampb.ConnectionProfile_ForwardSshConnectivity:
		d, err := protoToDict(c.ForwardSshConnectivity)
		return "forwardSsh", d, "", err
	case *datastreampb.ConnectionProfile_PrivateConnectivity:
		d, err := protoToDict(c.PrivateConnectivity)
		name := ""
		if c.PrivateConnectivity != nil {
			name = c.PrivateConnectivity.PrivateConnection
		}
		return "privateConnectivity", d, name, err
	}
	return "", nil, "", nil
}

// =====================
// PrivateConnection
// =====================

func (g *mqlGcpProjectDatastreamServicePrivateConnection) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectDatastreamServicePrivateConnectionInternal struct {
	cacheVpcNetwork string
}

func (g *mqlGcpProjectDatastreamServicePrivateConnection) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheVpcNetwork == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheVpcNetwork, g.MqlRuntime)
}

func initGcpProjectDatastreamServicePrivateConnection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.datastreamService.privateConnection requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.datastreamService.privateConnection requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, conn.ResourceID(), service_datastream); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Datastream API is not enabled on project " + conn.ResourceID())
	}

	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	pc, err := client.GetPrivateConnection(ctx, &datastreampb.GetPrivateConnectionRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlPrivateConnectionFromProto(runtime, conn.ResourceID(), pc)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (g *mqlGcpProjectDatastreamService) privateConnections() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListPrivateConnections(ctx, &datastreampb.ListPrivateConnectionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		pc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlPc, err := mqlPrivateConnectionFromProto(g.MqlRuntime, projectId, pc)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPc)
	}

	return res, nil
}

func mqlPrivateConnectionFromProto(runtime *plugin.Runtime, projectId string, pc *datastreampb.PrivateConnection) (*mqlGcpProjectDatastreamServicePrivateConnection, error) {
	errDict, err := protoToDict(pc.Error)
	if err != nil {
		return nil, err
	}

	vpcNetwork := ""
	subnet := ""
	if pc.VpcPeeringConfig != nil {
		vpcNetwork = pc.VpcPeeringConfig.Vpc
		subnet = pc.VpcPeeringConfig.Subnet
	}

	var createTime, updateTime *llx.RawData
	if pc.CreateTime != nil {
		createTime = llx.TimeData(pc.CreateTime.AsTime())
	} else {
		createTime = llx.NilData
	}
	if pc.UpdateTime != nil {
		updateTime = llx.TimeData(pc.UpdateTime.AsTime())
	} else {
		updateTime = llx.NilData
	}

	res, err := CreateResource(runtime, "gcp.project.datastreamService.privateConnection", map[string]*llx.RawData{
		"projectId":   llx.StringData(projectId),
		"name":        llx.StringData(pc.Name),
		"displayName": llx.StringData(pc.DisplayName),
		"labels":      llx.MapData(convert.MapToInterfaceMap(pc.Labels), types.String),
		"state":       llx.StringData(pc.State.String()),
		"error":       llx.DictData(errDict),
		"subnet":      llx.StringData(subnet),
		"createTime":  createTime,
		"updateTime":  updateTime,
	})
	if err != nil {
		return nil, err
	}
	mqlPc := res.(*mqlGcpProjectDatastreamServicePrivateConnection)
	mqlPc.cacheVpcNetwork = vpcNetwork
	return mqlPc, nil
}

// =====================
// Route (child of PrivateConnection)
// =====================

func (g *mqlGcpProjectDatastreamServicePrivateConnection) routes() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	pcName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(datastream.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := datastream.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListRoutes(ctx, &datastreampb.ListRoutesRequest{
		Parent: pcName,
	})

	var res []any
	for {
		route, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var createTime, updateTime *llx.RawData
		if route.CreateTime != nil {
			createTime = llx.TimeData(route.CreateTime.AsTime())
		} else {
			createTime = llx.NilData
		}
		if route.UpdateTime != nil {
			updateTime = llx.TimeData(route.UpdateTime.AsTime())
		} else {
			updateTime = llx.NilData
		}

		mqlRoute, err := CreateResource(g.MqlRuntime, "gcp.project.datastreamService.route", map[string]*llx.RawData{
			"projectId":             llx.StringData(projectId),
			"name":                  llx.StringData(route.Name),
			"displayName":           llx.StringData(route.DisplayName),
			"labels":                llx.MapData(convert.MapToInterfaceMap(route.Labels), types.String),
			"privateConnectionName": llx.StringData(pcName),
			"destinationAddress":    llx.StringData(route.DestinationAddress),
			"destinationPort":       llx.IntData(int64(route.DestinationPort)),
			"createTime":            createTime,
			"updateTime":            updateTime,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRoute)
	}

	return res, nil
}

func (g *mqlGcpProjectDatastreamServiceRoute) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}
