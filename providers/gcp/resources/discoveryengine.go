// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	discoveryengine "cloud.google.com/go/discoveryengine/apiv1"
	"cloud.google.com/go/discoveryengine/apiv1/discoveryenginepb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// discoveryEngineLocations lists the Discovery Engine multi-region locations.
// Unlike Vertex AI, Discovery Engine resources live in these three locations
// only. See https://docs.cloud.google.com/generative-ai-app-builder/docs/locations
var discoveryEngineLocations = []string{"global", "us", "eu"}

// defaultDiscoveryEngineCollection is the built-in collection that hosts data
// stores and engines. The API has no method to enumerate collections, so we
// scan the default collection that the console and most deployments use.
const defaultDiscoveryEngineCollection = "default_collection"

// discoveryEngineEndpoint returns the regional API endpoint for a location.
func discoveryEngineEndpoint(location string) string {
	if location == "global" {
		return "discoveryengine.googleapis.com:443"
	}
	return fmt.Sprintf("%s-discoveryengine.googleapis.com:443", location)
}

// discoveryEngineLocationFromName extracts the location from a Discovery Engine
// resource name of the form projects/{project}/locations/{location}/....
func discoveryEngineLocationFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProject) discoveryEngine() (*mqlGcpProjectDiscoveryEngineService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.discoveryEngineService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDiscoveryEngineService), nil
}

func initGcpProjectDiscoveryEngineService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectDiscoveryEngineService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/discoveryEngineService", g.ProjectId.Data), nil
}

// newMqlDiscoveryEngineDataStore maps a Discovery Engine DataStore proto into an
// MQL resource. Shared by the dataStores() lister and engine.dataStores().
func newMqlDiscoveryEngineDataStore(runtime *plugin.Runtime, ds *discoveryenginepb.DataStore) (*mqlGcpProjectDiscoveryEngineServiceDataStore, error) {
	solutionTypes := make([]any, 0, len(ds.SolutionTypes))
	for _, st := range ds.SolutionTypes {
		solutionTypes = append(solutionTypes, st.String())
	}

	res, err := CreateResource(runtime, "gcp.project.discoveryEngineService.dataStore", map[string]*llx.RawData{
		"name":             llx.StringData(ds.Name),
		"displayName":      llx.StringData(ds.DisplayName),
		"industryVertical": llx.StringData(ds.IndustryVertical.String()),
		"solutionTypes":    llx.ArrayData(solutionTypes, types.String),
		"contentConfig":    llx.StringData(ds.ContentConfig.String()),
		"defaultSchemaId":  llx.StringData(ds.DefaultSchemaId),
		"aclEnabled":       llx.BoolData(ds.AclEnabled),
		"kmsKeyName":       llx.StringData(ds.KmsKeyName),
		"createdAt":        llx.TimeDataPtr(timestampAsTimePtr(ds.CreateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlDs := res.(*mqlGcpProjectDiscoveryEngineServiceDataStore)
	mqlDs.cacheKmsKeyName = ds.KmsKeyName
	return mqlDs, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) listDataStoresInLocation(ctx context.Context, creds *googleoauth.Credentials, projectId, location string) ([]any, error) {
	client, err := discoveryengine.NewDataStoreClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListDataStores(ctx, &discoveryenginepb.ListDataStoresRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/collections/%s", projectId, location, defaultDiscoveryEngineCollection),
	})
	for {
		ds, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}
		mqlDs, err := newMqlDiscoveryEngineDataStore(g.MqlRuntime, ds)
		if err != nil {
			return nil, err
		}
		items = append(items, mqlDs)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) dataStores() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var items []any
	for _, location := range discoveryEngineLocations {
		locationItems, err := g.listDataStoresInLocation(ctx, creds, projectId, location)
		if err != nil {
			return nil, err
		}
		items = append(items, locationItems...)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceDataStore) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDiscoveryEngineServiceDataStoreInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectDiscoveryEngineServiceDataStore) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (g *mqlGcpProjectDiscoveryEngineService) listEnginesInLocation(ctx context.Context, creds *googleoauth.Credentials, projectId, location string) ([]any, error) {
	client, err := discoveryengine.NewEngineClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListEngines(ctx, &discoveryenginepb.ListEnginesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/collections/%s", projectId, location, defaultDiscoveryEngineCollection),
	})
	for {
		engine, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}

		mqlEngine, err := CreateResource(g.MqlRuntime, "gcp.project.discoveryEngineService.engine", map[string]*llx.RawData{
			"name":             llx.StringData(engine.Name),
			"displayName":      llx.StringData(engine.DisplayName),
			"solutionType":     llx.StringData(engine.SolutionType.String()),
			"industryVertical": llx.StringData(engine.IndustryVertical.String()),
			"disableAnalytics": llx.BoolData(engine.DisableAnalytics),
			"createdAt":        llx.TimeDataPtr(timestampAsTimePtr(engine.CreateTime)),
			"updatedAt":        llx.TimeDataPtr(timestampAsTimePtr(engine.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlEngine.(*mqlGcpProjectDiscoveryEngineServiceEngine).cacheDataStoreIds = engine.DataStoreIds
		items = append(items, mqlEngine)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) engines() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var items []any
	for _, location := range discoveryEngineLocations {
		locationItems, err := g.listEnginesInLocation(ctx, creds, projectId, location)
		if err != nil {
			return nil, err
		}
		items = append(items, locationItems...)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDiscoveryEngineServiceEngineInternal struct {
	cacheDataStoreIds []string
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) dataStores() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	if len(g.cacheDataStoreIds) == 0 {
		return []any{}, nil
	}

	engineName := g.Name.Data
	location := discoveryEngineLocationFromName(engineName)
	// The collection parent is the engine name up to and excluding "/engines/...".
	collectionParent := engineName
	if idx := strings.Index(engineName, "/engines/"); idx >= 0 {
		collectionParent = engineName[:idx]
	}
	if location == "" || collectionParent == engineName {
		return []any{}, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := discoveryengine.NewDataStoreClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	items := make([]any, 0, len(g.cacheDataStoreIds))
	for _, id := range g.cacheDataStoreIds {
		ds, err := client.GetDataStore(ctx, &discoveryenginepb.GetDataStoreRequest{
			Name: fmt.Sprintf("%s/dataStores/%s", collectionParent, id),
		})
		if err != nil {
			if isInapplicable(err) {
				continue
			}
			return nil, err
		}
		mqlDs, err := newMqlDiscoveryEngineDataStore(g.MqlRuntime, ds)
		if err != nil {
			return nil, err
		}
		items = append(items, mqlDs)
	}
	return items, nil
}
