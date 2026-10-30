// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	cosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v4"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) id() (string, error) {
	return a.Id.Data, nil
}

// cosmosAccountResourceGroup parses {subscriptionID, resourceGroup, accountName}
// from a Cosmos account ARM id in a single ParseResourceID call.
func cosmosAccountResourceGroup(accountId string) (string, string, string, error) {
	parsed, err := ParseResourceID(accountId)
	if err != nil {
		return "", "", "", err
	}
	name, err := parsed.Component("databaseAccounts")
	if err != nil {
		return "", "", "", err
	}
	return parsed.SubscriptionID, parsed.ResourceGroup, name, nil
}

// cosmosSqlDatabaseScope parses {subscriptionID, resourceGroup, accountName,
// databaseName} from a SQL database (or container) ARM id.
func cosmosSqlDatabaseScope(id string) (string, string, string, string, error) {
	parsed, err := ParseResourceID(id)
	if err != nil {
		return "", "", "", "", err
	}
	account, err := parsed.Component("databaseAccounts")
	if err != nil {
		return "", "", "", "", err
	}
	db, err := parsed.Component("sqlDatabases")
	if err != nil {
		return "", "", "", "", err
	}
	return parsed.SubscriptionID, parsed.ResourceGroup, account, db, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) sqlDatabases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId, rg, accountName, err := cosmosAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	dbClient, err := cosmos.NewSQLResourcesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := dbClient.NewListSQLDatabasesPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isCosmosForbiddenError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, db := range page.Value {
			if db == nil {
				continue
			}
			mqlDb, err := sqlDatabaseToMQL(a.MqlRuntime, db)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDb)
		}
	}
	return res, nil
}

func sqlDatabaseToMQL(runtime *plugin.Runtime, db *cosmos.SQLDatabaseGetResults) (plugin.Resource, error) {
	var dbName, etag string
	if db.Properties != nil && db.Properties.Resource != nil {
		if db.Properties.Resource.ID != nil {
			dbName = *db.Properties.Resource.ID
		}
		if db.Properties.Resource.Etag != nil {
			etag = *db.Properties.Resource.Etag
		}
	}
	if dbName == "" && db.Name != nil {
		dbName = *db.Name
	}

	res, err := CreateResource(runtime, "azure.subscription.cosmosDbService.account.sqlDatabase",
		map[string]*llx.RawData{
			"id":   llx.StringDataPtr(db.ID),
			"name": llx.StringData(dbName),
			"type": llx.StringDataPtr(db.Type),
			"etag": llx.StringData(etag),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(db.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase).cacheSystemData = sysData
	return res, nil
}

// throughputCache is a one-shot fetch result used by both the database and
// container resources to share a single GetSQL{Database,Container}Throughput
// call across the four lazy throughput methods.
type throughputCache struct {
	manual     int32
	autoMax    int32
	autoEn     bool
	sharedAway bool

	fetched atomic.Bool
	lock    sync.Mutex
}

type mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseInternal struct {
	throughput      throughputCache
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainerInternal struct {
	throughput      throughputCache
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) loadThroughput() error {
	if a.throughput.fetched.Load() {
		return nil
	}
	a.throughput.lock.Lock()
	defer a.throughput.lock.Unlock()
	if a.throughput.fetched.Load() {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId, rg, account, err := cosmosAccountResourceGroup(a.Id.Data)
	if err != nil {
		return err
	}
	client, err := cosmos.NewSQLResourcesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return err
	}
	a.throughput.manual, a.throughput.autoMax, a.throughput.autoEn, a.throughput.sharedAway =
		fetchSqlDatabaseThroughput(ctx, client, rg, account, a.Name.Data)
	a.throughput.fetched.Store(true)
	return nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) throughputPerContainer() (bool, error) {
	if err := a.loadThroughput(); err != nil {
		return false, err
	}
	return a.throughput.sharedAway, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) manualThroughput() (int64, error) {
	if err := a.loadThroughput(); err != nil {
		return 0, err
	}
	return int64(a.throughput.manual), nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) autoscaleMaxThroughput() (int64, error) {
	if err := a.loadThroughput(); err != nil {
		return 0, err
	}
	return int64(a.throughput.autoMax), nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) autoscaleEnabled() (bool, error) {
	if err := a.loadThroughput(); err != nil {
		return false, err
	}
	return a.throughput.autoEn, nil
}

// fetchSqlDatabaseThroughput resolves the database-level throughput offer.
// Returns (manualTP, autoscaleMax, autoscaleEnabled, sharedAcrossContainers).
// Cosmos returns 404 when the offer doesn't exist at this scope (i.e., throughput
// is configured per-container instead) — that case is reported as `shared = true`.
func fetchSqlDatabaseThroughput(ctx context.Context, dbClient *cosmos.SQLResourcesClient, rg, accountName, dbName string) (int32, int32, bool, bool) {
	resp, err := dbClient.GetSQLDatabaseThroughput(ctx, rg, accountName, dbName, nil)
	if err != nil {
		if isCosmosNotFoundError(err) {
			return 0, 0, false, true
		}
		if isCosmosServerlessThroughputError(err) {
			// Serverless accounts have no throughput offer — quietly return
			// zeros rather than logging on every query.
			return 0, 0, false, false
		}
		// Real failures (rate limits, network timeouts, 5xx) shouldn't read as
		// "no offer" — log so operators can correlate empty-throughput rows
		// with API errors. The default zero-value return is preserved so the
		// rest of the database row still renders.
		log.Warn().Err(err).Str("account", accountName).Str("database", dbName).
			Msg("failed to fetch Cosmos DB SQL database throughput")
		return 0, 0, false, false
	}
	return throughputFromResource(resp.Properties)
}

func fetchSqlContainerThroughput(ctx context.Context, dbClient *cosmos.SQLResourcesClient, rg, accountName, dbName, containerName string) (int32, int32, bool, bool) {
	resp, err := dbClient.GetSQLContainerThroughput(ctx, rg, accountName, dbName, containerName, nil)
	if err != nil {
		if isCosmosNotFoundError(err) {
			return 0, 0, false, true
		}
		if isCosmosServerlessThroughputError(err) {
			return 0, 0, false, false
		}
		log.Warn().Err(err).Str("account", accountName).Str("database", dbName).Str("container", containerName).
			Msg("failed to fetch Cosmos DB SQL container throughput")
		return 0, 0, false, false
	}
	return throughputFromResource(resp.Properties)
}

// throughputFromResource picks apart a Cosmos throughput offer into the four
// fields we surface: manual provisioned throughput, autoscale max throughput,
// autoscale-enabled flag, and a shared flag (always false when an offer exists
// at this scope; only the 404 path sets shared = true).
func throughputFromResource(props *cosmos.ThroughputSettingsGetProperties) (int32, int32, bool, bool) {
	if props == nil || props.Resource == nil {
		return 0, 0, false, false
	}
	r := props.Resource
	var manual, autoscale int32
	autoEnabled := false
	if r.Throughput != nil {
		manual = *r.Throughput
	}
	if r.AutoscaleSettings != nil && r.AutoscaleSettings.MaxThroughput != nil {
		autoscale = *r.AutoscaleSettings.MaxThroughput
		autoEnabled = true
	}
	return manual, autoscale, autoEnabled, false
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabase) containers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId, rg, accountName, dbName, err := cosmosSqlDatabaseScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	dbClient, err := cosmos.NewSQLResourcesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := dbClient.NewListSQLContainersPager(rg, accountName, dbName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isCosmosForbiddenError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			mqlC, err := sqlContainerToMQL(a.MqlRuntime, c)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlC)
		}
	}
	return res, nil
}

func sqlContainerToMQL(runtime *plugin.Runtime, c *cosmos.SQLContainerGetResults) (plugin.Resource, error) {
	var name, etag, partitionKeyKind, indexingMode, conflictMode, conflictPath string
	// SDK type difference: DefaultTTL is *int32, AnalyticalStorageTTL is *int64.
	// Both surface as int64 on the resource, so widen DefaultTTL with int64(...).
	var defaultTtl, analyticalTtl int64
	autoIndex := false
	partitionKeyPaths := []any{}
	uniqueKeys := []any{}

	if c.Properties != nil && c.Properties.Resource != nil {
		r := c.Properties.Resource
		if r.ID != nil {
			name = *r.ID
		}
		if r.Etag != nil {
			etag = *r.Etag
		}
		if r.DefaultTTL != nil {
			defaultTtl = int64(*r.DefaultTTL)
		}
		if r.AnalyticalStorageTTL != nil {
			analyticalTtl = *r.AnalyticalStorageTTL
		}
		if r.PartitionKey != nil {
			if r.PartitionKey.Kind != nil {
				partitionKeyKind = string(*r.PartitionKey.Kind)
			}
			for _, p := range r.PartitionKey.Paths {
				if p != nil {
					partitionKeyPaths = append(partitionKeyPaths, *p)
				}
			}
		}
		if r.IndexingPolicy != nil {
			if r.IndexingPolicy.IndexingMode != nil {
				indexingMode = string(*r.IndexingPolicy.IndexingMode)
			}
			if r.IndexingPolicy.Automatic != nil {
				autoIndex = *r.IndexingPolicy.Automatic
			}
		}
		if r.ConflictResolutionPolicy != nil {
			if r.ConflictResolutionPolicy.Mode != nil {
				conflictMode = string(*r.ConflictResolutionPolicy.Mode)
			}
			if r.ConflictResolutionPolicy.ConflictResolutionPath != nil {
				conflictPath = *r.ConflictResolutionPolicy.ConflictResolutionPath
			}
		}
		if r.UniqueKeyPolicy != nil {
			for _, uk := range r.UniqueKeyPolicy.UniqueKeys {
				if uk == nil {
					continue
				}
				paths := []any{}
				for _, p := range uk.Paths {
					if p != nil {
						paths = append(paths, *p)
					}
				}
				uniqueKeys = append(uniqueKeys, map[string]any{"paths": paths})
			}
		}
	}
	if name == "" && c.Name != nil {
		name = *c.Name
	}

	res, err := CreateResource(runtime, "azure.subscription.cosmosDbService.account.sqlDatabase.container",
		map[string]*llx.RawData{
			"id":                     llx.StringDataPtr(c.ID),
			"name":                   llx.StringData(name),
			"type":                   llx.StringDataPtr(c.Type),
			"etag":                   llx.StringData(etag),
			"partitionKeyPaths":      llx.ArrayData(partitionKeyPaths, types.String),
			"partitionKeyKind":       llx.StringData(partitionKeyKind),
			"defaultTtl":             llx.IntData(defaultTtl),
			"analyticalStorageTtl":   llx.IntData(analyticalTtl),
			"indexingMode":           llx.StringData(indexingMode),
			"automaticIndexing":      llx.BoolData(autoIndex),
			"uniqueKeys":             llx.ArrayData(uniqueKeys, types.Dict),
			"conflictResolutionMode": llx.StringData(conflictMode),
			"conflictResolutionPath": llx.StringData(conflictPath),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(c.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer).cacheSystemData = sysData
	return res, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) loadThroughput() error {
	if a.throughput.fetched.Load() {
		return nil
	}
	a.throughput.lock.Lock()
	defer a.throughput.lock.Unlock()
	if a.throughput.fetched.Load() {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId, rg, account, dbName, err := cosmosSqlDatabaseScope(a.Id.Data)
	if err != nil {
		return err
	}
	client, err := cosmos.NewSQLResourcesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return err
	}
	a.throughput.manual, a.throughput.autoMax, a.throughput.autoEn, a.throughput.sharedAway =
		fetchSqlContainerThroughput(ctx, client, rg, account, dbName, a.Name.Data)
	a.throughput.fetched.Store(true)
	return nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) throughputInherited() (bool, error) {
	if err := a.loadThroughput(); err != nil {
		return false, err
	}
	return a.throughput.sharedAway, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) manualThroughput() (int64, error) {
	if err := a.loadThroughput(); err != nil {
		return 0, err
	}
	return int64(a.throughput.manual), nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) autoscaleMaxThroughput() (int64, error) {
	if err := a.loadThroughput(); err != nil {
		return 0, err
	}
	return int64(a.throughput.autoMax), nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlDatabaseContainer) autoscaleEnabled() (bool, error) {
	if err := a.loadThroughput(); err != nil {
		return false, err
	}
	return a.throughput.autoEn, nil
}

// isCosmosNotFoundError reports whether err is a Cosmos throughput 404. Used
// to distinguish "no offer at this scope" (database/container has shared
// throughput) from real errors.
func isCosmosNotFoundError(err error) bool {
	if rerr, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return rerr.StatusCode == http.StatusNotFound
	}
	return false
}

// isCosmosServerlessThroughputError reports whether err is the 400 BadRequest
// Cosmos returns when you call the throughput endpoint on a serverless
// account. Serverless accounts have no offer concept at all, so the
// throughput row should render as zero/false rather than logging a warning
// for every database and container on every query.
//
// Cosmos returns the generic ErrorCode "BadRequest" for this case, so the
// distinguishing signal is the substring "serverless" in the response body
// message. We inspect rerr.Error() (not the wrapping err.Error()) so the
// match is scoped to the SDK response message rather than any outer
// "failed to fetch ..." wrapper that callers may add.
func isCosmosServerlessThroughputError(err error) bool {
	var rerr *azcore.ResponseError
	if !errors.As(err, &rerr) || rerr.StatusCode != http.StatusBadRequest {
		return false
	}
	// ErrorCode, when present, is "BadRequest" — match it to confirm this is
	// a structured ARM error rather than a generic transport 400, but don't
	// require it (older SDK responses may leave ErrorCode empty).
	if rerr.ErrorCode != "" && rerr.ErrorCode != "BadRequest" {
		return false
	}
	return strings.Contains(rerr.Error(), "serverless")
}

// isCosmosForbiddenError mirrors the convention used elsewhere in this
// provider — 403 from a sub-list is treated as "no entries visible" rather
// than fatal so an over-scoped audit role still works on the rest of the
// schema.
func isCosmosForbiddenError(err error) bool {
	if rerr, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return rerr.StatusCode == http.StatusForbidden
	}
	return false
}
