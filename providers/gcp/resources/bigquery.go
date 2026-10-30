// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func initGcpProjectBigqueryService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Only default the project from the connection when the caller did not
	// supply one; NewResource runs this init before the resource-cache lookup,
	// so an unconditional overwrite would redirect a caller-scoped reference at
	// the connection's own project.
	if pid, ok := args["projectId"]; !ok || pid == nil {
		args["projectId"] = llx.StringData(conn.ResourceID())
	}

	return args, nil, nil
}

type mqlGcpProjectBigqueryServiceInternal struct {
	serviceGate
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectBigqueryService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_bigquery)
}

func (g *mqlGcpProjectBigqueryService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("gcp.project.bigqueryService/%s", projectId), nil
}

func (g *mqlGcpProject) bigquery() (*mqlGcpProjectBigqueryService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_bigquery)
	if err != nil {
		return nil, err
	}
	bqService := res.(*mqlGcpProjectBigqueryService)
	bqService.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_bigquery).Msg("gcp service is not enabled, skipping")
	}

	return bqService, nil
}

func (g *mqlGcpProjectBigqueryService) datasets() ([]any, error) {
	// when the service is not enabled, we return nil
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	client, err := conn.Client("https://www.googleapis.com/auth/bigquery")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	bigquerySvc, err := bigquery.NewClient(ctx, projectId, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	it := bigquerySvc.Datasets(ctx)
	res := []any{}
	for {
		dataset, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := dataset.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		tags := map[string]string{}
		for i := range metadata.Tags {
			tag := metadata.Tags[i]
			tags[tag.TagKey] = tag.TagValue
		}

		var kmsName string
		if metadata.DefaultEncryptionConfig != nil {
			kmsName = metadata.DefaultEncryptionConfig.KMSKeyName
		}

		var externalDatasetReference any
		if metadata.ExternalDatasetReference != nil {
			externalDatasetReference = map[string]any{
				"externalSource": metadata.ExternalDatasetReference.ExternalSource,
				"connection":     metadata.ExternalDatasetReference.Connection,
			}
		}

		access := make([]any, 0, len(metadata.Access))
		for _, a := range metadata.Access {
			var viewRef any
			if a.View != nil {
				viewRef = map[string]any{
					"projectId": a.View.ProjectID,
					"datasetId": a.View.DatasetID,
					"tableId":   a.View.TableID,
				}
			}
			var routineRef any
			if a.Routine != nil {
				routineRef = map[string]any{
					"projectId": a.Routine.ProjectID,
					"datasetId": a.Routine.DatasetID,
					"tableId":   a.Routine.RoutineID,
				}
			}
			var datasetRef any
			if a.Dataset != nil {
				datasetRef = map[string]any{
					"projectId": a.Dataset.Dataset.ProjectID,
					"datasetId": a.Dataset.Dataset.DatasetID,
					// []string is not JSON-native inside a dict.
					"targetTypes": convert.SliceAnyToInterface(a.Dataset.TargetTypes),
				}
			}
			mqlA, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.dataset.accessEntry", map[string]*llx.RawData{
				"id":         llx.StringData(fmt.Sprintf("gcp.project.bigqueryService.dataset/%s/%s/accessEntry/%s/%s/%s", projectId, dataset.DatasetID, a.Role, entityTypeToString(a.EntityType), accessEntryKey(a))),
				"datasetId":  llx.StringData(dataset.DatasetID),
				"role":       llx.StringData(string(a.Role)),
				"entityType": llx.StringData(entityTypeToString(a.EntityType)),
				"entity":     llx.StringData(a.Entity),
				"viewRef":    llx.DictData(viewRef),
				"routineRef": llx.DictData(routineRef),
				"datasetRef": llx.DictData(datasetRef),
			})
			if err != nil {
				return nil, err
			}
			access = append(access, mqlA)
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.dataset", map[string]*llx.RawData{
			"id":                           llx.StringData(dataset.DatasetID),
			"projectId":                    llx.StringData(dataset.ProjectID),
			"name":                         llx.StringData(metadata.Name),
			"description":                  llx.StringData(metadata.Description),
			"location":                     llx.StringData(metadata.Location),
			"labels":                       llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
			"created":                      llx.TimeData(metadata.CreationTime),
			"modified":                     llx.TimeData(metadata.LastModifiedTime),
			"tags":                         llx.MapData(convert.MapToInterfaceMap(tags), types.String),
			"access":                       llx.ArrayData(access, types.Resource("gcp.project.bigqueryService.dataset.accessEntry")),
			"defaultTableExpirationMs":     llx.IntData(metadata.DefaultTableExpiration.Milliseconds()),
			"maxTimeTravelHours":           llx.IntData(int64(metadata.MaxTimeTravel / time.Hour)),
			"storageBillingModel":          llx.StringData(metadata.StorageBillingModel),
			"defaultCollation":             llx.StringData(metadata.DefaultCollation),
			"defaultPartitionExpirationMs": llx.IntData(metadata.DefaultPartitionExpiration.Milliseconds()),
			"isCaseInsensitive":            llx.BoolData(metadata.IsCaseInsensitive),
			"externalDatasetReference":     llx.DictData(externalDatasetReference),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlGcpProjectBigqueryServiceDataset).cacheKmsKeyName = kmsName
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlGcpProjectBigqueryServiceDatasetInternal struct {
	clientOnce      sync.Once
	client          *bigquery.Client
	clientErr       error
	cacheKmsKeyName string
}

type mqlGcpProjectBigqueryServiceTableInternal struct {
	cacheKmsKeyName        string
	cacheSnapshotBaseTable *bigquery.Table
	cacheCloneBaseTable    *bigquery.Table
}

type mqlGcpProjectBigqueryServiceTableBigLakeConfigInternal struct {
	cacheProjectId    string
	cacheConnectionId string
}

type mqlGcpProjectBigqueryServiceTableForeignKeyInternal struct {
	cacheProjectId         string
	cacheReferencedDataset string
	cacheReferencedTableID string
}

// bigqueryTableByRef resolves a table through its dataset's table list rather
// than constructing one from the reference alone.
//
// The list entries are fully populated, and they share a cache key with any
// resource built from the same identifiers, so creating a sparse stand-in here
// would degrade every field of that table to null for the rest of the scan.
// Both lists are cached after their first fetch.
func bigqueryTableByRef(runtime *plugin.Runtime, projectId, datasetId, tableId string) (*mqlGcpProjectBigqueryServiceTable, error) {
	if projectId == "" || datasetId == "" || tableId == "" {
		return nil, nil
	}

	obj, err := CreateResource(runtime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := obj.(*mqlGcpProjectBigqueryService)

	datasets := svc.GetDatasets()
	if datasets.Error != nil {
		return nil, datasets.Error
	}
	for _, d := range datasets.Data {
		ds, ok := d.(*mqlGcpProjectBigqueryServiceDataset)
		if !ok || ds.Id.Error != nil || ds.Id.Data != datasetId {
			continue
		}
		tables := ds.GetTables()
		if tables.Error != nil {
			return nil, tables.Error
		}
		for _, t := range tables.Data {
			tbl, ok := t.(*mqlGcpProjectBigqueryServiceTable)
			if !ok || tbl.Id.Error != nil {
				continue
			}
			if tbl.Id.Data == tableId {
				return tbl, nil
			}
		}
	}
	return nil, nil
}

// newMqlBigqueryForeignKey maps one declared foreign key. The referenced table
// is resolved on demand rather than here, so listing a table's constraints does
// not pull in every dataset the constraints happen to point at.
func newMqlBigqueryForeignKey(runtime *plugin.Runtime, table *bigquery.Table, fk *bigquery.ForeignKey) (plugin.Resource, error) {
	columnRefs := make([]any, 0, len(fk.ColumnReferences))
	for _, cr := range fk.ColumnReferences {
		if cr == nil {
			continue
		}
		columnRefs = append(columnRefs, map[string]any{
			"referencingColumn": cr.ReferencingColumn,
			"referencedColumn":  cr.ReferencedColumn,
		})
	}

	mqlFk, err := CreateResource(runtime, "gcp.project.bigqueryService.table.foreignKey", map[string]*llx.RawData{
		"__id": llx.StringData(fmt.Sprintf("%s/%s/%s/foreignKey/%s",
			table.ProjectID, table.DatasetID, table.TableID, fk.Name)),
		"name":             llx.StringData(fk.Name),
		"columnReferences": llx.ArrayData(columnRefs, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	res := mqlFk.(*mqlGcpProjectBigqueryServiceTableForeignKey)
	if ref := fk.ReferencedTable; ref != nil {
		res.cacheProjectId = ref.ProjectID
		res.cacheReferencedDataset = ref.DatasetID
		res.cacheReferencedTableID = ref.TableID
	}
	return mqlFk, nil
}

func (g *mqlGcpProjectBigqueryServiceTableForeignKey) referencedTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	tbl, err := bigqueryTableByRef(g.MqlRuntime, g.cacheProjectId, g.cacheReferencedDataset, g.cacheReferencedTableID)
	if err != nil {
		return nil, err
	}
	if tbl == nil {
		g.ReferencedTable.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return tbl, nil
}

// bucket resolves the Cloud Storage bucket named in storageUri. A BigLake
// table is only as private as the bucket behind it, so this is what lets the
// table's exposure be read from the bucket's own IAM policy.
func (g *mqlGcpProjectBigqueryServiceTableBigLakeConfig) bucket() (*mqlGcpProjectStorageServiceBucket, error) {
	return resolveGcsBucketFromURI(g.MqlRuntime, g.StorageUri.Data, &g.Bucket)
}

// connection resolves the BigLake connection through the project's connection
// list, which is already fetched and fully populated.
//
// BigQuery reports the connection as projects/{p}/locations/{loc}/connections/{id},
// matching the connection resource's own name.
func (g *mqlGcpProjectBigqueryServiceTableBigLakeConfig) connection() (*mqlGcpProjectBigqueryServiceConnection, error) {
	notFound := func() (*mqlGcpProjectBigqueryServiceConnection, error) {
		g.Connection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.cacheConnectionId == "" || g.cacheProjectId == "" {
		return notFound()
	}

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	conns := obj.(*mqlGcpProjectBigqueryService).GetConnections()
	if conns.Error != nil {
		return nil, conns.Error
	}
	wantLocation, wantID, ok := bigqueryConnectionKey(g.cacheConnectionId)
	if !ok {
		return notFound()
	}

	for _, c := range conns.Data {
		conn, ok := c.(*mqlGcpProjectBigqueryServiceConnection)
		if !ok || conn.Name.Error != nil {
			continue
		}
		gotLocation, gotID, ok := bigqueryConnectionKey(conn.Name.Data)
		if !ok {
			continue
		}
		if gotLocation == wantLocation && gotID == wantID {
			return conn, nil
		}
	}
	return notFound()
}

// bigqueryConnectionKey reduces the two spellings BigQuery uses for a
// connection to the (location, id) pair that actually identifies it.
//
// A table's biglakeConfiguration.connectionId comes back in the dotted form
// "<project-id>.<location>.<connection>", while the connections list reports
// "projects/<project-number>/locations/<location>/connections/<connection>".
// The project segment is not comparable between them -- one is the project ID
// and the other the project number -- so the leading segment is dropped and the
// match is made on the parts that do identify the connection. Comparing the two
// strings directly never matches, which left every BigLake table reporting no
// connection at all.
func bigqueryConnectionKey(s string) (location string, id string, ok bool) {
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		for i := 0; i+1 < len(parts); i += 2 {
			switch parts[i] {
			case "locations":
				location = parts[i+1]
			case "connections":
				id = parts[i+1]
			}
		}
		return location, id, location != "" && id != ""
	}

	// dotted form: <project>.<location>.<connection>
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[1], parts[2], parts[1] != "" && parts[2] != ""
}

// bigqueryTableId is the resource identity of a table. The runtime stores the
// resource under this value, so it is also what a cache lookup has to rebuild.
func bigqueryTableId(projectId, datasetId, tableId string) string {
	return fmt.Sprintf("gcp.project.bigqueryService.table/%s/%s/%s", projectId, datasetId, tableId)
}

// bigqueryTableCacheKey is the runtime cache key for a table resource, in the
// runtime's "<resource name>\x00<id>" form.
func bigqueryTableCacheKey(projectId, datasetId, tableId string) string {
	return "gcp.project.bigqueryService.table\x00" + bigqueryTableId(projectId, datasetId, tableId)
}

// resolveBaseTable returns the table that a snapshot or clone derives from.
//
// The BigQuery reference carries only project/dataset/table IDs. Building a
// resource out of those alone is not safe: the table has no init, so the
// resource would be created from exactly those args and every other field would
// read null. Worse, the runtime cache is first-writer-wins on the table's id, so
// that stand-in would take the key and be handed back to the later full listing
// of the same table, discarding the metadata that listing had just fetched.
//
// So the reference is resolved instead. A table already listed in this scan is
// returned straight from the cache at no cost; otherwise exactly that one
// table's metadata is fetched. Listing the whole referenced dataset would cost
// one API call per table in it to answer a single reference.
//
// A base table that has been deleted, or that lives in a project the caller
// cannot read, resolves to null rather than to a stand-in.
func (g *mqlGcpProjectBigqueryServiceTable) resolveBaseTable(ref *bigquery.Table) (*mqlGcpProjectBigqueryServiceTable, error) {
	if ref == nil {
		return nil, nil
	}
	return resolveBigqueryTable(g.MqlRuntime, ref.ProjectID, ref.DatasetID, ref.TableID)
}

// resolveBigqueryTable returns the table named by a project/dataset/table
// triple, or null when it does not exist or cannot be read.
//
// This is the shared body of every reference to a BigQuery table that arrives
// as three ID strings rather than as a listed resource. It carries the same
// guarantees resolveBaseTable documents above: a table already listed in this
// scan comes back from the runtime cache at no cost, an absent or unreadable
// table resolves to null rather than to a husk that would poison the cache
// entry for a later full listing, and any other failure surfaces as an error.
func resolveBigqueryTable(runtime *plugin.Runtime, projectID, datasetID, tableID string) (*mqlGcpProjectBigqueryServiceTable, error) {
	if projectID == "" || datasetID == "" || tableID == "" {
		return nil, nil
	}

	key := bigqueryTableCacheKey(projectID, datasetID, tableID)
	if cached, ok := runtime.Resources.Get(key); ok {
		return cached.(*mqlGcpProjectBigqueryServiceTable), nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("resolving a base table requires a GCP connection")
	}
	httpClient, err := conn.Client("https://www.googleapis.com/auth/bigquery")
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectID, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	table := client.DatasetInProject(projectID, datasetID).Table(tableID)
	metadata, err := table.Metadata(ctx)
	if err != nil {
		// A snapshot outlives the table it was taken from, so a base table that
		// is gone or that this caller cannot read is an ordinary state rather
		// than a failure. Report it as null.
		//
		// Anything else (a timeout, a 500, a quota rejection) is a real failure
		// and has to surface: degrading it to null would report "no base table"
		// for a table that exists, and a check asserting the base table is
		// absent would pass on a network blip.
		if isSkippable(err) {
			log.Debug().Err(err).
				Str("project", projectID).
				Str("dataset", datasetID).
				Str("table", tableID).
				Msg("could not read base table metadata")
			return nil, nil
		}
		return nil, err
	}

	res, err := newMqlBigqueryTable(runtime, table, metadata)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectBigqueryServiceTable), nil
}

func (g *mqlGcpProjectBigqueryServiceTable) snapshotBaseTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	t, err := g.resolveBaseTable(g.cacheSnapshotBaseTable)
	if err != nil {
		return nil, err
	}
	if t == nil {
		g.SnapshotBaseTable.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return t, nil
}

func (g *mqlGcpProjectBigqueryServiceTable) cloneBaseTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	t, err := g.resolveBaseTable(g.cacheCloneBaseTable)
	if err != nil {
		return nil, err
	}
	if t == nil {
		g.CloneBaseTable.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return t, nil
}

type mqlGcpProjectBigqueryServiceModelInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectBigqueryServiceModel) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectBigqueryServiceTable) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectBigqueryServiceTable) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.DatasetId.Error != nil {
		return nil, g.DatasetId.Error
	}
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.ProjectId.Data
	datasetId := g.DatasetId.Data
	tableId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	httpClient, err := conn.Client("https://www.googleapis.com/auth/bigquery")
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectId, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.DatasetInProject(projectId, datasetId).Table(tableId).IAM().Policy(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0)
	for _, role := range policy.Roles() {
		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(fmt.Sprintf("%s/%s/%s/%s", projectId, datasetId, tableId, role)),
			"role":                 llx.StringData(string(role)),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(policy.Members(role)), types.String),
			"conditionTitle":       llx.StringData(""),
			"conditionExpression":  llx.StringData(""),
			"conditionDescription": llx.StringData(""),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceTable) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectBigqueryServiceDataset) getClient() (*bigquery.Client, error) {
	g.clientOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		httpClient, err := conn.Client("https://www.googleapis.com/auth/bigquery")
		if err != nil {
			g.clientErr = err
			return
		}
		ctx := context.Background()
		// The client's project decides which project `Dataset(id)` resolves in, so
		// it must be the dataset's own project. ResourceID() is the connection
		// scope (an org or folder id on a non-project connection), which would
		// resolve every dataset's tables/models/routines in the wrong project.
		g.client, g.clientErr = bigquery.NewClient(ctx, g.ProjectId.Data, option.WithHTTPClient(httpClient))
	})
	return g.client, g.clientErr
}

func (g *mqlGcpProjectBigqueryServiceDataset) public() (bool, error) {
	access := g.GetAccess()
	if access.Error != nil {
		return false, access.Error
	}
	for _, raw := range access.Data {
		entry, ok := raw.(*mqlGcpProjectBigqueryServiceDatasetAccessEntry)
		if !ok || entry == nil {
			continue
		}
		entity := entry.GetEntity()
		if entity.Error != nil {
			return false, entity.Error
		}
		if isPublicMember(entity.Data) {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	name := g.Id.Data
	return "gcp.project.bigqueryService.dataset/" + projectId + "/" + name, nil
}

func initGcpProjectBigqueryServiceDataset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["id"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// The dataset is matched by (id, projectId, location); without all three we
	// can't do the lookup. Return an error rather than dereferencing a nil arg
	// (which would panic) or falling through to build a husk with unset fields.
	if args["id"] == nil || args["projectId"] == nil || args["location"] == nil {
		return nil, nil, errors.New("gcp.project.bigqueryService.dataset requires id, projectId, and location")
	}
	projectIdArg, ok := args["projectId"].Value.(string)
	if !ok {
		return nil, nil, errors.New("gcp.project.bigqueryService.dataset projectId must be a string")
	}

	obj, err := CreateResource(runtime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectIdArg),
	})
	if err != nil {
		return nil, nil, err
	}
	bigquerySvc := obj.(*mqlGcpProjectBigqueryService)
	datasets := bigquerySvc.GetDatasets()
	if datasets.Error != nil {
		return nil, nil, datasets.Error
	}

	for _, d := range datasets.Data {
		dataset := d.(*mqlGcpProjectBigqueryServiceDataset)
		id := dataset.GetId()
		if id.Error != nil {
			return nil, nil, id.Error
		}
		location := dataset.GetLocation()
		if location.Error != nil {
			return nil, nil, location.Error
		}
		projectId := dataset.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if id.Data == args["id"].Value && projectId.Data == args["projectId"].Value && location.Data == args["location"].Value {
			return args, dataset, nil
		}
	}
	return nil, nil, errors.New("dataset not found")
}

func (g *mqlGcpProjectBigqueryServiceDatasetAccessEntry) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectBigqueryServiceDataset) tables() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Tables(ctx)
	res := []any{}
	for {
		table, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := table.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		mqlInstance, err := newMqlBigqueryTable(g.MqlRuntime, table, metadata)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

// newMqlBigqueryTable maps a BigQuery table and its metadata onto the mql
// resource.
//
// Every path that produces a gcp.project.bigqueryService.table goes through
// here. The resource cache is first-writer-wins on
// "gcp.project.bigqueryService.table/<project>/<dataset>/<table>", so a partially
// populated table built anywhere else would take that key and stand in for the
// real one for the rest of the scan.
func newMqlBigqueryTable(runtime *plugin.Runtime, table *bigquery.Table, metadata *bigquery.TableMetadata) (plugin.Resource, error) {
	var kmsName string
	if metadata.EncryptionConfig != nil {
		kmsName = metadata.EncryptionConfig.KMSKeyName
	}

	var clusteringFields []any
	if metadata.Clustering != nil {
		clusteringFields = convert.SliceAnyToInterface(metadata.Clustering.Fields)
	}

	externalDataConfig, err := convert.JsonToDict(metadata.ExternalDataConfig)
	if err != nil {
		return nil, err
	}

	materializedView, err := convert.JsonToDict(metadata.MaterializedView)
	if err != nil {
		return nil, err
	}

	rangePartitioning, err := convert.JsonToDict(metadata.RangePartitioning)
	if err != nil {
		return nil, err
	}

	schema, err := convert.JsonToDictSlice(metadata.Schema)
	if err != nil {
		return nil, err
	}

	timePartitioning, err := convert.JsonToDict(metadata.TimePartitioning)
	if err != nil {
		return nil, err
	}

	var snapshotTime *time.Time
	if metadata.SnapshotDefinition != nil {
		snapshotTime = &metadata.SnapshotDefinition.SnapshotTime
	}

	var cloneTime *time.Time
	if metadata.CloneDefinition != nil {
		cloneTime = &metadata.CloneDefinition.CloneTime
	}

	// Most tables declare no staleness bound. Keep the field null in that
	// case rather than reporting "", which would read as a real interval of
	// zero (always fresh) instead of "not configured".
	var maxStaleness *string
	if metadata.MaxStaleness != nil {
		s := metadata.MaxStaleness.String()
		maxStaleness = &s
	}

	// A table with nothing buffered reports no streaming buffer. Leave the
	// timestamp null rather than letting it default to the zero time, which
	// would read as 1 January year 1 on every table that is not streaming.
	var streamingBufferBytes, streamingBufferRows int64
	var streamingBufferOldest *time.Time
	if sb := metadata.StreamingBuffer; sb != nil {
		streamingBufferBytes = int64(sb.EstimatedBytes)
		streamingBufferRows = int64(sb.EstimatedRows)
		if !sb.OldestEntryTime.IsZero() {
			streamingBufferOldest = &sb.OldestEntryTime
		}
	}

	primaryKeyColumns := []any{}
	foreignKeys := []any{}
	if tc := metadata.TableConstraints; tc != nil {
		if tc.PrimaryKey != nil {
			for _, col := range tc.PrimaryKey.Columns {
				primaryKeyColumns = append(primaryKeyColumns, col)
			}
		}
		for _, fk := range tc.ForeignKeys {
			if fk == nil {
				continue
			}
			mqlFk, err := newMqlBigqueryForeignKey(runtime, table, fk)
			if err != nil {
				return nil, err
			}
			foreignKeys = append(foreignKeys, mqlFk)
		}
	}

	// Only a BigLake managed table carries this. Leaving it null keeps a
	// check for an unencrypted storage URI from matching an ordinary
	// managed-storage table that has no external files at all.
	bigLakeData := llx.NilData
	if blc := metadata.BigLakeConfiguration; blc != nil {
		mqlBigLake, err := CreateResource(runtime, "gcp.project.bigqueryService.table.bigLakeConfig", map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("%s/%s/%s/bigLakeConfig", table.ProjectID, table.DatasetID, table.TableID)),
			"storageUri":  llx.StringData(blc.StorageURI),
			"fileFormat":  llx.StringData(string(blc.FileFormat)),
			"tableFormat": llx.StringData(string(blc.TableFormat)),
		})
		if err != nil {
			return nil, err
		}
		mqlBigLakeRes := mqlBigLake.(*mqlGcpProjectBigqueryServiceTableBigLakeConfig)
		mqlBigLakeRes.cacheProjectId = table.ProjectID
		mqlBigLakeRes.cacheConnectionId = blc.ConnectionID
		bigLakeData = llx.ResourceData(mqlBigLake, "gcp.project.bigqueryService.table.bigLakeConfig")
	}

	mqlInstance, err := CreateResource(runtime, "gcp.project.bigqueryService.table", map[string]*llx.RawData{
		"id":                             llx.StringData(table.TableID),
		"projectId":                      llx.StringData(table.ProjectID),
		"datasetId":                      llx.StringData(table.DatasetID),
		"name":                           llx.StringData(metadata.Name),
		"location":                       llx.StringData(metadata.Location),
		"description":                    llx.StringData(metadata.Description),
		"labels":                         llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
		"useLegacySQL":                   llx.BoolData(metadata.UseLegacySQL),
		"requirePartitionFilter":         llx.BoolData(metadata.RequirePartitionFilter),
		"created":                        llx.TimeData(metadata.CreationTime),
		"modified":                       llx.TimeData(metadata.LastModifiedTime),
		"numBytes":                       llx.IntData(metadata.NumBytes),
		"numLongTermBytes":               llx.IntData(metadata.NumLongTermBytes),
		"numRows":                        llx.IntData(int64(metadata.NumRows)),
		"type":                           llx.StringData(string(metadata.Type)),
		"expirationTime":                 llx.TimeData(metadata.ExpirationTime),
		"snapshotTime":                   llx.TimeDataPtr(snapshotTime),
		"cloneTime":                      llx.TimeDataPtr(cloneTime),
		"viewQuery":                      llx.StringData(metadata.ViewQuery),
		"clusteringFields":               llx.DictData(clusteringFields),
		"externalDataConfig":             llx.DictData(externalDataConfig),
		"materializedView":               llx.DictData(materializedView),
		"rangePartitioning":              llx.DictData(rangePartitioning),
		"timePartitioning":               llx.DictData(timePartitioning),
		"schema":                         llx.ArrayData(schema, types.Dict),
		"maxStaleness":                   llx.StringDataPtr(maxStaleness),
		"streamingBufferEstimatedBytes":  llx.IntData(streamingBufferBytes),
		"streamingBufferEstimatedRows":   llx.IntData(streamingBufferRows),
		"streamingBufferOldestEntryTime": llx.TimeDataPtr(streamingBufferOldest),
		"primaryKeyColumns":              llx.ArrayData(primaryKeyColumns, types.String),
		"foreignKeys":                    llx.ArrayData(foreignKeys, types.Resource("gcp.project.bigqueryService.table.foreignKey")),
		"bigLakeConfiguration":           bigLakeData,
	})
	if err != nil {
		return nil, err
	}
	mqlTable := mqlInstance.(*mqlGcpProjectBigqueryServiceTable)
	mqlTable.cacheKmsKeyName = kmsName
	if metadata.SnapshotDefinition != nil {
		mqlTable.cacheSnapshotBaseTable = metadata.SnapshotDefinition.BaseTableReference
	}
	if metadata.CloneDefinition != nil {
		mqlTable.cacheCloneBaseTable = metadata.CloneDefinition.BaseTableReference
	}
	return mqlInstance, nil
}

func (g *mqlGcpProjectBigqueryServiceTable) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.DatasetId.Error != nil {
		return "", g.DatasetId.Error
	}
	datasetId := g.DatasetId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return bigqueryTableId(projectId, datasetId, id), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) models() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Models(ctx)
	res := []any{}
	for {
		model, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := model.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		var kmsName string
		if metadata.EncryptionConfig != nil {
			kmsName = metadata.EncryptionConfig.KMSKeyName
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.model", map[string]*llx.RawData{
			"id":             llx.StringData(model.ModelID),
			"datasetId":      llx.StringData(model.DatasetID),
			"projectId":      llx.StringData(model.ProjectID),
			"name":           llx.StringData(metadata.Name),
			"description":    llx.StringData(metadata.Description),
			"location":       llx.StringData(metadata.Location),
			"labels":         llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
			"created":        llx.TimeData(metadata.CreationTime),
			"modified":       llx.TimeData(metadata.LastModifiedTime),
			"type":           llx.StringData(string(metadata.Type)),
			"expirationTime": llx.TimeData(metadata.ExpirationTime),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlGcpProjectBigqueryServiceModel).cacheKmsKeyName = kmsName
		res = append(res, mqlInstance)

	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceModel) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.DatasetId.Error != nil {
		return "", g.DatasetId.Error
	}
	datasetId := g.DatasetId.Data
	return fmt.Sprintf("gcp.project.bigqueryService.model/%s/%s/%s", projectId, datasetId, id), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) routines() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Routines(ctx)
	res := []any{}
	for {
		routine, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := routine.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.routine", map[string]*llx.RawData{
			"id":          llx.StringData(routine.RoutineID),
			"datasetId":   llx.StringData(routine.DatasetID),
			"projectId":   llx.StringData(routine.ProjectID),
			"language":    llx.StringData(metadata.Language),
			"description": llx.StringData(metadata.Description),
			"created":     llx.TimeData(metadata.CreationTime),
			"modified":    llx.TimeData(metadata.LastModifiedTime),
			"type":        llx.StringData(string(metadata.Type)),
			"body":        llx.StringData(metadata.Body),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)

	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceRoutine) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.DatasetId.Error != nil {
		return "", g.DatasetId.Error
	}
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	// Routine IDs are unique only within a dataset, so qualify with
	// project + dataset (matches the model/table ids).
	return fmt.Sprintf("gcp.project.bigqueryService.routine/%s/%s/%s", g.ProjectId.Data, g.DatasetId.Data, g.Id.Data), nil
}

// accessEntryKey returns the value that identifies a dataset access entry
// within its (role, entityType) pair.
//
// For most entity kinds that is AccessEntry.Entity, but the BigQuery SDK
// decoder leaves Entity EMPTY for view, routine and dataset entries and records
// the reference in the typed View/Routine/Dataset field instead. Keying the
// resource on Entity alone therefore produced the identical id for every
// authorized view on a dataset, and CreateResource returned the first one for
// all of them -- so a dataset sharing three views reported the same view three
// times.
func accessEntryKey(a *bigquery.AccessEntry) string {
	switch {
	case a.View != nil:
		return fmt.Sprintf("%s:%s:%s", a.View.ProjectID, a.View.DatasetID, a.View.TableID)
	case a.Routine != nil:
		return fmt.Sprintf("%s:%s:%s", a.Routine.ProjectID, a.Routine.DatasetID, a.Routine.RoutineID)
	case a.Dataset != nil:
		return fmt.Sprintf("%s:%s", a.Dataset.Dataset.ProjectID, a.Dataset.Dataset.DatasetID)
	default:
		return a.Entity
	}
}

func entityTypeToString(entityType bigquery.EntityType) string {
	switch entityType {
	case bigquery.DomainEntity:
		return "DOMAIN"
	case bigquery.GroupEmailEntity:
		return "GROUP_EMAIL"
	case bigquery.UserEmailEntity:
		return "USER_EMAIL"
	case bigquery.SpecialGroupEntity:
		return "SPECIAL_GROUP"
	case bigquery.ViewEntity:
		return "VIEW"
	case bigquery.IAMMemberEntity:
		return "IAM_MEMBER"
	case bigquery.RoutineEntity:
		return "ROUTINE"
	case bigquery.DatasetEntity:
		return "DATASET"
	default:
		return "UNKNOWN"
	}
}

// resolveBigqueryDataset returns the dataset named by a project/dataset pair,
// or null when the project holds no such dataset that this caller can see.
//
// A dataset is matched by (id, projectId, location), and a reference that
// arrives as two ID strings carries no location, so the dataset cannot be built
// through its init. It is resolved against the project's dataset listing
// instead: that listing is a single API call, the runtime caches it on the
// bigqueryService resource, and every later reference into the same project is
// answered from that cache rather than from a fresh call per reference.
//
// A project whose datasets cannot be listed at all (the BigQuery API disabled,
// or no permission on a cross-project destination) yields null rather than an
// error, because "there is a dataset here I am not allowed to see" is an
// ordinary state for a reference that points outside the scanned project.
func resolveBigqueryDataset(runtime *plugin.Runtime, projectID, datasetID string) (*mqlGcpProjectBigqueryServiceDataset, error) {
	if projectID == "" || datasetID == "" {
		return nil, nil
	}

	obj, err := CreateResource(runtime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectID),
	})
	if err != nil {
		return nil, err
	}

	datasets := obj.(*mqlGcpProjectBigqueryService).GetDatasets()
	if datasets.Error != nil {
		if isSkippable(datasets.Error) {
			log.Debug().Err(datasets.Error).
				Str("project", projectID).
				Str("dataset", datasetID).
				Msg("could not list datasets to resolve a dataset reference")
			return nil, nil
		}
		return nil, datasets.Error
	}

	for _, d := range datasets.Data {
		dataset, ok := d.(*mqlGcpProjectBigqueryServiceDataset)
		if !ok {
			continue
		}
		id := dataset.GetId()
		if id.Error != nil {
			return nil, id.Error
		}
		if id.Data == datasetID {
			return dataset, nil
		}
	}

	return nil, nil
}
