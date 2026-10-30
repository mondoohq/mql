// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/logs"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// datasetObjectTypeZone is the object_type Cloudflare reports for a dataset
// scoped to a single zone rather than to the whole account.
const datasetObjectTypeZone = "zone"

type mqlCloudflareLogExplorerDatasetInternal struct {
	// accountID is the account the dataset was listed under. A zone-scoped
	// dataset is reached through its own zone path, but an account-scoped one
	// needs this: deriving the account from objectId would make a mismatch
	// answer 404, which degrades to a null filter and reads as "no filter"
	// rather than as a failed lookup.
	accountID string
}

// logExplorerDatasets lists the Log Explorer datasets retained for the account,
// including those scoped to zones the account owns.
func (c *mqlCloudflareAccount) logExplorerDatasets() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	accountID := c.Id.Data
	if accountID == "" {
		return nil, errNoAccountBound
	}

	var res []any
	iter := conn.Cf.Logs.LogExplorer.Datasets.ListAutoPaging(context.TODO(), logs.LogExplorerDatasetListParams{
		AccountID: cloudflare.F(accountID),
		// Zone-scoped datasets are the ones most likely to be left
		// unprotected, so an account listing that omitted them would report a
		// clean account while its zones retained logs nothing guarded.
		IncludeZones: cloudflare.F(true),
	})
	for iter.Next() {
		ds := iter.Current()

		resource, err := CreateResource(c.MqlRuntime, "cloudflare.logExplorerDataset", map[string]*llx.RawData{
			"__id":               llx.StringData("cloudflare.logExplorerDataset@" + accountID + "/" + ds.DatasetID),
			"datasetId":          llx.StringData(ds.DatasetID),
			"dataset":            llx.StringData(ds.Dataset),
			"deletionProtection": llx.BoolData(ds.DeletionProtection),
			"enabled":            llx.BoolData(ds.Enabled),
			"objectType":         llx.StringData(string(ds.ObjectType)),
			"objectId":           llx.StringData(ds.ObjectID),
			"createdAt":          timeOrNil(ds.CreatedAt),
			"updatedAt":          timeOrNil(ds.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		resource.(*mqlCloudflareLogExplorerDataset).accountID = accountID
		res = append(res, resource)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return res, nil
}

// zone resolves a zone-scoped dataset to the zone it retains logs for, and is
// null for an account-scoped dataset.
//
// The lookup walks the already-fetched zone list rather than calling
// NewResource per dataset: a resource init runs before the runtime cache is
// consulted, so a per-dataset lookup would turn one listing into one call per
// dataset.
func (d *mqlCloudflareLogExplorerDataset) zone() (*mqlCloudflareZone, error) {
	if d.ObjectType.Data != datasetObjectTypeZone || d.ObjectId.Data == "" {
		d.Zone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cf, err := CreateResource(d.MqlRuntime, "cloudflare", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	zoneList := cf.(*mqlCloudflare).GetZones()
	if zoneList.Error != nil {
		return nil, zoneList.Error
	}

	for _, entry := range zoneList.Data {
		zone, ok := entry.(*mqlCloudflareZone)
		if !ok {
			continue
		}
		if zone.Id.Data == d.ObjectId.Data {
			return zone, nil
		}
	}

	// The dataset names a zone the calling token cannot list. Report null
	// rather than an error, so one out-of-scope zone does not fail a query
	// over every dataset.
	d.Zone.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// filter returns the expression limiting which log entries the dataset retains.
// The list endpoint omits it, so this reads the dataset individually.
func (d *mqlCloudflareLogExplorerDataset) filter() (string, error) {
	if d.DatasetId.Data == "" {
		d.Filter.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	conn := d.MqlRuntime.Connection.(*connection.CloudflareConnection)

	params := logs.LogExplorerDatasetGetParams{}
	if d.ObjectType.Data == datasetObjectTypeZone {
		params.ZoneID = cloudflare.F(d.ObjectId.Data)
	} else {
		if d.accountID == "" {
			d.Filter.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		params.AccountID = cloudflare.F(d.accountID)
	}

	ds, err := conn.Cf.Logs.LogExplorer.Datasets.Get(context.TODO(), d.DatasetId.Data, params)
	if err != nil {
		if isUnavailable(err) {
			// Null, not "": an unreadable dataset must not be indistinguishable
			// from one that retains every entry.
			d.Filter.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}

	return ds.Filter, nil
}
