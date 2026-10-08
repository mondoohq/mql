// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"

	logme "github.com/stackitcloud/stackit-sdk-go/services/logme/v2api"
	mariadb "github.com/stackitcloud/stackit-sdk-go/services/mariadb/v2api"
	mongodbflex "github.com/stackitcloud/stackit-sdk-go/services/mongodbflex/v2api"
	opensearch "github.com/stackitcloud/stackit-sdk-go/services/opensearch/v2api"
	postgresflex "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v2api"
	rabbitmq "github.com/stackitcloud/stackit-sdk-go/services/rabbitmq/v2api"
	redis "github.com/stackitcloud/stackit-sdk-go/services/redis/v2api"
	sqlserverflex "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Backup evidence and offering lifecycle for the DBaaS engines.
//
// The schema so far proved only that a backup *schedule* is configured; the
// backup lists prove that backups exist and how the last ones ended. The
// Flex engines (Postgres, MongoDB, SQL Server) share one backup model, the
// five CF-broker engines (OpenSearch, MariaDB, Redis, RabbitMQ, LogMe) share
// another, and each SDK package generates its own copy, so the mappers take
// the getters through interfaces. The CF engines also publish their offering
// catalog, which is where an instance's engine version is marked latest or
// carries a lifecycle state, and where its plan is marked free.

// ---- Flex backups ----

// flexBackup is the backup record the three Flex SDKs share.
type flexBackup interface {
	GetId() string
	GetName() string
	GetStartTime() string
	GetEndTime() string
	GetSize() int64
	GetError() string
	GetLabels() []string
}

// flexBackupArgs maps a Flex backup onto the engine's instance.backup
// resource. `error` is the failure text the service recorded; empty means the
// backup succeeded. The database is only set for SQL Server, whose backups
// are grouped per database.
func flexBackupArgs(idBase string, b flexBackup, database string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(idBase + "/" + b.GetId()),
		"id":         llx.StringData(b.GetId()),
		"name":       llx.StringData(b.GetName()),
		"database":   llx.StringData(database),
		"startedAt":  llx.TimeDataPtr(parseRFC3339(b.GetStartTime())),
		"finishedAt": llx.TimeDataPtr(parseRFC3339(b.GetEndTime())),
		"size":       llx.IntData(b.GetSize()),
		"error":      llx.StringData(b.GetError()),
		"labels":     strSliceData(b.GetLabels()),
	}
}

func (r *mqlStackitPostgresFlexInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	idBase := "stackit.postgresFlex.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.postgresFlex.instance.backup", flexBackupArgs(idBase, &items[i], ""))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMongoDbFlexInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	idBase := "stackit.mongoDbFlex.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.mongoDbFlex.instance.backup", flexBackupArgs(idBase, &items[i], ""))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// sqlServerBackups flattens the per-database grouping SQL Server Flex uses
// into one list, stamping each backup with its database.
func sqlServerBackups(groups []sqlserverflex.BackupListBackupsResponseGrouped) []struct {
	database string
	backup   *sqlserverflex.Backup
} {
	var out []struct {
		database string
		backup   *sqlserverflex.Backup
	}
	for g := range groups {
		backups := groups[g].GetBackups()
		for b := range backups {
			out = append(out, struct {
				database string
				backup   *sqlserverflex.Backup
			}{database: groups[g].GetName(), backup: &backups[b]})
		}
	}
	return out
}

func (r *mqlStackitSqlServerFlexInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	groups, _ := resp.GetDatabasesOk()
	idBase := "stackit.sqlServerFlex.instance.backup/" + r.Id.Data
	flat := sqlServerBackups(groups)
	out := make([]any, 0, len(flat))
	for _, entry := range flat {
		res, err := CreateResource(r.MqlRuntime, "stackit.sqlServerFlex.instance.backup", flexBackupArgs(idBase, entry.backup, entry.database))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- Flex supported versions ----

// versions lists the engine versions the service currently offers, so an
// instance whose version is not in the list is on a release the service no
// longer provisions.

func (r *mqlStackitPostgresFlex) versions() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListVersions(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	return strSlice(resp.GetVersions()), nil
}

func (r *mqlStackitMongoDbFlex) versions() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListVersions(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	return strSlice(resp.GetVersions()), nil
}

func (r *mqlStackitSqlServerFlex) versions() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListVersions(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	return strSlice(resp.GetVersions()), nil
}

// ---- CF-broker backups ----

// cfBackup is the backup record the five CF-broker SDKs share. The id is
// numeric there; the resource exposes it as a string like every other id.
type cfBackup interface {
	GetId() int32
	GetStatus() string
	GetSizeOk() (*int32, bool)
	GetDownloadableOk() (*bool, bool)
	GetTriggeredAt() string
	GetFinishedAt() string
}

// cfBackupArgs maps a CF-broker backup onto the engine's instance.backup
// resource. Size and downloadable are tri-state; an absent size reads null
// rather than 0 bytes.
func cfBackupArgs(idBase string, b cfBackup) map[string]*llx.RawData {
	id := strconv.FormatInt(int64(b.GetId()), 10)
	var size *int64
	if v, ok := b.GetSizeOk(); ok && v != nil {
		s := int64(*v)
		size = &s
	}
	return map[string]*llx.RawData{
		"__id":         llx.StringData(idBase + "/" + id),
		"id":           llx.StringData(id),
		"status":       llx.StringData(b.GetStatus()),
		"size":         llx.IntDataPtr(size),
		"downloadable": llx.BoolDataPtr(optBool(b.GetDownloadableOk())),
		"triggeredAt":  llx.TimeDataPtr(parseRFC3339(b.GetTriggeredAt())),
		"finishedAt":   llx.TimeDataPtr(parseRFC3339(b.GetFinishedAt())),
	}
}

func (r *mqlStackitOpenSearchInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.OpenSearch()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp
	idBase := "stackit.openSearch.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.openSearch.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMariaDbInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MariaDb()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp
	idBase := "stackit.mariaDb.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.mariaDb.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRedisInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Redis()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp
	idBase := "stackit.redis.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.redis.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRabbitMqInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.RabbitMq()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp
	idBase := "stackit.rabbitMq.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.rabbitMq.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitLogMeInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.LogMe()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp
	idBase := "stackit.logMe.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.logMe.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- CF-broker offerings ----

// cfOffering and cfPlan are the catalog records the five CF-broker SDKs share.
type cfOffering interface {
	GetName() string
	GetVersion() string
	GetLatest() bool
	GetLifecycleOk() (*string, bool)
	GetDescription() string
	GetDocumentationUrl() string
	GetQuotaCount() int32
}

type cfPlan interface {
	GetId() string
	GetName() string
	GetSkuName() string
	GetFree() bool
	GetDescription() string
}

// cfOfferingArgs maps an offering onto the engine's offering resource. The
// resource id is engine-scoped by name and version, since the same engine
// is offered at several versions.
func cfOfferingArgs(idBase string, o cfOffering) map[string]*llx.RawData {
	lifecycle := ""
	if v, ok := o.GetLifecycleOk(); ok && v != nil {
		lifecycle = *v
	}
	return map[string]*llx.RawData{
		"__id":             llx.StringData(idBase + "/" + o.GetName() + "/" + o.GetVersion()),
		"name":             llx.StringData(o.GetName()),
		"version":          llx.StringData(o.GetVersion()),
		"latest":           llx.BoolData(o.GetLatest()),
		"lifecycle":        llx.StringData(lifecycle),
		"description":      llx.StringData(o.GetDescription()),
		"documentationUrl": llx.StringData(o.GetDocumentationUrl()),
		"quotaCount":       llx.IntData(int64(o.GetQuotaCount())),
	}
}

func cfPlanArgs(idBase string, p cfPlan) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData(idBase + "/" + p.GetId()),
		"id":          llx.StringData(p.GetId()),
		"name":        llx.StringData(p.GetName()),
		"skuName":     llx.StringData(p.GetSkuName()),
		"free":        llx.BoolData(p.GetFree()),
		"description": llx.StringData(p.GetDescription()),
	}
}

// dbaasOfferingIndex memoizes an engine namespace's offering catalog indexed
// by version and its plans by id, so every instance's offering() and plan()
// resolve against one fetch. The failure is memoized with the value so a
// denied catalog read is not retried per instance.
type dbaasOfferingIndex struct {
	once      sync.Once
	byVersion map[string]any
	planByID  map[string]any
	err       error
}

// catalogOffering is what an engine's offering resource exposes to the
// index: its version and the plan resources built alongside it.
type catalogOffering interface {
	offeringVersion() string
	offeringPlans() []any
}

// catalogPlan is what an engine's plan resource exposes to the index.
type catalogPlan interface {
	planID() string
}

func (x *dbaasOfferingIndex) build(list func() ([]any, error)) (map[string]any, map[string]any, error) {
	x.once.Do(func() {
		items, err := list()
		if err != nil {
			x.err = err
			return
		}
		x.byVersion = map[string]any{}
		x.planByID = map[string]any{}
		for _, item := range items {
			o, ok := item.(catalogOffering)
			if !ok {
				continue
			}
			if v := o.offeringVersion(); v != "" {
				if _, dup := x.byVersion[v]; !dup {
					x.byVersion[v] = item
				}
			}
			for _, p := range o.offeringPlans() {
				plan, ok := p.(catalogPlan)
				if !ok {
					continue
				}
				if id := plan.planID(); id != "" {
					if _, dup := x.planByID[id]; !dup {
						x.planByID[id] = p
					}
				}
			}
		}
	})
	return x.byVersion, x.planByID, x.err
}

// listAny turns a TValue list into the (items, error) pair the index wants.
func listAny(v *plugin.TValue[[]any]) ([]any, error) {
	if v.Error != nil {
		return nil, v.Error
	}
	return v.Data, nil
}

// -- OpenSearch --

type mqlStackitOpenSearchInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}
type mqlStackitOpenSearchOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

func (r *mqlStackitOpenSearchOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitOpenSearchOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitOpenSearchOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitOpenSearch) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.OpenSearch()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.openSearch.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.openSearch.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitOpenSearchOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.openSearch.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitOpenSearchOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitOpenSearchInstance) offering() (*mqlStackitOpenSearchOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.openSearch")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitOpenSearch)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitOpenSearchOffering)
	if !ok {
		return markNull[mqlStackitOpenSearchOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitOpenSearchInstance) plan() (*mqlStackitOpenSearchOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.openSearch")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitOpenSearch)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitOpenSearchOfferingPlan)
	if !ok {
		return markNull[mqlStackitOpenSearchOfferingPlan](&r.Plan)
	}
	return p, nil
}

// -- MariaDB --

type mqlStackitMariaDbInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}
type mqlStackitMariaDbOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

func (r *mqlStackitMariaDbOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitMariaDbOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitMariaDbOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitMariaDb) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MariaDb()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.mariaDb.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.mariaDb.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitMariaDbOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.mariaDb.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMariaDbOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitMariaDbInstance) offering() (*mqlStackitMariaDbOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.mariaDb")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitMariaDb)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitMariaDbOffering)
	if !ok {
		return markNull[mqlStackitMariaDbOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitMariaDbInstance) plan() (*mqlStackitMariaDbOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.mariaDb")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitMariaDb)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitMariaDbOfferingPlan)
	if !ok {
		return markNull[mqlStackitMariaDbOfferingPlan](&r.Plan)
	}
	return p, nil
}

// -- Redis --

type mqlStackitRedisInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}
type mqlStackitRedisOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

func (r *mqlStackitRedisOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitRedisOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitRedisOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitRedis) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Redis()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.redis.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.redis.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitRedisOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.redis.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRedisOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitRedisInstance) offering() (*mqlStackitRedisOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.redis")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitRedis)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitRedisOffering)
	if !ok {
		return markNull[mqlStackitRedisOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitRedisInstance) plan() (*mqlStackitRedisOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.redis")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitRedis)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitRedisOfferingPlan)
	if !ok {
		return markNull[mqlStackitRedisOfferingPlan](&r.Plan)
	}
	return p, nil
}

// -- RabbitMQ --

type mqlStackitRabbitMqInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}
type mqlStackitRabbitMqOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

func (r *mqlStackitRabbitMqOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitRabbitMqOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitRabbitMqOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitRabbitMq) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.RabbitMq()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.rabbitMq.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.rabbitMq.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitRabbitMqOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.rabbitMq.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRabbitMqOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitRabbitMqInstance) offering() (*mqlStackitRabbitMqOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.rabbitMq")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitRabbitMq)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitRabbitMqOffering)
	if !ok {
		return markNull[mqlStackitRabbitMqOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitRabbitMqInstance) plan() (*mqlStackitRabbitMqOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.rabbitMq")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitRabbitMq)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitRabbitMqOfferingPlan)
	if !ok {
		return markNull[mqlStackitRabbitMqOfferingPlan](&r.Plan)
	}
	return p, nil
}

// -- LogMe --

type mqlStackitLogMeInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}
type mqlStackitLogMeOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

func (r *mqlStackitLogMeOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitLogMeOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitLogMeOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitLogMe) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.LogMe()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.logMe.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.logMe.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitLogMeOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.logMe.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitLogMeOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitLogMeInstance) offering() (*mqlStackitLogMeOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.logMe")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitLogMe)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitLogMeOffering)
	if !ok {
		return markNull[mqlStackitLogMeOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitLogMeInstance) plan() (*mqlStackitLogMeOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.logMe")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitLogMe)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitLogMeOfferingPlan)
	if !ok {
		return markNull[mqlStackitLogMeOfferingPlan](&r.Plan)
	}
	return p, nil
}

// Compile-time checks that each engine's SDK records satisfy the shared
// interfaces, so a regenerated SDK that drops a getter fails here rather than
// in a mapper at runtime.
var (
	_ flexBackup = (*postgresflex.Backup)(nil)
	_ flexBackup = (*mongodbflex.Backup)(nil)
	_ flexBackup = (*sqlserverflex.Backup)(nil)
	_ cfBackup   = (*opensearch.Backup)(nil)
	_ cfBackup   = (*mariadb.Backup)(nil)
	_ cfBackup   = (*redis.Backup)(nil)
	_ cfBackup   = (*rabbitmq.Backup)(nil)
	_ cfBackup   = (*logme.Backup)(nil)
	_ cfOffering = (*opensearch.Offering)(nil)
	_ cfOffering = (*mariadb.Offering)(nil)
	_ cfOffering = (*redis.Offering)(nil)
	_ cfOffering = (*rabbitmq.Offering)(nil)
	_ cfOffering = (*logme.Offering)(nil)
	_ cfPlan     = (*opensearch.Plan)(nil)
	_ cfPlan     = (*mariadb.Plan)(nil)
	_ cfPlan     = (*redis.Plan)(nil)
	_ cfPlan     = (*rabbitmq.Plan)(nil)
	_ cfPlan     = (*logme.Plan)(nil)
)
