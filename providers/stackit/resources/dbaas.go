// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	mongodbflex "github.com/stackitcloud/stackit-sdk-go/services/mongodbflex/v2api"
	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	postgresflex "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v2api"
	secretsmanager "github.com/stackitcloud/stackit-sdk-go/services/secretsmanager/v1api"
	sqlserverflex "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ------------------------- Postgres Flex -------------------------
//
// The ListInstances endpoint returns id/name/status only. Everything else
// (version, flavor, ACL, replicas, storage, backup schedule, options) lives
// behind GetInstance(projectId, region, instanceId). We model that detail as
// computed methods that share a single cached fetch per instance.

type mqlStackitPostgresFlexInstanceInternal struct {
	fetched atomic.Bool
	detail  *postgresflex.Instance
	lock    sync.Mutex

	// v3 holds the v3 API's record of the instance (dbaas_flex_v3.go).
	v3 flexV3Detail
}

func (r *mqlStackitPostgresFlex) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		args := map[string]*llx.RawData{
			"id":     llx.StringData(inst.GetId()),
			"name":   llx.StringData(inst.GetName()),
			"status": llx.StringData(inst.GetStatus()),
			"region": llx.StringData(c.Region()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.postgresFlex.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitPostgresFlexInstance) id() (string, error) {
	return "stackit.postgresFlex.instance/" + r.Id.Data, nil
}

// fetchDetail pulls the full instance object via GetInstance and caches it
// for the lifetime of this resource. Double-check locked so concurrent field
// accesses share one API call.
func (r *mqlStackitPostgresFlexInstance) fetchDetail() (*postgresflex.Instance, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitPostgresFlexInstance) version() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetVersion(), nil
}

func (r *mqlStackitPostgresFlexInstance) flavor() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetFlavor()), nil
}

func (r *mqlStackitPostgresFlexInstance) acl() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	if a, ok := d.GetAclOk(); ok {
		return strSlice(a.GetItems()), nil
	}
	return []any{}, nil
}

func (r *mqlStackitPostgresFlexInstance) replicas() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(d.GetReplicas()), nil
}

func (r *mqlStackitPostgresFlexInstance) storage() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetStorage()), nil
}

func (r *mqlStackitPostgresFlexInstance) backupSchedule() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetBackupSchedule(), nil
}

func (r *mqlStackitPostgresFlexInstance) options() (map[string]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return map[string]any{}, err
	}
	return stringMap(d.GetOptions()), nil
}

// ------------------------- MongoDB Flex -------------------------
//
// Mirrors the Postgres Flex pattern: list returns id/name/status only,
// detail (version/flavor/replicas/storage/backupSchedule/acl/options) is
// lazy-loaded once per instance.

type mqlStackitMongoDbFlexInstanceInternal struct {
	fetched atomic.Bool
	detail  *mongodbflex.Instance
	lock    sync.Mutex
}

func (r *mqlStackitMongoDbFlex) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	// Unlike the other Flex engines, the MongoDB Flex ListInstances endpoint
	// requires a `tag` query parameter. An empty tag returns all instances in
	// the project, so use the request builder rather than the convenience
	// ListInstancesExecute (which cannot set a tag).
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Tag("").Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		args := map[string]*llx.RawData{
			"id":     llx.StringData(inst.GetId()),
			"name":   llx.StringData(inst.GetName()),
			"status": llx.StringData(string(inst.GetStatus())),
			"region": llx.StringData(c.Region()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.mongoDbFlex.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMongoDbFlexInstance) id() (string, error) {
	return "stackit.mongoDbFlex.instance/" + r.Id.Data, nil
}

func (r *mqlStackitMongoDbFlexInstance) fetchDetail() (*mongodbflex.Instance, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitMongoDbFlexInstance) version() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetVersion(), nil
}

func (r *mqlStackitMongoDbFlexInstance) flavor() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetFlavor()), nil
}

func (r *mqlStackitMongoDbFlexInstance) replicas() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(d.GetReplicas()), nil
}

func (r *mqlStackitMongoDbFlexInstance) storage() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetStorage()), nil
}

func (r *mqlStackitMongoDbFlexInstance) backupSchedule() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetBackupSchedule(), nil
}

func (r *mqlStackitMongoDbFlexInstance) acl() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	if a, ok := d.GetAclOk(); ok {
		return strSlice(a.GetItems()), nil
	}
	return []any{}, nil
}

func (r *mqlStackitMongoDbFlexInstance) options() (map[string]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return map[string]any{}, err
	}
	return stringMap(d.GetOptions()), nil
}

// ------------------------- OpenSearch -------------------------

func (r *mqlStackitOpenSearch) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.OpenSearch()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		lop := inst.GetLastOperation()
		st, stOk := inst.GetStatusOk()
		args := cfBrokerInstanceArgs(c.Region(), &inst, st, stOk, &lop)
		res, err := CreateResource(r.MqlRuntime, "stackit.openSearch.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitOpenSearchInstance) id() (string, error) {
	return "stackit.openSearch.instance/" + r.Id.Data, nil
}

// ------------------------- MariaDB -------------------------

func (r *mqlStackitMariaDb) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MariaDb()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		lop := inst.GetLastOperation()
		st, stOk := inst.GetStatusOk()
		args := cfBrokerInstanceArgs(c.Region(), &inst, st, stOk, &lop)
		res, err := CreateResource(r.MqlRuntime, "stackit.mariaDb.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMariaDbInstance) id() (string, error) {
	return "stackit.mariaDb.instance/" + r.Id.Data, nil
}

// ------------------------- CF-broker instances (shared) -------------------------

// cfBrokerInstance is the slice of an OpenSearch, MariaDB, Redis, RabbitMQ, or
// LogMe instance record that every engine's SDK model exposes with the same
// signatures. The five SDK packages generate the same Instance shape, so one
// mapper serves all ten creation paths (five list, five init). The status and
// last-operation enums are package-specific named string types and are passed
// alongside through type parameters.
type cfBrokerInstance interface {
	GetInstanceId() string
	GetName() string
	GetPlanName() string
	GetPlanId() string
	GetOfferingName() string
	GetOfferingVersionOk() (*string, bool)
	GetCfGuid() string
	GetCfOrganizationGuid() string
	GetCfSpaceGuid() string
	GetDashboardUrl() string
	GetImageUrl() string
	GetParameters() map[string]interface{}
}

// cfLastOperation is the last provisioning operation on a CF-broker instance:
// what ran, how it ended, and why.
type cfLastOperation[S ~string, T ~string] interface {
	GetState() S
	GetType() T
	GetDescription() string
}

// cfBrokerInstanceArgs maps a CF-broker instance onto the fields shared by
// the five instance resources. `status` stays the outcome of the last
// operation, as shipped; the instance's own lifecycle state, which the
// schema never read before, lands in `state`. An absent status reads null
// rather than "" so a policy can tell "not reported" from a real value.
func cfBrokerInstanceArgs[ST ~string, LS ~string, LT ~string](region string, inst cfBrokerInstance, status *ST, statusOk bool, lop cfLastOperation[LS, LT]) map[string]*llx.RawData {
	var state *string
	if statusOk && status != nil {
		s := string(*status)
		state = &s
	}
	return map[string]*llx.RawData{
		"id":                       llx.StringData(inst.GetInstanceId()),
		"name":                     llx.StringData(inst.GetName()),
		"status":                   llx.StringData(string(lop.GetState())),
		"state":                    llx.StringDataPtr(state),
		"lastOperationType":        llx.StringData(string(lop.GetType())),
		"lastOperationDescription": llx.StringData(lop.GetDescription()),
		"region":                   llx.StringData(region),
		"planName":                 llx.StringData(inst.GetPlanName()),
		"planId":                   llx.StringData(inst.GetPlanId()),
		"offeringName":             llx.StringData(inst.GetOfferingName()),
		"offeringVersion":          llx.StringDataPtr(strOrNil(inst.GetOfferingVersionOk())),
		"cfGuid":                   llx.StringData(inst.GetCfGuid()),
		"cfOrganizationGuid":       llx.StringData(inst.GetCfOrganizationGuid()),
		"cfSpaceGuid":              llx.StringData(inst.GetCfSpaceGuid()),
		"dashboardUrl":             llx.StringData(inst.GetDashboardUrl()),
		"imageUrl":                 llx.StringData(inst.GetImageUrl()),
		"parameters":               llx.DictData(toDict(inst.GetParameters())),
	}
}

// ------------------------- Redis -------------------------

func (r *mqlStackitRedis) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Redis()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		lop := inst.GetLastOperation()
		st, stOk := inst.GetStatusOk()
		args := cfBrokerInstanceArgs(c.Region(), &inst, st, stOk, &lop)
		res, err := CreateResource(r.MqlRuntime, "stackit.redis.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRedisInstance) id() (string, error) {
	return "stackit.redis.instance/" + r.Id.Data, nil
}

// ------------------------- RabbitMQ -------------------------

func (r *mqlStackitRabbitMq) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.RabbitMq()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		lop := inst.GetLastOperation()
		st, stOk := inst.GetStatusOk()
		args := cfBrokerInstanceArgs(c.Region(), &inst, st, stOk, &lop)
		res, err := CreateResource(r.MqlRuntime, "stackit.rabbitMq.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitRabbitMqInstance) id() (string, error) {
	return "stackit.rabbitMq.instance/" + r.Id.Data, nil
}

// ------------------------- Secrets Manager -------------------------

func (r *mqlStackitSecretsManager) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildSecretsManagerInstance(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

type mqlStackitSecretsManagerInstanceInternal struct {
	// cacheKmsKey is the customer-managed key reference the instance
	// carries, resolved by the encryptionKey* accessors. Nil when the vault
	// relies on platform-managed encryption.
	cacheKmsKey *secretsmanager.KmsKeyPayload
}

// buildSecretsManagerInstance maps an instance record onto the resource. The
// list and the single-instance endpoints return the same model, so both
// creation paths share it.
func buildSecretsManagerInstance(runtime *plugin.Runtime, inst *secretsmanager.Instance) (plugin.Resource, error) {
	kmsKey, hasKmsKey := inst.GetKmsKeyOk()
	var keyVersion int64
	if hasKmsKey && kmsKey != nil {
		keyVersion = kmsKey.GetKeyVersion()
	}
	res, err := CreateResource(runtime, "stackit.secretsManager.instance", map[string]*llx.RawData{
		"id":                         llx.StringData(inst.GetId()),
		"name":                       llx.StringData(inst.GetName()),
		"state":                      llx.StringData(inst.GetState()),
		"apiUrl":                     llx.StringData(inst.GetApiUrl()),
		"secretsEngine":              llx.StringData(inst.GetSecretsEngine()),
		"secretCount":                llx.IntData(int64(inst.GetSecretCount())),
		"creationStartedAt":          llx.TimeDataPtr(parseDnsTime(inst.GetCreationStartDate())),
		"creationFinishedAt":         llx.TimeDataPtr(parseDnsTime(inst.GetCreationFinishedDate())),
		"encryptionKeyVersionNumber": llx.IntData(keyVersion),
	})
	if err != nil {
		return nil, err
	}
	if hasKmsKey && kmsKey != nil {
		res.(*mqlStackitSecretsManagerInstance).cacheKmsKey = kmsKey
	}
	return res, nil
}

func (r *mqlStackitSecretsManagerInstance) id() (string, error) {
	return "stackit.secretsManager.instance/" + r.Id.Data, nil
}

// encryptionKey resolves the customer-managed key that encrypts the vault.
// Null when the instance relies on platform-managed encryption. The instance
// names the ring, so the lookup reads that one ring's key list.
func (r *mqlStackitSecretsManagerInstance) encryptionKey() (*mqlStackitKmsKey, error) {
	k := r.cacheKmsKey
	if k == nil {
		return markNull[mqlStackitKmsKey](&r.EncryptionKey)
	}
	return kmsKeyInRingRef(r.MqlRuntime, k.GetKeyRingId(), k.GetKeyId(), &r.EncryptionKey)
}

// encryptionKeyRing resolves the key ring that holds the vault's
// customer-managed key. Null for platform-managed encryption.
func (r *mqlStackitSecretsManagerInstance) encryptionKeyRing() (*mqlStackitKmsKeyRing, error) {
	k := r.cacheKmsKey
	if k == nil {
		return markNull[mqlStackitKmsKeyRing](&r.EncryptionKeyRing)
	}
	return kmsKeyRingRef(r.MqlRuntime, k.GetKeyRingId(), &r.EncryptionKeyRing)
}

// encryptionKeyVersion resolves the generation of key material the vault
// is pinned to. Version numbers start at 1, so 0 means nothing is pinned.
func (r *mqlStackitSecretsManagerInstance) encryptionKeyVersion() (*mqlStackitKmsKeyVersion, error) {
	field := &r.EncryptionKeyVersion
	number := r.EncryptionKeyVersionNumber.Data
	if number == 0 {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	key := r.GetEncryptionKey()
	if key.Error != nil {
		return nil, key.Error
	}
	if key.Data == nil {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	versions := key.Data.GetVersions()
	if versions.Error != nil {
		return nil, versions.Error
	}
	v := findKmsKeyVersion(versions.Data, number)
	if v == nil {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	return v, nil
}

// encryptionKeyServiceAccount resolves the service account the vault uses
// to reach its customer-managed key. Null for platform-managed encryption,
// and null when the account is not one of this project's.
func (r *mqlStackitSecretsManagerInstance) encryptionKeyServiceAccount() (*mqlStackitServiceAccount, error) {
	k := r.cacheKmsKey
	if k == nil {
		return markNull[mqlStackitServiceAccount](&r.EncryptionKeyServiceAccount)
	}
	return serviceAccountRef(r.MqlRuntime, k.GetServiceAccountEmail(), &r.EncryptionKeyServiceAccount)
}

func (r *mqlStackitSecretsManagerInstance) acls() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListACLs(bgctx(), c.ProjectID(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	acls, _ := resp.GetAclsOk()
	out := make([]any, 0, len(acls))
	for i := range acls {
		out = append(out, acls[i].GetCidr())
	}
	return out, nil
}

// mqlStackitSecretsManagerUserInternal caches the owning instance id so the
// back-reference resolves without the schema repeating it as a raw field.
type mqlStackitSecretsManagerUserInternal struct {
	cacheInstanceId string
}

// users lists the instance's credentialed principals. The SDK's User model
// also carries the user's password; it is deliberately not mapped into the
// resource, since a scan result is not a place to reproduce a credential.
func (r *mqlStackitSecretsManagerInstance) users() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUsers(bgctx(), c.ProjectID(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	users, _ := resp.GetUsersOk()
	out := make([]any, 0, len(users))
	for i := range users {
		u := &users[i]
		args := map[string]*llx.RawData{
			// the user id is only unique within its instance, so the cache key
			// has to carry the instance it belongs to
			"__id":        llx.StringData(qualifiedId("stackit.secretsManager.user", r.Id.Data, u.GetId())),
			"id":          llx.StringData(u.GetId()),
			"username":    llx.StringData(u.GetUsername()),
			"description": llx.StringData(u.GetDescription()),
			"write":       llx.BoolData(u.GetWrite()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.secretsManager.user", args)
		if err != nil {
			return nil, err
		}
		if mu, ok := res.(*mqlStackitSecretsManagerUser); ok {
			mu.cacheInstanceId = r.Id.Data
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSecretsManagerUser) instance() (*mqlStackitSecretsManagerInstance, error) {
	if r.cacheInstanceId == "" {
		return markNull[mqlStackitSecretsManagerInstance](&r.Instance)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.secretsManager.instance", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheInstanceId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecretsManagerInstance), nil
}

// ------------------------- Observability -------------------------
//
// The list endpoint returns id/name/status/planName/serviceName only.
// planId/dashboardUrl/parameters/isUpdatable live behind GetInstance and
// are lazy-loaded once per instance.

type mqlStackitObservabilityInstanceInternal struct {
	fetched atomic.Bool
	detail  *observability.GetInstanceResponse
	lock    sync.Mutex

	// Grafana configuration comes from a separate endpoint, so it gets its
	// own guard rather than sharing the instance-detail one.
	grafanaFetched atomic.Bool
	grafana        *observability.GrafanaConfigs
	grafanaLock    sync.Mutex

	// The three metrics retention fields share one call (observability_config.go).
	retentionFetched atomic.Bool
	retention        *observability.GetMetricsStorageRetentionResponse
	retentionLock    sync.Mutex
}

func (r *mqlStackitObservability) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		args := map[string]*llx.RawData{
			"id":           llx.StringData(inst.GetId()),
			"name":         llx.StringData(inst.GetName()),
			"status":       llx.StringData(string(inst.GetStatus())),
			"planName":     llx.StringData(inst.GetPlanName()),
			"offeringName": llx.StringData(inst.GetServiceName()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.observability.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitObservabilityInstance) id() (string, error) {
	return "stackit.observability.instance/" + r.Id.Data, nil
}

func (r *mqlStackitObservabilityInstance) fetchDetail() (*observability.GetInstanceResponse, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.detail = resp
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitObservabilityInstance) planId() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetPlanId(), nil
}

func (r *mqlStackitObservabilityInstance) dashboardUrl() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetDashboardUrl(), nil
}

func (r *mqlStackitObservabilityInstance) parameters() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	params, ok := d.GetParametersOk()
	if !ok || params == nil {
		return map[string]any{}, nil
	}
	return stringPtrMap(*params), nil
}

func (r *mqlStackitObservabilityInstance) isUpdatable() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return d.GetIsUpdatable(), nil
}

func (r *mqlStackitObservabilityInstance) acl() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListACL(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	acl, _ := resp.GetAclOk()
	return strSlice(acl), nil
}

// fetchGrafana pulls the instance's Grafana configuration once and caches it
// for the lifetime of this resource, so the generic OAuth fields share a
// single API call. Double-check locked like fetchDetail.
//
// The response also carries the generic OAuth provider's client secret. Only
// the posture flags are lifted onto the resource; the secret is left behind.
func (r *mqlStackitObservabilityInstance) fetchGrafana() (*observability.GrafanaConfigs, error) {
	if r.grafanaFetched.Load() {
		return r.grafana, nil
	}
	r.grafanaLock.Lock()
	defer r.grafanaLock.Unlock()
	if r.grafanaFetched.Load() {
		return r.grafana, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetGrafanaConfigs(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.grafanaFetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.grafana = resp
	r.grafanaFetched.Store(true)
	return r.grafana, nil
}

// The instance detail already carries the two Grafana access flags on its
// InstanceSensitiveData block, so they are read from the detail every other
// field shares rather than spending the Grafana-config call on them. That call
// is only paid when the generic OAuth fields are queried. If the detail was
// denied, the Grafana endpoint is tried as a fallback before giving up.

func (r *mqlStackitObservabilityInstance) grafanaPublicReadAccess() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	if d != nil {
		if inst, ok := d.GetInstanceOk(); ok && inst != nil {
			return inst.GetGrafanaPublicReadAccess(), nil
		}
	}
	g, err := r.fetchGrafana()
	if err != nil || g == nil {
		return false, err
	}
	return g.GetPublicReadAccess(), nil
}

func (r *mqlStackitObservabilityInstance) grafanaUseStackitSso() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	if d != nil {
		if inst, ok := d.GetInstanceOk(); ok && inst != nil {
			return inst.GetGrafanaUseStackitSso(), nil
		}
	}
	g, err := r.fetchGrafana()
	if err != nil || g == nil {
		return false, err
	}
	return g.GetUseStackitSso(), nil
}

func (r *mqlStackitObservabilityInstance) grafanaGenericOauthEnabled() (bool, error) {
	g, err := r.fetchGrafana()
	if err != nil || g == nil {
		return false, err
	}
	oauth, ok := g.GetGenericOauthOk()
	if !ok || oauth == nil {
		return false, nil
	}
	return oauth.GetEnabled(), nil
}

func (r *mqlStackitObservabilityInstance) grafanaGenericOauthAllowAssignAdmin() (bool, error) {
	g, err := r.fetchGrafana()
	if err != nil || g == nil {
		return false, err
	}
	oauth, ok := g.GetGenericOauthOk()
	if !ok || oauth == nil {
		return false, nil
	}
	return oauth.GetAllowAssignGrafanaAdmin(), nil
}

// ------------------------- Flex database users -------------------------
//
// Each Flex engine lists its users with id/username only; roles, host, port,
// and the default database need a per-user GetUser call, so they are computed
// fields behind a cached fetch. A query that only reads usernames therefore
// costs one call per instance, not one per user.
//
// The three engines take the same five string arguments in DIFFERENT orders:
// postgresflex is (projectId, region, instanceId[, userId]) while mongodbflex
// and sqlserverflex are (projectId, instanceId[, userId], region). Swapping
// them still compiles.

type mqlStackitPostgresFlexInstanceUserInternal struct {
	cacheInstanceId string
	fetched         atomic.Bool
	detail          *postgresflex.UserResponse
	lock            sync.Mutex
}

func (r *mqlStackitPostgresFlexInstance) users() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUsers(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		u := &items[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.postgresFlex.instance.user", map[string]*llx.RawData{
			// the user id is only unique within its instance, so the cache key
			// has to carry the instance it belongs to
			"__id":     llx.StringData(qualifiedId("stackit.postgresFlex.instance.user", r.Id.Data, u.GetId())),
			"id":       llx.StringData(u.GetId()),
			"username": llx.StringData(u.GetUsername()),
		})
		if err != nil {
			return nil, err
		}
		if mu, ok := res.(*mqlStackitPostgresFlexInstanceUser); ok {
			mu.cacheInstanceId = r.Id.Data
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitPostgresFlexInstanceUser) fetchDetail() (*postgresflex.UserResponse, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetUser(bgctx(), c.ProjectID(), c.Region(), r.cacheInstanceId, r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitPostgresFlexInstanceUser) roles() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	return strSlice(d.GetRoles()), nil
}

func (r *mqlStackitPostgresFlexInstanceUser) host() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetHost(), nil
}

func (r *mqlStackitPostgresFlexInstanceUser) port() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return d.GetPort(), nil
}

type mqlStackitMongoDbFlexInstanceUserInternal struct {
	cacheInstanceId string
	fetched         atomic.Bool
	detail          *mongodbflex.InstanceResponseUser
	lock            sync.Mutex
}

func (r *mqlStackitMongoDbFlexInstance) users() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUsers(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		u := &items[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.mongoDbFlex.instance.user", map[string]*llx.RawData{
			// the user id is only unique within its instance, so the cache key
			// has to carry the instance it belongs to
			"__id":     llx.StringData(qualifiedId("stackit.mongoDbFlex.instance.user", r.Id.Data, u.GetId())),
			"id":       llx.StringData(u.GetId()),
			"username": llx.StringData(u.GetUsername()),
		})
		if err != nil {
			return nil, err
		}
		if mu, ok := res.(*mqlStackitMongoDbFlexInstanceUser); ok {
			mu.cacheInstanceId = r.Id.Data
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitMongoDbFlexInstanceUser) fetchDetail() (*mongodbflex.InstanceResponseUser, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetUser(bgctx(), c.ProjectID(), r.cacheInstanceId, r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitMongoDbFlexInstanceUser) roles() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	return strSlice(d.GetRoles()), nil
}

func (r *mqlStackitMongoDbFlexInstanceUser) database() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetDatabase(), nil
}

func (r *mqlStackitMongoDbFlexInstanceUser) host() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetHost(), nil
}

func (r *mqlStackitMongoDbFlexInstanceUser) port() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return d.GetPort(), nil
}

type mqlStackitSqlServerFlexInstanceUserInternal struct {
	cacheInstanceId string
	fetched         atomic.Bool
	detail          *sqlserverflex.UserResponseUser
	lock            sync.Mutex
}

func (r *mqlStackitSqlServerFlexInstance) users() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUsers(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		u := &items[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.sqlServerFlex.instance.user", map[string]*llx.RawData{
			// the user id is only unique within its instance, so the cache key
			// has to carry the instance it belongs to
			"__id":     llx.StringData(qualifiedId("stackit.sqlServerFlex.instance.user", r.Id.Data, u.GetId())),
			"id":       llx.StringData(u.GetId()),
			"username": llx.StringData(u.GetUsername()),
		})
		if err != nil {
			return nil, err
		}
		if mu, ok := res.(*mqlStackitSqlServerFlexInstanceUser); ok {
			mu.cacheInstanceId = r.Id.Data
		}
		out = append(out, res)
	}
	return out, nil
}

// fetchDetail loads the user record. The SQLServer Flex response model also
// carries the user's password and a ready-to-use connection URI; neither is
// mapped onto the resource.
func (r *mqlStackitSqlServerFlexInstanceUser) fetchDetail() (*sqlserverflex.UserResponseUser, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetUser(bgctx(), c.ProjectID(), r.cacheInstanceId, r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitSqlServerFlexInstanceUser) roles() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	return strSlice(d.GetRoles()), nil
}

func (r *mqlStackitSqlServerFlexInstanceUser) defaultDatabase() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetDefaultDatabase(), nil
}

func (r *mqlStackitSqlServerFlexInstanceUser) host() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetHost(), nil
}

func (r *mqlStackitSqlServerFlexInstanceUser) port() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return d.GetPort(), nil
}

// ------------------------- DBaaS init functions -------------------------
//
// Each instance type's schema declares `init(id? string)` so a user can
// query a single instance by id without listing first. Without these
// functions, `stackit.postgresFlex.instance(id: "uuid")` would hand back
// a zero-value resource and silently fail any downstream field reads.

func initStackitPostgresFlexInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("postgres-flex")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.PostgresFlex()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	inst, ok := resp.GetItemOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.postgresFlex.instance with id %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.postgresFlex.instance", map[string]*llx.RawData{
		"id":     llx.StringData(inst.GetId()),
		"name":   llx.StringData(inst.GetName()),
		"status": llx.StringData(inst.GetStatus()),
		"region": llx.StringData(c.Region()),
	})
	if err != nil {
		return nil, nil, err
	}
	r := res.(*mqlStackitPostgresFlexInstance)
	r.detail = inst
	r.fetched.Store(true)
	return nil, res, nil
}

func initStackitMongoDbFlexInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("mongodb-flex")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.MongoDbFlex()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), id, c.Region()).Execute()
	if err != nil {
		return nil, nil, err
	}
	inst, ok := resp.GetItemOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.mongoDbFlex.instance with id %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.mongoDbFlex.instance", map[string]*llx.RawData{
		"id":     llx.StringData(inst.GetId()),
		"name":   llx.StringData(inst.GetName()),
		"status": llx.StringData(string(inst.GetStatus())),
		"region": llx.StringData(c.Region()),
	})
	if err != nil {
		return nil, nil, err
	}
	r := res.(*mqlStackitMongoDbFlexInstance)
	r.detail = inst
	r.fetched.Store(true)
	return nil, res, nil
}

func initStackitOpenSearchInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("opensearch")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.OpenSearch()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.openSearch.instance with id %q not found", id)
	}
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	res, err := CreateResource(runtime, "stackit.openSearch.instance", cfBrokerInstanceArgs(c.Region(), inst, st, stOk, &lop))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func initStackitMariaDbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("mariadb")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.MariaDb()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.mariaDb.instance with id %q not found", id)
	}
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	res, err := CreateResource(runtime, "stackit.mariaDb.instance", cfBrokerInstanceArgs(c.Region(), inst, st, stOk, &lop))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func initStackitRedisInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("redis")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Redis()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.redis.instance with id %q not found", id)
	}
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	res, err := CreateResource(runtime, "stackit.redis.instance", cfBrokerInstanceArgs(c.Region(), inst, st, stOk, &lop))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func initStackitRabbitMqInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("rabbitmq")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.RabbitMq()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.rabbitMq.instance with id %q not found", id)
	}
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	res, err := CreateResource(runtime, "stackit.rabbitMq.instance", cfBrokerInstanceArgs(c.Region(), inst, st, stOk, &lop))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func initStackitSecretsManagerInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("secrets-manager")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.secretsManager.instance with id %q not found", id)
	}
	res, err := buildSecretsManagerInstance(runtime, inst)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func initStackitObservabilityInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Observability()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), id, c.ProjectID()).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := CreateResource(runtime, "stackit.observability.instance", map[string]*llx.RawData{
		"id":           llx.StringData(resp.GetId()),
		"name":         llx.StringData(resp.GetName()),
		"status":       llx.StringData(string(resp.GetStatus())),
		"planName":     llx.StringData(resp.GetPlanName()),
		"offeringName": llx.StringData(resp.GetServiceName()),
	})
	if err != nil {
		return nil, nil, err
	}
	r := res.(*mqlStackitObservabilityInstance)
	r.detail = resp
	r.fetched.Store(true)
	return nil, res, nil
}

// ------------------------- LogMe -------------------------
//
// CF service-broker shape, identical to MariaDB/Redis/RabbitMQ: the list
// returns the full instance surface (plan, offering, parameters), so there
// is no separate detail fetch.

func (r *mqlStackitLogMe) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.LogMe()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetInstancesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		lop := inst.GetLastOperation()
		st, stOk := inst.GetStatusOk()
		args := cfBrokerInstanceArgs(c.Region(), &inst, st, stOk, &lop)
		res, err := CreateResource(r.MqlRuntime, "stackit.logMe.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitLogMeInstance) id() (string, error) {
	return "stackit.logMe.instance/" + r.Id.Data, nil
}

func initStackitLogMeInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("logme")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.LogMe()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.logMe.instance with id %q not found", id)
	}
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	res, err := CreateResource(runtime, "stackit.logMe.instance", cfBrokerInstanceArgs(c.Region(), inst, st, stOk, &lop))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- SQLServer Flex -------------------------
//
// Flex shape, identical to Postgres/MongoDB Flex: the list returns
// id/name/status only; version/flavor/acl/replicas/storage/backupSchedule/
// options are lazy-loaded once per instance via GetInstance.

type mqlStackitSqlServerFlexInstanceInternal struct {
	fetched atomic.Bool
	detail  *sqlserverflex.Instance
	lock    sync.Mutex

	// v3 holds the v3 API's record of the instance (dbaas_flex_v3.go).
	v3 flexV3Detail
}

func (r *mqlStackitSqlServerFlex) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		inst := items[i]
		args := map[string]*llx.RawData{
			"id":     llx.StringData(inst.GetId()),
			"name":   llx.StringData(inst.GetName()),
			"status": llx.StringData(inst.GetStatus()),
			"region": llx.StringData(c.Region()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.sqlServerFlex.instance", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSqlServerFlexInstance) id() (string, error) {
	return "stackit.sqlServerFlex.instance/" + r.Id.Data, nil
}

func (r *mqlStackitSqlServerFlexInstance) fetchDetail() (*sqlserverflex.Instance, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if item, ok := resp.GetItemOk(); ok {
		r.detail = item
	}
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitSqlServerFlexInstance) version() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetVersion(), nil
}

func (r *mqlStackitSqlServerFlexInstance) flavor() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetFlavor()), nil
}

func (r *mqlStackitSqlServerFlexInstance) acl() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return []any{}, err
	}
	if a, ok := d.GetAclOk(); ok {
		return strSlice(a.GetItems()), nil
	}
	return []any{}, nil
}

func (r *mqlStackitSqlServerFlexInstance) replicas() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(d.GetReplicas()), nil
}

func (r *mqlStackitSqlServerFlexInstance) storage() (any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return toDict(d.GetStorage()), nil
}

func (r *mqlStackitSqlServerFlexInstance) backupSchedule() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return d.GetBackupSchedule(), nil
}

func (r *mqlStackitSqlServerFlexInstance) options() (map[string]any, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return map[string]any{}, err
	}
	return stringMap(d.GetOptions()), nil
}

// The SDK documents two keys inside the SQL Server Flex options map
// (InstanceDocumentationOptions): `edition` and `retentionDays`. They are
// hoisted here so a policy reads a typed value instead of a string in a map.

// edition reports the SQL Server edition the instance runs (for example
// developer, express, standard, or enterprise), which decides the feature
// set available to it. Null when the instance detail could not be read or
// carries no edition.
func (r *mqlStackitSqlServerFlexInstance) edition() (string, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return "", err
	}
	edition, ok := sqlServerOption(d, "edition")
	if !ok {
		r.Edition.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return edition, nil
}

// backupRetentionDays reports how many days backup files are kept before
// cleanup, from the instance's `retentionDays` option. Null when the detail
// could not be read, the option is absent, or it does not parse as a number.
func (r *mqlStackitSqlServerFlexInstance) backupRetentionDays() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return 0, err
	}
	days, ok := sqlServerRetentionDays(d)
	if !ok {
		r.BackupRetentionDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return days, nil
}

// sqlServerOption reads one key from the instance's options map, reporting
// whether it was present and non-empty.
func sqlServerOption(d *sqlserverflex.Instance, key string) (string, bool) {
	if d == nil {
		return "", false
	}
	opts, ok := d.GetOptionsOk()
	if !ok || opts == nil {
		return "", false
	}
	v, ok := (*opts)[key]
	if !ok || strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}

// sqlServerRetentionDays parses the `retentionDays` option, which the API
// carries as a decimal string, into days. It reports false rather than a
// zero when the option is absent or malformed, so the field reads null.
func sqlServerRetentionDays(d *sqlserverflex.Instance) (int64, bool) {
	raw, ok := sqlServerOption(d, "retentionDays")
	if !ok {
		return 0, false
	}
	days, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || days < 0 {
		return 0, false
	}
	return days, true
}

func initStackitSqlServerFlexInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("sqlserver-flex")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.SqlServerFlex()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), id, c.Region()).Execute()
	if err != nil {
		return nil, nil, err
	}
	inst, ok := resp.GetItemOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.sqlServerFlex.instance with id %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.sqlServerFlex.instance", map[string]*llx.RawData{
		"id":     llx.StringData(inst.GetId()),
		"name":   llx.StringData(inst.GetName()),
		"status": llx.StringData(inst.GetStatus()),
		"region": llx.StringData(c.Region()),
	})
	if err != nil {
		return nil, nil, err
	}
	r := res.(*mqlStackitSqlServerFlexInstance)
	r.detail = inst
	r.fetched.Store(true)
	return nil, res, nil
}
