// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

const (
	gcsAllUsers              = "allUsers"
	gcsAllAuthenticatedUsers = "allAuthenticatedUsers"
)

func (g *mqlGcpProjectStorageService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("gcp.project.storageService/%s", projectId), nil
}

func initGcpProjectStorageService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

type mqlGcpProjectStorageServiceInternal struct {
	serviceGate
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectStorageService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_storage)
}

func (g *mqlGcpProject) storage() (*mqlGcpProjectStorageService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.storageService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_storage)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectStorageService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_storage).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func (g *mqlGcpProjectStorageService) buckets() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, storage.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	storageSvc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// List the buckets of the project this service resource belongs to, not the
	// project the connection happens to be scoped to: `gcp.projects` materializes
	// every accessible project in one runtime, and on an organization or folder
	// connection ResourceID() is not a project id at all.
	var res []any
	if err := storageSvc.Buckets.List(projectId).Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			if conn.Filters.Storage.IsFilteredOut(bucket.Name) {
				continue
			}
			mqlBucket, err := mqlBucketFromAPI(g.MqlRuntime, projectId, bucket)
			if err != nil {
				return err
			}
			res = append(res, mqlBucket)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// bucketRetentionPeriodSeconds returns the retention period (in seconds)
// enforced by a bucket's retention policy, or 0 when no policy is set.
func bucketRetentionPeriodSeconds(rp *storage.BucketRetentionPolicy) int64 {
	if rp == nil {
		return 0
	}
	return rp.RetentionPeriod
}

// bucketSoftDeleteRetentionSeconds returns the soft-delete retention duration
// (in seconds), or 0 when no soft-delete policy is set.
func bucketSoftDeleteRetentionSeconds(sdp *storage.BucketSoftDeletePolicy) int64 {
	if sdp == nil {
		return 0
	}
	return sdp.RetentionDurationSeconds
}

// bucketHardDeletePause returns whether hard deletion of soft-deleted objects
// is paused and the time the pause became effective. An absent soft-delete
// policy or pause block means hard deletes are not paused; the time is nil
// when absent or unparseable.
func bucketHardDeletePause(sdp *storage.BucketSoftDeletePolicy) (bool, *time.Time) {
	if sdp == nil || sdp.HardDeletePause == nil {
		return false, nil
	}
	return sdp.HardDeletePause.Enabled, parseTime(sdp.HardDeletePause.EffectiveTime)
}

// mqlBucketFromAPI converts a *storage.Bucket into a fully-populated mql
// resource. Used by buckets() during a list and by init when resolving a
// single bucket by name.
func mqlBucketFromAPI(runtime *plugin.Runtime, projectId string, bucket *storage.Bucket) (*mqlGcpProjectStorageServiceBucket, error) {
	created := parseTime(bucket.TimeCreated)
	updated := parseTime(bucket.Updated)

	iamConfigurationDict := bucketIamConfigurationDict(bucket.IamConfiguration)
	retentionPolicy := bucketRetentionPolicyDict(bucket.RetentionPolicy)
	enc, err := convert.JsonToDict(bucket.Encryption)
	if err != nil {
		return nil, err
	}

	publicAccessPrevention := ""
	var uniformBucketLevelAccess map[string]any
	if bucket.IamConfiguration != nil {
		publicAccessPrevention = bucket.IamConfiguration.PublicAccessPrevention
		uniformBucketLevelAccess = bucketUniformBucketLevelAccessDict(bucket.IamConfiguration.UniformBucketLevelAccess)
	}

	softDeletePolicy, err := convert.JsonToDict(bucket.SoftDeletePolicy)
	if err != nil {
		return nil, err
	}

	objectRetentionMode := ""
	if bucket.ObjectRetention != nil {
		objectRetentionMode = bucket.ObjectRetention.Mode
	}

	autoclass := bucketAutoclassDict(bucket.Autoclass)
	ipFilter := bucketIpFilterDict(bucket.IpFilter)
	hierarchicalNamespace := bucketHierarchicalNamespaceDict(bucket.HierarchicalNamespace)

	customPlacementConfig, err := convert.JsonToDict(bucket.CustomPlacementConfig)
	if err != nil {
		return nil, err
	}

	logging, err := convert.JsonToDict(bucket.Logging)
	if err != nil {
		return nil, err
	}

	cors, err := convert.JsonToDictSlice(bucket.Cors)
	if err != nil {
		return nil, err
	}

	website, err := convert.JsonToDict(bucket.Website)
	if err != nil {
		return nil, err
	}

	billing := bucketBillingDict(bucket.Billing)

	owner, err := convert.JsonToDict(bucket.Owner)
	if err != nil {
		return nil, err
	}

	softDeleteTime := parseTime(bucket.SoftDeleteTime)
	hardDeletePauseEnabled, hardDeletePauseEffectiveTime := bucketHardDeletePause(bucket.SoftDeletePolicy)

	ipFilterConfig, err := newMqlBucketIpFilterConfig(runtime, "gcp.project.storageService.bucket/"+bucket.Id, bucket.IpFilter)
	if err != nil {
		return nil, err
	}

	mqlInstance, err := CreateResource(runtime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"id":                    llx.StringData(bucket.Id),
		"projectId":             llx.StringData(projectId),
		"name":                  llx.StringData(bucket.Name),
		"labels":                llx.MapData(convert.MapToInterfaceMap(bucket.Labels), types.String),
		"location":              llx.StringData(bucket.Location),
		"locationType":          llx.StringData(bucket.LocationType),
		"projectNumber":         llx.StringData(strconv.FormatUint(bucket.ProjectNumber, 10)),
		"storageClass":          llx.StringData(bucket.StorageClass),
		"created":               llx.TimeDataPtr(created),
		"updated":               llx.TimeDataPtr(updated),
		"iamConfiguration":      llx.DictData(iamConfigurationDict),
		"retentionPolicy":       llx.DictData(retentionPolicy),
		"retentionPolicyLocked": llx.BoolData(bucket.RetentionPolicy != nil && bucket.RetentionPolicy.IsLocked),
		"retentionPeriod":       llx.IntData(bucketRetentionPeriodSeconds(bucket.RetentionPolicy)),
		"loggingEnabled":        llx.BoolData(bucket.Logging != nil && bucket.Logging.LogBucket != ""),
		"encryption":            llx.DictData(enc),
		"lifecycle": llx.ArrayData(
			storageLifecycleRulesToArrayInterface(runtime, bucket.Id, bucket.Lifecycle),
			types.Resource("gcp.project.storageService.bucket.lifecycleRule"),
		),
		"defaultEventBasedHold":        llx.BoolData(bucket.DefaultEventBasedHold),
		"rpo":                          llx.StringData(bucket.Rpo),
		"satisfiesPZS":                 llx.BoolData(bucket.SatisfiesPZS),
		"satisfiesPZI":                 llx.BoolData(bucket.SatisfiesPZI),
		"versioningEnabled":            llx.BoolData(bucket.Versioning != nil && bucket.Versioning.Enabled),
		"publicAccessPrevention":       llx.StringData(publicAccessPrevention),
		"metageneration":               llx.IntData(bucket.Metageneration),
		"uniformBucketLevelAccess":     llx.DictData(uniformBucketLevelAccess),
		"softDeletePolicy":             llx.DictData(softDeletePolicy),
		"softDeleteRetentionDuration":  llx.IntData(bucketSoftDeleteRetentionSeconds(bucket.SoftDeletePolicy)),
		"softDeleteTime":               llx.TimeDataPtr(softDeleteTime),
		"hardDeletePauseEnabled":       llx.BoolData(hardDeletePauseEnabled),
		"hardDeletePauseEffectiveTime": llx.TimeDataPtr(hardDeletePauseEffectiveTime),
		"objectRetentionMode":          llx.StringData(objectRetentionMode),
		"autoclass":                    llx.DictData(autoclass),
		"ipFilter":                     llx.DictData(ipFilter),
		"ipFilterConfig":               ipFilterConfig,
		"hierarchicalNamespace":        llx.DictData(hierarchicalNamespace),
		"customPlacementConfig":        llx.DictData(customPlacementConfig),
		"logging":                      llx.DictData(logging),
		"cors":                         llx.ArrayData(cors, types.Dict),
		"website":                      llx.DictData(website),
		"billing":                      llx.DictData(billing),
		"owner":                        llx.DictData(owner),
	})
	if err != nil {
		return nil, err
	}
	mqlBucket := mqlInstance.(*mqlGcpProjectStorageServiceBucket)
	if bucket.Encryption != nil {
		mqlBucket.cacheDefaultKmsKeyName = bucket.Encryption.DefaultKmsKeyName
	}
	if bucket.Logging != nil {
		mqlBucket.cacheLogBucket = bucket.Logging.LogBucket
	}
	return mqlBucket, nil
}

type mqlGcpProjectStorageServiceBucketInternal struct {
	cacheDefaultKmsKeyName string
	cacheLogBucket         string

	aclLock sync.Mutex
	// atomic: acl(), defaultObjectAcl() and public() all call fetchAcls() and
	// the executor runs block members concurrently, so the fast-path read
	// races the write with a plain bool.
	aclFetched         atomic.Bool
	cacheAcl           []*storage.BucketAccessControl
	cacheDefaultObjAcl []*storage.ObjectAccessControl
}

func (g *mqlGcpProjectStorageServiceBucket) defaultKmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheDefaultKmsKeyName == "" {
		g.DefaultKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheDefaultKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectStorageServiceBucket) defaultEncryptionEnabled() (bool, error) {
	return g.cacheDefaultKmsKeyName != "", nil
}

func (g *mqlGcpProjectStorageServiceBucket) logBucket() (*mqlGcpProjectStorageServiceBucket, error) {
	if g.cacheLogBucket == "" {
		g.LogBucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.storageService.bucket",
		map[string]*llx.RawData{"name": llx.StringData(g.cacheLogBucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}

func (g *mqlGcpProjectStorageServiceBucket) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectStorageServiceBucket) tags() (map[string]interface{}, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	bucketName := g.Name.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}

	// The bucket location is required to route to the correct regional endpoint.
	if g.Location.Error != nil {
		return nil, g.Location.Error
	}
	location := strings.ToLower(g.Location.Data)

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// GCS bucket tag bindings require the regional cloudresourcemanager endpoint.
	// The global endpoint rejects the request with "not a valid One Platform resource name".
	regionalEndpoint := fmt.Sprintf("https://%s-cloudresourcemanager.googleapis.com/", location)
	svc, err := cloudresourcemanager.NewService(ctx,
		option.WithHTTPClient(client),
		option.WithEndpoint(regionalEndpoint),
	)
	if err != nil {
		return nil, err
	}

	// Use EffectiveTagBindingCollections to get both directly-attached tags AND
	// tags inherited from parent resources (project, folder, organization).
	// Use projects/_ wildcard — the documented format for GCS bucket resource names.
	fullResource := fmt.Sprintf("//storage.googleapis.com/projects/_/buckets/%s", bucketName)
	encodedResource := url.PathEscape(fullResource)
	name := fmt.Sprintf("locations/%s/effectiveTagBindingCollections/%s", location, encodedResource)

	resp, err := svc.Locations.EffectiveTagBindingCollections.Get(name).Context(ctx).Do()
	if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && (gerr.Code == 403 || gerr.Code == 404) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}

	return effectiveTagsToInterface(resp.EffectiveTags), nil
}

// effectiveTagsToInterface converts the EffectiveTags map from the
// cloudresourcemanager API (map[string]string) to map[string]interface{}
// as required by MQL. Unexported; tested directly in storage_test.go.
func effectiveTagsToInterface(in map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func storageLifecycleRulesToArrayInterface(runtime *plugin.Runtime, bucketId string, lifecycle *storage.BucketLifecycle) (list []any) {
	if lifecycle == nil {
		return
	}
	for i, rule := range lifecycle.Rule {
		if rule == nil {
			continue
		}

		var (
			action      plugin.Resource
			condition   plugin.Resource
			err         error
			skip        = true
			ruleRawData = map[string]*llx.RawData{}
		)

		// create rule action resource
		if rule.Action != nil {
			action, err = CreateResource(runtime, "gcp.project.storageService.bucket.lifecycleRuleAction", map[string]*llx.RawData{
				"__id": llx.StringData(
					fmt.Sprintf("gcp.project.storageService.bucket.lifecycleRuleAction/%s/%d", bucketId, i),
				),
				"storageClass": llx.StringData(rule.Action.StorageClass),
				"type":         llx.StringData(rule.Action.Type),
			})
			if err != nil {
				continue
			}
			ruleRawData["action"] = llx.ResourceData(action, action.MqlName())
			skip = false
		}

		// create rule condition resource
		if rule.Condition != nil {
			condition, err = CreateResource(runtime, "gcp.project.storageService.bucket.lifecycleRuleCondition", map[string]*llx.RawData{
				"__id": llx.StringData(
					fmt.Sprintf("gcp.project.storageService.bucket.lifecycleRuleCondition/%s/%d", bucketId, i),
				),
				"age":                     llx.IntDataPtr(rule.Condition.Age),
				"daysSinceCustomTime":     llx.IntData(rule.Condition.DaysSinceCustomTime),
				"daysSinceNoncurrentTime": llx.IntData(rule.Condition.DaysSinceNoncurrentTime),
				"numNewerVersions":        llx.IntData(rule.Condition.NumNewerVersions),
				"isLive":                  llx.BoolDataPtr(rule.Condition.IsLive),
				"createdBefore":           llx.StringData(rule.Condition.CreatedBefore),
				"customTimeBefore":        llx.StringData(rule.Condition.CustomTimeBefore),
				"matchesPattern":          llx.StringData(rule.Condition.MatchesPattern),
				"noncurrentTimeBefore":    llx.StringData(rule.Condition.NoncurrentTimeBefore),
				"matchesPrefix":           llx.ArrayData(convert.SliceAnyToInterface(rule.Condition.MatchesPrefix), types.String),
				"matchesStorageClass":     llx.ArrayData(convert.SliceAnyToInterface(rule.Condition.MatchesStorageClass), types.String),
				"matchesSuffix":           llx.ArrayData(convert.SliceAnyToInterface(rule.Condition.MatchesSuffix), types.String),
			})
			if err != nil {
				continue
			}
			ruleRawData["condition"] = llx.ResourceData(condition, condition.MqlName())
			skip = false
		}

		// if the rule doesn't have an action or a condition, skip it
		if skip {
			continue
		}

		// add the rule id
		ruleRawData["__id"] = llx.StringData(
			fmt.Sprintf("gcp.project.storageService.bucket.lifecycleRule/%s/%d", bucketId, i),
		)

		r, err := CreateResource(runtime, "gcp.project.storageService.bucket.lifecycleRule", ruleRawData)
		if err != nil {
			continue
		}
		list = append(list, r)
	}

	return
}

func (g *mqlGcpProjectStorageServiceBucket) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("gcp.project.storageService.bucket/%s/%s", projectId, id), nil
}

func initGcpProjectStorageServiceBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID. The asset
	// identifier path supplies all three (name + projectId + location).
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(ids.name)
		args["projectId"] = llx.StringData(ids.project)
		args["location"] = llx.StringData(ids.region)
	}

	// Resolve the bucket directly via Buckets.Get(name). Bucket names are
	// globally unique in GCS, so a single Get returns everything we need —
	// including projectNumber and location — even when the caller only
	// supplied "name" (e.g. cross-resource references like a Datastream
	// connection profile pointing at a GCS bucket).
	nameRaw, ok := args["name"]
	if !ok || nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.storageService.bucket requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.storageService.bucket requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, storage.CloudPlatformScope)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	storageSvc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}
	bucket, err := storageSvc.Buckets.Get(name).Do()
	if err != nil {
		return nil, nil, err
	}

	// Derive projectId from caller args when supplied; otherwise fall back to
	// the connection's project. Bucket.ProjectNumber is numeric (not the
	// human ID) so we can't use it directly as projectId.
	projectId := conn.ResourceID()
	if pidRaw, ok := args["projectId"]; ok && pidRaw != nil {
		if s, ok := pidRaw.Value.(string); ok && s != "" {
			projectId = s
		}
	}
	mqlBucket, err := mqlBucketFromAPI(runtime, projectId, bucket)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlBucket, nil
}

func (g *mqlGcpProjectStorageServiceBucket) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	bucketName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, storage.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	storeSvc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// Request policy schema v3 so conditional bindings are returned; the
	// default v1 omits any binding carrying an IAM condition, which would hide
	// conditional grants (including conditional public-access bindings).
	policy, err := storeSvc.Buckets.GetIamPolicy(bucketName).OptionsRequestedPolicyVersion(3).Do()
	if err != nil {
		// Degrade a permission gap to an empty policy rather than a hard error,
		// matching sibling IAM-policy accessors, and so public() can still fall
		// back to its ACL check instead of failing outright.
		if isSkippable(err) {
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	for i := range policy.Bindings {
		b := policy.Bindings[i]

		var conditionTitle, conditionExpression, conditionDescription string
		if b.Condition != nil {
			conditionTitle = b.Condition.Title
			conditionExpression = b.Condition.Expression
			conditionDescription = b.Condition.Description
		}

		mqlServiceaccount, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(bucketName + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(conditionTitle),
			"conditionExpression":  llx.StringData(conditionExpression),
			"conditionDescription": llx.StringData(conditionDescription),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServiceaccount)
	}

	return res, nil
}

// Buckets.List defaults to projection=noAcl, so acl/defaultObjectAcl require a
// follow-up Buckets.Get with projection=full. They're also nil when uniform
// bucket-level access is enabled.
func (g *mqlGcpProjectStorageServiceBucket) fetchAcls() error {
	if g.aclFetched.Load() {
		return nil
	}
	g.aclLock.Lock()
	defer g.aclLock.Unlock()
	if g.aclFetched.Load() {
		return nil
	}

	if g.Name.Error != nil {
		return g.Name.Error
	}
	bucketName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, storage.CloudPlatformScope)
	if err != nil {
		return err
	}
	ctx := context.Background()
	storeSvc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return err
	}

	bucket, err := storeSvc.Buckets.Get(bucketName).Projection("full").Do()
	if err != nil {
		return err
	}

	g.cacheAcl = bucket.Acl
	g.cacheDefaultObjAcl = bucket.DefaultObjectAcl
	g.aclFetched.Store(true)
	return nil
}

func (g *mqlGcpProjectStorageServiceBucket) acl() ([]any, error) {
	if err := g.fetchAcls(); err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(g.cacheAcl)
}

func (g *mqlGcpProjectStorageServiceBucket) defaultObjectAcl() ([]any, error) {
	if err := g.fetchAcls(); err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(g.cacheDefaultObjAcl)
}

func (g *mqlGcpProjectStorageServiceBucket) public() (bool, error) {
	if g.PublicAccessPrevention.Error != nil {
		return false, g.PublicAccessPrevention.Error
	}
	// PAP=enforced is GCS's hard block — short-circuit before any IAM/ACL fetch.
	if g.PublicAccessPrevention.Data == "enforced" {
		return false, nil
	}

	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	for _, raw := range bindings.Data {
		binding, ok := raw.(*mqlGcpResourcemanagerBinding)
		if !ok || binding == nil {
			continue
		}
		members := binding.GetMembers()
		if members.Error != nil {
			return false, members.Error
		}
		for _, m := range members.Data {
			if s, ok := m.(string); ok && isPublicEntity(s) {
				return true, nil
			}
		}
	}

	if err := g.fetchAcls(); err != nil {
		return false, err
	}
	return aclsHavePublicEntity(g.cacheAcl, g.cacheDefaultObjAcl), nil
}

// evaluateBucketPublic is the canonical logic behind bucket.public(), used for
// unit testing. The bucket.public() method itself short-circuits on PAP and IAM
// before fetching ACLs to avoid an unnecessary Buckets.Get call.
func evaluateBucketPublic(pap string, iamMembers []string, acl []*storage.BucketAccessControl, defaultObjectAcl []*storage.ObjectAccessControl) bool {
	if pap == "enforced" {
		return false
	}
	if anyPublicEntity(iamMembers) {
		return true
	}
	return aclsHavePublicEntity(acl, defaultObjectAcl)
}

func aclsHavePublicEntity(acl []*storage.BucketAccessControl, defaultObjectAcl []*storage.ObjectAccessControl) bool {
	for _, entry := range acl {
		if entry != nil && isPublicEntity(entry.Entity) {
			return true
		}
	}
	for _, entry := range defaultObjectAcl {
		if entry != nil && isPublicEntity(entry.Entity) {
			return true
		}
	}
	return false
}

func isPublicEntity(s string) bool {
	return s == gcsAllUsers || s == gcsAllAuthenticatedUsers
}

func anyPublicEntity(entities []string) bool {
	return slices.ContainsFunc(entities, isPublicEntity)
}

func (g *mqlGcpProjectStorageServiceBucket) uniformBucketLevelAccessEnabled() (bool, error) {
	v := g.GetUniformBucketLevelAccess()
	if v.Error != nil {
		return false, v.Error
	}
	if v.Data == nil {
		return false, nil
	}
	m, ok := v.Data.(map[string]any)
	if !ok {
		return false, nil
	}
	enabled, _ := m["enabled"].(bool)
	return enabled, nil
}

func (g *mqlGcpProjectStorageServiceBucket) softDeletePolicyEnabled() (bool, error) {
	v := g.GetSoftDeletePolicy()
	if v.Error != nil {
		return false, v.Error
	}
	if v.Data == nil {
		return false, nil
	}
	m, ok := v.Data.(map[string]any)
	if !ok {
		return false, nil
	}
	switch d := m["retentionDurationSeconds"].(type) {
	case string:
		return d != "" && d != "0" && d != "0s", nil
	case float64:
		return d > 0, nil
	case int64:
		return d > 0, nil
	case int:
		return d > 0, nil
	}
	return false, nil
}
