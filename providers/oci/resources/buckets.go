// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (e *mqlOciObjectStorage) id() (string, error) {
	return "oci.objectStorage", nil
}

func (o *mqlOciObjectStorage) namespace() (string, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	ctx := context.Background()
	tenant, err := conn.Tenant(ctx)
	if err != nil {
		return "", err
	}
	if tenant.HomeRegionKey == nil {
		return "", errors.New("tenancy has no home region configured")
	}

	region := *tenant.HomeRegionKey
	client, err := conn.ObjectStorageClient(region)
	if err != nil {
		return "", err
	}

	response, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return "", err
	}

	if response.Value == nil {
		return "", nil
	} else {
		return *response.Value, nil
	}
}

func (o *mqlOciObjectStorage) buckets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	regions, err := ociRegionsFor(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	regionsByID, err := ociRegionsByID(regions)
	if err != nil {
		return nil, err
	}

	namespace, err := o.namespace()
	if err != nil {
		return nil, err
	}

	// Buckets live in any compartment, and ListBuckets answers for one.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			regionResource, ok := regionsByID[region]
			if !ok {
				return nil, errors.New("no oci.region resource for region " + region)
			}

			svc, err := conn.ObjectStorageClient(region)
			if err != nil {
				return nil, err
			}

			buckets, err := o.getBucketsForRegion(ctx, svc, compartmentID, namespace)
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range buckets {
				bucket := buckets[i]

				if conn.Filters.IsFilteredOutByTags(bucket.FreeformTags, bucket.DefinedTags) {
					continue
				}

				var created *time.Time
				if bucket.TimeCreated != nil {
					created = &bucket.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.objectStorage.bucket", stringValue(bucket.CompartmentId), map[string]*llx.RawData{
					"__id":      llx.StringData(ociBucketCacheKey(stringValue(bucket.Namespace), stringValue(bucket.Name))),
					"namespace": llx.StringDataPtr(bucket.Namespace),
					"name":      llx.StringDataPtr(bucket.Name),
					"region":    llx.ResourceData(regionResource, "oci.region"),
					"created":   llx.TimeDataPtr(created),
					// Listed with the bucket, so no GetBucket is needed for them.
					"freeformTags": llx.MapData(strMapToAny(bucket.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(bucket.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}
			return res, nil
		})
}

// getBucketsForRegion lists a compartment's buckets with their tags.
// ListBuckets returns tags only when they are asked for: without them every
// bucket failed a tag filter, and the bucket assets carried no labels.
func (o *mqlOciObjectStorage) getBucketsForRegion(ctx context.Context, objectStorageClient *objectstorage.ObjectStorageClient, compartmentID string, namespace string) ([]objectstorage.BucketSummary, error) {
	fields := []objectstorage.ListBucketsFieldsEnum{objectstorage.ListBucketsFieldsTags}
	entries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]objectstorage.BucketSummary, *string, error) {
		request := objectstorage.ListBucketsRequest{
			NamespaceName: common.String(namespace),
			CompartmentId: common.String(compartmentID),
			Fields:        fields,
			Page:          page,
		}

		response, err := objectStorageClient.ListBuckets(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

type mqlOciObjectStorageBucketInternal struct {
	ociCompartmentRef
	bucket ociRetryLazy[*objectstorage.Bucket]
}

// ociBucketCacheKey is the bucket's cache key. It is passed explicitly as
// "__id" at every construction site rather than derived from an id() method,
// because id() now reports the real bucket OCID, which is only knowable from
// the detail call - deriving the cache key from it would make constructing a
// bucket resource issue an API request.
func ociBucketCacheKey(namespace, name string) string {
	return "oci.objectStorage.bucket/" + namespace + "/" + name
}

// ocid reports the bucket OCID, which ListBuckets does not return. It resolves
// identically on the listing and single-bucket paths, since both reach the
// detail call.
func (o *mqlOciObjectStorageBucket) ocid() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return stringValue(bucketInfo.Id), nil
}

func initOciObjectStorageBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// There is deliberately no id-only fast path. OCI keys GetBucket on
	// namespace+name, not on the bucket OCID, so an id alone cannot be
	// resolved - and the resulting resource would take the cache key
	// "oci.objectStorage.bucket//" (both name parts empty), which every
	// id-only bucket would share.

	// When cnspec scans a discovered oci-objectstorage-bucket asset the only
	// context we have is the Conf.PlatformId. Parse out namespace/name so the
	// singular `oci.objectStorage.bucket` resolves to that specific bucket
	// without the policy having to pass explicit args.
	if ociArgString(args, "namespace") == "" && ociArgString(args, "name") == "" {
		if conn, ok := runtime.Connection.(*connection.OciConnection); ok && conn.Conf != nil && conn.Conf.PlatformId != "" {
			if parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId); ok &&
				parsed.service == "objectstorage" && parsed.objectType == "bucket" {
				// Bucket platform ids encode "<namespace>/<name>".
				if slash := strings.IndexByte(parsed.id, '/'); slash > 0 && slash < len(parsed.id)-1 {
					if args == nil {
						args = map[string]*llx.RawData{}
					}
					args["namespace"] = llx.StringData(parsed.id[:slash])
					args["name"] = llx.StringData(parsed.id[slash+1:])
					if parsed.region != "" && parsed.region != "unknown" {
						// region is a typed oci.region resource; we have only
						// its id (the region key). Create the reference so
						// subsequent accessors can use it.
						regionRes, err := NewResource(runtime, "oci.region", map[string]*llx.RawData{
							"id": llx.StringData(parsed.region),
						})
						if err == nil {
							args["region"] = llx.ResourceData(regionRes, "oci.region")
						}
					}
				}
			}
		}
	}

	// The cache key must be supplied explicitly: id() reports the bucket OCID
	// from the detail call, so letting the generated Create fall back to it
	// would issue an API request just to key the resource.
	if ns, name := ociArgString(args, "namespace"), ociArgString(args, "name"); ns != "" || name != "" {
		if args == nil {
			args = map[string]*llx.RawData{}
		}
		args["__id"] = llx.StringData(ociBucketCacheKey(ns, name))
	}

	obj, err := CreateResource(runtime, "oci.objectStorage.bucket", args)
	if err != nil {
		return nil, nil, err
	}
	bucket := obj.(*mqlOciObjectStorageBucket)

	// This is the only compartment-bearing resource whose init constructs its
	// own resource rather than handing back one the listing path already built,
	// so nothing has recorded the compartment OCID for it. The detail call is
	// made here anyway, and it carries the compartment - take it from there, or
	// a single-bucket lookup reports a null compartment().
	details, err := bucket.getBucketDetails()
	if err != nil {
		return nil, nil, err
	}
	bucket.setCompartmentID(stringValue(details.CompartmentId))

	return args, bucket, nil
}

// getBucketDetails lazily fetches the full bucket, which carries the fields
// ListBuckets omits (public access, versioning, encryption, counts). Sixteen
// accessors share it, and the runtime resolves them concurrently, so the fetch
// is guarded rather than racing sixteen identical GetBucket calls.
func (o *mqlOciObjectStorageBucket) getBucketDetails() (*objectstorage.Bucket, error) {
	return o.bucket.get(func() (*objectstorage.Bucket, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		region := o.GetRegion()
		if region.Error != nil {
			return nil, region.Error
		}

		if region.Data == nil {
			return nil, errors.New("oci.objectStorage.bucket: region is required to fetch bucket details")
		}

		r := region.Data
		client, err := conn.ObjectStorageClient(r.Id.Data)
		if err != nil {
			return nil, err
		}

		namespace := o.GetNamespace()
		if namespace.Error != nil {
			return nil, namespace.Error
		}

		name := o.GetName()
		if name.Error != nil {
			return nil, name.Error
		}

		response, err := client.GetBucket(context.Background(), objectstorage.GetBucketRequest{
			NamespaceName: common.String(namespace.Data),
			BucketName:    common.String(name.Data),
			Fields: []objectstorage.GetBucketFieldsEnum{
				objectstorage.GetBucketFieldsApproximatecount,
				objectstorage.GetBucketFieldsApproximatesize,
				objectstorage.GetBucketFieldsAutotiering,
			},
		})
		if err != nil {
			return nil, err
		}

		return &response.Bucket, nil
	})
}

func (o *mqlOciObjectStorageBucket) publicAccessType() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return string(bucketInfo.PublicAccessType), nil
}

func (o *mqlOciObjectStorageBucket) storageTier() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return string(bucketInfo.StorageTier), nil
}

func (o *mqlOciObjectStorageBucket) autoTiering() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return string(bucketInfo.AutoTiering), nil
}

func (o *mqlOciObjectStorageBucket) versioning() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return string(bucketInfo.Versioning), nil
}

func (o *mqlOciObjectStorageBucket) objectEventsEnabled() (bool, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return false, err
	}
	if bucketInfo.ObjectEventsEnabled == nil {
		return false, nil
	}
	return *bucketInfo.ObjectEventsEnabled, nil
}

func (o *mqlOciObjectStorageBucket) replicationEnabled() (bool, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return false, err
	}
	if bucketInfo.ReplicationEnabled == nil {
		return false, nil
	}
	return *bucketInfo.ReplicationEnabled, nil
}

func (o *mqlOciObjectStorageBucket) isReadOnly() (bool, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return false, err
	}
	if bucketInfo.IsReadOnly == nil {
		return false, nil
	}
	return *bucketInfo.IsReadOnly, nil
}

func (o *mqlOciObjectStorageBucket) etag() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	if bucketInfo.Etag == nil {
		return "", nil
	}
	return *bucketInfo.Etag, nil
}

func (o *mqlOciObjectStorageBucket) kmsKeyId() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	if bucketInfo.KmsKeyId == nil {
		return "", nil
	}
	return *bucketInfo.KmsKeyId, nil
}

// kmsKey resolves the customer-managed key the bucket is encrypted with.
//
// Null for a bucket on an Oracle-managed key, which is the absence of a
// customer key rather than an unread one.
func (o *mqlOciObjectStorageBucket) kmsKey() (*mqlOciKmsKey, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(stringValue(bucketInfo.KmsKeyId)), &o.KmsKey)
}

func (o *mqlOciObjectStorageBucket) isBucketKeyEnabled() (bool, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return false, err
	}
	return boolValue(bucketInfo.IsBucketKeyEnabled), nil
}

func (o *mqlOciObjectStorageBucket) bucketScope() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	return string(bucketInfo.BucketScope), nil
}

func (o *mqlOciObjectStorageBucket) metadata() (map[string]any, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return nil, err
	}
	return strMapToAny(bucketInfo.Metadata), nil
}

func (o *mqlOciObjectStorageBucket) approximateCount() (int64, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return 0, err
	}
	if bucketInfo.ApproximateCount == nil {
		return 0, nil
	}
	return *bucketInfo.ApproximateCount, nil
}

func (o *mqlOciObjectStorageBucket) approximateSize() (int64, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return 0, err
	}
	if bucketInfo.ApproximateSize == nil {
		return 0, nil
	}
	return *bucketInfo.ApproximateSize, nil
}

func (o *mqlOciObjectStorageBucket) objectLifecyclePolicyEtag() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	if bucketInfo.ObjectLifecyclePolicyEtag == nil {
		return "", nil
	}
	return *bucketInfo.ObjectLifecyclePolicyEtag, nil
}

func (o *mqlOciObjectStorageBucket) freeformTags() (map[string]interface{}, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return nil, err
	}
	tags := make(map[string]interface{})
	for k, v := range bucketInfo.FreeformTags {
		tags[k] = v
	}
	return tags, nil
}

func (o *mqlOciObjectStorageBucket) definedTags() (map[string]interface{}, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return nil, err
	}
	tags := make(map[string]interface{})
	for k, v := range bucketInfo.DefinedTags {
		tags[k] = v
	}
	return tags, nil
}

func (o *mqlOciObjectStorageBucket) createdBy() (string, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return "", err
	}
	if bucketInfo.CreatedBy == nil {
		return "", nil
	}
	return *bucketInfo.CreatedBy, nil
}

func (o *mqlOciObjectStorageBucket) createdByUser() (*mqlOciIdentityUser, error) {
	bucketInfo, err := o.getBucketDetails()
	if err != nil {
		return nil, err
	}
	createdBy := stringValue(bucketInfo.CreatedBy)
	if !strings.HasPrefix(createdBy, "ocid1.user.") {
		o.CreatedByUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.identity.user", map[string]*llx.RawData{
		"id": llx.StringData(createdBy),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciIdentityUser), nil
}

func (o *mqlOciObjectStorageBucket) retentionRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	region := o.GetRegion()
	if region.Error != nil {
		return nil, region.Error
	}
	if region.Data == nil {
		return nil, errors.New("oci.objectStorage.bucket: region is required")
	}

	client, err := conn.ObjectStorageClient(region.Data.Id.Data)
	if err != nil {
		return nil, err
	}

	namespace := o.GetNamespace()
	if namespace.Error != nil {
		return nil, namespace.Error
	}

	name := o.GetName()
	if name.Error != nil {
		return nil, name.Error
	}

	ctx := context.Background()
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]objectstorage.RetentionRuleSummary, *string, error) {
		response, err := client.ListRetentionRules(ctx, objectstorage.ListRetentionRulesRequest{
			NamespaceName: common.String(namespace.Data),
			BucketName:    common.String(name.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(rules))
	for i := range rules {
		r := rules[i]

		var created *time.Time
		if r.TimeCreated != nil {
			created = &r.TimeCreated.Time
		}
		var timeModified *time.Time
		if r.TimeModified != nil {
			timeModified = &r.TimeModified.Time
		}
		var timeRuleLocked *time.Time
		if r.TimeRuleLocked != nil {
			timeRuleLocked = &r.TimeRuleLocked.Time
		}

		var durationAmount int64
		var durationTimeUnit string
		if r.Duration != nil {
			durationAmount = int64Value(r.Duration.TimeAmount)
			durationTimeUnit = string(r.Duration.TimeUnit)
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.objectStorage.retentionRule", map[string]*llx.RawData{
			"id":               llx.StringDataPtr(r.Id),
			"name":             llx.StringDataPtr(r.DisplayName),
			"durationAmount":   llx.IntData(durationAmount),
			"durationTimeUnit": llx.StringData(durationTimeUnit),
			"timeRuleLocked":   llx.TimeDataPtr(timeRuleLocked),
			"created":          llx.TimeDataPtr(created),
			"timeModified":     llx.TimeDataPtr(timeModified),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciObjectStorageRetentionRule) id() (string, error) {
	return "oci.objectStorage.retentionRule/" + o.Id.Data, nil
}

func (o *mqlOciObjectStorageBucket) preauthenticatedRequests() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	region := o.GetRegion()
	if region.Error != nil {
		return nil, region.Error
	}
	if region.Data == nil {
		return nil, errors.New("oci.objectStorage.bucket: region is required")
	}

	client, err := conn.ObjectStorageClient(region.Data.Id.Data)
	if err != nil {
		return nil, err
	}

	namespace := o.GetNamespace()
	if namespace.Error != nil {
		return nil, namespace.Error
	}

	name := o.GetName()
	if name.Error != nil {
		return nil, name.Error
	}

	ctx := context.Background()
	pars, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]objectstorage.PreauthenticatedRequestSummary, *string, error) {
		response, err := client.ListPreauthenticatedRequests(ctx, objectstorage.ListPreauthenticatedRequestsRequest{
			NamespaceName: common.String(namespace.Data),
			BucketName:    common.String(name.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(pars))
	for i := range pars {
		p := pars[i]

		var created *time.Time
		if p.TimeCreated != nil {
			created = &p.TimeCreated.Time
		}
		var timeExpires *time.Time
		if p.TimeExpires != nil {
			timeExpires = &p.TimeExpires.Time
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.objectStorage.preauthenticatedRequest", map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(p.Id),
			"name":                llx.StringDataPtr(p.Name),
			"accessType":          llx.StringData(string(p.AccessType)),
			"objectName":          llx.StringDataPtr(p.ObjectName),
			"bucketListingAction": llx.StringData(string(p.BucketListingAction)),
			"timeExpires":         llx.TimeDataPtr(timeExpires),
			"created":             llx.TimeDataPtr(created),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciObjectStoragePreauthenticatedRequest) id() (string, error) {
	return "oci.objectStorage.preauthenticatedRequest/" + o.Id.Data, nil
}
