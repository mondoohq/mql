// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	objectstorage "github.com/stackitcloud/stackit-sdk-go/services/objectstorage/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlStackitObjectStorageBucketInternal struct {
	retentionFetched bool
	retentionDays    int64
	retentionMode    string
	retentionLock    sync.Mutex
}

type mqlStackitObjectStorageAccessKeyInternal struct {
	// cacheCredentialsGroupId holds the owning group's UUID so the lazy
	// credentialsGroup() reference can resolve it. It is not exposed as a
	// field because credentialsGroup() already carries the same value.
	cacheCredentialsGroupId string
}

func (r *mqlStackitObjectStorage) buckets() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorage()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBuckets(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		// A 404 here means the project is not onboarded to Object Storage
		// (the service returns "project.not_found"); treat it as no buckets.
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetBucketsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildBucket(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildBucket(runtime *plugin.Runtime, b *objectstorage.Bucket) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"name":                  llx.StringData(b.GetName()),
		"region":                llx.StringData(b.GetRegion()),
		"urlPathStyle":          llx.StringData(b.GetUrlPathStyle()),
		"urlVirtualHostedStyle": llx.StringData(b.GetUrlVirtualHostedStyle()),
		"objectLockEnabled":     llx.BoolData(b.GetObjectLockEnabled()),
	}
	return CreateResource(runtime, "stackit.objectStorage.bucket", args)
}

func (r *mqlStackitObjectStorageBucket) id() (string, error) {
	return "stackit.objectStorage.bucket/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

func initStackitObjectStorageBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name := ""
	if v, ok := args["name"]; ok && v != nil {
		name, _ = v.Value.(string)
	}
	if name == "" {
		// Scope to the connected discovered bucket asset when no name is given.
		name, _ = conn(runtime).AssetObjectID("object-storage")
	}
	if name == "" {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ObjectStorage()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetBucket(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	b, ok := resp.GetBucketOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.objectStorage.bucket %q not found", name)
	}
	res, err := buildBucket(runtime, b)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// fetchDefaultRetention pulls the bucket's default-retention policy and
// caches it so callers querying both `defaultRetentionDays` and
// `defaultRetentionMode` only hit the API once. A 404 means no default
// retention is set; we cache the zero values so we don't retry.
func (r *mqlStackitObjectStorageBucket) fetchDefaultRetention() (int64, string, error) {
	if r.retentionFetched {
		return r.retentionDays, r.retentionMode, nil
	}
	r.retentionLock.Lock()
	defer r.retentionLock.Unlock()
	if r.retentionFetched {
		return r.retentionDays, r.retentionMode, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorage()
	if err != nil {
		return 0, "", err
	}
	resp, err := client.DefaultAPI.GetDefaultRetention(bgctx(), c.ProjectID(), c.Region(), r.Name.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			r.retentionFetched = true
			return 0, "", nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.retentionFetched = true
				return 0, "", nil
			}
			return 0, "", refusal(err)
		}
		return 0, "", err
	}
	r.retentionDays = int64(resp.GetDays())
	r.retentionMode = string(resp.GetMode())
	r.retentionFetched = true
	return r.retentionDays, r.retentionMode, nil
}

func (r *mqlStackitObjectStorageBucket) defaultRetentionDays() (int64, error) {
	days, _, err := r.fetchDefaultRetention()
	return days, err
}

func (r *mqlStackitObjectStorageBucket) defaultRetentionMode() (string, error) {
	_, mode, err := r.fetchDefaultRetention()
	return mode, err
}

// ------------------------- credentials groups & access keys -------------------------

func (r *mqlStackitObjectStorage) credentialsGroups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorage()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListCredentialsGroups(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		// A 404 means the project is not onboarded to Object Storage; treat it
		// as no credentials groups.
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	groups, _ := resp.GetCredentialsGroupsOk()
	out := make([]any, 0, len(groups))
	for i := range groups {
		res, err := CreateResource(r.MqlRuntime, "stackit.objectStorage.credentialsGroup", map[string]*llx.RawData{
			"id":          llx.StringData(groups[i].GetCredentialsGroupId()),
			"displayName": llx.StringData(groups[i].GetDisplayName()),
			"urn":         llx.StringData(groups[i].GetUrn()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitObjectStorageCredentialsGroup) id() (string, error) {
	return "stackit.objectStorage.credentialsGroup/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Id.Data, nil
}

// initStackitObjectStorageCredentialsGroup resolves a credentials group by ID,
// used when navigating to it from an access key.
func initStackitObjectStorageCredentialsGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ObjectStorage()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetCredentialsGroup(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	g, ok := resp.GetCredentialsGroupOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit object storage credentials group %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.objectStorage.credentialsGroup", map[string]*llx.RawData{
		"id":          llx.StringData(g.GetCredentialsGroupId()),
		"displayName": llx.StringData(g.GetDisplayName()),
		"urn":         llx.StringData(g.GetUrn()),
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitObjectStorageCredentialsGroup) accessKeys() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorage()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListAccessKeys(bgctx(), c.ProjectID(), c.Region()).
		CredentialsGroup(r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	keys, _ := resp.GetAccessKeysOk()
	out := make([]any, 0, len(keys))
	for i := range keys {
		keyID := keys[i].GetKeyId()
		// Synthetic cache key: the access key ID is unique within a group, so
		// project + group + key keeps instances distinct. It mirrors the
		// project-qualified form used by credentialsGroup.id().
		accessKeyID := "stackit.objectStorage.accessKey/" + c.ProjectID() + "/" + r.Id.Data + "/" + keyID
		res, err := CreateResource(r.MqlRuntime, "stackit.objectStorage.accessKey", map[string]*llx.RawData{
			"__id":        llx.StringData(accessKeyID),
			"keyId":       llx.StringData(keyID),
			"displayName": llx.StringData(keys[i].GetDisplayName()),
			"expires":     llx.TimeDataPtr(parseRFC3339(keys[i].GetExpires())),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlStackitObjectStorageAccessKey).cacheCredentialsGroupId = r.Id.Data
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitObjectStorageAccessKey) credentialsGroup() (*mqlStackitObjectStorageCredentialsGroup, error) {
	if r.cacheCredentialsGroupId == "" {
		return markNull[mqlStackitObjectStorageCredentialsGroup](&r.CredentialsGroup)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.objectStorage.credentialsGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheCredentialsGroupId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitObjectStorageCredentialsGroup), nil
}
