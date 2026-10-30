// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/objectstorage/v1/accounts"
	"github.com/gophercloud/gophercloud/v2/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/v2/openstack/objectstorage/v1/objects"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.objectstorage.account ----

func (r *mqlOpenstackObjectstorageAccount) id() (string, error) {
	return "openstack.objectstorage.account/" + r.Id.Data, nil
}

func (o *mqlOpenstack) objectStorageAccount() (*mqlOpenstackObjectstorageAccount, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ObjectStorageClient()
	if err != nil {
		if serviceMissing(err) {
			o.ObjectStorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	getResult := accounts.Get(ctx(), client, accounts.GetOpts{})
	resHdr, err := getResult.Extract()
	if err != nil {
		if translateGetError(err) == nil {
			o.ObjectStorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	meta, err := getResult.ExtractMetadata()
	if err != nil {
		meta = map[string]string{}
	}

	id := c.ProjectID()

	quota := int64(-1)
	if resHdr.QuotaBytes != nil {
		quota = *resHdr.QuotaBytes
	}

	res, err := CreateResource(o.MqlRuntime, "openstack.objectstorage.account", map[string]*llx.RawData{
		"__id":           llx.StringData("openstack.objectstorage.account/" + id),
		"id":             llx.StringData(id),
		"bytesUsed":      llx.IntData(resHdr.BytesUsed),
		"containerCount": llx.IntData(resHdr.ContainerCount),
		"objectCount":    llx.IntData(resHdr.ObjectCount),
		"quotaBytes":     llx.IntData(quota),
		"tempUrlKeySet":  llx.BoolData(resHdr.TempURLKey != "" || resHdr.TempURLKey2 != ""),
		"metadata":       stringMapData(meta),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackObjectstorageAccount), nil
}

// ---- openstack.objectstorage.container ----

type mqlOpenstackObjectstorageContainerInternal struct {
	headerLock    sync.Mutex
	headerFetched bool
	headerErr     error
	header        *containers.GetHeader
	headerMeta    map[string]string
}

func (r *mqlOpenstackObjectstorageContainer) id() (string, error) {
	return "openstack.objectstorage.container/" + r.Name.Data, nil
}

func initOpenstackObjectstorageContainer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := stringArg(args, "name")
	if !ok || name == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetObjectStorageContainers()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		cc := raw.(*mqlOpenstackObjectstorageContainer)
		if cc.Name.Data == name {
			return args, cc, nil
		}
	}
	initSyntheticID("openstack.objectstorage.container", "name", args)
	return args, nil, nil
}

func (o *mqlOpenstack) objectStorageContainers() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ObjectStorageClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := containers.List(client, containers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := containers.ExtractInfo(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, ci := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.objectstorage.container", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.objectstorage.container/" + ci.Name),
			"name":        llx.StringData(ci.Name),
			"objectCount": llx.IntData(ci.Count),
			"bytes":       llx.IntData(ci.Bytes),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackObjectstorageContainer) fetchHeader() (*containers.GetHeader, map[string]string, error) {
	r.headerLock.Lock()
	defer r.headerLock.Unlock()
	if r.headerFetched {
		return r.header, r.headerMeta, r.headerErr
	}
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorageClient()
	if err != nil {
		r.headerFetched = true
		r.headerErr = err
		return nil, nil, err
	}
	getResult := containers.Get(ctx(), client, r.Name.Data, containers.GetOpts{})
	header, err := getResult.Extract()
	if err != nil {
		// 404 means the container was just deleted; treat as empty rather than failing the query.
		// gophercloud frequently wraps ErrUnexpectedResponseCode, so use errors.As, not a
		// direct type assertion (which misses wrapped errors and would fail the query).
		var respErr gophercloud.ErrUnexpectedResponseCode
		if errors.As(err, &respErr) && (respErr.Actual == 401 || respErr.Actual == 403 || respErr.Actual == 404) {
			r.headerFetched = true
			r.headerMeta = map[string]string{}
			return nil, r.headerMeta, nil
		}
		r.headerFetched = true
		r.headerErr = err
		return nil, nil, err
	}
	meta, err := getResult.ExtractMetadata()
	if err != nil {
		meta = map[string]string{}
	}
	r.headerFetched = true
	r.header = header
	r.headerMeta = meta
	return header, meta, nil
}

func (r *mqlOpenstackObjectstorageContainer) created() (*time.Time, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return nil, err
	}
	// X-Timestamp is a Unix epoch (seconds, with fractional part) recording when
	// the container was created. Guard the zero/absent value so it surfaces as null.
	if h.Timestamp == 0 {
		return nil, nil
	}
	t := time.Unix(int64(h.Timestamp), 0).UTC()
	return &t, nil
}

func (r *mqlOpenstackObjectstorageContainer) readACL() ([]any, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return []any{}, err
	}
	return stringSlice(nonEmpty(h.Read)), nil
}

func (r *mqlOpenstackObjectstorageContainer) writeACL() ([]any, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return []any{}, err
	}
	return stringSlice(nonEmpty(h.Write)), nil
}

// nonEmpty drops empty/whitespace-only entries from a string slice (gophercloud
// splits comma-separated ACL headers and yields [""] for an unset header).
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (r *mqlOpenstackObjectstorageContainer) storagePolicy() (string, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return "", err
	}
	return h.StoragePolicy, nil
}

func (r *mqlOpenstackObjectstorageContainer) versionsLocation() (string, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return "", err
	}
	return h.VersionsLocation, nil
}

func (r *mqlOpenstackObjectstorageContainer) historyLocation() (string, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return "", err
	}
	return h.HistoryLocation, nil
}

func (r *mqlOpenstackObjectstorageContainer) versioningEnabled() (bool, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return false, err
	}
	return h.VersionsEnabled, nil
}

func (r *mqlOpenstackObjectstorageContainer) syncTo() (string, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return "", err
	}
	return h.SyncTo, nil
}

// hasSyncKey reports whether a container-sync secret is set. The key itself is
// the shared secret that authorizes the peer cluster to write into this
// container, so only its presence is exposed, never its value.
func (r *mqlOpenstackObjectstorageContainer) hasSyncKey() (bool, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return false, err
	}
	return strings.TrimSpace(h.SyncKey) != "", nil
}

// hasTempUrlKey reports whether a temporary-URL signing key is set. Anyone
// holding the key can mint URLs that read (or write) objects without
// authenticating at all, so only its presence is exposed, never its value.
func (r *mqlOpenstackObjectstorageContainer) hasTempUrlKey() (bool, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return false, err
	}
	return strings.TrimSpace(h.TempURLKey) != "", nil
}

// hasTempUrlKey2 reports whether the second temporary-URL signing key slot is
// set. Swift honours signatures from either slot, so a stale second key keeps
// minting valid URLs after the first is rotated. Presence only.
func (r *mqlOpenstackObjectstorageContainer) hasTempUrlKey2() (bool, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return false, err
	}
	return strings.TrimSpace(h.TempURLKey2) != "", nil
}

// secretContainerMetaKeys are the container metadata keys whose value is
// credential material. Swift stores the temporary-URL signing keys as ordinary
// X-Container-Meta-* headers, so they arrive in the metadata map alongside
// user-set labels. Anyone holding one can mint pre-signed URLs that read or
// write objects with no authentication, so the values are dropped from the
// metadata map; hasTempUrlKey and hasTempUrlKey2 report their presence instead.
// Keys are compared lower-cased because net/http canonicalizes header casing.
var secretContainerMetaKeys = map[string]struct{}{
	"temp-url-key":   {},
	"temp-url-key-2": {},
}

// redactContainerMetadata copies the metadata map without the entries whose
// value is credential material.
func redactContainerMetadata(meta map[string]string) map[string]string {
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		if _, secret := secretContainerMetaKeys[strings.ToLower(k)]; secret {
			continue
		}
		out[k] = v
	}
	return out
}

func (r *mqlOpenstackObjectstorageContainer) metadata() (map[string]any, error) {
	_, meta, err := r.fetchHeader()
	if err != nil {
		return map[string]any{}, err
	}
	return stringMap(redactContainerMetadata(meta)), nil
}

func (r *mqlOpenstackObjectstorageContainer) public() (bool, error) {
	h, _, err := r.fetchHeader()
	if err != nil || h == nil {
		return false, err
	}
	for _, entry := range h.Read {
		if strings.TrimSpace(entry) == ".r:*" {
			return true, nil
		}
	}
	return false, nil
}

func (r *mqlOpenstackObjectstorageContainer) objects() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ObjectStorageClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := objects.List(client, r.Name.Data, objects.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := objects.ExtractInfo(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, obj := range items {
		res, err := CreateResource(r.MqlRuntime, "openstack.objectstorage.object", map[string]*llx.RawData{
			"__id":          llx.StringData("openstack.objectstorage.object/" + r.Name.Data + "/" + obj.Name),
			"name":          llx.StringData(obj.Name),
			"containerName": llx.StringData(r.Name.Data),
			"contentType":   llx.StringData(obj.ContentType),
			"bytes":         llx.IntData(obj.Bytes),
			"hash":          llx.StringData(obj.Hash),
			"lastModified":  llx.TimeDataPtr(timePtr(obj.LastModified)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.objectstorage.object ----

func (r *mqlOpenstackObjectstorageObject) id() (string, error) {
	return "openstack.objectstorage.object/" + r.ContainerName.Data + "/" + r.Name.Data, nil
}

func initOpenstackObjectstorageObject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, _ := stringArg(args, "name")
	containerName, _ := stringArg(args, "containerName")
	if name == "" || containerName == "" {
		return args, nil, nil
	}
	if _, ok := args["__id"]; !ok {
		args["__id"] = llx.StringData("openstack.objectstorage.object/" + containerName + "/" + name)
	}
	return args, nil, nil
}

func (r *mqlOpenstackObjectstorageObject) container() (*mqlOpenstackObjectstorageContainer, error) {
	if r.ContainerName.Data == "" {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.objectstorage.container", map[string]*llx.RawData{
		"name": llx.StringData(r.ContainerName.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackObjectstorageContainer), nil
}
