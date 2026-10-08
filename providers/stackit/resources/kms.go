// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"

	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlStackitKmsInternal memoizes the project-wide key index that backs every
// reference to a KMS key from elsewhere in the schema. stackit.kms.key has no
// init and its cache key is ring-qualified, so a bare key UUID (which is all a
// volume records) cannot address one; the only way to resolve it is to walk the
// key rings. Doing that per referencing resource would cost 1 + N_rings calls
// each, so it is done once and shared through the stackit.kms singleton.
type mqlStackitKmsInternal struct {
	keyIndexLock  sync.Mutex
	keyIndexBuilt bool
	keyIndex      map[string]*mqlStackitKmsKey
	keyIndexErr   error
}

// kmsResource returns the stackit.kms singleton for this project. Its id is
// constant per project, so CreateResource hands back the one cached instance
// and with it the shared key index.
func kmsResource(runtime *plugin.Runtime) (*mqlStackitKms, error) {
	res, err := CreateResource(runtime, "stackit.kms", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	k, ok := res.(*mqlStackitKms)
	if !ok {
		return nil, errors.New("stackit: unexpected type for the stackit.kms resource")
	}
	return k, nil
}

// keyIndexByID builds (once) and returns the project's keys indexed by UUID.
// The failure is memoized alongside the value: a denied or broken key-ring read
// would otherwise be retried once per referencing resource.
func (r *mqlStackitKms) keyIndexByID() (map[string]*mqlStackitKmsKey, error) {
	r.keyIndexLock.Lock()
	defer r.keyIndexLock.Unlock()
	if r.keyIndexBuilt {
		return r.keyIndex, r.keyIndexErr
	}
	r.keyIndexBuilt = true

	rings := r.GetKeyRings()
	if rings.Error != nil {
		r.keyIndexErr = rings.Error
		return nil, r.keyIndexErr
	}

	keys := []any{}
	for _, ring := range rings.Data {
		kr, ok := ring.(*mqlStackitKmsKeyRing)
		if !ok {
			continue
		}
		ringKeys := kr.GetKeys()
		if ringKeys.Error != nil {
			r.keyIndexErr = ringKeys.Error
			return nil, r.keyIndexErr
		}
		keys = append(keys, ringKeys.Data...)
	}

	r.keyIndex = indexKmsKeysByID(keys)
	return r.keyIndex, nil
}

// indexKmsKeysByID indexes key resources by their bare UUID. Keys are addressed
// by ring plus id in the KMS API, but the resources that reference a key record
// only the UUID, so that is what the index has to be keyed on. Entries that are
// not keys, and keys without an id, are skipped; the first key wins on the
// (service-anomalous) chance that one UUID shows up under two rings.
func indexKmsKeysByID(items []any) map[string]*mqlStackitKmsKey {
	idx := make(map[string]*mqlStackitKmsKey, len(items))
	for _, item := range items {
		key, ok := item.(*mqlStackitKmsKey)
		if !ok || key == nil {
			continue
		}
		id := key.Id.Data
		if id == "" {
			continue
		}
		if _, seen := idx[id]; seen {
			continue
		}
		idx[id] = key
	}
	return idx
}

// findKmsKeyVersion picks the generation with the given version number out of a
// key's version list, or nil when the key never had that generation.
func findKmsKeyVersion(items []any, number int64) *mqlStackitKmsKeyVersion {
	for _, item := range items {
		v, ok := item.(*mqlStackitKmsKeyVersion)
		if !ok || v == nil {
			continue
		}
		if v.Number.Data == number {
			return v
		}
	}
	return nil
}

func (r *mqlStackitKms) keyRings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.KMS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListKeyRings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetKeyRingsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildKmsKeyRing(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// keys() is a convenience that flattens key rings → keys so callers can
// audit every key in the project without an explicit two-level traversal.
func (r *mqlStackitKms) keys() ([]any, error) {
	rings, err := r.keyRings()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ring := range rings {
		kr, ok := ring.(*mqlStackitKmsKeyRing)
		if !ok {
			continue
		}
		keys, err := kr.keys()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
	}
	return out, nil
}

func buildKmsKeyRing(runtime *plugin.Runtime, kr *kms.KeyRing) (plugin.Resource, error) {
	createdAt, ok1 := kr.GetCreatedAtOk()
	args := map[string]*llx.RawData{
		"id":          llx.StringData(kr.GetId()),
		"displayName": llx.StringData(kr.GetDisplayName()),
		"description": llx.StringData(kr.GetDescription()),
		"state":       llx.StringData(string(kr.GetState())),
		"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
	}
	return CreateResource(runtime, "stackit.kms.keyRing", args)
}

func (r *mqlStackitKmsKeyRing) id() (string, error) {
	return "stackit.kms.keyRing/" + r.Id.Data, nil
}

func initStackitKmsKeyRing(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.KMS()
	if err != nil {
		return nil, nil, err
	}
	kr, err := client.DefaultAPI.GetKeyRing(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildKmsKeyRing(runtime, kr)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitKmsKeyRing) keys() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.KMS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListKeys(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetKeysOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildKmsKey(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildKmsKey(runtime *plugin.Runtime, k *kms.Key) (plugin.Resource, error) {
	createdAt, ok1 := k.GetCreatedAtOk()
	deletionDate, ok2 := k.GetDeletionDateOk()
	args := map[string]*llx.RawData{
		"id":           llx.StringData(k.GetId()),
		"keyRingId":    llx.StringData(k.GetKeyRingId()),
		"displayName":  llx.StringData(k.GetDisplayName()),
		"description":  llx.StringData(k.GetDescription()),
		"purpose":      llx.StringData(string(k.GetPurpose())),
		"algorithm":    llx.StringData(string(k.GetAlgorithm())),
		"protection":   llx.StringData(string(k.GetProtection())),
		"accessScope":  llx.StringData(string(k.GetAccessScope())),
		"importOnly":   llx.BoolData(k.GetImportOnly()),
		"state":        llx.StringData(string(k.GetState())),
		"createdAt":    llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"deletionDate": llx.TimeDataPtr(timeOrNil(deletionDate, ok2)),
	}
	return CreateResource(runtime, "stackit.kms.key", args)
}

func (r *mqlStackitKmsKey) id() (string, error) {
	return "stackit.kms.key/" + r.KeyRingId.Data + "/" + r.Id.Data, nil
}

// versions lists the key's material generations. Rotation appends a version
// and keeps the older ones readable, so the newest createdAt is what a
// key-age check reads.
func (r *mqlStackitKmsKey) versions() ([]any, error) {
	// A deleted key's versions can no longer be listed: the API answers 404
	// "key not found" for it. A deleted key genuinely has no versions to
	// read, so answer that without the call; a 404 on a live key stays an
	// error.
	if r.State.Data == string(kms.KEYSTATE_DELETED) {
		return []any{}, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.KMS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListVersions(bgctx(), c.ProjectID(), c.Region(), r.KeyRingId.Data, r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetVersionsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		v := &items[i]
		createdAt, ok1 := v.GetCreatedAtOk()
		destroyDate, ok2 := v.GetDestroyDateOk()
		args := map[string]*llx.RawData{
			// The version number is only unique within its key, so qualify the
			// cache key with the ring and key it belongs to. Kept out of the
			// schema: nobody selects a version by this path.
			"__id":        llx.StringData(fmt.Sprintf("stackit.kms.key.version/%s/%s/%d", v.GetKeyRingId(), v.GetKeyId(), v.GetNumber())),
			"number":      llx.IntData(v.GetNumber()),
			"state":       llx.StringData(string(v.GetState())),
			"disabled":    llx.BoolData(v.GetDisabled()),
			"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
			"destroyDate": llx.TimeDataPtr(timeOrNil(destroyDate, ok2)),
			"publicKey":   llx.StringData(v.GetPublicKey()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.kms.key.version", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlStackitKmsWrappingKeyInternal caches the owning ring id so keyRing()
// can resolve without the schema carrying a duplicate raw id field.
type mqlStackitKmsWrappingKeyInternal struct {
	cacheKeyRingId string
}

func (r *mqlStackitKmsKeyRing) wrappingKeys() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.KMS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListWrappingKeys(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetWrappingKeysOk()
	out := make([]any, 0, len(items))
	for i := range items {
		wk := &items[i]
		createdAt, ok1 := wk.GetCreatedAtOk()
		expiresAt, ok2 := wk.GetExpiresAtOk()
		// the response carries the key ring, but the listing is already scoped
		// to one, so fall back to it rather than lose the qualifier
		keyRingId := wk.GetKeyRingId()
		if keyRingId == "" {
			keyRingId = r.Id.Data
		}
		args := map[string]*llx.RawData{
			// the wrapping key id is only unique within its key ring, so the
			// cache key has to carry the ring it belongs to
			"__id":        llx.StringData(qualifiedId("stackit.kms.wrappingKey", keyRingId, wk.GetId())),
			"id":          llx.StringData(wk.GetId()),
			"displayName": llx.StringData(wk.GetDisplayName()),
			"description": llx.StringData(wk.GetDescription()),
			"algorithm":   llx.StringData(string(wk.GetAlgorithm())),
			"purpose":     llx.StringData(string(wk.GetPurpose())),
			"protection":  llx.StringData(string(wk.GetProtection())),
			"accessScope": llx.StringData(string(wk.GetAccessScope())),
			"state":       llx.StringData(string(wk.GetState())),
			"expiresAt":   llx.TimeDataPtr(timeOrNil(expiresAt, ok2)),
			"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
			"publicKey":   llx.StringData(wk.GetPublicKey()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.kms.wrappingKey", args)
		if err != nil {
			return nil, err
		}
		if mwk, ok := res.(*mqlStackitKmsWrappingKey); ok {
			mwk.cacheKeyRingId = keyRingId
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitKmsWrappingKey) keyRing() (*mqlStackitKmsKeyRing, error) {
	if r.cacheKeyRingId == "" {
		return markNull[mqlStackitKmsKeyRing](&r.KeyRing)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.kms.keyRing", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheKeyRingId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitKmsKeyRing), nil
}

func (r *mqlStackitKmsKey) keyRing() (*mqlStackitKmsKeyRing, error) {
	if r.KeyRingId.Data == "" {
		return markNull[mqlStackitKmsKeyRing](&r.KeyRing)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.kms.keyRing", map[string]*llx.RawData{
		"id": llx.StringData(r.KeyRingId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitKmsKeyRing), nil
}
