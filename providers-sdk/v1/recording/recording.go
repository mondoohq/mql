// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/mapx"
	"go.mondoo.com/mql/utils/multierr"
	"go.mondoo.com/mql/utils/syncx"
)

var _ llx.Recording = &recording{}

const internalLookupId = "mql/internal-lookup-id"

// keySep is the separator used to build composite map keys (e.g. resource + id).
// We use the ASCII Record Separator (\x1e) instead of \x00 because Postgres
// does not allow null bytes in text/JSON columns.
const keySep = "\x1e"

type recording struct {
	Assets []*Asset `json:"assets"`
	Path   string   `json:"-"`
	// assets is used for fast connection to asset lookup
	assets          syncx.Map[*Asset] `json:"-"`
	prettyPrintJSON bool              `json:"-"`
	// this mode is used when we use the recording layer for data,
	// but not for storing it on disk
	doNotSave bool `json:"-"`
}

// Creates a recording that holds only the specified asset
func FromAsset(asset *inventory.Asset) (*recording, error) {
	r := &recording{
		Assets: []*Asset{
			NewAssetRecording(asset),
		},
	}

	r.refreshCache()
	if err := r.reconnectResources(); err != nil {
		return nil, err
	}

	return r, nil
}

func FromAssetRecording(assetRec *Asset) (*recording, error) {
	r := &recording{
		Assets: []*Asset{assetRec},
	}

	return r, nil
}

// ReadOnly converts the recording into a read-only recording
func (r *recording) ReadOnly() *readOnly {
	return &readOnly{r}
}

type RecordingOptions struct {
	DoRecord        bool
	PrettyPrintJSON bool
	DoNotSave       bool
}

// NewWithFile loads and creates a new recording based on user settings.
// If no file is available and users don't wish to record, it throws an error.
// If users don't wish to record and no recording is available, it will return
// the null-recording.
func NewWithFile(path string, opts RecordingOptions) (llx.Recording, error) {
	if path == "" && !opts.DoNotSave {
		// we don't want to record and we don't want to load a recording path...
		// so there is nothing to do, so return nil
		if !opts.DoRecord {
			return Null{}, nil
		}
		// for all remaining cases we do want to record and we want to check
		// if the recording exists at the default location
		path = "recording.json"
	}

	if _, err := os.Stat(path); err == nil {
		res, err := LoadRecordingFile(path)
		if err != nil {
			return nil, multierr.Wrap(err, "failed to load recording")
		}
		res.Path = path

		if opts.DoRecord {
			res.prettyPrintJSON = opts.PrettyPrintJSON
			return res, nil
		}
		return &readOnly{res}, nil

	} else if errors.Is(err, os.ErrNotExist) {
		if opts.DoRecord {
			res := &recording{
				Path:            path,
				prettyPrintJSON: opts.PrettyPrintJSON,
				doNotSave:       opts.DoNotSave,
				assets:          syncx.Map[*Asset]{},
			}
			res.refreshCache() // only for initialization
			return res, nil
		}
		return nil, errors.New("failed to load recording: '" + path + "' does not exist")

	} else {
		// Schrodinger's file, may be permissions or something else...
		return nil, multierr.Wrap(err, "failed to access recording in '"+path+"'")
	}
}

func NewWithAsset(asset *inventory.Asset) *recording {
	rec := &recording{
		Assets: []*Asset{
			{
				Asset:       asset,
				connections: map[string]*connection{},
				resources:   map[string]*Resource{},
				IdsLookup:   map[string]string{},
			},
		},
		assets: syncx.Map[*Asset]{},
	}
	rec.refreshCache()
	return rec
}

func LoadRecordingFile(path string) (*recording, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var res recording
	err = json.Unmarshal(raw, &res)
	if err != nil {
		return nil, err
	}

	pres := &res
	pres.refreshCache()

	if err = pres.reconnectResources(); err != nil {
		return nil, err
	}

	return pres, err
}

func (r *recording) Save() error {
	r.finalize()
	if r.doNotSave {
		return nil
	}

	var raw []byte
	var err error
	if r.prettyPrintJSON {
		raw, err = json.MarshalIndent(r, "", "  ")
	} else {
		raw, err = json.Marshal(r)
	}
	if err != nil {
		return multierr.Wrap(err, "failed to marshal json for recording")
	}

	if err := os.WriteFile(r.Path, raw, 0o644); err != nil {
		return multierr.Wrap(err, "failed to store recording")
	}

	log.Info().Msg("stored recording in " + r.Path)
	return nil
}

func mrnKey(mrn string) string {
	return "mrn:" + mrn
}

func platformIdKey(pid string) string {
	return "pid:" + pid
}

func connIdKey(id uint32) string {
	return fmt.Sprintf("conn-id:%d", id)
}

func (r *recording) refreshCache() {
	r.assets = syncx.Map[*Asset]{}
	for _, asset := range r.Assets {
		if asset == nil {
			continue
		}
		asset.RefreshCache()
		r.resyncAsset(asset)
	}
}

// resolveAsset looks up an asset by the given lookup criteria.
// Priority: asset MRN > platform IDs > connection ID.
func (r *recording) resolveAsset(lookup llx.AssetRecordingLookup) (*Asset, bool) {
	if lookup.Mrn != "" {
		if asset, ok := r.assets.Get(mrnKey(lookup.Mrn)); ok {
			return asset, true
		}
	}

	for _, pid := range lookup.PlatformIds {
		if asset, ok := r.assets.Get(platformIdKey(pid)); ok {
			return asset, true
		}
	}

	if lookup.ConnectionId > 0 {
		if asset, ok := r.assets.Get(connIdKey(lookup.ConnectionId)); ok {
			return asset, true
		}
	}

	return nil, false
}

func (r *recording) reconnectResources() error {
	var err error
	for i := range r.Assets {
		asset := r.Assets[i]
		for j := range asset.Resources {
			if err = r.reconnectResource(&asset.Resources[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *recording) reconnectResource(resource *Resource) error {
	var err error
	for k, v := range resource.Fields {
		if v.Error != nil {
			// in this case we have neither type information nor a value
			resource.Fields[k].Error = v.Error
			continue
		}

		typ := types.Type(v.Type)
		resource.Fields[k].Value, err = tryReconnect(typ, v.Value, resource)
		if err != nil {
			return err
		}
	}
	return nil
}

func tryReconnect(typ types.Type, v any, resource *Resource) (any, error) {
	var err error

	if typ.IsArray() {
		arr, ok := v.([]any)
		if !ok {
			return nil, errors.New("failed to reconnect array type")
		}
		ct := typ.Child()
		for i := range arr {
			arr[i], err = tryReconnect(ct, arr[i], resource)
			if err != nil {
				return nil, err
			}
		}
		return arr, nil
	}

	if typ.IsMap() {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("failed to reconnect map type")
		}
		ct := typ.Child()
		for i := range m {
			m[i], err = tryReconnect(ct, m[i], resource)
			if err != nil {
				return nil, err
			}
		}
		return m, nil
	}

	if !typ.IsResource() || v == nil {
		return v, nil
	}

	return reconnectResource(v, resource)
}

func reconnectResource(v any, resource *Resource) (any, error) {
	vals, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("error in recording: resource '%s' (ID:%s) has incorrect reference %T type", resource.Resource, resource.ID, v)
	}
	name, ok := vals["Name"].(string)
	if !ok {
		return nil, errors.New("error in recording: resource '" + resource.Resource + "' (ID:" + resource.ID + ") has incorrect type in Name field")
	}
	id, ok := vals["ID"].(string)
	if !ok {
		return nil, errors.New("error in recording: resource '" + resource.Resource + "' (ID:" + resource.ID + ") has incorrect type in ID field")
	}

	// TODO: Not sure yet if we need to check the recording for the reference.
	// Unless it is used by the code, we may get away with it.
	// if _, ok = asset.resources[name+keySep+id]; !ok {
	// 	return errors.New("cannot find resource '" + resource.Resource + "' (ID:" + resource.ID + ") in recording")
	// }

	return &llx.MockResource{Name: name, ID: id}, nil
}

func (r *recording) finalize() {
	for i := range r.Assets {
		if r.Assets[i] != nil {
			r.Assets[i].finalize()
		}
	}
}

func (r *recording) EnsureAsset(asset *inventory.Asset, providerID string, connectionID uint32, conf *inventory.Config) {
	if asset.Platform == nil {
		log.Warn().Msg("cannot store asset in recording, asset has no platform")
		return
	}
	if asset.Mrn == "" && len(asset.PlatformIds) == 0 {
		log.Debug().Msg("cannot store asset in recording, asset has no mrn or platform ids")
		return
	}

	lookup := llx.AssetRecordingLookup{
		Mrn:         asset.Mrn,
		PlatformIds: asset.PlatformIds,
	}
	recordingAsset, ok := r.resolveAsset(lookup)
	if !ok {
		recordingAsset = &Asset{
			Asset:       asset,
			connections: map[string]*connection{},
			resources:   map[string]*Resource{},
		}
		r.Assets = append(r.Assets, recordingAsset)
	}

	// always update the mrn and platform ids for the asset, sometimes we
	// get assets by id and then they get updated with an MRN attached
	if asset.Mrn != "" {
		recordingAsset.Asset.Mrn = asset.Mrn
	}
	if len(asset.PlatformIds) > 0 {
		recordingAsset.Asset.PlatformIds = asset.PlatformIds
	}

	if conf.Id > 0 {
		// Scope the lock to just the map write via a closure: resyncAsset below
		// also takes recordingAsset.mu, so a function-level defer would deadlock.
		func() {
			recordingAsset.mu.Lock()
			defer recordingAsset.mu.Unlock()
			recordingAsset.connections[fmt.Sprintf("%d", conf.Id)] = &connection{
				Url:        conf.ToUrl(),
				ProviderID: providerID,
				Connector:  conf.Type,
				Id:         conf.Id,
			}
		}()
	}

	r.resyncAsset(recordingAsset)
}

func (r *recording) resyncAsset(recordingAsset *Asset) {
	if recordingAsset.Asset.Mrn != "" {
		r.assets.Set(mrnKey(recordingAsset.Asset.Mrn), recordingAsset)
	}
	for _, pid := range recordingAsset.Asset.PlatformIds {
		r.assets.Set(platformIdKey(pid), recordingAsset)
	}
	// Index by connection IDs from the runtime connections (added via EnsureAsset)
	recordingAsset.mu.Lock()
	defer recordingAsset.mu.Unlock()
	for _, conn := range recordingAsset.connections {
		if conn.Id > 0 {
			r.assets.Set(connIdKey(conn.Id), recordingAsset)
		}
	}
}

func (r *recording) AddData(req llx.AddDataReq) {
	// The connection id is only the last resort: resolveAsset prefers the mrn
	// and platform ids the caller may have supplied, which identify the asset
	// unambiguously even when a loaded recording reuses one connection id across
	// several of its assets.
	lookup := req.Lookup
	if lookup.ConnectionId == 0 {
		lookup.ConnectionId = req.ConnectionID
	}
	asset, ok := r.resolveAsset(lookup)
	if !ok {
		return
	}

	asset.mu.Lock()
	defer asset.mu.Unlock()

	if asset.IdsLookup == nil {
		asset.IdsLookup = map[string]string{}
	}

	// When the caller created the resource by name + args (no request id),
	// derive a deterministic key from the args so e.g. file(path: "/a")
	// and file(path: "/b") don't collide on the empty request id.
	requestID := req.RequestResourceId
	if requestID == "" && len(req.Args) > 0 {
		requestID = llx.ArgsLookupID(req.Args)
	}

	if requestID != req.ResourceID {
		asset.IdsLookup[req.Resource+keySep+requestID] = req.ResourceID
	}

	obj, exist := asset.resources[req.Resource+keySep+req.ResourceID]
	if !exist {
		obj = &Resource{
			Resource: req.Resource,
			ID:       req.ResourceID,
			Fields:   map[string]*llx.RawData{},
		}
		asset.resources[req.Resource+keySep+req.ResourceID] = obj
	}

	if req.Field != "" {
		obj.Fields[req.Field] = req.Data
	}
}

// resolveResource looks up a recorded resource. It returns the owning *Asset so
// that callers can hold asset.mu while reading the resolved resource's Fields
// map, which AddData mutates concurrently.
func (r *recording) resolveResource(lookup llx.AssetRecordingLookup, resource string, id string) (*Resource, *Asset, string, bool) {
	asset, ok := r.resolveAsset(lookup)
	if !ok {
		return nil, nil, "", false
	}

	asset.mu.Lock()
	defer asset.mu.Unlock()

	// overwrite resourceId if there exists a lookup entry
	if lookupId, ok := asset.IdsLookup[resource+keySep+id]; ok {
		id = lookupId
	}

	// special case: we're asking for the asset. we can use the recording's asset directly
	// since that provides the most detailed information about the asset
	if resource == "asset" {
		assetResource := createResourceAsset(asset.Asset, id)
		return assetResource, asset, id, true
	}

	obj, exist := asset.resources[resource+keySep+id]
	if !exist {
		return nil, nil, "", false
	}

	return obj, asset, id, true
}

func createResourceAsset(asset *inventory.Asset, id string) *Resource {
	args := CreateAssetResourceArgs(asset)
	return &Resource{
		Resource: "asset",
		ID:       id,
		Fields:   args,
	}
}

func CreateAssetResourceArgs(asset *inventory.Asset) map[string]*llx.RawData {
	// FIXME: remove in v12 (or later) vv
	// we merge `asset.Labels` and `asset.Platform.Labels` for backwards compatibility
	assetLabelsMergedV11Compat := mapx.Merge(asset.GetPlatform().GetLabels(), asset.Labels)
	// ^^
	args := map[string]*llx.RawData{
		"ids":              llx.ArrayData(llx.TArr2Raw(asset.GetPlatformIds()), types.String),
		"platform":         llx.StringData(asset.GetPlatform().GetName()),
		"name":             llx.StringData(asset.Name),
		"kind":             llx.StringData(asset.GetPlatform().GetKind()),
		"runtime":          llx.StringData(asset.GetPlatform().GetRuntime()),
		"version":          llx.StringData(asset.GetPlatform().GetVersion()),
		"arch":             llx.StringData(asset.GetPlatform().GetArch()),
		"title":            llx.StringData(asset.GetPlatform().PrettyTitle()),
		"family":           llx.ArrayData(llx.TArr2Raw(asset.GetPlatform().GetFamily()), types.String),
		"build":            llx.StringData(asset.GetPlatform().GetBuild()),
		"annotations":      llx.MapData(llx.TMap2Raw(asset.Annotations), types.String),
		"fqdn":             llx.StringData(asset.Fqdn),
		"platformMetadata": llx.MapData(llx.TMap2Raw(asset.GetPlatform().GetMetadata()), types.String),
		// FIXME: remove in v12 (or later) vv
		"labels": llx.MapData(llx.TMap2Raw(assetLabelsMergedV11Compat), types.String),
		// ^^
		// Instead, we should only use `asset.Labels` like:
		// "labels": llx.MapData(llx.TMap2Raw(asset.Labels), types.String),
	}
	return args
}

func (r *recording) GetData(lookup llx.AssetRecordingLookup, resource string, id string, field string) (*llx.RawData, bool) {
	obj, asset, resolvedID, ok := r.resolveResource(lookup, resource, id)
	if !ok {
		return nil, false
	}

	if field == "" {
		return &llx.RawData{Type: types.Resource(resource), Value: resolvedID}, true
	}

	// AddData mutates obj.Fields under asset.mu, so we must hold it while reading.
	asset.mu.Lock()
	defer asset.mu.Unlock()
	data, ok := obj.Fields[field]
	return data, ok
}

func (r *recording) GetResource(lookup llx.AssetRecordingLookup, resource string, id string) (map[string]*llx.RawData, bool) {
	obj, asset, _, ok := r.resolveResource(lookup, resource, id)
	if !ok {
		return nil, false
	}

	// Return a snapshot of the fields: the caller iterates the map after we
	// return, while AddData may still be inserting into obj.Fields under asset.mu.
	asset.mu.Lock()
	defer asset.mu.Unlock()
	fields := make(map[string]*llx.RawData, len(obj.Fields))
	maps.Copy(fields, obj.Fields)
	return fields, true
}

func (r *recording) GetAssetData(assetMrn string) (map[string]*llx.ResourceRecording, bool) {
	cur, ok := r.resolveAsset(llx.AssetRecordingLookup{Mrn: assetMrn})
	if !ok {
		return nil, false
	}

	cur.mu.Lock()
	defer cur.mu.Unlock()

	ensureAssetMetadata(cur.resources, cur.Asset)

	res := make(map[string]*llx.ResourceRecording, len(cur.resources))
	for k, v := range cur.resources {
		fields := make(map[string]*llx.Result, len(v.Fields))
		for fk, fv := range v.Fields {
			fields[fk] = fv.Result()
		}
		res[k] = &llx.ResourceRecording{
			Resource: v.Resource,
			Id:       v.ID,
			Fields:   fields,
		}
	}
	// we need to also store the id lookups as part of the resource recording
	// so that they can be reused later when only reading the resource recording
	for k, v := range cur.IdsLookup {
		res[internalLookupId+keySep+k] = &llx.ResourceRecording{
			Resource: internalLookupId,
			Id:       k,
			Fields: map[string]*llx.Result{
				"value": llx.StringData(v).Result(),
			},
		}
	}

	return res, true
}

func (r *recording) GetAssetRecordings() []*Asset {
	return r.Assets
}

func (r *recording) GetAssets() []*inventory.Asset {
	assets := make([]*inventory.Asset, 0, len(r.Assets))
	for i := range r.Assets {
		if r.Assets[i] != nil {
			assets = append(assets, r.Assets[i].Asset)
		}
	}
	return assets
}

func (r *recording) SetAssetRecording(id uint32, reco *Asset) {
	r.assets.Set(connIdKey(id), reco)
}

// This method makes sure the asset metadata is always included in the data
// dump of a recording
func ensureAssetMetadata(resources map[string]*Resource, asset *inventory.Asset) {
	id := "asset" + keySep
	existing, ok := resources[id]
	if !ok {
		existing = &Resource{
			Resource: "asset",
			ID:       "",
			Fields:   map[string]*llx.RawData{},
		}
		resources[id] = existing
	}

	existing.Fields = CreateAssetResourceArgs(asset)
}
