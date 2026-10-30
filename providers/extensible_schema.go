// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

type ExtensibleSchema interface {
	Add(name string, schema resources.ResourcesSchema)
}

type extensibleSchema struct {
	// Note: this object is re-created every time we refresh. It is treated
	// as unsafe and may be returned to concurrent processes for reading.
	// Thus, its contents are read-only and may only be replaced entirely.
	roAggregate resources.Schema
	// These are all individual schemas that have been added (not their aggregate)
	loaded map[string]resources.ResourcesSchema
	// Optional prioritization order of select schemas in aggregation.
	prioritization []string
	lastRefreshed  int64
	coordinator    ProvidersCoordinator
	sync           sync.Mutex
}

func newExtensibleSchema() extensibleSchema {
	return extensibleSchema{
		roAggregate: resources.Schema{
			Resources:        map[string]*resources.ResourceInfo{},
			ProviderVersions: map[string]string{},
		},
		loaded:         map[string]resources.ResourcesSchema{},
		prioritization: []string{BuiltinCoreID},
	}
}

func (x *extensibleSchema) Add(name string, schema resources.ResourcesSchema) {
	x.sync.Lock()
	x.unsafeAdd(name, schema)
	x.unsafeRefresh()
	x.sync.Unlock()
}

func (x *extensibleSchema) Schema() *resources.Schema {
	x.sync.Lock()
	defer x.sync.Unlock()

	if x.roAggregate.Resources == nil {
		x.unsafeRefresh()
	}

	return &x.roAggregate
}

func (x *extensibleSchema) AllResources() map[string]*resources.ResourceInfo {
	x.sync.Lock()
	defer x.sync.Unlock()

	if x.lastRefreshed < LastProviderInstall {
		x.unsafeLoadAll()
		x.unsafeRefresh()
	} else if x.roAggregate.Resources == nil {
		x.unsafeRefresh()
	}

	return x.roAggregate.Resources
}

func (x *extensibleSchema) AllDependencies() map[string]*resources.ProviderInfo {
	x.sync.Lock()
	defer x.sync.Unlock()

	if x.lastRefreshed < LastProviderInstall {
		x.unsafeLoadAll()
		x.unsafeRefresh()
	}

	return x.roAggregate.Dependencies
}

func (x *extensibleSchema) AllProviderVersions() map[string]string {
	x.sync.Lock()
	defer x.sync.Unlock()

	if x.lastRefreshed < LastProviderInstall {
		x.unsafeLoadAll()
		x.unsafeRefresh()
	}

	return x.roAggregate.ProviderVersions
}

func (x *extensibleSchema) AllProviderRoots() map[string]string {
	x.sync.Lock()
	defer x.sync.Unlock()

	if x.lastRefreshed < LastProviderInstall {
		x.unsafeLoadAll()
		x.unsafeRefresh()
	}

	return x.roAggregate.ProviderRoots
}

func (x *extensibleSchema) Close() {
	x.sync.Lock()
	x.loaded = map[string]resources.ResourcesSchema{}
	x.roAggregate = resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		ProviderVersions: map[string]string{},
	}
	x.sync.Unlock()
}

func (x *extensibleSchema) Lookup(name string) *resources.ResourceInfo {
	x.sync.Lock()
	defer x.sync.Unlock()

	if found, ok := x.roAggregate.Resources[name]; ok {
		return found
	}
	if x.lastRefreshed >= LastProviderInstall {
		return nil
	}

	x.unsafeLoadAll()
	x.unsafeRefresh()

	return x.roAggregate.Resources[name]
}

func (x *extensibleSchema) LookupField(resource string, field string) (*resources.ResourceInfo, *resources.Field) {
	x.sync.Lock()
	defer x.sync.Unlock()

	res, f := x.roAggregate.LookupField(resource, field)
	if res != nil && f != nil {
		return res, f
	}

	if x.lastRefreshed >= LastProviderInstall {
		return res, f
	}

	x.unsafeLoadAll()
	x.unsafeRefresh()

	return x.roAggregate.LookupField(resource, field)
}

func (x *extensibleSchema) FindField(resource *resources.ResourceInfo, field string) (resources.FieldPath, []*resources.Field, bool) {
	x.sync.Lock()
	defer x.sync.Unlock()

	filePath, fieldinfos, found := x.roAggregate.FindField(resource, field)
	if found {
		return filePath, fieldinfos, found
	}

	if x.lastRefreshed >= LastProviderInstall {
		return filePath, fieldinfos, found
	}

	x.unsafeLoadAll()
	x.unsafeRefresh()

	return x.roAggregate.FindField(resource, field)
}

// ---------------------------- unsafe methods ----------------------------
// |  Only use these calls inside of a lock.                              |
// |  Do NOT lock the object during these calls.                          |
// V  Do NOT call to locking methods (~ everything above this line).      V
// ------------------------------------------------------------------------

func (x *extensibleSchema) unsafeLoadAll() {
	// If another goroutine started to load this before us, it will be locked until
	// we complete to load everything and then it will be dumped into this
	// position. At this point, if it has been loaded we can return safely, since
	// we don't unlock until we are finished loading.
	if x.lastRefreshed >= LastProviderInstall {
		return
	}
	x.lastRefreshed = LastProviderInstall

	providers, err := ListActive()
	if err != nil {
		log.Error().Err(err).Msg("failed to list all providers, can't load additional schemas")
		return
	}

	for name := range providers {
		schema, err := x.coordinator.LoadSchema(name)
		if err != nil {
			log.Error().Err(err).Msg("load schema failed")
		} else {
			x.unsafeAdd(name, schema)
		}
	}
}

func (x *extensibleSchema) unsafeAdd(name string, schema resources.ResourcesSchema) {
	if schema == nil {
		return
	}
	if name == "" {
		log.Error().Msg("tried to add a schema with no name")
		return
	}

	x.loaded[name] = schema
}

func (x *extensibleSchema) unsafeRefresh() {
	res := resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{},
		ProviderRoots:    map[string]string{},
	}

	for _, schema := range x.loaded {
		res.Add(schema)
	}

	// Note: This object is read-only and thus must be re-created to
	// prevent concurrency issues with access outside this struct
	x.roAggregate = resources.Schema{
		Resources:        res.Resources,
		Dependencies:     res.Dependencies,
		ProviderVersions: res.ProviderVersions,
		// Each provider's declared asset root, so a compile that reads the
		// aggregate can tell what hangs off an asset's tree (ADR 031).
		ProviderRoots: res.ProviderRoots,
	}
}
