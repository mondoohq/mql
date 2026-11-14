// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"google.golang.org/protobuf/proto"
)

// The compile cache.
//
// What Compile gives is decided by the query's text, the types of the
// properties it uses, the schema and the configuration. A scan of many assets
// compiles the same policy for each of them, against the same schema: a
// thousand assets, a thousand times the same code. With MQL_COMPILE_CACHE=1
// the second and every later compile of a query is a copy of the first.
//
// It is off unless asked for, and only used where the schema can say which
// version of itself it is (SchemaVersion); a schema that cannot is compiled
// against every time, as before.

var (
	compileCacheEnabled = os.Getenv("MQL_COMPILE_CACHE") == "1" || compileCacheShared
	// With MQL_COMPILE_CACHE=share every compile of a query gets the same
	// bundle, not a copy of it. That is only right for callers that treat a
	// compiled bundle as read-only, which is how the executors treat it; it
	// is what keeps a scan from holding one copy of a policy's code per asset.
	compileCacheShared = os.Getenv("MQL_COMPILE_CACHE") == "share" || compileCacheVerify
	// MQL_COMPILE_CACHE=verify is the shared mode with a check: every time a
	// bundle is handed out again it is compared with a copy kept aside. A
	// caller that changed a bundle it was given is logged, and the bundle is
	// replaced. It is how to find out whether a program can use the shared
	// mode.
	compileCacheVerify = os.Getenv("MQL_COMPILE_CACHE") == "verify"
	// compileCacheChanged counts the changed bundles the check found.
	compileCacheChanged atomic.Uint64
)

// versionedSchema is a schema that can tell one state of itself from another.
type versionedSchema interface {
	SchemaVersion() (object uintptr, version uint64)
}

type compileKey struct {
	input string
	conf  string
	// schema is the schema itself, not its address: the key keeps it alive,
	// so another schema cannot come to sit where it was.
	schema  versionedSchema
	version uint64
}

var compileCache = struct {
	sync.RWMutex
	entries map[compileKey]compiled
}{}

// compiled is a kept bundle and, where bundles are checked, the copy of it
// that nobody else has.
type compiled struct {
	bundle *llx.CodeBundle
	aside  *llx.CodeBundle
}

// A cached bundle is kept by everything that decides it. Too many of them
// and the cache starts over: this is for the queries of the policies in use,
// not for everything a long-lived process ever compiled.
const compileCacheLimit = 8192

// compileCacheKey is the key of a compile, or false if this compile cannot
// be cached: statistics are being collected, or something it depends on has
// no identity to key on.
//
// A compile with a source of translations is one of those. What the source
// answers is only known by asking it, per provider, while compiling, and it
// belongs to one runtime: there is nothing of it to put in a key.
func compileCacheKey(input string, conf CompilerConfig) (compileKey, bool) {
	if !compileCacheEnabled {
		return compileKey{}, false
	}
	if _, quiet := conf.Stats.(compilerStatsNull); !quiet {
		return compileKey{}, false
	}
	if conf.Translations != nil {
		return compileKey{}, false
	}
	schema, ok := conf.Schema.(versionedSchema)
	// Only a pointer is the same schema when it compares equal.
	if !ok || reflect.ValueOf(schema).Kind() != reflect.Pointer {
		return compileKey{}, false
	}
	key := compileKey{input: input, schema: schema}
	_, key.version = schema.SchemaVersion()

	floor := make([]string, 0, len(conf.DowngradeFloor))
	for provider, version := range conf.DowngradeFloor {
		floor = append(floor, provider+"="+version)
	}
	sort.Strings(floor)
	key.conf = fmt.Sprintf("%t|%x|%t|%q|%q|%t|%q", conf.UseAssetContext, []byte(conf.Features), conf.Strict,
		conf.AssetRoot, conf.DeclaredAssetRoot, conf.RootedNamespace, floor)
	return key, true
}

// cachedCompile returns a copy of what an earlier compile of the same query
// gave, if the properties it used are still there with the same types.
//
// The properties are asked for by name, as the compiler asks: a handler may
// keep track of what a query used.
func cachedCompile(key compileKey, props PropsHandler) *llx.CodeBundle {
	compileCache.RLock()
	entry := compileCache.entries[key]
	compileCache.RUnlock()
	bundle := entry.bundle
	if bundle == nil {
		return nil
	}
	// The check reads a bundle that a caller who changes it may be writing
	// at that moment. That is the fault it is there to find, not one it
	// can guard against: it is for trying a program out, not for running it.
	if entry.aside != nil && !proto.Equal(bundle, entry.aside) {
		compileCacheChanged.Add(1)
		log.Error().Str("query", key.input).
			Msg("a caller changed a compiled query it shares with others; MQL_COMPILE_CACHE=share is not safe for this program")
		bundle = proto.Clone(entry.aside).(*llx.CodeBundle)
		compileCache.Lock()
		compileCache.entries[key] = compiled{bundle: bundle, aside: entry.aside}
		compileCache.Unlock()
	}
	for name, typ := range bundle.Props {
		if props == nil {
			return nil
		}
		if prop := props.Get(name); prop == nil || prop.Type != typ {
			return nil
		}
	}
	if compileCacheShared {
		return bundle
	}
	// A copy: whoever gets a bundle from Compile owns it.
	return proto.Clone(bundle).(*llx.CodeBundle)
}

func storeCompile(key compileKey, bundle *llx.CodeBundle) {
	kept := bundle
	if !compileCacheShared {
		kept = proto.Clone(bundle).(*llx.CodeBundle)
	}
	entry := compiled{bundle: kept}
	if compileCacheVerify {
		entry.aside = proto.Clone(bundle).(*llx.CodeBundle)
	}
	compileCache.Lock()
	if compileCache.entries == nil || len(compileCache.entries) >= compileCacheLimit {
		compileCache.entries = map[compileKey]compiled{}
	}
	compileCache.entries[key] = entry
	compileCache.Unlock()
}
