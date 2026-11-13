// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"

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
	compileCacheShared = os.Getenv("MQL_COMPILE_CACHE") == "share"
)

// versionedSchema is a schema that can tell one state of itself from another.
type versionedSchema interface {
	SchemaVersion() (object uintptr, version uint64)
}

type compileKey struct {
	input   string
	conf    string
	schema  uintptr
	version uint64
}

var compileCache = struct {
	sync.RWMutex
	entries map[compileKey]*llx.CodeBundle
}{}

// A cached bundle is kept by everything that decides it. Too many of them
// and the cache starts over: this is for the queries of the policies in use,
// not for everything a long-lived process ever compiled.
const compileCacheLimit = 8192

// compileCacheKey is the key of a compile, or false if this compile cannot
// be cached: statistics are being collected, or something it depends on has
// no identity to key on.
func compileCacheKey(input string, conf CompilerConfig) (compileKey, bool) {
	if !compileCacheEnabled {
		return compileKey{}, false
	}
	if _, quiet := conf.Stats.(compilerStatsNull); !quiet {
		return compileKey{}, false
	}
	schema, ok := conf.Schema.(versionedSchema)
	if !ok {
		return compileKey{}, false
	}
	key := compileKey{input: input}
	key.schema, key.version = schema.SchemaVersion()

	translations := uintptr(0)
	if conf.Translations != nil {
		v := reflect.ValueOf(conf.Translations)
		if v.Kind() != reflect.Pointer {
			return compileKey{}, false
		}
		translations = v.Pointer()
	}
	floor := make([]string, 0, len(conf.DowngradeFloor))
	for provider, version := range conf.DowngradeFloor {
		floor = append(floor, provider+"="+version)
	}
	sort.Strings(floor)
	key.conf = fmt.Sprintf("%t|%x|%t|%s|%s|%t|%x|%s", conf.UseAssetContext, []byte(conf.Features), conf.Strict,
		conf.AssetRoot, conf.DeclaredAssetRoot, conf.RootedNamespace, translations, strings.Join(floor, ","))
	return key, true
}

// cachedCompile returns a copy of what an earlier compile of the same query
// gave, if the properties it used are still there with the same types.
//
// The properties are asked for by name, as the compiler asks: a handler may
// keep track of what a query used.
func cachedCompile(key compileKey, props PropsHandler) *llx.CodeBundle {
	compileCache.RLock()
	bundle := compileCache.entries[key]
	compileCache.RUnlock()
	if bundle == nil {
		return nil
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
	compileCache.Lock()
	if compileCache.entries == nil || len(compileCache.entries) >= compileCacheLimit {
		compileCache.entries = map[compileKey]*llx.CodeBundle{}
	}
	compileCache.entries[key] = kept
	compileCache.Unlock()
}
