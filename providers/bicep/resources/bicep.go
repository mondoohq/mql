// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlBicep) id() (string, error) {
	return "bicep", nil
}

func (r *mqlBicep) files() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BicepConnection)
	bicepFiles := conn.BicepFiles()

	var mqlFiles []any
	for _, f := range bicepFiles {
		mqlF, err := newMqlBicepFile(r.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		mqlFiles = append(mqlFiles, mqlF)
	}
	return mqlFiles, nil
}

// resources flattens every file's top-level resources into a single list so
// policies can query `bicep.resources` directly, mirroring `terraform.resources`.
func (r *mqlBicep) resources() ([]any, error) {
	files, err := r.files()
	if err != nil {
		return nil, err
	}
	var out []any
	for _, f := range files {
		rs, err := f.(*mqlBicepFile).resources()
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

func (r *mqlBicep) paramFiles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BicepConnection)
	paramFiles := conn.BicepParamFiles()

	var mqlFiles []any
	for _, f := range paramFiles {
		using, params := parseBicepParam(f.Content)

		mqlParams := make(map[string]any, len(params))
		for k, v := range params {
			mqlParams[k] = v
		}

		res, err := CreateResource(r.MqlRuntime, "bicep.paramFile", map[string]*llx.RawData{
			"__id":    llx.StringData(f.Path),
			"path":    llx.StringData(f.Path),
			"using":   llx.StringData(using),
			"params":  llx.MapData(mqlParams, types.String),
			"content": llx.StringData(f.Content),
		})
		if err != nil {
			return nil, err
		}
		mqlFiles = append(mqlFiles, res)
	}
	return mqlFiles, nil
}

// template returns the first ARM template the scan discovered. It stays the
// right answer for a direct `bicep <file>.json` connection, where the scan
// yields exactly one; a tree holding several is reached through templates.
func (r *mqlBicep) template() (*mqlBicepTemplate, error) {
	conn := r.MqlRuntime.Connection.(*connection.BicepConnection)
	tmpls := conn.ARMTemplates()
	if len(tmpls) == 0 {
		r.Template.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newMqlBicepTemplate(r.MqlRuntime, tmpls[0].Path, tmpls[0].Template)
}

// templates returns every ARM template the scan discovered, each keyed by its
// own path so a repo with more than one has all of them audited.
func (r *mqlBicep) templates() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BicepConnection)
	tmpls := conn.ARMTemplates()
	out := make([]any, 0, len(tmpls))
	for _, t := range tmpls {
		mqlT, err := newMqlBicepTemplate(r.MqlRuntime, t.Path, t.Template)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlT)
	}
	return out, nil
}

type mqlBicepFileInternal struct {
	parseOnce sync.Once
	parsed    *parsedBicepFile

	resolverOnce   sync.Once
	cachedResolver *symbolResolver
}

func newMqlBicepFile(runtime *plugin.Runtime, f *connection.BicepFile) (*mqlBicepFile, error) {
	parsed := parseBicep(f.Content)

	metadata := make(map[string]any, len(parsed.metadata))
	for k, v := range parsed.metadata {
		metadata[k] = v
	}

	res, err := CreateResource(runtime, "bicep.file", map[string]*llx.RawData{
		"__id":        llx.StringData("bicep.file:" + f.Path),
		"path":        llx.StringData(f.Path),
		"targetScope": llx.StringData(parsed.targetScope),
		"metadata":    llx.MapData(metadata, types.String),
		"content":     llx.StringData(f.Content),
	})
	if err != nil {
		return nil, err
	}
	mqlF := res.(*mqlBicepFile)
	// CreateResource may return a cached instance for the same __id;
	// parseOnce keeps the stamp race-free under concurrent callers and
	// happens-before any subsequent reader.
	mqlF.parseOnce.Do(func() { mqlF.parsed = parsed })
	return mqlF, nil
}

// getParsed returns the parsed Bicep model, parsing on demand if the
// resource was reconstructed across a gRPC boundary (where Internal
// fields are zeroed but the public `content` field survives).
func (f *mqlBicepFile) getParsed() *parsedBicepFile {
	f.parseOnce.Do(func() {
		f.parsed = parseBicep(f.Content.Data)
	})
	return f.parsed
}

func (f *mqlBicepFile) id() (string, error) {
	return "bicep.file:" + f.Path.Data, nil
}

// resolver builds the per-file symbol table once and caches it. It's invoked
// from variables()/resources()/modules()/outputs(), so caching avoids
// rebuilding the index (and its maps) on each call. The resolver lets
// expression-tree nodes resolve a root identifier (`target`) to the
// declaration it names within this file, and is derived purely from the
// already-parsed model.
func (f *mqlBicepFile) resolver() *symbolResolver {
	f.resolverOnce.Do(func() {
		f.cachedResolver = newSymbolResolver(f.Path.Data, f.getParsed())
	})
	return f.cachedResolver
}

func (f *mqlBicepFile) parameters() ([]any, error) {
	return createMqlParameters(f.MqlRuntime, f.Path.Data, f.getParsed().parameters, f.resolver())
}

func (f *mqlBicepFile) variables() ([]any, error) {
	return createMqlVariables(f.MqlRuntime, f.Path.Data, f.getParsed().variables, f.resolver())
}

func (f *mqlBicepFile) resources() ([]any, error) {
	return createMqlResources(f.MqlRuntime, f.Path.Data, f.getParsed().resources, f.resolver())
}

func (f *mqlBicepFile) modules() ([]any, error) {
	return createMqlModules(f.MqlRuntime, f.Path.Data, f.getParsed().modules, f.resolver())
}

func (f *mqlBicepFile) outputs() ([]any, error) {
	return createMqlOutputs(f.MqlRuntime, f.Path.Data, f.getParsed().outputs, f.resolver())
}

func (f *mqlBicepFile) types() ([]any, error) {
	return createMqlTypes(f.MqlRuntime, f.Path.Data, f.getParsed().types)
}

func (f *mqlBicepFile) functions() ([]any, error) {
	return createMqlFunctions(f.MqlRuntime, f.Path.Data, f.getParsed().functions)
}

func (f *mqlBicepFile) imports() ([]any, error) {
	return createMqlImports(f.MqlRuntime, f.Path.Data, f.getParsed().imports)
}
