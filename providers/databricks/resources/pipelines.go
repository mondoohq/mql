// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/databricks/databricks-sdk-go/service/pipelines"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlDatabricksPipelineInternal memoizes the pipeline detail. The list response
// carries only the pipeline's identity and run state, so everything describing
// what the pipeline publishes and what it runs on comes from a Get, which is
// issued at most once per pipeline and only when one of those fields is read.
type mqlDatabricksPipelineInternal struct {
	specFetched atomic.Bool
	spec        *pipelines.PipelineSpec
	specLock    sync.Mutex
}

func (r *mqlDatabricks) pipelines() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	list, err := ws.Pipelines.ListPipelinesAll(context.Background(), pipelines.ListPipelinesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range list {
		p := list[i]
		res, err := newMqlDatabricksPipeline(r.MqlRuntime, p.PipelineId, p.Name, string(p.State),
			string(p.Health), p.CreatorUserName, p.RunAsUserName)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksPipeline maps a pipeline's identity and run state to its
// resource. Shared by the list path and the init lookup so a pipeline hydrated
// by id carries the same fields as a listed one.
func newMqlDatabricksPipeline(runtime *plugin.Runtime, id, name, state, health, creator, runAs string) (*mqlDatabricksPipeline, error) {
	res, err := CreateResource(runtime, "databricks.pipeline", map[string]*llx.RawData{
		"__id":            llx.StringData("databricks.pipeline/" + id),
		"id":              llx.StringData(id),
		"name":            llx.StringData(name),
		"state":           llx.StringData(state),
		"health":          llx.StringData(health),
		"creatorUserName": llx.StringData(creator),
		"runAs":           llx.StringData(runAs),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksPipeline), nil
}

// initDatabricksPipeline resolves a single pipeline by id so references from a
// job task can hydrate a full pipeline from just its id.
func initDatabricksPipeline(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, fmt.Errorf("databricks.pipeline requires a non-empty id")
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	detail, err := ws.Pipelines.GetByPipelineId(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	if detail == nil {
		return nil, nil, fmt.Errorf("databricks.pipeline with id %q not found", id)
	}

	res, err := newMqlDatabricksPipeline(runtime, detail.PipelineId, detail.Name, string(detail.State),
		string(detail.Health), detail.CreatorUserName, detail.RunAsUserName)
	if err != nil {
		return nil, nil, err
	}
	// The detail is already in hand, so seed the memo rather than fetching it
	// again the first time a spec-backed field is read.
	res.spec = detail.Spec
	res.specFetched.Store(true)
	return nil, res, nil
}

// pipelineSpec returns the pipeline's declarative specification, fetching it
// once on first use. A pipeline with no specification yields nil, which every
// caller reads as the field's zero value.
func (r *mqlDatabricksPipeline) pipelineSpec() (*pipelines.PipelineSpec, error) {
	if r.specFetched.Load() {
		return r.spec, nil
	}
	r.specLock.Lock()
	defer r.specLock.Unlock()
	if r.specFetched.Load() {
		return r.spec, nil
	}

	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	detail, err := ws.Pipelines.GetByPipelineId(context.Background(), r.Id.Data)
	if err != nil {
		return nil, err
	}
	if detail != nil {
		r.spec = detail.Spec
	}
	r.specFetched.Store(true)
	return r.spec, nil
}

func (r *mqlDatabricksPipeline) catalog() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Catalog, nil
}

func (r *mqlDatabricksPipeline) schema() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Schema, nil
}

func (r *mqlDatabricksPipeline) target() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Target, nil
}

func (r *mqlDatabricksPipeline) storage() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Storage, nil
}

func (r *mqlDatabricksPipeline) rootPath() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.RootPath, nil
}

func (r *mqlDatabricksPipeline) channel() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Channel, nil
}

func (r *mqlDatabricksPipeline) edition() (string, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return "", err
	}
	return spec.Edition, nil
}

func (r *mqlDatabricksPipeline) photon() (bool, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return false, err
	}
	return spec.Photon, nil
}

func (r *mqlDatabricksPipeline) development() (bool, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return false, err
	}
	return spec.Development, nil
}

func (r *mqlDatabricksPipeline) serverless() (bool, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return false, err
	}
	return spec.Serverless, nil
}

func (r *mqlDatabricksPipeline) continuous() (bool, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return false, err
	}
	return spec.Continuous, nil
}

func (r *mqlDatabricksPipeline) configuration() (map[string]any, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return map[string]any{}, err
	}
	return strMap(spec.Configuration), nil
}

func (r *mqlDatabricksPipeline) tags() (map[string]any, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return map[string]any{}, err
	}
	return strMap(spec.Tags), nil
}

// pipelineLibraryToDict flattens a pipeline library to its type and the path or
// coordinate it resolves to. The library is a union in which exactly one source
// field is set, and only JSON-native values are used, as llx dicts accept
// nothing else.
func pipelineLibraryToDict(libs []pipelines.PipelineLibrary) []any {
	out := make([]any, 0, len(libs))
	for i := range libs {
		l := libs[i]
		var entry map[string]any
		switch {
		case l.Notebook != nil:
			entry = map[string]any{"type": "notebook", "path": l.Notebook.Path}
		case l.File != nil:
			entry = map[string]any{"type": "file", "path": l.File.Path}
		case l.Glob != nil:
			entry = map[string]any{"type": "glob", "path": l.Glob.Include}
		case l.Maven != nil:
			entry = map[string]any{
				"type":       "maven",
				"coordinate": l.Maven.Coordinates,
				"repository": l.Maven.Repo,
			}
		case l.Jar != "":
			entry = map[string]any{"type": "jar", "path": l.Jar}
		case l.Whl != "":
			entry = map[string]any{"type": "whl", "path": l.Whl}
		default:
			// A library whose source this SDK version does not model still needs
			// to appear, otherwise the list silently under-reports.
			entry = map[string]any{"type": "", "path": ""}
		}
		out = append(out, entry)
	}
	return out
}

func (r *mqlDatabricksPipeline) libraries() ([]any, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return []any{}, err
	}
	return pipelineLibraryToDict(spec.Libraries), nil
}

func (r *mqlDatabricksPipeline) clusters() ([]any, error) {
	spec, err := r.pipelineSpec()
	if err != nil || spec == nil {
		return []any{}, err
	}

	idPrefix := "databricks.pipeline/" + r.Id.Data
	out := []any{}
	for i := range spec.Clusters {
		res, err := newMqlDatabricksClusterSpec(r.MqlRuntime, idPrefix, pipelineClusterSpecFields(spec.Clusters[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
