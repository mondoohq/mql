// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"

	"go.mondoo.com/mql/llx"
)

// WithContext gives one query its own call lifetime. The connection, resource
// cache and recording stay shared, but cancellation is never stored on them.
func (r *Runtime) WithContext(ctx context.Context) llx.Runtime {
	return &contextRuntime{Runtime: r, ctx: ctx}
}

type contextRuntime struct {
	*Runtime
	ctx context.Context
}

func (r *contextRuntime) CreateResource(name string, args map[string]*llx.Primitive) (llx.Resource, error) {
	return r.createResource(r.ctx, name, args)
}

func (r *contextRuntime) CloneResource(src llx.Resource, id string, fields []string, args map[string]*llx.Primitive) (llx.Resource, error) {
	return r.cloneResource(r.ctx, src, id, fields, args)
}

func (r *contextRuntime) WatchAndUpdate(resource llx.Resource, field, watcherUID string, callback func(any, error)) error {
	return r.watchAndUpdateCallback(r.ctx, resource, field, watcherUID, callback)
}

func (r *contextRuntime) ResolveAssetRoot(v *llx.AssetValue, root string) (llx.Resource, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	resource, err := r.Runtime.ResolveAssetRoot(v, root)
	if err != nil {
		return nil, err
	}
	if bound, ok := resource.(llx.RuntimeBoundResource); ok {
		if runtime, ok := bound.MqlRuntime().(llx.ContextRuntime); ok {
			return llx.BindResource(resource, runtime.WithContext(r.ctx)), nil
		}
	}
	return resource, nil
}
