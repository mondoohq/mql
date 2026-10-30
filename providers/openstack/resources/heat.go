// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/gophercloud/gophercloud/v2/openstack/orchestration/v1/stacks"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.orchestration.stack ----

type mqlOpenstackOrchestrationStackInternal struct {
	detailLock           sync.Mutex
	detailDone           bool
	cacheDisableRollback bool
	cacheTimeout         int
	cacheParameters      map[string]string
}

func (r *mqlOpenstackOrchestrationStack) id() (string, error) {
	return "openstack.orchestration.stack/" + r.Id.Data, nil
}

func initOpenstackOrchestrationStack(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetStacks()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackOrchestrationStack)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.orchestration.stack", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) stacks() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.OrchestrationClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := stacks.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := stacks.ExtractStacks(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.orchestration.stack", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.orchestration.stack/" + s.ID),
			"id":           llx.StringData(s.ID),
			"name":         llx.StringData(s.Name),
			"description":  llx.StringData(s.Description),
			"status":       llx.StringData(s.Status),
			"statusReason": llx.StringData(s.StatusReason),
			"tags":         stringSliceData(s.Tags),
			"createdAt":    llx.TimeDataPtr(timePtr(s.CreationTime)),
			"updatedAt":    llx.TimeDataPtr(timePtr(s.UpdatedTime)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// fetchDetail loads the fields that only the per-stack Get returns
// (disable_rollback, timeout, parameters), caching them so the three
// detail accessors share a single API call. Double-checked locking guards
// the one-time fetch.
func (r *mqlOpenstackOrchestrationStack) fetchDetail() error {
	if r.detailDone {
		return nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailDone {
		return nil
	}

	c := conn(r.MqlRuntime)
	client, err := c.OrchestrationClient()
	if err != nil {
		if serviceMissing(err) {
			r.detailDone = true
			return nil
		}
		return err
	}
	stack, err := stacks.Get(ctx(), client, r.Name.Data, r.Id.Data).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			r.detailDone = true
			return nil
		}
		return err
	}
	r.cacheDisableRollback = stack.DisableRollback
	r.cacheTimeout = stack.Timeout
	r.cacheParameters = stack.Parameters
	r.detailDone = true
	return nil
}

func (r *mqlOpenstackOrchestrationStack) disableRollback() (bool, error) {
	if err := r.fetchDetail(); err != nil {
		return false, err
	}
	return r.cacheDisableRollback, nil
}

func (r *mqlOpenstackOrchestrationStack) timeoutMinutes() (int64, error) {
	if err := r.fetchDetail(); err != nil {
		return 0, err
	}
	return int64(r.cacheTimeout), nil
}

func (r *mqlOpenstackOrchestrationStack) parameters() (map[string]any, error) {
	if err := r.fetchDetail(); err != nil {
		return nil, err
	}
	return stringMap(r.cacheParameters), nil
}
