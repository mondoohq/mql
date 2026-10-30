// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlOpenstack) id() (string, error) {
	c := conn(r.MqlRuntime)
	return "openstack/" + c.ProjectID(), nil
}

// initOpenstack populates the top-level resource's scalar fields from the
// connection. Without this, MQL tries to use the explicit "create" path and
// the runtime fails because no field setter is registered for these inputs.
func initOpenstack(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	c := conn(runtime)
	if _, ok := args["authUrl"]; !ok {
		args["authUrl"] = llx.StringData(c.AuthURL())
	}
	if _, ok := args["projectId"]; !ok {
		args["projectId"] = llx.StringData(c.ProjectID())
	}
	return args, nil, nil
}

// region resolves the connection's target region to a typed Keystone region
// reference. The raw region id remains available via `region.id` even when the
// region list can't be read (e.g. a non-admin token), since it is the cache
// key. Null when the connection is not bound to a region.
func (r *mqlOpenstack) region() (*mqlOpenstackIdentityRegion, error) {
	name := conn(r.MqlRuntime).Region()
	if name == "" {
		r.Region.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.identity.region", map[string]*llx.RawData{
		"id": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackIdentityRegion), nil
}
