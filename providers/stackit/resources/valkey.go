// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	valkey "github.com/stackitcloud/stackit-sdk-go/services/valkey/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Valkey is a CF-broker engine with the same instance, backup, and offering
// shapes as Redis, so it reuses the shared CF-broker mappers. Unlike the
// older engines it exposes no raw `parameters` dict: the blob carries
// metrics_prefix, which the SDK documents as commonly holding an API key for
// the Graphite receiver. The blob is kept on the resource's internal state
// and only the posture keys are lifted onto typed fields.

func (r *mqlStackitValkey) id() (string, error) {
	return "stackit.valkey/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackit) valkey() (*mqlStackitValkey, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.valkey")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitValkey), nil
}

type mqlStackitValkeyInternal struct {
	// offeringIndex memoizes the engine catalog for the instance edges.
	offeringIndex dbaasOfferingIndex
}

type mqlStackitValkeyInstanceInternal struct {
	// cacheParams is the instance's parameters blob, never exposed as a whole.
	cacheParams any
}

type mqlStackitValkeyOfferingInternal struct {
	// cachePlans holds the plan resources built with the offering.
	cachePlans []any
}

// valkeyInstanceArgs maps a Valkey instance onto the shared CF-broker fields,
// dropping the parameters blob the schema does not carry.
func valkeyInstanceArgs(region string, inst *valkey.Instance) (map[string]*llx.RawData, any) {
	lop := inst.GetLastOperation()
	st, stOk := inst.GetStatusOk()
	args := cfBrokerInstanceArgs(region, inst, st, stOk, &lop)
	delete(args, "parameters")
	return args, toDict(inst.GetParameters())
}

func newValkeyInstance(runtime *plugin.Runtime, region string, inst *valkey.Instance) (*mqlStackitValkeyInstance, error) {
	args, params := valkeyInstanceArgs(region, inst)
	res, err := CreateResource(runtime, "stackit.valkey.instance", args)
	if err != nil {
		return nil, err
	}
	v := res.(*mqlStackitValkeyInstance)
	v.cacheParams = params
	return v, nil
}

func (r *mqlStackitValkey) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Valkey()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		// The broker answers 404 for a project that never enabled the service.
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items := resp.GetInstances()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := newValkeyInstance(r.MqlRuntime, c.Region(), &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitValkeyInstance) id() (string, error) {
	return "stackit.valkey.instance/" + r.Id.Data, nil
}

func initStackitValkeyInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := idArg(args, "id")
	if !ok {
		return nil, nil, fmt.Errorf("stackit.valkey.instance requires an id")
	}
	c := conn(runtime)
	client, err := c.Valkey()
	if err != nil {
		return nil, nil, err
	}
	inst, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if inst == nil {
		return nil, nil, fmt.Errorf("stackit.valkey.instance with id %q not found", id)
	}
	res, err := newValkeyInstance(runtime, c.Region(), inst)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// params presents the cached blob in the shape the shared parameter readers take.
func (r *mqlStackitValkeyInstance) params() *plugin.TValue[any] {
	return &plugin.TValue[any]{Data: r.cacheParams, State: plugin.StateIsSet}
}

func (r *mqlStackitValkeyInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.params(), "sgw_acl")
}

func (r *mqlStackitValkeyInstance) internetReachable() (bool, error) {
	return dbaasInstanceReachable(r.cacheParams), nil
}

func (r *mqlStackitValkeyInstance) syslog() ([]any, error) {
	return tlsParamList(r.params(), "syslog")
}

func (r *mqlStackitValkeyInstance) graphite() (string, error) {
	return tlsParamString(r.params(), "graphite")
}

func (r *mqlStackitValkeyInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.params(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitValkeyInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.params(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitValkeyInstance) maxDiskThreshold() (int64, error) {
	return r.paramIntOrNull("max_disk_threshold", &r.MaxDiskThreshold)
}

func (r *mqlStackitValkeyInstance) snapshot() (string, error) {
	return tlsParamString(r.params(), "snapshot")
}

func (r *mqlStackitValkeyInstance) maxmemoryPolicy() (string, error) {
	return tlsParamString(r.params(), "maxmemory-policy")
}

func (r *mqlStackitValkeyInstance) notifyKeyspaceEvents() (string, error) {
	return tlsParamString(r.params(), "notify-keyspace-events")
}

func (r *mqlStackitValkeyInstance) maxClients() (int64, error) {
	return r.paramIntOrNull("maxclients", &r.MaxClients)
}

func (r *mqlStackitValkeyInstance) minReplicasToWrite() (int64, error) {
	return r.paramIntOrNull("min-replicas-to-write", &r.MinReplicasToWrite)
}

func (r *mqlStackitValkeyInstance) paramIntOrNull(key string, field *plugin.TValue[int64]) (int64, error) {
	v, ok, err := paramInt(r.params(), key)
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(field)
	}
	return v, nil
}

func (r *mqlStackitValkeyInstance) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Valkey()
	if err != nil {
		return nil, err
	}
	items, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	idBase := "stackit.valkey.instance.backup/" + r.Id.Data
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.valkey.instance.backup", cfBackupArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitValkeyOffering) offeringVersion() string { return r.Version.Data }
func (r *mqlStackitValkeyOffering) offeringPlans() []any    { return r.cachePlans }
func (r *mqlStackitValkeyOfferingPlan) planID() string      { return r.Id.Data }

func (r *mqlStackitValkey) offerings() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Valkey()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListOfferings(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items := resp.GetOfferings()
	idBase := "stackit.valkey.offering/" + c.ProjectID()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.valkey.offering", cfOfferingArgs(idBase, &items[i]))
		if err != nil {
			return nil, err
		}
		off := res.(*mqlStackitValkeyOffering)
		plans := items[i].GetPlans()
		planBase := idBase + "/" + items[i].GetName() + "/" + items[i].GetVersion() + "/plan"
		for p := range plans {
			plan, err := CreateResource(r.MqlRuntime, "stackit.valkey.offering.plan", cfPlanArgs(planBase, &plans[p]))
			if err != nil {
				return nil, err
			}
			off.cachePlans = append(off.cachePlans, plan)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitValkeyOffering) plans() ([]any, error) { return r.cachePlans, nil }

func (r *mqlStackitValkeyInstance) offering() (*mqlStackitValkeyOffering, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.valkey")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitValkey)
	byVersion, _, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	o, ok := byVersion[r.OfferingVersion.Data].(*mqlStackitValkeyOffering)
	if !ok {
		return markNull[mqlStackitValkeyOffering](&r.Offering)
	}
	return o, nil
}

func (r *mqlStackitValkeyInstance) plan() (*mqlStackitValkeyOfferingPlan, error) {
	ns, err := makeNamespace(r.MqlRuntime, "stackit.valkey")
	if err != nil {
		return nil, err
	}
	n := ns.(*mqlStackitValkey)
	_, byID, err := n.offeringIndex.build(func() ([]any, error) { return listAny(n.GetOfferings()) })
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.PlanId.Data].(*mqlStackitValkeyOfferingPlan)
	if !ok {
		return markNull[mqlStackitValkeyOfferingPlan](&r.Plan)
	}
	return p, nil
}

var (
	_ cfBrokerInstance = (*valkey.Instance)(nil)
	_ cfBackup         = (*valkey.Backup)(nil)
	_ cfOffering       = (*valkey.Offering)(nil)
	_ cfPlan           = (*valkey.Plan)(nil)
)
