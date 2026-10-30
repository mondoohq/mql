// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlSnowflakeAccount) resourceMonitors() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	monitors, err := client.ResourceMonitors.Show(ctx, &sdk.ShowResourceMonitorRequest{})
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(monitors))
	for i := range monitors {
		mqlMonitor, err := newMqlSnowflakeResourceMonitor(r.MqlRuntime, monitors[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlMonitor)
	}

	return list, nil
}

func newMqlSnowflakeResourceMonitor(runtime *plugin.Runtime, monitor sdk.ResourceMonitor) (*mqlSnowflakeResourceMonitor, error) {
	level := ""
	if monitor.Level != nil {
		level = string(*monitor.Level)
	}

	notifyAt := make([]any, 0, len(monitor.NotifyAt))
	for _, n := range monitor.NotifyAt {
		notifyAt = append(notifyAt, int64(n))
	}

	notifyUsers := make([]any, 0, len(monitor.NotifyUsers))
	for _, u := range monitor.NotifyUsers {
		notifyUsers = append(notifyUsers, u)
	}

	args := map[string]*llx.RawData{
		"__id":             llx.StringData(monitor.ID().FullyQualifiedName()),
		"name":             llx.StringData(monitor.Name),
		"level":            llx.StringData(level),
		"creditQuota":      llx.FloatData(monitor.CreditQuota),
		"usedCredits":      llx.FloatData(monitor.UsedCredits),
		"remainingCredits": llx.FloatData(monitor.RemainingCredits),
		"frequency":        llx.StringDataPtr((*string)(monitor.Frequency)),
		"startTime":        llx.StringData(monitor.StartTime),
		"endTime":          llx.StringData(monitor.EndTime),
		"comment":          llx.StringData(monitor.Comment),
		"notifyAt":         llx.ArrayData(notifyAt, types.Int),
		"notifyUsers":      llx.ArrayData(notifyUsers, types.String),
		"createdAt":        llx.TimeData(monitor.CreatedOn),
	}

	res, err := CreateResource(runtime, "snowflake.resourceMonitor", args)
	if err != nil {
		return nil, err
	}
	mqlMonitor := res.(*mqlSnowflakeResourceMonitor)
	mqlMonitor.cacheOwner = monitor.Owner

	// suspendAt and suspendImmediateAt are computed methods (nullable int) — set
	// the TValue directly so the stub accessors don't trigger a recomputation.
	if monitor.SuspendAt != nil {
		mqlMonitor.SuspendAt = plugin.TValue[int64]{Data: int64(*monitor.SuspendAt), State: plugin.StateIsSet}
	} else {
		mqlMonitor.SuspendAt = plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet | plugin.StateIsNull}
	}
	if monitor.SuspendImmediatelyAt != nil {
		mqlMonitor.SuspendImmediateAt = plugin.TValue[int64]{Data: int64(*monitor.SuspendImmediatelyAt), State: plugin.StateIsSet}
	} else {
		mqlMonitor.SuspendImmediateAt = plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet | plugin.StateIsNull}
	}

	return mqlMonitor, nil
}

// suspendAt and suspendImmediateAt are populated eagerly by
// newMqlSnowflakeResourceMonitor; these stubs exist only to satisfy the
// generator's computed-method dispatch and should never actually run.
func (r *mqlSnowflakeResourceMonitor) suspendAt() (int64, error) {
	return 0, nil
}

func (r *mqlSnowflakeResourceMonitor) suspendImmediateAt() (int64, error) {
	return 0, nil
}

// initSnowflakeResourceMonitor resolves a resource monitor by name so typed
// references (such as snowflake.warehouse.resourceMonitorRef) can hydrate a full
// monitor from just its name.
func initSnowflakeResourceMonitor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("snowflake.resourceMonitor requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	monitors, err := client.ResourceMonitors.Show(ctx, &sdk.ShowResourceMonitorRequest{Like: &sdk.Like{Pattern: new(name)}})
	if err != nil {
		return nil, nil, err
	}
	for i := range monitors {
		if monitors[i].Name == name {
			res, err := newMqlSnowflakeResourceMonitor(runtime, monitors[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.resourceMonitor %q not found", name)
}

// snowflakeResourceMonitorByName resolves a monitor name to a typed
// snowflake.resourceMonitor, or a null resource when the name is empty.
func snowflakeResourceMonitorByName(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlSnowflakeResourceMonitor]) (*mqlSnowflakeResourceMonitor, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "snowflake.resourceMonitor", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSnowflakeResourceMonitor), nil
}

// mqlSnowflakeResourceMonitorInternal holds the owning role name that
// ownerRole() resolves.
type mqlSnowflakeResourceMonitorInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeResourceMonitor) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}
