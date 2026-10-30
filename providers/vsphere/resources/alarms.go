// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/vmware/govmomi/alarm"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

// mqlVsphereAlarmStateInternal caches the triggered alarm's definition moid so
// vsphere.alarm.state.alarm can resolve the typed reference against the
// (memoized) vsphere.alarms list.
type mqlVsphereAlarmStateInternal struct {
	cacheAlarmMoid string
}

func (v *mqlVsphere) alarms() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	client := conn.Client().Client

	// Alarm definitions are registered on inventory entities and inherited down
	// the hierarchy; querying the root folder returns the full set of alarms
	// visible at the top of the inventory (the default vCenter alarms plus any
	// defined globally).
	defs, err := alarm.NewManager(client).GetAlarm(ctx, object.NewRootFolder(client))
	if err != nil {
		return nil, fmt.Errorf("failed to list alarm definitions: %w", err)
	}

	res := make([]any, 0, len(defs))
	for i := range defs {
		info := defs[i].Info
		mqlAlarm, err := CreateResource(v.MqlRuntime, "vsphere.alarm", map[string]*llx.RawData{
			"__id":             llx.StringData(defs[i].Self.Encode()),
			"moid":             llx.StringData(defs[i].Self.Encode()),
			"key":              llx.StringData(info.Key),
			"name":             llx.StringData(info.Name),
			"systemName":       llx.StringData(info.SystemName),
			"description":      llx.StringData(info.Description),
			"enabled":          llx.BoolData(info.Enabled),
			"entityMoid":       llx.StringData(info.Entity.Encode()),
			"entityType":       llx.StringData(info.Entity.Type),
			"lastModifiedTime": llx.TimeData(info.LastModifiedTime),
			"lastModifiedUser": llx.StringData(info.LastModifiedUser),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlarm)
	}
	return res, nil
}

func (v *mqlVsphere) triggeredAlarms() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	client := conn.Client().Client

	// Triggered alarm states propagate up to ancestor entities, so the root
	// folder aggregates every currently-triggered alarm in the inventory.
	pc := property.DefaultCollector(client)
	var folder mo.Folder
	if err := pc.RetrieveOne(ctx, client.ServiceContent.RootFolder, []string{"triggeredAlarmState"}, &folder); err != nil {
		return nil, fmt.Errorf("failed to retrieve triggered alarms: %w", err)
	}

	res := make([]any, 0, len(folder.TriggeredAlarmState))
	for _, s := range folder.TriggeredAlarmState {
		acknowledged := false
		if s.Acknowledged != nil {
			acknowledged = *s.Acknowledged
		}

		mqlState, err := CreateResource(v.MqlRuntime, "vsphere.alarm.state", map[string]*llx.RawData{
			"__id":               llx.StringData(s.Key),
			"id":                 llx.StringData(s.Key),
			"entityMoid":         llx.StringData(s.Entity.Encode()),
			"entityType":         llx.StringData(s.Entity.Type),
			"overallStatus":      llx.StringData(string(s.OverallStatus)),
			"time":               llx.TimeData(s.Time),
			"acknowledged":       llx.BoolData(acknowledged),
			"acknowledgedByUser": llx.StringData(s.AcknowledgedByUser),
			"acknowledgedTime":   llx.TimeDataPtr(s.AcknowledgedTime),
		})
		if err != nil {
			return nil, err
		}
		mqlState.(*mqlVsphereAlarmState).cacheAlarmMoid = s.Alarm.Encode()
		res = append(res, mqlState)
	}
	return res, nil
}

func (s *mqlVsphereAlarmState) alarm() (*mqlVsphereAlarm, error) {
	if s.cacheAlarmMoid == "" {
		s.Alarm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(s.MqlRuntime, "vsphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	alarms := res.(*mqlVsphere).GetAlarms()
	if alarms.Error != nil {
		return nil, alarms.Error
	}
	for _, a := range alarms.Data {
		mqlAlarm := a.(*mqlVsphereAlarm)
		if mqlAlarm.Moid.Data == s.cacheAlarmMoid {
			return mqlAlarm, nil
		}
	}

	s.Alarm.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
