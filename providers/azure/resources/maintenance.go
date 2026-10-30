// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const maintenanceWindowResource = "azure.subscription.maintenanceWindow"

// maintenanceWindowRefData maps an ARM maintenance window onto the shared
// window resource.
//
// armmysqlflexibleservers, armpostgresqlflexibleservers and
// armcosmosforpostgresql each declare their own MaintenanceWindow type with
// the same four members, so one resource covers all three. A server that takes
// the system default window reports nothing, and the field then reads null
// rather than a window that opens at midnight on Sunday.
func maintenanceWindowRefData(runtime *plugin.Runtime, parentID string, customWindow *string, dayOfWeek, startHour, startMinute *int32) (*llx.RawData, error) {
	if customWindow == nil && dayOfWeek == nil && startHour == nil && startMinute == nil {
		return llx.NilData, nil
	}
	if parentID == "" {
		return nil, errors.New("cannot key a maintenance window: the parent has no id")
	}
	res, err := CreateResource(runtime, maintenanceWindowResource, map[string]*llx.RawData{
		"__id":         llx.StringData(parentID + "/maintenanceWindow"),
		"customWindow": llx.StringDataPtr(customWindow),
		"dayOfWeek":    llx.IntDataPtr(dayOfWeek),
		"startHour":    llx.IntDataPtr(startHour),
		"startMinute":  llx.IntDataPtr(startMinute),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, maintenanceWindowResource), nil
}
