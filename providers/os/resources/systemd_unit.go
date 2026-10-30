// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/services"
	"go.mondoo.com/mql/types"
)

func (u *mqlSystemdUnit) id() (string, error) {
	return "systemd.unit:" + u.Name.Data, nil
}

func initSystemdUnit(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("cannot initialize systemd.unit, need at least a name")
	}

	name, ok := x.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("cannot look for a systemd unit with an empty name")
	}

	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, nil, errors.New("systemd.unit is not supported on this connection")
	}

	mgr := services.ResolveSystemdUnitManager(conn)
	unit, err := mgr.Get(name)
	if err != nil {
		if errors.Is(err, services.ErrServiceNotFound) {
			res, err := createSystemdUnitResource(runtime, &services.SystemdUnit{Name: name})
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
		return nil, nil, err
	}

	res, err := createSystemdUnitResource(runtime, unit)
	if err != nil {
		return nil, nil, err
	}

	return nil, res, nil
}

// createSystemdUnitResource builds the resource from a unit. A unit that was not
// found is passed in zero-valued apart from its name, which reports every
// setting as explicitly off rather than as null, so an assertion over several of
// them fails on a miss instead of passing vacuously.
func createSystemdUnitResource(runtime *plugin.Runtime, unit *services.SystemdUnit) (plugin.Resource, error) {
	// a setting the running systemd does not have is null: it neither
	// applies nor is off by choice
	supported := func(property string, value *llx.RawData) *llx.RawData {
		if !unit.Supports(property) {
			return llx.NilData
		}
		return value
	}
	return CreateResource(runtime, "systemd.unit", map[string]*llx.RawData{
		"__id":          llx.StringData("systemd.unit:" + unit.Name),
		"name":          llx.StringData(unit.Name),
		"description":   llx.StringData(unit.Description),
		"installed":     llx.BoolData(unit.Installed),
		"fragmentPath":  llx.StringData(unit.FragmentPath),
		"loadState":     llx.StringData(unit.LoadState),
		"activeState":   llx.StringData(unit.ActiveState),
		"unitFileState": llx.StringData(unit.UnitFileState),
		"type":          llx.StringData(unit.Type),
		"execStart":     llx.StringData(unit.ExecStart),

		"user":        llx.StringData(unit.User),
		"group":       llx.StringData(unit.Group),
		"dynamicUser": supported("DynamicUser", llx.BoolData(unit.DynamicUser)),
		"umask":       supported("UMask", llx.StringData(unit.UMask)),

		"noNewPrivileges":         supported("NoNewPrivileges", llx.BoolData(unit.NoNewPrivileges)),
		"protectSystem":           supported("ProtectSystem", llx.StringData(unit.ProtectSystem)),
		"protectHome":             supported("ProtectHome", llx.StringData(unit.ProtectHome)),
		"privateTmp":              supported("PrivateTmp", llx.BoolData(unit.PrivateTmp)),
		"privateDevices":          supported("PrivateDevices", llx.BoolData(unit.PrivateDevices)),
		"privateNetwork":          supported("PrivateNetwork", llx.BoolData(unit.PrivateNetwork)),
		"privateUsers":            supported("PrivateUsers", llx.BoolData(unit.PrivateUsers)),
		"protectKernelTunables":   supported("ProtectKernelTunables", llx.BoolData(unit.ProtectKernelTunables)),
		"protectKernelModules":    supported("ProtectKernelModules", llx.BoolData(unit.ProtectKernelModules)),
		"protectKernelLogs":       supported("ProtectKernelLogs", llx.BoolData(unit.ProtectKernelLogs)),
		"protectControlGroups":    supported("ProtectControlGroups", llx.StringData(unit.ProtectControlGroups)),
		"protectClock":            supported("ProtectClock", llx.BoolData(unit.ProtectClock)),
		"protectHostname":         supported("ProtectHostname", llx.BoolData(unit.ProtectHostname)),
		"protectProc":             supported("ProtectProc", llx.StringData(unit.ProtectProc)),
		"procSubset":              supported("ProcSubset", llx.StringData(unit.ProcSubset)),
		"restrictSUIDSGID":        supported("RestrictSUIDSGID", llx.BoolData(unit.RestrictSUIDSGID)),
		"restrictRealtime":        supported("RestrictRealtime", llx.BoolData(unit.RestrictRealtime)),
		"restrictNamespaces":      supported("RestrictNamespaces", llx.StringData(unit.RestrictNamespaces)),
		"restrictAddressFamilies": supported("RestrictAddressFamilies", restrictAddressFamiliesData(unit)),
		"lockPersonality":         supported("LockPersonality", llx.BoolData(unit.LockPersonality)),
		"memoryDenyWriteExecute":  supported("MemoryDenyWriteExecute", llx.BoolData(unit.MemoryDenyWriteExecute)),
		"removeIPC":               supported("RemoveIPC", llx.BoolData(unit.RemoveIPC)),
		"keyringMode":             supported("KeyringMode", llx.StringData(unit.KeyringMode)),

		"capabilityBoundingSet":      supported("CapabilityBoundingSet", llx.ArrayData(convert.SliceAnyToInterface(unit.CapabilityBoundingSet), types.String)),
		"ambientCapabilities":        supported("AmbientCapabilities", llx.ArrayData(convert.SliceAnyToInterface(unit.AmbientCapabilities), types.String)),
		"systemCallFilter":           supported("SystemCallFilter", llx.ArrayData(convert.SliceAnyToInterface(unit.SystemCallFilter), types.String)),
		"systemCallFilterIsDenylist": supported("SystemCallFilter", llx.BoolData(unit.SystemCallFilterIsDenylist)),
		"systemCallArchitectures":    supported("SystemCallArchitectures", llx.StringData(unit.SystemCallArchitectures)),
		"readWritePaths":             supported("ReadWritePaths", llx.ArrayData(convert.SliceAnyToInterface(unit.ReadWritePaths), types.String)),
		"readOnlyPaths":              supported("ReadOnlyPaths", llx.ArrayData(convert.SliceAnyToInterface(unit.ReadOnlyPaths), types.String)),
		"inaccessiblePaths":          supported("InaccessiblePaths", llx.ArrayData(convert.SliceAnyToInterface(unit.InaccessiblePaths), types.String)),
	})
}

// restrictAddressFamiliesData is null when the setting could not be read, so
// it does not read as a unit without any restriction.
func restrictAddressFamiliesData(unit *services.SystemdUnit) *llx.RawData {
	if unit.RestrictAddressFamiliesUnknown {
		return llx.NilData
	}
	return llx.StringData(unit.RestrictAddressFamilies)
}

func (u *mqlSystemdUnits) id() (string, error) {
	return "systemd.units", nil
}

func (u *mqlSystemdUnits) list() ([]any, error) {
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("systemd.units is not supported on this connection")
	}

	mgr := services.ResolveSystemdUnitManager(conn)
	units, err := mgr.List()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(units))
	for _, unit := range units {
		resource, err := createSystemdUnitResource(u.MqlRuntime, unit)
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}

	return res, nil
}
