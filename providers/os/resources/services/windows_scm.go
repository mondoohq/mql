// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// useNativeWindowsServices reports whether services are listed through the
// Service Control Manager: only when the native Windows paths are switched on
// (shared.WindowsNativeEnabled) and mql runs on the Windows machine it scans
// (goos is runtime.GOOS). Every other scan uses Get-Service.
func useNativeWindowsServices(conn shared.Connection, goos string) bool {
	return shared.WindowsNativeEnabled() && goos == "windows" && conn.Type() == shared.Type_Local
}

// Values the Windows Service Control Manager reports for a service's
// dwCurrentState, from SERVICE_STATUS_PROCESS:
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
const (
	scmStateStopped         uint32 = 1
	scmStateStartPending    uint32 = 2
	scmStateStopPending     uint32 = 3
	scmStateRunning         uint32 = 4
	scmStateContinuePending uint32 = 5
	scmStatePausePending    uint32 = 6
	scmStatePaused          uint32 = 7
)

// Values the Service Control Manager reports for a service's dwStartType,
// from QUERY_SERVICE_CONFIG:
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw
const (
	scmStartBoot     uint32 = 0
	scmStartSystem   uint32 = 1
	scmStartAuto     uint32 = 2
	scmStartDemand   uint32 = 3
	scmStartDisabled uint32 = 4
)

// startTypeSource says where resolveEnabled got a service's start type from.
type startTypeSource int

const (
	startTypeFromSCM startTypeSource = iota
	startTypeFromRegistry
	startTypeUnknown
)

// resolveEnabled reports whether a service is enabled, from its dwStartType
// as the Service Control Manager returns it. When that fails for any reason,
// it reads the Start value the Service Control Manager keeps in the registry,
// and accepts only a documented start type from there. On Windows 11 25H2
// both agree for every service whose configuration is readable.
//
// When neither can be read, the service counts as enabled. That is what the
// PowerShell path reports for it: Get-Service returns no StartType, which
// parses as 0 (boot start).
func resolveEnabled(fromSCM, fromReg func() (uint32, error)) (enabled bool, src startTypeSource, scmErr, regErr error) {
	startType, scmErr := fromSCM()
	if scmErr == nil {
		return scmStartTypeEnabled(startType), startTypeFromSCM, nil, nil
	}
	startType, regErr = fromReg()
	if regErr == nil && startType > scmStartDisabled {
		regErr = fmt.Errorf("undocumented start type %d", startType)
	}
	if regErr != nil {
		return true, startTypeUnknown, scmErr, regErr
	}
	return scmStartTypeEnabled(startType), startTypeFromRegistry, scmErr, nil
}

// scmServiceState maps a Service Control Manager dwCurrentState to State.
func scmServiceState(state uint32) State {
	switch state {
	case scmStateStopped:
		return ServiceStopped
	case scmStateStartPending:
		return ServiceStartPending
	case scmStateStopPending:
		return ServiceStopPending
	case scmStateRunning:
		return ServiceRunning
	case scmStateContinuePending:
		return ServiceContinuePending
	case scmStatePausePending:
		return ServicePausePending
	case scmStatePaused:
		return ServicePaused
	default:
		return ServiceUnknown
	}
}

// scmStartTypeEnabled reports whether a service with the given dwStartType can
// be started: boot, system, automatic and manual (demand) start are enabled,
// disabled is not. Values outside the documented range count as not enabled.
// This matches how the PowerShell path reads Get-Service's StartType.
func scmStartTypeEnabled(startType uint32) bool {
	switch startType {
	case scmStartBoot, scmStartSystem, scmStartAuto, scmStartDemand:
		return true
	default:
		return false
	}
}

// newSCMService builds a Service from what the Service Control Manager reports
// for it. It produces the same shape as WindowsService.Service does for the
// PowerShell path.
func newSCMService(name, description string, state uint32, enabled bool) *Service {
	s := scmServiceState(state)
	return &Service{
		Name:        name,
		Description: description,
		Installed:   true,
		Running:     s == ServiceRunning,
		Enabled:     enabled,
		State:       s,
		Type:        "windows",
	}
}
