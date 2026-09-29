// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package services

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// listNativeWindowsServices lists the services the local Service Control
// Manager knows about, the same set Get-Service returns.
//
// It asks only for the rights it needs. SC_MANAGER_ENUMERATE_SERVICE returns
// every service's name, display name and current state in one call, and each
// service is then opened with SERVICE_QUERY_CONFIG alone to read its start
// type. Asking for more (SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS) is refused
// for protected services even to an administrator, among them WinDefend,
// mpssvc, RpcSs and Schedule.
//
// Any service it cannot read fails the whole call instead of being left out,
// so the caller falls back to PowerShell rather than reporting an installed
// service as missing.
func listNativeWindowsServices() ([]*Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm) //nolint:errcheck

	buf, count, err := enumServices(scm)
	if err != nil {
		return nil, fmt.Errorf("could not enumerate services: %w", err)
	}
	if count == 0 {
		return []*Service{}, nil
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(count))

	res := make([]*Service, 0, len(entries))
	for i := range entries {
		name := windows.UTF16PtrToString(entries[i].ServiceName)
		displayName := windows.UTF16PtrToString(entries[i].DisplayName)
		startType, err := queryStartType(scm, name)
		if err != nil {
			return nil, fmt.Errorf("could not read the start type of service %q: %w", name, err)
		}
		res = append(res, newSCMService(name, displayName, entries[i].ServiceStatusProcess.CurrentState, startType))
	}

	log.Debug().Int("count", len(res)).Msg("listed services through the service control manager")
	return res, nil
}

// enumServices returns the raw ENUM_SERVICE_STATUS_PROCESS array for all
// Win32 services in any state. The returned buffer backs the strings the
// entries point to.
func enumServices(scm windows.Handle) ([]byte, uint32, error) {
	var buf []byte
	var bytesNeeded, count uint32
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &bytesNeeded, &count, nil, nil)
		if err == nil {
			return buf, count, nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) || bytesNeeded <= uint32(len(buf)) {
			return nil, 0, err
		}
		// Services can be installed between two calls, so leave some room.
		buf = make([]byte, bytesNeeded+bytesNeeded/8)
	}
}

// queryStartType opens a service with SERVICE_QUERY_CONFIG only and returns
// its dwStartType. It reads just QUERY_SERVICE_CONFIG. mgr.Service.Config also
// loads the service's description, and that fails for services whose
// description resource cannot be found (IsolationSession, PrintNotify and
// WaaSMedicSvc on Windows 11), which would fail the whole listing.
func queryStartType(scm windows.Handle, name string) (uint32, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(h) //nolint:errcheck

	n := uint32(1024)
	for {
		b := make([]byte, n)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
		err := windows.QueryServiceConfig(h, cfg, n, &n)
		if err == nil {
			return cfg.StartType, nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || n <= uint32(len(b)) {
			return 0, err
		}
	}
}
