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
// every service's name and current state in one call, and each service is
// then opened with SERVICE_QUERY_CONFIG alone to read its start type and
// description. Asking for more (SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS) is refused
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
		startType, description, err := queryConfig(scm, name)
		if err != nil {
			return nil, fmt.Errorf("could not read the start type of service %q: %w", name, err)
		}
		res = append(res, newSCMService(name, description, entries[i].ServiceStatusProcess.CurrentState, startType))
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

// queryConfig opens a service with SERVICE_QUERY_CONFIG only and returns its
// dwStartType and description. A start type it cannot read fails the call. A
// description it cannot read is empty instead: the description resource of
// some services cannot be found (IsolationSession, PrintNotify and
// WaaSMedicSvc on Windows 11), and that must not fail the whole listing. This
// is also why it does not use mgr.Service.Config, which fails on it.
func queryConfig(scm windows.Handle, name string) (uint32, string, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, "", err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, "", err
	}
	defer windows.CloseServiceHandle(h) //nolint:errcheck

	startType, err := queryStartType(h)
	if err != nil {
		return 0, "", err
	}
	description, err := queryDescription(h)
	if err != nil {
		log.Debug().Err(err).Str("service", name).Msg("could not read the service description")
	}
	return startType, description, nil
}

// queryStartType reads just QUERY_SERVICE_CONFIG and returns its dwStartType.
func queryStartType(h windows.Handle) (uint32, error) {
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

// queryDescription reads SERVICE_CONFIG_DESCRIPTION. Windows resolves
// localized descriptions, as Win32_Service does on the PowerShell path. A
// service without a description returns "".
func queryDescription(h windows.Handle) (string, error) {
	n := uint32(1024)
	for {
		b := make([]byte, n)
		err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, &b[0], n, &n)
		if err == nil {
			d := (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&b[0]))
			if d.Description == nil {
				return "", nil
			}
			return windows.UTF16PtrToString(d.Description), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || n <= uint32(len(b)) {
			return "", err
		}
	}
}
