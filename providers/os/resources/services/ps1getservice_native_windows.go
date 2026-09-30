// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package services

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	shlwapi                  = windows.NewLazySystemDLL("shlwapi.dll")
	procSHLoadIndirectString = shlwapi.NewProc("SHLoadIndirectString")
)

// nativeWindowsServices lists the Win32 services through the Service Control
// Manager, with the rights a standard user has by default: SC_MANAGER_CONNECT
// and SC_MANAGER_ENUMERATE_SERVICE on the manager, SERVICE_QUERY_CONFIG on
// each service. One EnumServicesStatusExW call returns every service's name
// and state; the start type and the description need the service's
// configuration. A service whose configuration cannot be read is kept, with
// its enabled flag and description unknown (null), never dropped.
//
// The result matches the PowerShell path (Get-Service with Win32_Service
// descriptions): the same services, State and StartType values (the SCM's
// SERVICE_* constants are the numbers ServiceControllerStatus and
// ServiceStartMode use), and the resolved description.
func nativeWindowsServices() ([]*Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(scm)

	entries, err := enumServices(scm)
	if err != nil {
		return nil, err
	}

	res := make([]*Service, 0, len(entries))
	for _, e := range entries {
		ws := WindowsService{Name: e.name, DisplayName: e.displayName, Status: int(e.state)}
		startType, description, err := serviceConfig(scm, e.name)
		if err != nil {
			log.Debug().Err(err).Str("service", e.name).Msg("mql[services]> could not read the service configuration")
			srv := ws.Service()
			srv.ConfigUnknown = true
			res = append(res, srv)
			continue
		}
		ws.StartType = int(startType)
		ws.Description = description
		res = append(res, ws.Service())
	}

	logEnumerationDelta(len(entries))
	return res, nil
}

type serviceEntry struct {
	name        string
	displayName string
	state       uint32
}

// enumServices returns every Win32 service the caller may see, following
// EnumServicesStatusExW's resume handle. The buffer is []uint64 so the
// ENUM_SERVICE_STATUS_PROCESS array at its start is 8-byte aligned.
func enumServices(scm windows.Handle) ([]serviceEntry, error) {
	var (
		res    []serviceEntry
		resume uint32
		buf    = make([]uint64, 8*1024)
	)
	for {
		var needed, returned uint32
		size := uint32(len(buf) * 8)
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL, (*byte)(unsafe.Pointer(&buf[0])), size, &needed, &returned, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		if returned > 0 {
			list := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), returned)
			for i := range list {
				res = append(res, serviceEntry{
					name:        windows.UTF16PtrToString(list[i].ServiceName),
					displayName: windows.UTF16PtrToString(list[i].DisplayName),
					state:       list[i].ServiceStatusProcess.CurrentState,
				})
			}
		}
		if err == nil {
			return res, nil
		}
		// ERROR_MORE_DATA: continue from the resume handle, with a buffer at
		// least as large as the next entry needs.
		if needed > size {
			buf = make([]uint64, (needed+7)/8)
		}
	}
}

// serviceConfig reads a service's start type and description with
// SERVICE_QUERY_CONFIG only.
func serviceConfig(scm windows.Handle, name string) (uint32, string, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, "", err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, "", err
	}
	defer windows.CloseServiceHandle(h)

	var needed uint32
	buf := make([]uint64, 128)
	for {
		size := uint32(len(buf) * 8)
		err = windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), size, &needed)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed <= size {
			return 0, "", err
		}
		buf = make([]uint64, (needed+7)/8)
	}
	startType := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])).StartType

	description, err := serviceDescription(h)
	if err != nil {
		// The start type is known; only the description is missing. The
		// PowerShell path reports an empty description in the same case.
		log.Debug().Err(err).Str("service", name).Msg("mql[services]> could not read the service description")
		description = ""
	}
	return startType, description, nil
}

func serviceDescription(h windows.Handle) (string, error) {
	var needed uint32
	buf := make([]uint64, 64)
	for {
		size := uint32(len(buf) * 8)
		err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&buf[0])), size, &needed)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed <= size {
			return "", err
		}
		buf = make([]uint64, (needed+7)/8)
	}
	d := (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&buf[0]))
	if d.Description == nil {
		return "", nil
	}
	return resolveIndirectString(windows.UTF16PtrToString(d.Description)), nil
}

// resolveIndirectString resolves an "@file,-id" resource reference to the
// localized text, as Win32_Service does for the description. A plain string,
// or one that does not resolve, is returned as it is.
func resolveIndirectString(s string) string {
	if !strings.HasPrefix(s, "@") {
		return s
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return s
	}
	out := make([]uint16, 4096)
	hr, _, _ := procSHLoadIndirectString.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), 0)
	if hr != 0 {
		return s
	}
	return windows.UTF16ToString(out)
}

// logEnumerationDelta compares the enumerated services with the Win32 services
// registered under HKLM\SYSTEM\CurrentControlSet\Services. The SCM leaves out,
// without an error, services the caller may not query, so a shorter list is
// logged instead of passing silently as complete.
func logEnumerationDelta(enumerated int) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	registered := 0
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		t, _, err := sk.GetIntegerValue("Type")
		sk.Close()
		if err == nil && t&windows.SERVICE_WIN32 != 0 {
			registered++
		}
	}
	if registered > enumerated {
		log.Debug().Int("enumerated", enumerated).Int("registered", registered).
			Msg("mql[services]> the service manager listed fewer services than the registry holds; the caller may not query all of them")
	}
}
