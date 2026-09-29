// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"encoding/json"
	"io"
	"runtime"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// WindowsService calls powershell Get-Service
//
// Get-Service | Select-Object -Property *
// Name                : defragsvc
// RequiredServices    : {RPCSS}
// CanPauseAndContinue : False
// CanShutdown         : False
// CanStop             : False
// DisplayName         : Optimize drives
// DependentServices   : {}
// MachineName         : .
// ServiceName         : defragsvc
// ServicesDependedOn  : {RPCSS}
// ServiceHandle       : SafeServiceHandle
// Status              : Stopped
// ServiceType         : Win32OwnProcess
// StartType           : Manual
// Site                :
// Container           :
type WindowsService struct {
	Status      int
	Name        string
	DisplayName string
	StartType   int
	// Description is the service's own description (Win32_Service), not its
	// display name. Empty when the service has none or it could not be read.
	Description string
}

// State returns the State value for a Windows service
//
// int values of the services have the following values:
// 1: Stopped
// 2: Starting
// 3: Stopping
// 4: Running
// 5: Continue Pending
// 6: Pause Pending
// 7: Paused
//
// those are documented in https://msdn.microsoft.com/en-us/library/windows/desktop/ms685996(v=vs.85).aspx
func (s WindowsService) State() State {
	res := ServiceUnknown
	switch s.Status {
	case 1:
		res = ServiceStopped
	case 2:
		res = ServiceStartPending
	case 3:
		res = ServiceStopPending
	case 4:
		res = ServiceRunning
	case 5:
		res = ServiceContinuePending
	case 6:
		res = ServicePausePending
	case 7:
		res = ServicePaused
	}
	return res
}

func (s WindowsService) IsRunning() bool {
	return s.State() == ServiceRunning
}

// Modes are documented in https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicestartmode?view=netframework-4.8
// NOTE: only newer powershell versions support this approach, we may need WMI fallback later
// see: https://mikefrobbins.com/2015/12/17/starttype-property-added-to-get-service-in-powershell-version-5-build-10586-on-windows-10-version-1511/
// 0: Boot
// 1: System
// 2: Automatic
// 3: Manual
// 4: Disabled
func (s WindowsService) Enabled() bool {
	return s.StartType <= 3
}

func (s WindowsService) Service() *Service {
	return &Service{
		Name:        s.Name,
		Description: s.Description,
		Installed:   true,
		Running:     s.IsRunning(),
		Enabled:     s.Enabled(),
		State:       s.State(),
		Type:        "windows",
	}
}

func ParseWindowsService(r io.Reader) ([]*Service, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var srvs []WindowsService
	err = json.Unmarshal(data, &srvs)
	if err != nil {
		return nil, err
	}

	res := make([]*Service, len(srvs))
	for i := range srvs {
		res[i] = srvs[i].Service()
	}

	return res, nil
}

type WindowsServiceManager struct {
	conn shared.Connection
}

func (s *WindowsServiceManager) Name() string {
	return "Windows Service Manager"
}

// windowsServicesScript lists the services with Get-Service (status and start
// type as before) and adds each one's description from Win32_Service, which
// Get-Service does not return. Win32_Service resolves localized descriptions.
// One process: the description lookup runs in the same PowerShell. If
// Win32_Service cannot be read, the descriptions are empty and the rest of
// the list is unaffected.
const windowsServicesScript = `$d = @{}
try { Get-CimInstance -ClassName Win32_Service -Property Name,Description -ErrorAction Stop | ForEach-Object { $d[$_.Name] = $_.Description } } catch {}
Get-Service | Select-Object -Property Status, Name, DisplayName, StartType, @{Name='Description';Expression={$d[$_.Name]}} | ConvertTo-Json`

func (s *WindowsServiceManager) List() ([]*Service, error) {
	// With MONDOO_WINDOWS_NATIVE on and mql running on the Windows machine it
	// scans, ask the Service Control Manager directly instead of starting
	// PowerShell. If that fails for any service, use Get-Service for the whole
	// list so nothing goes missing.
	if useNativeWindowsServices(s.conn, runtime.GOOS) {
		res, err := listNativeWindowsServices()
		if err == nil {
			return res, nil
		}
		log.Debug().Err(err).Msg("could not list services through the service control manager, falling back to PowerShell")
	}
	return s.listPowerShell()
}

func (s *WindowsServiceManager) listPowerShell() ([]*Service, error) {
	c, err := s.conn.RunCommand(powershell.Encode(windowsServicesScript))
	if err != nil {
		return nil, err
	}
	return ParseWindowsService(c.Stdout)
}

func (s *WindowsServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}
