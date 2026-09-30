// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	// Ps1GetProcess lists every process. It must not use -IncludeUserName: that
	// switch needs elevation and ends Get-Process with a terminating error for a
	// non-elevated agent, so the whole list failed for a user name nothing reads.
	Ps1GetProcess = "Get-Process | Select-Object Name, Description, Id, PriorityClass, PM, NPM, CPU, VirtualMemorySize, Responding, SessionId, StartTime, TotalProcessorTime, Path | ConvertTo-Json"

	// ps1GetProcessByID reads one process; a pid that does not exist prints
	// nothing and exits 0.
	ps1GetProcessByID = "Get-Process -Id %d -ErrorAction SilentlyContinue | Select-Object Name, Id, Path | ConvertTo-Json"
)

// Get-Process -IncludeUserName | Select-Object -Property *
// UserName                   : NT AUTHORITY\SYSTEM
// Name                       : winlogon
// Id                         : 584
// PriorityClass              : High
// FileVersion                : 10.0.17763.1 (WinBuild.160101.0800)
// HandleCount                : 234
// WorkingSet                 : 10424320
// PagedMemorySize            : 2641920
// PrivateMemorySize          : 2641920
// VirtualMemorySize          : 100098048
// TotalProcessorTime         : 00:00:00.0156250
// SI                         : 1
// Handles                    : 234
// VM                         : 2203418320896
// WS                         : 10424320
// PM                         : 2641920
// NPM                        : 11392
// Path                       : C:\windows\system32\winlogon.exe
// Company                    : Microsoft Corporation
// CPU                        : 0.015625
// ProductVersion             : 10.0.17763.1
// Description                : Windows Logon Application
// Product                    : Microsoft® Windows® Operating System
// __NounName                 : Process
// BasePriority               : 13
// ExitCode                   :
// HasExited                  : False
// ExitTime                   :
// Handle                     : 3492
// SafeHandle                 : Microsoft.Win32.SafeHandles.SafeProcessHandle
// MachineName                : .
// MainWindowHandle           : 0
// MainWindowTitle            :
// MainModule                 : System.Diagnostics.ProcessModule (winlogon.exe)
// MaxWorkingSet              : 1413120
// MinWorkingSet              : 204800
// Modules                    : {System.Diagnostics.ProcessModule (winlogon.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostics.ProcessModule (KERNEL32.DLL), System.Diagnostics.ProcessModule (KERNELBASE.dll)...}
// NonpagedSystemMemorySize   : 11392
// NonpagedSystemMemorySize64 : 11392
// PagedMemorySize64          : 2641920
// PagedSystemMemorySize      : 135128
// PagedSystemMemorySize64    : 135128
// PeakPagedMemorySize        : 3715072
// PeakPagedMemorySize64      : 3715072
// PeakWorkingSet             : 11091968
// PeakWorkingSet64           : 11091968
// PeakVirtualMemorySize      : 104349696
// PeakVirtualMemorySize64    : 2203422572544
// PriorityBoostEnabled       : True
// PrivateMemorySize64        : 2641920
// PrivilegedProcessorTime    : 00:00:00.0156250
// ProcessName                : winlogon
// ProcessorAffinity          : 1
// Responding                 : True
// SessionId                  : 1
// StartInfo                  : System.Diagnostics.ProcessStartInfo
// StartTime                  : 4/16/2020 8:24:41 AM
// SynchronizingObject        :
// Threads                    : {588, 924, 2788}
// UserProcessorTime          : 00:00:00
// VirtualMemorySize64        : 2203418320896
// EnableRaisingEvents        : False
// StandardInput              :
// StandardOutput             :
// StandardError              :
// WorkingSet64               : 10424320
// Site                       :
// Container                  :
type WindowsProcess struct {
	ID                 int64
	Name               string
	Description        string
	PriorityClass      int
	PM                 int64
	NPM                int64
	CPU                float64
	VirtualMemorySize  int64
	Responding         bool
	SessionId          int
	StartTime          string
	TotalProcessorTime WindowsTotalProcessorTime
	UserName           string
	Path               string
}

type WindowsTotalProcessorTime struct {
	Ticks             int
	Days              int
	Hours             int
	Milliseconds      int
	Minutes           int
	Seconds           int
	TotalDays         float64
	TotalHours        float64
	TotalMilliseconds float64
	TotalMinutes      float64
	TotalSeconds      float64
}

func (p WindowsProcess) ToOSProcess() *OSProcess {
	return &OSProcess{
		Pid:        p.ID,
		Command:    p.Path,
		Executable: p.Name,
	}
}

func ParseWindowsProcesses(r io.Reader) ([]WindowsProcess, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	processes, err := powershell.UnmarshalList[WindowsProcess](data)
	if err != nil {
		return nil, err
	}

	return processes, nil
}

type WindowsProcessManager struct {
	conn shared.Connection
}

func (wpm *WindowsProcessManager) Name() string {
	return "Windows Process Manager"
}

func (wpm *WindowsProcessManager) List() ([]*OSProcess, error) {
	c, err := wpm.conn.RunCommand(powershell.Encode(Ps1GetProcess))
	if err != nil {
		return nil, fmt.Errorf("processes> could not run command")
	}

	if c.ExitStatus != 0 {
		stderr, err := io.ReadAll(c.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve process list: " + string(stderr))
	}

	entries, err := ParseWindowsProcesses(c.Stdout)
	if err != nil {
		return nil, err
	}

	log.Debug().Int("processes", len(entries)).Msg("found processes")

	var ps []*OSProcess
	for i := range entries {
		ps = append(ps, entries[i].ToOSProcess())
	}
	return ps, nil
}

// Exists reports whether a process with the pid is running.
func (wpm *WindowsProcessManager) Exists(pid int64) (bool, error) {
	if shared.WindowsNative(wpm.conn) {
		if exists, ok := nativeProcessExists(pid); ok {
			return exists, nil
		}
	}
	p, err := wpm.processByID(pid)
	if err != nil {
		return false, err
	}
	return p != nil, nil
}

// Process returns the process with the pid, and an error when there is none.
func (wpm *WindowsProcessManager) Process(pid int64) (*OSProcess, error) {
	if shared.WindowsNative(wpm.conn) {
		// A process the agent may not query (a protected process, or pid 0
		// and 4) is answered by the PowerShell path below.
		if p, ok := nativeProcess(pid); ok {
			return p, nil
		}
	}
	p, err := wpm.processByID(pid)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}
	return p, nil
}

// processByID reads one process over PowerShell; nil means it does not exist.
func (wpm *WindowsProcessManager) processByID(pid int64) (*OSProcess, error) {
	c, err := wpm.conn.RunCommand(powershell.Encode(fmt.Sprintf(ps1GetProcessByID, pid)))
	if err != nil {
		return nil, fmt.Errorf("processes> could not run command: %w", err)
	}
	if c.ExitStatus != 0 {
		stderr, _ := io.ReadAll(c.Stderr)
		return nil, errors.New("failed to retrieve process " + strconv.FormatInt(pid, 10) + ": " + string(stderr))
	}
	return parseWindowsProcessByID(c.Stdout, pid)
}

// parseWindowsProcessByID decodes ps1GetProcessByID output. No output means
// the pid does not exist.
func parseWindowsProcessByID(r io.Reader, pid int64) (*OSProcess, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	entries, err := powershell.UnmarshalList[WindowsProcess](data)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].ID == pid {
			return entries[i].ToOSProcess(), nil
		}
	}
	return nil, nil
}

func (wpm *WindowsProcessManager) ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error) {
	// This function is always invoked when listing processes (for unix and windows). If we return an error
	// here, we break process listing. Instead we return an empty map
	return map[int64]plugin.TValue[[]int64]{}, nil
}

// processName is Get-Process's Name for an image path: the file name, with a
// trailing .exe removed and any other extension kept.
func processName(path string) string {
	name := path
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	if len(name) > 4 && strings.EqualFold(name[len(name)-4:], ".exe") {
		name = name[:len(name)-4]
	}
	return name
}
