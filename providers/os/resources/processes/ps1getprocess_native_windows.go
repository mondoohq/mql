// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package processes

import (
	"errors"

	"golang.org/x/sys/windows"
)

// nativeProcessExists answers whether pid is running with OpenProcess, and
// false for ok when it cannot tell. A process the agent may not open still
// exists: OpenProcess then fails with access denied, not with an invalid
// parameter. OpenProcess also rejects pid 0, the System Idle Process, with an
// invalid parameter, so pid 0 is left to the PowerShell path, as in
// nativeProcess.
func nativeProcessExists(pid int64) (exists bool, ok bool) {
	if pid < 0 || pid > 0xFFFFFFFF {
		return false, true
	}
	if pid == 0 {
		return false, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		windows.CloseHandle(h)
		return true, true
	}
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return true, true
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		return false, true
	}
	return false, false
}

// nativeProcess reads a process's image path with OpenProcess and
// QueryFullProcessImageName, the same values Get-Process reports as Path and
// Name (the file name without .exe). ok is false when the image cannot be read,
// so the caller asks PowerShell instead of reporting a process without a name.
func nativeProcess(pid int64) (*OSProcess, bool) {
	if pid <= 0 || pid > 0xFFFFFFFF {
		return nil, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, false
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return nil, false
	}
	path := windows.UTF16ToString(buf[:size])
	return &OSProcess{
		Pid:        pid,
		Command:    path,
		Executable: processName(path),
	}, true
}
