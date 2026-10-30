// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (r *mqlWindowsSmartScreen) id() (string, error) {
	return "windows.smartScreen", nil
}

// smartScreen exposes the Microsoft Defender SmartScreen policy from the parent
// windows resource. Every field is a computed method backed by a single lazy
// policy read, so the resource is created without up-front arguments.
func (w *mqlWindows) smartScreen() (*mqlWindowsSmartScreen, error) {
	o, err := CreateResource(w.MqlRuntime, "windows.smartScreen", map[string]*llx.RawData{
		"__id": llx.StringData("windows.smartScreen"),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsSmartScreen), nil
}

// mqlWindowsSmartScreenInternal caches the policy read so every accessor shares
// a single PowerShell invocation.
type mqlWindowsSmartScreenInternal struct {
	lock     sync.Mutex
	fetched  bool
	settings *windows.SmartScreenSettings
	err      error
}

func (s *mqlWindowsSmartScreen) get() (*windows.SmartScreenSettings, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return s.settings, s.err
	}
	conn := s.MqlRuntime.Connection.(shared.Connection)
	s.settings, s.err = windows.GetSmartScreenSettings(conn)
	s.fetched = true
	return s.settings, s.err
}

// Every field reads null when its policy value is absent, which means Windows
// applies its own default rather than a policy turning the surface off.

func (s *mqlWindowsSmartScreen) explorerEnabled() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.ExplorerEnabled, v.ExplorerEnabled())
}

func (s *mqlWindowsSmartScreen) explorerLevel() (string, error) {
	v, err := s.get()
	if err != nil {
		return "", err
	}
	if v.ShellSmartScreenLevel == nil {
		s.ExplorerLevel = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *v.ShellSmartScreenLevel, nil
}

func (s *mqlWindowsSmartScreen) edgeEnabled() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.EdgeEnabled, v.EdgeEnabled())
}

func (s *mqlWindowsSmartScreen) edgePuaEnabled() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.EdgePuaEnabled, v.EdgePuaEnabled())
}

func (s *mqlWindowsSmartScreen) edgePreventOverride() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.EdgePreventOverride, v.EdgePreventOverrideEnabled())
}

func (s *mqlWindowsSmartScreen) edgePreventOverrideForFiles() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.EdgePreventOverrideForFiles, v.EdgePreventOverrideForFilesEnabled())
}

func (s *mqlWindowsSmartScreen) storeAppsEnabled() (bool, error) {
	v, err := s.get()
	if err != nil {
		return false, err
	}
	return resolveNullableBool(&s.StoreAppsEnabled, v.StoreAppsEnabled())
}
