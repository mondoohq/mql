// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/providers/os/resources/windows"
)

type mqlWindowsTpmInternal struct {
	lock    sync.Mutex
	loaded  atomic.Bool
	loadErr error
	info    *windows.TpmInfo
}

func (w *mqlWindowsTpm) id() (string, error) {
	return "windows.tpm", nil
}

// load runs the TPM query exactly once and caches the result so every field
// shares a single PowerShell invocation.
func (w *mqlWindowsTpm) load() (*windows.TpmInfo, error) {
	if w.loaded.Load() {
		return w.info, nil
	}
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.loaded.Load() || w.loadErr != nil {
		return w.info, w.loadErr
	}

	stdout, err := runWindowsPowerShell(w.MqlRuntime, windows.PSGetTpm, "retrieve TPM information")
	if err != nil {
		w.loadErr = err
		return nil, err
	}

	info, err := windows.ParseTpm(stdout)
	if err != nil {
		w.loadErr = err
		return nil, err
	}

	w.info = info
	w.loaded.Store(true)
	return info, nil
}

func (w *mqlWindowsTpm) present() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.TpmPresent, nil
}

func (w *mqlWindowsTpm) ready() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.TpmReady, nil
}

func (w *mqlWindowsTpm) enabled() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.TpmEnabled, nil
}

func (w *mqlWindowsTpm) activated() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.TpmActivated, nil
}

func (w *mqlWindowsTpm) specVersion() (string, error) {
	info, err := w.load()
	if err != nil {
		return "", err
	}
	return info.MajorSpecVersion(), nil
}

func (w *mqlWindowsTpm) manufacturerVersion() (string, error) {
	info, err := w.load()
	if err != nil {
		return "", err
	}
	return info.ManufacturerVersion, nil
}

func (w *mqlWindowsTpm) lockedOut() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.LockedOut, nil
}

func (w *mqlWindowsTpm) lockoutCount() (int64, error) {
	info, err := w.load()
	if err != nil {
		return 0, err
	}
	return info.LockoutCount, nil
}

func (w *mqlWindowsTpm) lockoutHealTime() (string, error) {
	info, err := w.load()
	if err != nil {
		return "", err
	}
	return info.LockoutHealTime, nil
}

func (w *mqlWindowsTpm) autoProvisioning() (string, error) {
	info, err := w.load()
	if err != nil {
		return "", err
	}
	return info.AutoProvisioning, nil
}

func (w *mqlWindowsTpm) manufacturerId() (int64, error) {
	info, err := w.load()
	if err != nil {
		return 0, err
	}
	return info.ManufacturerId, nil
}

func (w *mqlWindowsTpm) manufacturerIdTxt() (string, error) {
	info, err := w.load()
	if err != nil {
		return "", err
	}
	return info.Manufacturer(), nil
}

func (w *mqlWindowsTpm) ownerClearDisabled() (bool, error) {
	info, err := w.load()
	if err != nil {
		return false, err
	}
	return info.OwnerClearDisabled, nil
}
