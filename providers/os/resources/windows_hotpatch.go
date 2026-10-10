// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
)

// =============================================================================
// windows.hotpatch — Windows security updates without a reboot
// =============================================================================

type mqlWindowsHotpatchInternal struct {
	lock     sync.Mutex
	loaded   bool
	state    *detwin.HotpatchState
	platform *inventory.Platform
	loadErr  error
}

func (w *mqlWindowsHotpatch) id() (string, error) {
	return "windows.hotpatch", nil
}

// hotpatchPlatform returns the asset's platform. A platform that is known not
// to be Windows makes the resource not applicable.
func hotpatchPlatform(conn shared.Connection) (*inventory.Platform, error) {
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("windows.hotpatch requires a detected platform")
	}
	if !asset.Platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return nil, llx.NotApplicable(errors.New("windows.hotpatch is only available on Windows"))
	}
	return asset.Platform, nil
}

// load reads the hotpatch state once and shares it across all fields. It uses
// the same readers as platform detection: the native registry and WMI on the
// local machine, PowerShell on remote connections, and the registry hives of
// an offline filesystem otherwise.
func (w *mqlWindowsHotpatch) load() (*detwin.HotpatchState, *inventory.Platform, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.loaded {
		return w.state, w.platform, w.loadErr
	}
	w.loaded = true

	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		w.loadErr = errors.New("windows.hotpatch is not supported on this connection")
		return nil, nil, w.loadErr
	}
	w.platform, w.loadErr = hotpatchPlatform(conn)
	if w.loadErr != nil {
		return nil, nil, w.loadErr
	}
	w.state, w.loadErr = detwin.GetHotpatchState(conn, w.platform.Arch)
	return w.state, w.platform, w.loadErr
}

// hotpatchPlatformKnown reports whether the product type and build are known,
// which eligibility and the enrollment rule need.
func hotpatchPlatformKnown(pf *inventory.Platform) bool {
	return pf.Labels["windows.mondoo.com/product-type"] != "" && pf.Version != ""
}

func nullBool(v *bool, field *plugin.TValue[bool]) (bool, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

func (w *mqlWindowsHotpatch) eligible() (bool, error) {
	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return false, errors.New("windows.hotpatch is not supported on this connection")
	}
	pf, err := hotpatchPlatform(conn)
	if err != nil {
		return false, err
	}
	if !hotpatchPlatformKnown(pf) {
		w.Eligible.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return detwin.HotpatchEligible(pf), nil
}

func (w *mqlWindowsHotpatch) enrolled() (bool, error) {
	st, pf, err := w.load()
	if err != nil {
		return false, err
	}
	if !hotpatchPlatformKnown(pf) {
		w.Enrolled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if !detwin.HotpatchEligible(pf) {
		return false, nil
	}
	return st.Enrolled(detwin.IsClientOS(pf)), nil
}

func (w *mqlWindowsHotpatch) enrollmentPackage() (string, error) {
	st, _, err := w.load()
	if err != nil {
		return "", err
	}
	if st.EnrollmentPackage == nil {
		w.EnrollmentPackage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *st.EnrollmentPackage, nil
}

func (w *mqlWindowsHotpatch) hotPatchTableSize() (int64, error) {
	st, _, err := w.load()
	if err != nil {
		return 0, err
	}
	return intValue(st.HotPatchTableSize, &w.HotPatchTableSize)
}

func (w *mqlWindowsHotpatch) rebootlessUpdatesPolicy() (bool, error) {
	st, pf, err := w.load()
	if err != nil {
		return false, err
	}
	// AllowRebootlessUpdates is a client policy; servers are enrolled through
	// the enrollment package instead.
	if !detwin.IsClientOS(pf) {
		return nullBool(nil, &w.RebootlessUpdatesPolicy)
	}
	return nullBool(st.RebootlessUpdatesPolicy(), &w.RebootlessUpdatesPolicy)
}

func (w *mqlWindowsHotpatch) vbsConfigured() (bool, error) {
	st, _, err := w.load()
	if err != nil {
		return false, err
	}
	return nullBool(st.VBSConfigured(), &w.VbsConfigured)
}

func (w *mqlWindowsHotpatch) vbsRunning() (bool, error) {
	st, _, err := w.load()
	if err != nil {
		return false, err
	}
	return nullBool(st.VBSRunning(), &w.VbsRunning)
}
