// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dismapi                = windows.NewLazySystemDLL("dismapi.dll")
	procDismInitialize     = dismapi.NewProc("DismInitialize")
	procDismOpenSession    = dismapi.NewProc("DismOpenSession")
	procDismGetFeatures    = dismapi.NewProc("DismGetFeatures")
	procDismGetFeatureInfo = dismapi.NewProc("DismGetFeatureInfo")
	procDismDelete         = dismapi.NewProc("DismDelete")
)

// dismOnlineImage is DISM_ONLINE_IMAGE: the running Windows installation.
const dismOnlineImage = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"

const (
	dismLogErrors      = 0 // DismLogErrors
	dismPackageNone    = 0 // DismPackageNone: features of the whole image
	sOK                = 0
	dismUnknownFeature = 0x800F080C // the feature name is not in the image
)

// The DismFeatureInfo members the reader uses, as indexes into
// dismFeatureInfoLayout.
const (
	dismFeatureInfoName = iota
	dismFeatureInfoState
	dismFeatureInfoDisplayName
	dismFeatureInfoDescription
)

// ptr reads the pointer-sized member i of the structure at base.
func (l dismLayout) ptr(base unsafe.Pointer, i int) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Add(base, l.offsets[i]))
}

// dismSession is the process's one DISM session on the online image. DISM may
// be initialized once per process and its sessions are not safe for concurrent
// use, so the session is opened on first use, kept for the life of the provider
// process, and every call goes through mu. An initialization error (typically
// ERROR_ELEVATION_REQUIRED for a non-elevated agent) is kept too, so a scan
// does not retry it for every feature.
var dismSession struct {
	mu      sync.Mutex
	opened  bool
	err     error
	session uint32
}

// dismOpen returns the session, opening it on first use. The caller must hold
// dismSession.mu, and keep holding it for the DISM calls that use the
// session: the lock guards the session's use, not only its opening, so it
// cannot be taken in here.
func dismOpen() (uint32, error) {
	if dismSession.opened {
		return dismSession.session, dismSession.err
	}
	dismSession.opened = true
	if err := dismapi.Load(); err != nil {
		dismSession.err = err
		return 0, err
	}
	if hr, _, _ := procDismInitialize.Call(dismLogErrors, 0, 0); hr != sOK {
		dismSession.err = fmt.Errorf("DismInitialize: HRESULT 0x%08X", uint32(hr))
		return 0, dismSession.err
	}
	image, err := windows.UTF16PtrFromString(dismOnlineImage)
	if err != nil {
		dismSession.err = err
		return 0, err
	}
	var session uint32
	if hr, _, _ := procDismOpenSession.Call(uintptr(unsafe.Pointer(image)), 0, 0, uintptr(unsafe.Pointer(&session))); hr != sOK {
		dismSession.err = fmt.Errorf("DismOpenSession: HRESULT 0x%08X", uint32(hr))
		return 0, dismSession.err
	}
	dismSession.session = session
	return session, nil
}

// NativeOptionalFeatures lists the optional features of the running Windows
// installation through the DISM API, with the same names and states as
// Get-WindowsOptionalFeature -Online. Display names and descriptions are not
// part of this list (as with the cmdlet); see NativeOptionalFeature.
func NativeOptionalFeatures() ([]WindowsOptionalFeature, error) {
	dismSession.mu.Lock()
	defer dismSession.mu.Unlock()

	session, err := dismOpen()
	if err != nil {
		return nil, err
	}

	var features unsafe.Pointer
	var count uint32
	hr, _, _ := procDismGetFeatures.Call(uintptr(session), 0, dismPackageNone,
		uintptr(unsafe.Pointer(&features)), uintptr(unsafe.Pointer(&count)))
	if hr != sOK {
		return nil, fmt.Errorf("DismGetFeatures: HRESULT 0x%08X", uint32(hr))
	}
	defer procDismDelete.Call(uintptr(features)) //nolint:errcheck

	res := make([]WindowsOptionalFeature, 0, count)
	for i := 0; i < int(count); i++ {
		f := dismFeatureLayout.element(features, i)
		name := windows.UTF16PtrToString((*uint16)(dismFeatureLayout.ptr(f, dismFeatureName)))
		rawState := dismFeatureLayout.uint32(f, dismFeatureState)
		state, err := featureStateFromDism(rawState)
		if err != nil || name == "" {
			return nil, fmt.Errorf("DismGetFeatures: feature %d of %d could not be read (name %q, state %d)", i, count, name, rawState)
		}
		res = append(res, WindowsOptionalFeature{Name: name, State: state, Enabled: state == 2})
	}
	return res, nil
}

// NativeOptionalFeature returns one feature by its exact name, with its
// display name and description, through DismGetFeatureInfo. found is false when
// the image has no feature of that name.
func NativeOptionalFeature(name string) (feature WindowsOptionalFeature, found bool, err error) {
	dismSession.mu.Lock()
	defer dismSession.mu.Unlock()

	session, err := dismOpen()
	if err != nil {
		return feature, false, err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return feature, false, err
	}

	var info unsafe.Pointer
	hr, _, _ := procDismGetFeatureInfo.Call(uintptr(session), uintptr(unsafe.Pointer(namePtr)), 0, dismPackageNone,
		uintptr(unsafe.Pointer(&info)))
	if uint32(hr) == dismUnknownFeature {
		return feature, false, nil
	}
	if hr != sOK {
		return feature, false, fmt.Errorf("DismGetFeatureInfo: HRESULT 0x%08X", uint32(hr))
	}
	defer procDismDelete.Call(uintptr(info)) //nolint:errcheck

	l := dismFeatureInfoLayout
	rawState := l.uint32(info, dismFeatureInfoState)
	state, err := featureStateFromDism(rawState)
	if err != nil {
		return feature, false, fmt.Errorf("DismGetFeatureInfo %q: the result could not be read (state %d)", name, rawState)
	}
	feature = WindowsOptionalFeature{
		Name:        windows.UTF16PtrToString((*uint16)(l.ptr(info, dismFeatureInfoName))),
		DisplayName: windows.UTF16PtrToString((*uint16)(l.ptr(info, dismFeatureInfoDisplayName))),
		Description: windows.UTF16PtrToString((*uint16)(l.ptr(info, dismFeatureInfoDescription))),
		State:       state,
		Enabled:     state == 2,
	}
	// DISM matches names without regard to case; the PowerShell path has always
	// required the exact name, so a different spelling is not found.
	if feature.Name != name {
		return WindowsOptionalFeature{}, false, nil
	}
	return feature, true, nil
}
