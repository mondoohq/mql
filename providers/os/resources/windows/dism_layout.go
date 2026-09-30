// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"errors"
	"unsafe"
)

// The DISM API (dismapi.h) declares its structures inside `#pragma pack(push,
// 4)`: a pointer member is not padded to 8 bytes on 64-bit Windows. Go cannot
// declare such a struct (its fields always have their natural alignment), so a
// Go struct mirroring DismFeature would be 16 bytes on amd64 where DISM hands
// out an array of 12-byte elements, and every element after the first would be
// misread. The layouts are therefore described field by field, in declaration
// order, and every offset is computed from the field sizes; dism_layout_test.go
// pins the results for 64-bit and 32-bit pointers.

// dismField is one member of a packed DISM structure: its size in bytes.
type dismField uintptr

const (
	dismPtr  = dismField(unsafe.Sizeof(uintptr(0))) // PCWSTR or a pointer to a structure
	dismEnum = dismField(4)                         // an enum or a UINT
)

// dismLayout is a packed structure: the offset of each field, and the size of
// one element when the structure comes as an array.
type dismLayout struct {
	offsets []uintptr
	size    uintptr
}

// packedLayout lays out fields with `#pragma pack(4)`. Every DISM member is 4
// bytes or a pointer (4 or 8), so no field is ever padded: each offset is the
// sum of the sizes before it.
func packedLayout(fields ...dismField) dismLayout {
	l := dismLayout{offsets: make([]uintptr, len(fields))}
	for i, f := range fields {
		l.offsets[i] = l.size
		l.size += uintptr(f)
	}
	return l
}

// DismFeature: PCWSTR FeatureName; DismPackageFeatureState State.
var dismFeatureLayout = packedLayout(dismPtr, dismEnum)

const (
	dismFeatureName = iota
	dismFeatureState
)

// DismFeatureInfo: PCWSTR FeatureName; DismPackageFeatureState FeatureState;
// PCWSTR DisplayName; PCWSTR Description; DismRestartType RestartRequired;
// DismCustomProperty* CustomProperty; UINT CustomPropertyCount.
var dismFeatureInfoLayout = packedLayout(dismPtr, dismEnum, dismPtr, dismPtr, dismEnum, dismPtr, dismEnum)

// The DismFeatureInfo field indexes and the pointer reader are only used by
// the Windows reader, so they live in dism_windows.go.

// DismPackageFeatureState, the state DISM reports for a feature.
const (
	dismStateNotPresent         = 0
	dismStateUninstallPending   = 1
	dismStateStaged             = 2
	dismStateResolved           = 3 // also DismStateRemoved
	dismStateInstalled          = 4
	dismStateInstallPending     = 5
	dismStateSuperseded         = 6
	dismStatePartiallyInstalled = 7
)

// featureStateFromDism maps a DismPackageFeatureState to the FeatureState that
// Get-WindowsOptionalFeature reports (Microsoft.Dism.Commands.FeatureState),
// which is what windows.optionalFeature.state has always carried, so the
// native path returns the same number. The cmdlet's enum, read from Windows
// Server 2022:
//
//	Disabled = 0, DisablePending = 1, Enabled = 2, EnablePending = 3,
//	Superseded = 4, PartiallyInstalled = 5, DisabledWithPayloadRemoved = 6
//
// A state outside the DISM enum is an error: it means the structure was not
// read the way DISM wrote it, and the caller falls back to PowerShell.
func featureStateFromDism(s uint32) (int64, error) {
	switch s {
	// NotPresent is what DISM reports for a feature whose package is not in the
	// image, such as Server-Gui-Mgmt_onecore on Server 2022 with the desktop
	// experience; the cmdlet reports it as Disabled. A removed payload
	// (DismStateRemoved, the same value as Resolved), such as NetFx3, is
	// DisabledWithPayloadRemoved.
	case dismStateStaged, dismStateNotPresent:
		return 0, nil
	case dismStateUninstallPending:
		return 1, nil
	case dismStateInstalled:
		return 2, nil
	case dismStateInstallPending:
		return 3, nil
	case dismStateSuperseded:
		return 4, nil
	case dismStatePartiallyInstalled:
		return 5, nil
	case dismStateResolved:
		return 6, nil
	}
	return 0, errors.New("unexpected DISM feature state")
}

// uint32 reads the 4-byte member i of the structure at base.
func (l dismLayout) uint32(base unsafe.Pointer, i int) uint32 {
	return *(*uint32)(unsafe.Add(base, l.offsets[i]))
}

// element returns the i-th structure of an array that starts at base.
func (l dismLayout) element(base unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Add(base, uintptr(i)*l.size)
}
