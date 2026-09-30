// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

// Package wmiquery runs WMI queries for the local Windows fast paths without
// letting the WMI library take the scan down.
package wmiquery

import (
	"fmt"

	wmi "github.com/StackExchange/wmi"
)

// query is the WMI call; tests replace it to simulate a failing library.
var query = wmi.Query

// Query runs a WMI query into dst, like wmi.Query. The WMI library has no
// recover() of its own and panics when a COM variant type does not match the
// destination field (for example a VT_I4 array read into []uint16), which
// would end the whole scan. Query turns such a panic into an error, so the
// caller can fall back to its PowerShell path.
func Query(q string, dst any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("WMI query %q panicked: %v", q, r)
		}
	}()
	return query(q, dst)
}
