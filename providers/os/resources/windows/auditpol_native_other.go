// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "errors"

// NativeAuditPolicy reads the audit policy natively, which only works on
// Windows; the caller then runs auditpol.
func NativeAuditPolicy() ([]AuditpolEntry, error) {
	return nil, errors.New("the native audit policy is only available on Windows")
}
