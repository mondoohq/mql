// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// certificateReadError decides what a failure to read a configured certificate
// file reports. A missing file is an absence and reports nothing. Any other
// failure means the server's certificate exists but the scan could not read
// it, typically a non-root scan of a key-and-certificate PEM the server's own
// account owns, and an empty list would pass an expiry or key-size check on a
// certificate nobody looked at. That is a refusal (ADR 046), returned only
// with structured errors on, since v13 returned an empty list here.
func certificateReadError(err error) error {
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if !plugin.StructuredErrors() {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return llx.Forbidden(err)
	}
	return err
}
