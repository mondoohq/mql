// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"errors"
	"fmt"
	"syscall"

	"go.mondoo.com/mql/llx"
)

// errorAccessDenied is the Win32 ERROR_ACCESS_DENIED that RegOpenKeyEx
// returns for a key the caller may not read, such as HKLM\SECURITY for anyone
// but SYSTEM. It is declared here rather than taken from x/sys/windows so the
// classifier builds and is tested on every platform.
const errorAccessDenied = syscall.Errno(5)

// classifyOpenKeyError classifies a failure to open a registry key through the
// native API. Access denied is a refusal: forbidden. Anything else stays
// unclassified. Both keep the key's path and the underlying error.
func classifyOpenKeyError(path string, err error) error {
	wrapped := fmt.Errorf("could not open registry key %s: %w", path, err)
	if errors.Is(err, errorAccessDenied) {
		return llx.Forbidden(wrapped)
	}
	return wrapped
}
