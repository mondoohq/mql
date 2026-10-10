// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// requireAix returns a not-applicable error on any platform but AIX: the
// aix.* resources read files and commands only AIX has.
func requireAix(runtime *plugin.Runtime, resource string) error {
	conn := runtime.Connection.(shared.Connection)
	if pf := conn.Asset().GetPlatform(); pf != nil && pf.Name == "aix" {
		return nil
	}
	return llx.NotApplicable(errors.New(resource + " is only available on AIX"))
}
