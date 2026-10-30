// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

func (a *mqlAsset) purl() (string, error) {
	// use platform and version to generate the purl
	conn, ok := a.MqlRuntime.Connection.(shared.Connection)
	if ok && conn.Asset() != nil && conn.Asset().Platform != nil {
		purlString, err := purl.NewPlatformPurl(conn.Asset().Platform)
		if err != nil {
			return "", err
		}
		return purlString, nil
	}

	return "", nil
}
