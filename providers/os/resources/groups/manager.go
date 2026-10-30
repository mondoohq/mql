// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"errors"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

func ResolveManager(conn shared.Connection) (OSGroupManager, error) {
	var gm OSGroupManager

	asset := conn.Asset()
	if osFamilyConn, ok := conn.(shared.ConnectionWithOSFamily); ok {
		osFamily := osFamilyConn.OSFamily()
		switch osFamily {
		case shared.OSFamily_Windows:
			gm = &WindowsGroupManager{conn: conn}
		case shared.OSFamily_Unix:
			gm = &UnixGroupManager{conn: conn}
		case shared.OSFamily_Darwin:
			gm = &OSXGroupManager{conn: conn}
		default:
			return nil, errors.New("could not detect suitable group manager for platform: " + string(osFamily))
		}
	} else {
		if asset == nil || asset.Platform == nil {
			return nil, errors.New("cannot find OS information for users detection")
		}

		// check darwin before unix since darwin is also a unix
		if asset.Platform.IsFamily("darwin") {
			gm = &OSXGroupManager{conn: conn}
		} else if asset.Platform.IsFamily("unix") {
			gm = &UnixGroupManager{conn: conn}
		} else if asset.Platform.IsFamily("windows") {
			gm = &WindowsGroupManager{conn: conn}
		}
	}
	if gm == nil {
		return nil, errors.New("could not detect suitable group manager for platform: " + asset.Platform.Name)
	}

	return gm, nil
}
