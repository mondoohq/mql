// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package crowdstrike

import (
	"errors"
	"runtime"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows/registry"
)

func detectWindows(conn shared.Connection) *Identity {
	// Locally, read the registry directly instead of starting powershell.
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		return detectWindowsFromRegistry()
	}
	return powershellDetectWindows(conn)
}

func detectWindowsFromRegistry() *Identity {
	for _, path := range windowsSensorKeys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			// absent sensor, or not running with administrative privileges
			if !errors.Is(err, registry.ErrNotExist) {
				log.Debug().Err(err).Str("key", path).Msg("could not open CrowdStrike Falcon sensor key")
			}
			continue
		}
		aid, _, err := key.GetBinaryValue(windowsAIDValue)
		if err != nil {
			key.Close()
			continue
		}
		id := &Identity{AID: binaryToID(aid)}
		if cid, _, err := key.GetBinaryValue(windowsCIDValue); err == nil {
			id.CID = binaryToID(cid)
		}
		key.Close()
		return id
	}
	return nil
}
