// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package crowdstrike

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows/registry"
)

func detectWindows(conn shared.Connection) *Identity {
	// Locally, read the registry directly instead of starting powershell.
	if conn.Type() == shared.Type_Local {
		return detectWindowsFromRegistry()
	}
	return powershellDetectWindows(conn)
}

func detectWindowsFromRegistry() *Identity {
	for _, path := range windowsSensorKeys {
		if id := readSensorKey(path); id != nil {
			return id
		}
	}
	return nil
}

// readSensorKey reads the sensor identity from one registry key, or returns nil
// when the key or its AID value is absent or unreadable.
func readSensorKey(path string) *Identity {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		// absent sensor, or not running with administrative privileges
		if !errors.Is(err, registry.ErrNotExist) {
			log.Debug().Err(err).Str("key", path).Msg("could not open CrowdStrike Falcon sensor key")
		}
		return nil
	}
	defer key.Close()

	aid, _, err := key.GetBinaryValue(windowsAIDValue)
	if err != nil {
		return nil
	}
	id := &Identity{AID: binaryToID(aid)}
	if cid, _, err := key.GetBinaryValue(windowsCIDValue); err == nil {
		id.CID = binaryToID(cid)
	}
	return id
}
