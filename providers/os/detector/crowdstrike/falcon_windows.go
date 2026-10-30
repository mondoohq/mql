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

// detectWindowsFromRegistry takes AG and CU each from the first sensor key
// that holds them, like the powershell path does.
func detectWindowsFromRegistry() *Identity {
	id := &Identity{}
	for _, path := range windowsSensorKeys {
		readSensorKey(path, id)
	}
	if id.AID == "" && id.CID == "" {
		return nil
	}
	return id
}

// readSensorKey fills the IDs still missing from id with the values of one
// registry key. An absent or unreadable key or value leaves them unchanged.
func readSensorKey(path string, id *Identity) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		// absent sensor, or not running with administrative privileges
		if !errors.Is(err, registry.ErrNotExist) {
			log.Debug().Err(err).Str("key", path).Msg("could not open CrowdStrike Falcon sensor key")
		}
		return
	}
	defer key.Close()

	if id.AID == "" {
		if aid, _, err := key.GetBinaryValue(windowsAIDValue); err == nil {
			id.AID = binaryToID(aid)
		}
	}
	if id.CID == "" {
		if cid, _, err := key.GetBinaryValue(windowsCIDValue); err == nil {
			id.CID = binaryToID(cid)
		}
	}
}
