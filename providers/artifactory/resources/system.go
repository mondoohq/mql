// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/artifactory/connection"
)

// SystemInfo identifies the instance a scan connected to.
type SystemInfo struct {
	ServiceID string
	Version   string
	Revision  string
	Addons    []string
}

type versionRecord struct {
	Version  string   `json:"version"`
	Revision string   `json:"revision"`
	Addons   []string `json:"addons"`
}

// FetchSystemInfo reads the identity of the instance.
//
// It is called during connect, before any resource exists, so a failing read
// must not fail the connection: an instance that denies the version endpoint
// to the token is still worth scanning for everything the token can read. Each
// unread field stays empty and is logged.
func FetchSystemInfo(ctx context.Context, conn *connection.ArtifactoryConnection) SystemInfo {
	var info SystemInfo

	serviceID, err := conn.GetText(ctx, conn.ArtifactoryURL("/api/system/service_id"))
	if err != nil {
		log.Debug().Err(err).Msg("artifactory> could not read the service id")
	} else {
		info.ServiceID = serviceID
	}

	var version versionRecord
	if err := conn.GetJSON(ctx, conn.ArtifactoryURL("/api/system/version"), &version); err != nil {
		log.Debug().Err(err).Msg("artifactory> could not read the product version")
		return info
	}

	info.Version = version.Version
	info.Revision = version.Revision
	info.Addons = version.Addons
	return info
}
