// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package containerid

import "strings"

func MondooContainerImageID(id string) string {
	id = strings.ReplaceAll(id, "sha256:", "")
	return "//platformid.api.mondoo.app/runtime/docker/images/" + id
}

func ShortContainerID(id string) string {
	if len(id) > 12 {
		return id[0:12]
	}
	return id
}

func ShortContainerImageID(id string) string {
	id = strings.ReplaceAll(id, "sha256:", "")
	if len(id) > 12 {
		return id[0:12]
	}
	return id
}

const mondooContainerIDPrefix = "//platformid.api.mondoo.app/runtime/docker/containers/"

func MondooContainerID(id string) string {
	return mondooContainerIDPrefix + id
}

// ContainerIDFromPlatformID returns the container ID in a platform ID made by
// MondooContainerID.
func ContainerIDFromPlatformID(platformID string) (string, bool) {
	id, ok := strings.CutPrefix(platformID, mondooContainerIDPrefix)
	return id, ok && id != ""
}
