// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package action1 detects the endpoint ID of an Action1 agent installed on the
// scanned host, so the asset can be correlated with the endpoint record Action1
// keeps for it.
package action1

import (
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// linuxAgentIDFile holds the endpoint ID on Linux. Only root and the file's
// group can read it.
const linuxAgentIDFile = "/var/opt/action1/agent_id.txt"

// windowsAgentIDScript reads the endpoint ID on Windows, where the agent keeps it
// in the registry under WOW6432Node.
const windowsAgentIDScript = `(Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Action1' -Name 'agent.guid' -ErrorAction SilentlyContinue).'agent.guid'`

var endpointID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Detect returns the endpoint ID of the Action1 agent on the host as a lowercase
// GUID, the form the Action1 API uses, or "" when no agent is installed or the
// ID cannot be read. It never returns an error: detection is best-effort.
//
// macOS is not covered: the location of the ID on a macOS agent is not known.
func Detect(conn shared.Connection, pf *inventory.Platform) string {
	if conn == nil || pf == nil {
		return ""
	}
	if pf.Kind == "container" || pf.Kind == "container-image" {
		return ""
	}
	// An image or a snapshot holds a copy of the ID, not a running endpoint.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return ""
	}

	switch {
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		return readWindows(conn)
	case pf.IsFamily(inventory.FAMILY_LINUX):
		return readLinux(conn)
	default:
		return ""
	}
}

// PlatformID returns the platform identifier of the endpoint, or "" for an empty
// ID. Endpoint IDs are GUIDs, so the ID is not scoped by the organization.
func PlatformID(id string) string {
	if id == "" {
		return ""
	}
	return "//platformid.api.mondoo.app/runtime/action1/endpoints/" + id
}

func readLinux(conn shared.Connection) string {
	f, err := conn.FileSystem().Open(linuxAgentIDFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Action1 agent ID")
		return ""
	}
	return normalize(string(data))
}

func readWindows(conn shared.Connection) string {
	cmd, err := conn.RunCommand(powershell.Encode(windowsAgentIDScript))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Action1 agent ID")
		return ""
	}
	if cmd.ExitStatus != 0 {
		return ""
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return ""
	}
	return normalize(string(data))
}

// normalize returns the ID in lowercase, or "" for anything that is not a GUID.
func normalize(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if !endpointID.MatchString(id) {
		return ""
	}
	return id
}
