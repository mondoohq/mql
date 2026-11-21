// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sentinelone detects the agent UUID of a SentinelOne agent installed
// on the scanned host, so the asset can be correlated with the agent record the
// SentinelOne management console keeps for it.
package sentinelone

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// linuxBasicConf is the Linux agent's management configuration. It is JSON;
// mgmt_uuid is the agent UUID the console lists for the agent. Only root and
// the agent's own user can read it.
const linuxBasicConf = "/opt/sentinelone/configuration/basic.conf"

// macosAgentBundle exists when the macOS agent is installed. The macOS agent
// UUID is the Mac's IOPlatformUUID: the console, `sentinelctl status` and
// `ioreg` report the same value.
const macosAgentBundle = "/Library/Sentinel/sentinel-agent.bundle"

// windowsAgentUIDScript reads the Windows agent's UUID. The agent keeps it as
// AgentUID under its SentinelMonitor service key, as 32 hex digits without
// dashes, the form the management console lists. Users can read the key.
const windowsAgentUIDScript = `(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SentinelMonitor\Config' -Name 'AgentUID' -ErrorAction SilentlyContinue).AgentUID`

var (
	// agentUUID is a UUID with dashes (Linux, macOS) or 32 hex digits
	// (Windows), in lower case. Each OS keeps the spelling its agent reports.
	agentUUID      = regexp.MustCompile(`^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
)

// Detect returns the agent UUID of the SentinelOne agent on the host in lower
// case, or "" when no agent is installed or the UUID cannot be read. It never
// returns an error: detection is best-effort.
func Detect(conn shared.Connection, pf *inventory.Platform) string {
	if conn == nil || pf == nil {
		return ""
	}
	if pf.Kind == "container" || pf.Kind == "container-image" {
		return ""
	}
	// An image or a snapshot holds a copy of the agent, not a running one.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return ""
	}

	switch {
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		return readWindows(conn)
	case pf.IsFamily(inventory.FAMILY_LINUX):
		return readLinux(conn)
	case pf.IsFamily(inventory.FAMILY_DARWIN):
		return readMacos(conn)
	default:
		return ""
	}
}

// PlatformID returns the platform identifier of the agent, or "" for an empty
// UUID. Agent UUIDs are unique across consoles, so the ID is not scoped.
func PlatformID(uuid string) string {
	if uuid == "" {
		return ""
	}
	return "//platformid.api.mondoo.app/runtime/sentinelone/agents/" + uuid
}

func readLinux(conn shared.Connection) string {
	f, err := conn.FileSystem().Open(linuxBasicConf)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the SentinelOne agent configuration")
		return ""
	}
	var conf struct {
		UUID string `json:"mgmt_uuid"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		log.Debug().Err(err).Msg("could not parse the SentinelOne agent configuration")
		return ""
	}
	return normalize(conf.UUID)
}

func readMacos(conn shared.Connection) string {
	if _, err := conn.FileSystem().Stat(macosAgentBundle); err != nil {
		return ""
	}
	cmd, err := conn.RunCommand("ioreg -rd1 -c IOPlatformExpertDevice")
	if err != nil || cmd.ExitStatus != 0 {
		log.Debug().Err(err).Msg("could not read the platform UUID for the SentinelOne agent")
		return ""
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return ""
	}
	m := ioPlatformUUID.FindStringSubmatch(string(data))
	if m == nil {
		return ""
	}
	return normalize(m[1])
}

func readWindows(conn shared.Connection) string {
	cmd, err := conn.RunCommand(powershell.Encode(windowsAgentUIDScript))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the SentinelOne agent UUID")
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

// normalize returns the UUID in lower case, or "" for anything that is not one.
// An all-zero UUID is not an identity: hosts reporting one would all share a
// platform ID and merge into one asset.
func normalize(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if !agentUUID.MatchString(id) {
		return ""
	}
	if strings.Trim(id, "0-") == "" {
		return ""
	}
	return id
}
