// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package crowdstrike detects the identity of a CrowdStrike Falcon sensor
// installed on the scanned host, so the asset can be correlated with the
// device record Falcon keeps for it.
package crowdstrike

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	// LabelAID is the platform label holding the Falcon agent ID (AID) of the
	// sensor on this host, as 32 lowercase hex characters.
	LabelAID = "crowdstrike.com/aid"
	// LabelCID is the platform label holding the Falcon customer ID (CID) the
	// sensor is registered to, as 32 lowercase hex characters without the
	// checksum suffix.
	LabelCID = "crowdstrike.com/cid"

	// linuxFalconctl is the sensor control utility of the Falcon sensor for Linux.
	linuxFalconctl = "/opt/CrowdStrike/falconctl"
	// macosFalconctl is the sensor control utility of the Falcon sensor for macOS.
	macosFalconctl = "/Applications/Falcon.app/Contents/Resources/falconctl"

	// windowsSensorKey holds the sensor's identity values on current Windows
	// sensors. Older sensors keep the same values under windowsLegacySensorKey.
	windowsSensorKey       = `SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`
	windowsLegacySensorKey = `SYSTEM\CurrentControlSet\Services\CSAgent\Sim`
	// windowsAIDValue and windowsCIDValue are REG_BINARY values holding the
	// raw 16-byte agent ID and customer ID.
	windowsAIDValue = "AG"
	windowsCIDValue = "CU"
)

var windowsSensorKeys = []string{windowsSensorKey, windowsLegacySensorKey}

// Identity is the identity of a Falcon sensor. Both fields are normalized to
// 32 lowercase hex characters, the form the Falcon API uses. Either can be
// empty when the sensor does not expose it.
type Identity struct {
	AID string
	CID string
}

// Detect returns the identity of the Falcon sensor on the host, or nil when
// no sensor is installed or its identity cannot be read. Reading the identity
// requires administrative privileges on every platform; without them Detect
// returns nil. It never returns an error: sensor detection is best-effort and
// must not fail platform detection.
//
// Detection is gated by a cheap existence check (a file stat or a registry
// key lookup) so hosts without the sensor pay almost nothing.
func Detect(conn shared.Connection, pf *inventory.Platform) *Identity {
	if conn == nil || pf == nil {
		return nil
	}
	if pf.Kind == "container" || pf.Kind == "container-image" {
		return nil
	}
	// All sources need to execute something on the host (or read the live
	// registry). Connections to images, snapshots and file systems can't.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil
	}

	var id *Identity
	switch {
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		id = detectWindows(conn)
	case pf.IsFamily(inventory.FAMILY_DARWIN):
		id = detectFalconctl(conn, macosFalconctl, macosFalconctl+" stats agent_info", parseMacosAgentInfo)
	case pf.IsFamily(inventory.FAMILY_LINUX):
		id = detectFalconctl(conn, linuxFalconctl, linuxFalconctl+" -g --aid --cid", parseLinuxFalconctl)
	default:
		return nil
	}

	if id == nil || id.AID == "" {
		// A CID without an AID does not identify a host.
		return nil
	}
	return id
}

// ApplyLabels detects the Falcon sensor identity and records it in the
// platform labels.
func ApplyLabels(conn shared.Connection, pf *inventory.Platform) {
	id := Detect(conn, pf)
	if id == nil {
		return
	}
	if pf.Labels == nil {
		pf.Labels = map[string]string{}
	}
	pf.Labels[LabelAID] = id.AID
	if id.CID != "" {
		pf.Labels[LabelCID] = id.CID
	}
	log.Debug().Str("aid", id.AID).Str("cid", id.CID).Msg("detected CrowdStrike Falcon sensor")
}

// FromLabels returns the sensor identity recorded in the platform labels, or
// nil if there is none.
func FromLabels(pf *inventory.Platform) *Identity {
	if pf == nil || pf.Labels == nil {
		return nil
	}
	aid := pf.Labels[LabelAID]
	if aid == "" {
		return nil
	}
	return &Identity{AID: aid, CID: pf.Labels[LabelCID]}
}

// PlatformID returns the platform identifier for the host the sensor runs on,
// scoped by the customer ID because agent IDs are only unique within a
// Falcon customer. It returns "" when either ID is missing.
func (id *Identity) PlatformID() string {
	if id == nil || id.AID == "" || id.CID == "" {
		return ""
	}
	return "//platformid.api.mondoo.app/runtime/crowdstrike/cids/" + id.CID + "/aids/" + id.AID
}

func detectFalconctl(conn shared.Connection, bin string, command string, parse func(string) *Identity) *Identity {
	if _, err := conn.FileSystem().Stat(bin); err != nil {
		return nil
	}
	cmd, err := conn.RunCommand(command)
	if err != nil {
		log.Debug().Err(err).Str("command", command).Msg("could not run falconctl")
		return nil
	}
	if cmd.ExitStatus != 0 {
		// falconctl refuses to run without root privileges
		log.Debug().Int("exit", cmd.ExitStatus).Msg("falconctl did not report the sensor identity")
		return nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil
	}
	return parse(string(data))
}

// falconctlValue matches the key="value" pairs `falconctl -g` prints, e.g.
// `cid="0123456789abcdef0123456789abcdef", aid="4d7f5b8b9e0b4c2a8d1e2f3a4b5c6d7e".`
var falconctlValue = regexp.MustCompile(`(?i)\b(aid|cid)\s*=\s*"([^"]*)"`)

// parseLinuxFalconctl parses the output of `falconctl -g --aid --cid`.
// An unset value is reported as `aid is not set.` and yields an empty field.
func parseLinuxFalconctl(out string) *Identity {
	id := &Identity{}
	for _, m := range falconctlValue.FindAllStringSubmatch(out, -1) {
		switch strings.ToLower(m[1]) {
		case "aid":
			id.AID = NormalizeID(m[2])
		case "cid":
			id.CID = NormalizeID(m[2])
		}
	}
	return id
}

// parseMacosAgentInfo parses the output of `falconctl stats agent_info`,
// which lists the sensor state as `key: value` lines, including
// `agentID: FEDCBA98-7654-3210-FEDC-BA9876543210`.
func parseMacosAgentInfo(out string) *Identity {
	id := &Identity{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "agentid", "agent id", "aid":
			id.AID = NormalizeID(value)
		case "customerid", "customer id", "cid":
			id.CID = NormalizeID(value)
		}
	}
	return id
}

// windowsIdentityScript reads the sensor identity from the registry and
// prints it as `aid=<hex>` and `cid=<hex>` lines. It prints nothing when the
// sensor key is absent or not readable (the key requires administrative
// privileges).
var windowsIdentityScript = func() string {
	var b strings.Builder
	b.WriteString(`$ErrorActionPreference = 'SilentlyContinue'
foreach ($p in @(`)
	for i, key := range windowsSensorKeys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`'HKLM:\` + key + `'`)
	}
	b.WriteString(`)) {
  if (-not (Test-Path -LiteralPath $p)) { continue }
  $k = Get-ItemProperty -LiteralPath $p
  if ($null -eq $k.` + windowsAIDValue + `) { continue }
  'aid=' + (($k.` + windowsAIDValue + ` | ForEach-Object { $_.ToString('x2') }) -join '')
  if ($null -ne $k.` + windowsCIDValue + `) { 'cid=' + (($k.` + windowsCIDValue + ` | ForEach-Object { $_.ToString('x2') }) -join '') }
  break
}
`)
	return b.String()
}()

func powershellDetectWindows(conn shared.Connection) *Identity {
	cmd, err := conn.RunCommand(powershell.Encode(windowsIdentityScript))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the CrowdStrike Falcon sensor identity")
		return nil
	}
	if cmd.ExitStatus != 0 {
		return nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil
	}
	return parseWindowsScriptOutput(string(data))
}

// parseWindowsScriptOutput parses the `aid=<hex>` / `cid=<hex>` lines printed
// by windowsIdentityScript.
func parseWindowsScriptOutput(out string) *Identity {
	id := &Identity{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "aid":
			id.AID = NormalizeID(value)
		case "cid":
			id.CID = NormalizeID(value)
		}
	}
	return id
}

// binaryToID converts a REG_BINARY identity value to its normalized form.
func binaryToID(b []byte) string {
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, c := range b {
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0f])
	}
	return NormalizeID(sb.String())
}

var (
	hexID          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	checksumSuffix = regexp.MustCompile(`^([0-9a-f]{32})-[0-9a-f]{2}$`)
)

// NormalizeID converts a Falcon AID or CID to the form the Falcon API uses:
// 32 lowercase hex characters. It accepts the plain hex form, the UUID form
// with dashes (as the macOS sensor prints the AID), and the CID form with the
// `-XX` checksum suffix. Anything else, including an all-zero ID, yields "".
func NormalizeID(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.Trim(s, `"'.,`)
	if m := checksumSuffix.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	s = strings.ReplaceAll(s, "-", "")
	if !hexID.MatchString(s) {
		return ""
	}
	if strings.Trim(s, "0") == "" {
		return ""
	}
	return s
}
