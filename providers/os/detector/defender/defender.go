// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package defender detects the identity of the Microsoft Defender for Endpoint
// sensor on a Windows host: the machine ID the Defender portal and API use for
// the device, and the ID of the organization the sensor is onboarded to.
package defender

import (
	"bufio"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	// sensorKey is where the sensor keeps its identity, relative to the
	// SOFTWARE hive. It holds the senseId value.
	sensorKey = `Microsoft\Windows Advanced Threat Protection`
	// statusKey is where the sensor reports its onboarding state and the
	// organization it is onboarded to, relative to the SOFTWARE hive.
	statusKey = sensorKey + `\Status`

	// machineIDValue is the device's Defender for Endpoint machine ID. The
	// sensor keeps it in sensorKey; statusKey is read as a fallback.
	machineIDValue = "senseId"
	// orgIDValue is the ID of the organization the sensor is onboarded to.
	orgIDValue = "OrgId"
	// onboardingStateValue is 1 while the sensor is onboarded. Offboarding
	// leaves senseId in place, so it is only reported while this reads 1.
	onboardingStateValue = "OnboardingState"
)

// Identity is the identity of an onboarded Defender for Endpoint sensor.
// MachineID is 40 lowercase hex characters, the form the Defender API uses
// for a machine ID. OrgID is a lowercase GUID and may be empty.
type Identity struct {
	MachineID string
	OrgID     string
}

// Detect returns the identity of the Defender for Endpoint sensor on a
// Windows host, or nil when the sensor is not onboarded or its identity
// cannot be read. It reads the registry natively on a local Windows host,
// from the SOFTWARE hive file on a filesystem or device connection, and
// through PowerShell on any other connection that can run commands. It never
// returns an error: a host without the sensor is not a failure.
func Detect(conn shared.Connection) *Identity {
	if conn == nil {
		return nil
	}
	switch {
	case conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return fromKeys(liveKeys{})
	case conn.Type() == shared.Type_FileSystem || conn.Type() == shared.Type_Device:
		return detectOffline(conn)
	case conn.Capabilities().Has(shared.Capability_RunCommand):
		return detectPowershell(conn)
	}
	return nil
}

// keyReader reads the values of a key relative to the SOFTWARE hive.
type keyReader interface {
	Items(path string) ([]registry.RegistryKeyItem, error)
}

// liveKeys reads the running system's registry.
type liveKeys struct{}

func (liveKeys) Items(path string) ([]registry.RegistryKeyItem, error) {
	return registry.GetNativeRegistryKeyItems(`HKEY_LOCAL_MACHINE\SOFTWARE\` + path)
}

// hiveReader is the part of the registry handler offline reads need;
// *registry.RegistryHandler implements it.
type hiveReader interface {
	GetNativeRegistryKeyItems(registryId string, path string) ([]registry.RegistryKeyItem, error)
}

// hiveKeys reads a SOFTWARE hive loaded from a file.
type hiveKeys struct{ rh hiveReader }

func (h hiveKeys) Items(path string) ([]registry.RegistryKeyItem, error) {
	return h.rh.GetNativeRegistryKeyItems(registry.Software, path)
}

func detectOffline(conn shared.Connection) *Identity {
	fi, err := conn.FileInfo(registry.SoftwareRegPath)
	if err != nil {
		log.Debug().Err(err).Msg("could not find SOFTWARE registry hive")
		return nil
	}
	rh := registry.NewRegistryHandler()
	defer func() {
		if err := rh.UnloadSubkeys(); err != nil {
			log.Debug().Err(err).Msg("could not unload registry subkeys")
		}
	}()
	if err := rh.LoadSubkey(registry.Software, fi.Path); err != nil {
		log.Debug().Err(err).Msg("could not load SOFTWARE registry hive")
		return nil
	}
	return fromKeys(hiveKeys{rh: rh})
}

// fromKeys reads the sensor and status keys. An absent key is how a host
// without the sensor looks, so read errors yield no identity.
func fromKeys(r keyReader) *Identity {
	status, err := r.Items(statusKey)
	if err != nil {
		log.Debug().Err(err).Msg("could not read Defender for Endpoint status key")
		return nil
	}
	sensor, err := r.Items(sensorKey)
	if err != nil {
		log.Debug().Err(err).Msg("could not read Defender for Endpoint sensor key")
	}

	onboarded := false
	if it, ok := findItem(status, onboardingStateValue); ok {
		onboarded = registryNumber(it) == 1
	}

	machineID := ""
	if it, ok := findItem(sensor, machineIDValue); ok {
		machineID = it.Value.String
	}
	if machineID == "" {
		if it, ok := findItem(status, machineIDValue); ok {
			machineID = it.Value.String
		}
	}

	orgID := ""
	if it, ok := findItem(status, orgIDValue); ok {
		orgID = it.Value.String
	}

	return newIdentity(onboarded, machineID, orgID)
}

// newIdentity applies the rules every read path shares: only an onboarded
// sensor with a well-formed machine ID has an identity.
func newIdentity(onboarded bool, machineID, orgID string) *Identity {
	if !onboarded {
		return nil
	}
	id := &Identity{MachineID: NormalizeMachineID(machineID), OrgID: NormalizeOrgID(orgID)}
	if id.MachineID == "" {
		// An organization without a machine ID does not identify a device.
		return nil
	}
	return id
}

// findItem looks up a value by name. Registry value names are
// case-insensitive.
func findItem(items []registry.RegistryKeyItem, name string) (registry.RegistryKeyItem, bool) {
	for _, it := range items {
		if strings.EqualFold(it.Key, name) {
			return it, true
		}
	}
	return registry.RegistryKeyItem{}, false
}

// registryNumber returns a DWORD or QWORD value, or the number a string value
// holds, and -1 for anything else.
func registryNumber(it registry.RegistryKeyItem) int64 {
	switch it.Value.Kind {
	case registry.DWORD, registry.QWORD:
		return it.Value.Number
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(it.Value.String), 10, 64); err == nil {
		return n
	}
	return -1
}

// powershellScript reads the sensor identity and prints it as
// `onboardingstate=`, `senseid=` and `orgid=` lines. Values that are absent or
// unreadable are not printed.
var powershellScript = `$ErrorActionPreference = 'SilentlyContinue'
$s = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\` + statusKey + `'
if ($null -eq $s) { exit 0 }
$k = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\` + sensorKey + `'
if ($null -ne $s.` + onboardingStateValue + `) { 'onboardingstate=' + $s.` + onboardingStateValue + ` }
if ($null -ne $k.` + machineIDValue + `) { 'senseid=' + $k.` + machineIDValue + ` } elseif ($null -ne $s.` + machineIDValue + `) { 'senseid=' + $s.` + machineIDValue + ` }
if ($null -ne $s.` + orgIDValue + `) { 'orgid=' + $s.` + orgIDValue + ` }
`

func detectPowershell(conn shared.Connection) *Identity {
	cmd, err := conn.RunCommand(powershell.Encode(powershellScript))
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Defender for Endpoint sensor identity")
		return nil
	}
	if cmd.ExitStatus != 0 {
		return nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil
	}
	return parsePowershellOutput(string(data))
}

// parsePowershellOutput parses the lines powershellScript prints.
func parsePowershellOutput(out string) *Identity {
	var onboarded bool
	var machineID, orgID string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "onboardingstate":
			onboarded = value == "1"
		case "senseid":
			machineID = value
		case "orgid":
			orgID = value
		}
	}
	return newIdentity(onboarded, machineID, orgID)
}

var (
	machineIDPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	guidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// NormalizeMachineID returns a Defender for Endpoint machine ID as 40
// lowercase hex characters, or "" when raw is not one.
func NormalizeMachineID(raw string) string {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(raw), `"'`))
	if !machineIDPattern.MatchString(s) || strings.Trim(s, "0") == "" {
		return ""
	}
	return s
}

// NormalizeOrgID returns an organization ID as a lowercase GUID without
// braces, or "" when raw is not one.
func NormalizeOrgID(raw string) string {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(raw), `"'{}`))
	if !guidPattern.MatchString(s) || strings.Trim(s, "0-") == "" {
		return ""
	}
	return s
}
