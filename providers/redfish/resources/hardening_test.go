// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stmcginnis/gofish/oem/smc"
	"github.com/stmcginnis/gofish/schemas"
)

// smcSyslogCollection is a Syslog document of a Supermicro controller running
// Gen 14 firmware 1.08 or newer, which reports SyslogServer as a collection.
// The second destination carries no port. Firmware older than gofish v0.25.0
// could not decode this shape at all.
const smcSyslogCollection = `{
  "@odata.id": "/redfish/v1/Managers/1/Oem/Supermicro/Syslog",
  "EnableSyslog": true,
  "SyslogServer": [
    {"ServerIP": "10.0.0.10", "Port": 514},
    {"ServerIP": "10.0.0.11"}
  ]
}`

// smcSyslogSingular is a Syslog document of a Supermicro controller running
// firmware older than Gen 13 1.10, which reports one destination as a string
// alongside a separate port property.
const smcSyslogSingular = `{
  "@odata.id": "/redfish/v1/Managers/1/Oem/Supermicro/Syslog",
  "EnableSyslog": true,
  "SyslogServer": "10.0.0.10",
  "SyslogPortNumber": 514
}`

// smcSyslogUnconfigured is a Syslog document of a controller that forwards
// nothing, which is the state an audit is looking for.
const smcSyslogUnconfigured = `{
  "@odata.id": "/redfish/v1/Managers/1/Oem/Supermicro/Syslog",
  "EnableSyslog": false,
  "SyslogServer": ""
}`

func decodeSyslog(t *testing.T, raw string) *smc.Syslog {
	t.Helper()
	var syslog smc.Syslog
	if err := json.Unmarshal([]byte(raw), &syslog); err != nil {
		t.Fatalf("decoding the syslog document failed: %v", err)
	}
	return &syslog
}

func TestSyslogServerDictsCollection(t *testing.T) {
	got := syslogServerDicts(decodeSyslog(t, smcSyslogCollection))
	if len(got) != 2 {
		t.Fatalf("syslogServerDicts() returned %d destinations, want 2", len(got))
	}

	first, ok := got[0].(map[string]any)
	if !ok {
		t.Fatalf("destination 0 = %T, want a map", got[0])
	}
	if first["host"] != "10.0.0.10" {
		t.Errorf("destination 0 host = %v, want 10.0.0.10", first["host"])
	}
	if first["port"] != int64(514) {
		t.Errorf("destination 0 port = %v, want 514", first["port"])
	}

	second := got[1].(map[string]any)
	if second["host"] != "10.0.0.11" {
		t.Errorf("destination 1 host = %v, want 10.0.0.11", second["host"])
	}
	// The controller reports no port for this destination, so it may not read
	// as port 0.
	if second["port"] != nil {
		t.Errorf("destination 1 port = %v, want null", second["port"])
	}
}

func TestSyslogServerDictsSingular(t *testing.T) {
	// Firmware that reports one destination as a string appears as a list of
	// one, so a query does not have to know which firmware answered it.
	got := syslogServerDicts(decodeSyslog(t, smcSyslogSingular))
	if len(got) != 1 {
		t.Fatalf("syslogServerDicts() returned %d destinations, want 1", len(got))
	}
	entry := got[0].(map[string]any)
	if entry["host"] != "10.0.0.10" {
		t.Errorf("host = %v, want 10.0.0.10", entry["host"])
	}
	if entry["port"] != int64(514) {
		t.Errorf("port = %v, want 514", entry["port"])
	}
}

func TestSyslogServerDictsUnconfigured(t *testing.T) {
	// gofish fills Servers with one address-less entry for this document, so a
	// mapper that copies the collection straight through reports a controller
	// forwarding nowhere as one that forwards to a destination with no address.
	// That is the finding an audit is looking for, so the empty entry is dropped.
	got := syslogServerDicts(decodeSyslog(t, smcSyslogUnconfigured))
	if len(got) != 0 {
		t.Errorf("syslogServerDicts() = %v, want no destination", got)
	}
}

func TestTrustedModuleDicts(t *testing.T) {
	modules := []schemas.TrustedModules{
		{
			FirmwareVersion: "7.2.1.0",
			InterfaceType:   schemas.TPM20InterfaceType,
			Status:          schemas.Status{Health: "OK", State: "Enabled"},
		},
		{
			// A module the controller describes by interface type alone.
			InterfaceType: schemas.TPM12InterfaceType,
		},
	}

	got := trustedModuleDicts(modules)
	if len(got) != 2 {
		t.Fatalf("trustedModuleDicts() returned %d modules, want 2", len(got))
	}

	first := got[0].(map[string]any)
	want := map[string]any{
		"interfaceType":   "TPM2_0",
		"firmwareVersion": "7.2.1.0",
		"health":          "OK",
		"state":           "Enabled",
	}
	for key, value := range want {
		if first[key] != value {
			t.Errorf("module 0 %s = %v, want %v", key, first[key], value)
		}
	}
	// Not reported by this module, and an empty string here would read as a
	// value the controller supplied.
	if first["firmwareVersion2"] != nil {
		t.Errorf("module 0 firmwareVersion2 = %v, want null", first["firmwareVersion2"])
	}

	second := got[1].(map[string]any)
	if second["interfaceType"] != "TPM1_2" {
		t.Errorf("module 1 interfaceType = %v, want TPM1_2", second["interfaceType"])
	}
	for _, key := range []string{"firmwareVersion", "health", "state", "interfaceTypeSelection"} {
		if second[key] != nil {
			t.Errorf("module 1 %s = %v, want null", key, second[key])
		}
	}
}

func TestTrustedModuleDictsNoModules(t *testing.T) {
	// A system with no trusted module reports an empty list rather than null,
	// because the system itself answered: there is no TPM.
	if got := trustedModuleDicts(nil); len(got) != 0 {
		t.Errorf("trustedModuleDicts(nil) = %v, want an empty list", got)
	}
}
