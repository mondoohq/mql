// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// Measured: DMTF Redfish-Mockup-Server public-rackmount1, fetched 2026-11-23.
// The ComputerSystem document links a Bios resource and reports neither a
// production date nor virtualization capabilities.
const mockupSystem = `{
  "@odata.id": "/redfish/v1/Systems/437XR1138R2",
  "Id": "437XR1138R2",
  "Bios": {"@odata.id": "/redfish/v1/Systems/437XR1138R2/Bios"}
}`

func TestParseSystemExtrasUnreported(t *testing.T) {
	extras := parseSystemExtras([]byte(mockupSystem))
	if extras.Bios == nil || extras.Bios.ODataID != "/redfish/v1/Systems/437XR1138R2/Bios" {
		t.Errorf("Bios link = %+v, want /redfish/v1/Systems/437XR1138R2/Bios", extras.Bios)
	}
	// A controller that does not report virtualization may not read as a
	// system without hardware isolation.
	if got := extras.virtualizationCPUOffload(); got != nil {
		t.Errorf("virtualizationCPUOffload = %v, want null", *got)
	}
	if got := extras.virtualizationDeviceIsolation(); got != nil {
		t.Errorf("virtualizationDeviceIsolation = %v, want null", *got)
	}
	if got := parseRedfishTime(extras.ProductionDate); got != nil {
		t.Errorf("productionDate = %v, want null", got)
	}
}

func TestParseSystemExtrasReported(t *testing.T) {
	// Synthetic: a ComputerSystem v1.29 document with every new property set;
	// no target showed this.
	extras := parseSystemExtras([]byte(`{
  "ProductionDate": "2025-03-14T00:00:00Z",
  "Virtualization": {"CPUOffload": true, "DeviceIsolation": false}
}`))
	if got := extras.virtualizationCPUOffload(); got == nil || !*got {
		t.Errorf("virtualizationCPUOffload = %v, want true", got)
	}
	// Reported as false, which must stay false rather than null.
	if got := extras.virtualizationDeviceIsolation(); got == nil || *got {
		t.Errorf("virtualizationDeviceIsolation = %v, want false", got)
	}
	want := time.Date(2025, 3, 14, 0, 0, 0, 0, time.UTC)
	if got := parseRedfishTime(extras.ProductionDate); got == nil || !got.Equal(want) {
		t.Errorf("productionDate = %v, want %v", got, want)
	}
	if extras.Bios != nil {
		t.Errorf("Bios link = %+v, want none", extras.Bios)
	}
}

func TestParseSystemExtrasPartialVirtualization(t *testing.T) {
	// Synthetic: a Virtualization block that reports one capability only; no
	// target showed this.
	extras := parseSystemExtras([]byte(`{"Virtualization": {"CPUOffload": false}}`))
	if got := extras.virtualizationCPUOffload(); got == nil || *got {
		t.Errorf("virtualizationCPUOffload = %v, want false", got)
	}
	if got := extras.virtualizationDeviceIsolation(); got != nil {
		t.Errorf("virtualizationDeviceIsolation = %v, want null", *got)
	}
}

func TestParseSystemExtrasMalformed(t *testing.T) {
	// Synthetic: a document that does not decode leaves every field null.
	extras := parseSystemExtras([]byte(`{"Virtualization": "yes"}`))
	if extras.Virtualization != nil || extras.Bios != nil || extras.ProductionDate != "" {
		t.Errorf("parseSystemExtras(malformed) = %+v, want empty", extras)
	}
	if extras := parseSystemExtras(nil); extras.Virtualization != nil {
		t.Error("parseSystemExtras(nil) reported virtualization")
	}
}

func TestBiosPasswordsUnreported(t *testing.T) {
	// Measured: DMTF Redfish-Mockup-Server public-rackmount1 Bios document,
	// fetched 2026-11-23. It carries attributes but no Passwords block.
	var doc biosPasswordsJSON
	if err := json.Unmarshal([]byte(`{
  "@odata.id": "/redfish/v1/Systems/437XR1138R2/Bios",
  "AttributeRegistry": "BiosAttributeRegistryP89.v1_0_0",
  "Attributes": {"AdminPhone": "", "BootMode": "Uefi"}
}`), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.setupSet(); got != nil {
		t.Errorf("setupSet = %v, want null", *got)
	}
	if got := doc.bootSet(); got != nil {
		t.Errorf("bootSet = %v, want null", *got)
	}

	// No BIOS resource at all.
	var none *biosPasswordsJSON
	if none.setupSet() != nil || none.bootSet() != nil {
		t.Error("a missing BIOS resource reported a password state")
	}
}

func TestBiosPasswordsReported(t *testing.T) {
	// Synthetic: a Bios v1.3 document with a boot password but no setup
	// password, and one with a Setup entry that leaves out Set; no target
	// showed this.
	var doc biosPasswordsJSON
	if err := json.Unmarshal([]byte(`{"Passwords": {"Setup": {"Set": false}, "Boot": {"Set": true}}}`), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.setupSet(); got == nil || *got {
		t.Errorf("setupSet = %v, want false", got)
	}
	if got := doc.bootSet(); got == nil || !*got {
		t.Errorf("bootSet = %v, want true", got)
	}

	var partial biosPasswordsJSON
	if err := json.Unmarshal([]byte(`{"Passwords": {"Setup": {"Name": "Setup"}}}`), &partial); err != nil {
		t.Fatal(err)
	}
	if got := partial.setupSet(); got != nil {
		t.Errorf("setupSet without Set = %v, want null", *got)
	}
	if got := partial.bootSet(); got != nil {
		t.Errorf("bootSet without Boot = %v, want null", *got)
	}
}

func TestParseSoftwareArmed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want *bool
	}{
		// Measured: DMTF Redfish-Mockup-Server public-rackmount1
		// FirmwareInventory/BMC, fetched 2026-11-23. No Armed property.
		{"unreported", `{"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BMC", "Version": "1.45.455b66-rev4", "Updateable": true}`, nil},
		// Synthetic: SoftwareInventory v1.15 documents; no target showed this.
		{"armed", `{"Armed": true, "ImageState": "Armed"}`, new(true)},
		{"not armed", `{"Armed": false, "ImageState": "Active"}`, new(false)},
		{"malformed", `{"Armed": "yes"}`, nil},
		{"empty", ``, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSoftwareArmed([]byte(tt.raw))
			switch {
			case tt.want == nil && got != nil:
				t.Errorf("parseSoftwareArmed = %v, want null", *got)
			case tt.want != nil && (got == nil || *got != *tt.want):
				t.Errorf("parseSoftwareArmed = %v, want %v", got, *tt.want)
			}
		})
	}
}

// mockupHostInterface is the HostInterface document of the DMTF
// Redfish-Mockup-Server public-rackmount1 mockup, fetched 2026-11-23, trimmed
// to the properties the provider reads. It accepts AuthNone and keeps
// credential bootstrapping enabled with the Administrator role, and reports no
// expiration window and no firmware or kernel authentication.
const mockupHostInterface = `{
  "@odata.id": "/redfish/v1/Managers/BMC/HostInterfaces/1",
  "Name": "Host Interface",
  "HostInterfaceType": "NetworkHostInterface",
  "InterfaceEnabled": true,
  "ExternallyAccessible": false,
  "AuthenticationModes": ["AuthNone", "BasicAuth", "RedfishSessionAuth", "OemAuth"],
  "CredentialBootstrapping": {"RoleId": "Administrator", "Enabled": true, "EnableAfterReset": true}
}`

func TestHostInterfaceArgsMockup(t *testing.T) {
	// Measured: DMTF Redfish-Mockup-Server public-rackmount1, fetched
	// 2026-11-23.
	hi, err := parseHostInterface([]byte(mockupHostInterface))
	if err != nil {
		t.Fatal(err)
	}
	args := hostInterfaceArgs("/redfish/v1/Managers/BMC/HostInterfaces/1", hi)

	wantValues := map[string]any{
		"__id":                           "/redfish/v1/Managers/BMC/HostInterfaces/1",
		"name":                           "Host Interface",
		"hostInterfaceType":              "NetworkHostInterface",
		"interfaceEnabled":               true,
		"externallyAccessible":           false,
		"credentialBootstrappingEnabled": true,
		"credentialBootstrappingEnableAfterReset": true,
		"credentialBootstrappingRoleId":           "Administrator",
	}
	for field, want := range wantValues {
		if got := args[field]; got == nil || got.Value != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}

	// The mockup does not report these, so they may not read as switched off.
	for _, field := range []string{
		"authNoneRoleId", "firmwareAuthEnabled", "firmwareAuthRoleId", "kernelAuthEnabled", "kernelAuthRoleId",
		"credentialBootstrappingExpirationWindowEnabled", "credentialBootstrappingExpirationWindowMinutes",
	} {
		if got := args[field]; got != llx.NilData {
			t.Errorf("%s = %v, want null", field, got)
		}
	}

	modes, ok := args["authenticationModes"].Value.([]any)
	if !ok || args["authenticationModes"].Type != types.Array(types.String) {
		t.Fatalf("authenticationModes = %v, want a string list", args["authenticationModes"])
	}
	if len(modes) != 4 || modes[0] != "AuthNone" {
		t.Errorf("authenticationModes = %v, want AuthNone first of 4", modes)
	}
}

func TestHostInterfaceArgsExpirationWindow(t *testing.T) {
	// Synthetic: HostInterface v1.4 with an expiration window and no
	// AuthenticationModes property; no target showed this.
	hi, err := parseHostInterface([]byte(`{
  "InterfaceEnabled": false,
  "AuthNoneRoleId": "ReadOnly",
  "KernelAuthEnabled": false,
  "CredentialBootstrapping": {"Enabled": false, "ExpirationWindowEnabled": true, "ExpirationWindowMinutes": 0}
}`))
	if err != nil {
		t.Fatal(err)
	}
	args := hostInterfaceArgs("hi", hi)

	wantValues := map[string]any{
		"interfaceEnabled":                               false,
		"authNoneRoleId":                                 "ReadOnly",
		"kernelAuthEnabled":                              false,
		"credentialBootstrappingEnabled":                 false,
		"credentialBootstrappingExpirationWindowEnabled": true,
		// Zero is a window that closes at once, not an unreported one.
		"credentialBootstrappingExpirationWindowMinutes": int64(0),
	}
	for field, want := range wantValues {
		if got := args[field]; got == nil || got.Value != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	// No AuthenticationModes property may not read as accepting no mode.
	if got := args["authenticationModes"]; got != llx.NilData {
		t.Errorf("authenticationModes = %v, want null", got)
	}
}

func TestHostInterfaceArgsNoBootstrapping(t *testing.T) {
	// Synthetic: a HostInterface v1.0 document that predates credential
	// bootstrapping and lists no authentication mode; no target showed this.
	hi, err := parseHostInterface([]byte(`{"InterfaceEnabled": true, "AuthenticationModes": []}`))
	if err != nil {
		t.Fatal(err)
	}
	args := hostInterfaceArgs("hi", hi)
	for _, field := range []string{
		"credentialBootstrappingEnabled", "credentialBootstrappingEnableAfterReset", "credentialBootstrappingRoleId",
		"credentialBootstrappingExpirationWindowEnabled", "credentialBootstrappingExpirationWindowMinutes",
		"externallyAccessible", "hostInterfaceType",
	} {
		if got := args[field]; got != llx.NilData {
			t.Errorf("%s = %v, want null", field, got)
		}
	}
	// An empty list is reported, so it stays an empty list rather than null.
	if modes, ok := args["authenticationModes"].Value.([]any); !ok || len(modes) != 0 {
		t.Errorf("authenticationModes = %v, want an empty list", args["authenticationModes"])
	}
}

func TestParseHostInterfaceMalformed(t *testing.T) {
	if _, err := parseHostInterface([]byte(`{"InterfaceEnabled": "on"}`)); err == nil {
		t.Error("parseHostInterface(malformed) returned no error")
	}
}

func TestNonEmpty(t *testing.T) {
	if got := nonEmpty(""); got != nil {
		t.Errorf("nonEmpty(\"\") = %q, want nil", *got)
	}
	if got := nonEmpty("Active"); got == nil || *got != "Active" {
		t.Errorf("nonEmpty(\"Active\") = %v, want Active", got)
	}
}
