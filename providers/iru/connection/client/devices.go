// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"encoding/json"
	"net/url"
)

// Device is the summary row returned by GET /v1/devices (and the identical
// GET /v1/devices/{id}). Booleans here are real JSON booleans, unlike the
// device detail endpoint which serializes them as strings.
type Device struct {
	DeviceID        string          `json:"device_id"`
	DeviceName      string          `json:"device_name"`
	Model           string          `json:"model"`
	SerialNumber    string          `json:"serial_number"`
	UDID            string          `json:"udid"`
	Platform        string          `json:"platform"`
	OSVersion       string          `json:"os_version"`
	LastCheckIn     string          `json:"last_check_in"`
	User            json.RawMessage `json:"user,omitempty"`
	AssetTag        string          `json:"asset_tag"`
	BlueprintID     string          `json:"blueprint_id"`
	BlueprintName   string          `json:"blueprint_name"`
	MDMEnabled      bool            `json:"mdm_enabled"`
	AgentInstalled  bool            `json:"agent_installed"`
	AgentVersion    string          `json:"agent_version"`
	IsMissing       bool            `json:"is_missing"`
	IsRemoved       bool            `json:"is_removed"`
	FirstEnrollment string          `json:"first_enrollment"`
	LastEnrollment  string          `json:"last_enrollment"`
	LostModeStatus  string          `json:"lost_mode_status"`
	Tags            []string        `json:"tags"`
}

// DeviceDetails is the nested response from GET /v1/devices/{id}/details.
// Only the subsections we surface as typed fields are modeled. The API
// returns several booleans as the strings "True"/"False" and several
// numbers as strings, so those fields are typed `string` here and parsed
// in the resource layer.
type DeviceDetails struct {
	General           DeviceDetailsGeneral   `json:"general"`
	MDM               DeviceDetailsMDM       `json:"mdm"`
	ActivationLock    DeviceDetailsActLock   `json:"activation_lock"`
	FileVault         DeviceDetailsFileVault `json:"filevault"`
	HardwareOverview  DeviceDetailsHardware  `json:"hardware_overview"`
	SecurityInfo      DeviceDetailsSecurity  `json:"security_information"`
	Network           DeviceDetailsNetwork   `json:"network"`
	Recovery          DeviceDetailsRecovery  `json:"recovery_information"`
	Volumes           []DeviceDetailsVolume  `json:"volumes"`
	InstalledProfiles []DeviceDetailsProfile `json:"installed_profiles"`
}

type DeviceDetailsGeneral struct {
	SystemVersion   string `json:"system_version"`
	BootVolume      string `json:"boot_volume"`
	LastUser        string `json:"last_user"`
	TimeSinceBoot   string `json:"time_since_boot"`
	FirstEnrollment string `json:"first_enrollment"`
	LastEnrollment  string `json:"last_enrollment"`
}

// DeviceDetailsMDM carries string-typed booleans ("True"/"False").
type DeviceDetailsMDM struct {
	MDMEnabled  string `json:"mdm_enabled"`
	Supervised  string `json:"supervised"`
	InstallDate string `json:"install_date"`
	LastCheckIn string `json:"last_check_in"`
}

type DeviceDetailsActLock struct {
	UserEnabled            bool `json:"user_activation_lock_enabled"`
	DeviceEnabled          bool `json:"device_activation_lock_enabled"`
	Supported              bool `json:"activation_lock_supported"`
	AllowedWhileSupervised bool `json:"activation_lock_allowed_while_supervised"`
	BypassCodeFailed       bool `json:"bypass_code_failed"`
}

type DeviceDetailsFileVault struct {
	Enabled         bool   `json:"filevault_enabled"`
	PRKEscrowed     bool   `json:"filevault_prk_escrowed"`
	RecoveryKeyType string `json:"filevault_recoverykey_type"`
	NextRotation    string `json:"filevault_next_rotation"`
	RegenRequired   bool   `json:"filevault_regen_required"`
}

// DeviceDetailsHardware carries a string-typed core count and a
// human-readable memory string ("32 GB LPDDR5"), matching the API.
type DeviceDetailsHardware struct {
	ModelName          string `json:"model_name"`
	ModelIdentifier    string `json:"model_identifier"`
	ProcessorName      string `json:"processor_name"`
	ProcessorSpeed     string `json:"processor_speed"`
	NumberOfProcessors string `json:"number_of_processors"`
	TotalNumberOfCores string `json:"total_number_of_cores"`
	Memory             string `json:"memory"`
	BatteryHealth      string `json:"battery_health"`
	SerialNumber       string `json:"serial_number"`
	UDID               string `json:"udid"`
}

// DeviceDetailsSecurity is sparse in the Iru API: across the fleet the only
// field reliably present is remote_desktop_enabled. The richer posture
// controls (Gatekeeper, SIP, firewall, …) are not exposed here; they live
// in the compliance parameters (GET /v1/devices/{id}/parameters).
type DeviceDetailsSecurity struct {
	RemoteDesktopEnabled bool `json:"remote_desktop_enabled"`
}

type DeviceDetailsNetwork struct {
	IPAddress     string `json:"ip_address"`
	PublicIP      string `json:"public_ip"`
	LocalHostname string `json:"local_hostname"`
	MACAddress    string `json:"mac_address"`
}

type DeviceDetailsRecovery struct {
	RecoveryLockEnabled     bool `json:"recovery_lock_enabled"`
	FirmwarePasswordExists  bool `json:"firmware_password_exist"`
	FirmwarePasswordPending bool `json:"firmware_password_pending"`
	PasswordHasBeenSet      bool `json:"password_has_been_set"`
}

// DeviceDetailsVolume carries string-typed capacity/availability values
// ("926.3 GB") and a string-typed encryption flag ("Yes"/"No").
type DeviceDetailsVolume struct {
	Name        string `json:"name"`
	Format      string `json:"format"`
	Identifier  string `json:"identifier"`
	Capacity    string `json:"capacity"`
	Available   string `json:"available"`
	PercentUsed string `json:"percent_used"`
	Encrypted   string `json:"encrypted"`
}

type DeviceDetailsProfile struct {
	Name         string   `json:"name"`
	UUID         string   `json:"uuid"`
	Identifier   string   `json:"identifier"`
	Organization string   `json:"organization"`
	Verified     string   `json:"verified"`
	InstallDate  string   `json:"install_date"`
	PayloadTypes []string `json:"payload_types"`
}

// App is one row from GET /v1/devices/{id}/apps.
type App struct {
	AppID            string `json:"app_id"`
	Name             string `json:"app_name"`
	BundleID         string `json:"bundle_id"`
	Version          string `json:"version"`
	BundleSize       string `json:"bundle_size"`
	Source           string `json:"source"`
	Process          string `json:"process"`
	Signature        string `json:"signature"`
	Path             string `json:"path"`
	CreationDate     string `json:"creation_date"`
	ModificationDate string `json:"modification_date"`
}

// Parameter is one compliance control reported for a device by
// GET /v1/devices/{id}/parameters. Status is one of PASS, WARNING, ERROR,
// REMEDIATED, MUTED, and similar values.
type Parameter struct {
	ItemID      string `json:"item_id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Subcategory string `json:"subcategory"`
	Status      string `json:"status"`
}

// EmbeddedUser returns the user object embedded on a device row, or nil
// when the device has no assigned user. The API is inconsistent here: an
// unassigned device returns an empty string for `user` rather than null or
// an object, so a bare `*User` cannot decode it.
func (d *Device) EmbeddedUser() *User {
	if len(d.User) == 0 || d.User[0] != '{' {
		return nil
	}
	var u User
	if err := json.Unmarshal(d.User, &u); err != nil {
		return nil
	}
	return &u
}

// ListDevices walks /v1/devices (bare array, limit/offset paging).
func (c *Client) ListDevices() ([]Device, error) {
	var all []Device
	err := c.paginateArray("/api/v1/devices", func(raw json.RawMessage) (int, error) {
		var page []Device
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, err
		}
		all = append(all, page...)
		return len(page), nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// GetDeviceDetails fetches /v1/devices/{id}/details.
func (c *Client) GetDeviceDetails(id string) (*DeviceDetails, error) {
	var out DeviceDetails
	if err := c.do("/api/v1/devices/"+url.PathEscape(id)+"/details", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetDeviceApps fetches /v1/devices/{id}/apps, which returns
// {"device_id": "...", "apps": [...]}.
func (c *Client) GetDeviceApps(id string) ([]App, error) {
	var out struct {
		Apps []App `json:"apps"`
	}
	if err := c.do("/api/v1/devices/"+url.PathEscape(id)+"/apps", nil, &out); err != nil {
		return nil, err
	}
	return out.Apps, nil
}

// GetDeviceParameters fetches /v1/devices/{id}/parameters, which returns
// {"device_id": "...", "parameters": [...]}.
func (c *Client) GetDeviceParameters(id string) ([]Parameter, error) {
	var out struct {
		Parameters []Parameter `json:"parameters"`
	}
	if err := c.do("/api/v1/devices/"+url.PathEscape(id)+"/parameters", nil, &out); err != nil {
		return nil, err
	}
	return out.Parameters, nil
}
