// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const smbiosWindowsScript = `
$bios = Get-CimInstance -ClassName Win32_Bios
$baseboard = Get-CimInstance -ClassName Win32_BaseBoard
$chassis = @(Get-CimInstance -ClassName Win32_SystemEnclosure)
$sys = Get-CimInstance -ClassName Win32_ComputerSystem
$sysProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct

$smbios = New-Object -TypeName PSObject
$smbios | Add-Member -MemberType NoteProperty -Value $bios -Name Bios
$smbios | Add-Member -MemberType NoteProperty -Value $baseboard -Name BaseBoard
$smbios | Add-Member -MemberType NoteProperty -Value $chassis -Name Chassis
$smbios | Add-Member -MemberType NoteProperty -Value $sys -Name System
$smbios | Add-Member -MemberType NoteProperty -Value $sysProduct -Name SystemProduct

$smbios | ConvertTo-Json
`

type smbiosWindows struct {
	Bios          smbiosWinBios       `json:"Bios"`
	BaseBoard     smbiosBaseBoard     `json:"BaseBoard"`
	Chassis       []smbiosChassis     `json:"Chassis"`
	System        smbiosSystem        `json:"System"`
	SystemProduct smbiosSystemProduct `json:"SystemProduct"`
}

type smbiosWinBios struct {
	Manufacturer      string `json:"Manufacturer"`
	SMBIOSBIOSVersion string `json:"SMBIOSBIOSVersion"`
	ReleaseDate       string `json:"ReleaseDate"`
	SerialNumber      string `json:"SerialNumber"`
}

type smbiosBaseBoard struct {
	Manufacturer string `json:"Manufacturer"`
	Product      string `json:"Product"`
	Version      string `json:"Version"`
	SerialNumber string `json:"SerialNumber"`
}

type smbiosChassis struct {
	Manufacturer string  `json:"Manufacturer"`
	Model        *string `json:"Model"`

	ChassisTypes *smbiosChassisTypes `json:"ChassisTypes"`

	Version        string `json:"Version"`
	SerialNumber   string `json:"SerialNumber"`
	SMBIOSAssetTag string `json:"SMBIOSAssetTag"`
}

func (s smbiosChassis) GetChassisTypes() *smbiosChassisTypes {
	if s.ChassisTypes == nil {
		return &smbiosChassisTypes{}
	}

	return s.ChassisTypes
}

type smbiosChassisTypes struct {
	ChassisTypes []string
}

func (t *smbiosChassisTypes) Value() []string {
	if len(t.ChassisTypes) == 0 {
		return []string{""}
	}
	return t.ChassisTypes
}

func (t *smbiosChassisTypes) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	var handleValue func(value any)
	handleValue = func(value any) {
		switch v := value.(type) {
		case []any:
			for _, val := range v {
				handleValue(val)
			}
		case string:
			t.ChassisTypes = append(t.ChassisTypes, v)
		case int:
			t.ChassisTypes = append(t.ChassisTypes, strconv.Itoa(v))
		case float64:
			t.ChassisTypes = append(t.ChassisTypes, strconv.Itoa(int(v)))
		case nil:
			t.ChassisTypes = append(t.ChassisTypes, "")
		default:
			return
		}
	}

	handleValue(value)

	return nil
}

type smbiosSystem struct{}

type smbiosSystemProduct struct {
	Vendor            string `json:"Vendor"`
	Name              string `json:"Name"`
	Version           string `json:"Version"`
	SKUNumber         string `json:"SKUNumber"`
	UUID              string `json:"UUID"`
	IdentifyingNumber string `json:"IdentifyingNumber"`
}

// see https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/sample-powershell-script-to-query-smbios-locally
// https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/smbios
type WindowsSmbiosManager struct {
	provider shared.Connection
}

func (s *WindowsSmbiosManager) Name() string {
	return "Windows Smbios Manager"
}

func (s *WindowsSmbiosManager) Info() (*SmBiosInfo, error) {
	winBios, err := fetchWindowsSmbios(s.provider)
	if err != nil {
		return nil, err
	}

	if len(winBios.Chassis) == 0 {
		winBios.Chassis = append(winBios.Chassis, smbiosChassis{})
	}

	smInfo := SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      winBios.Bios.Manufacturer,
			Version:     winBios.Bios.SMBIOSBIOSVersion,
			ReleaseDate: winBios.Bios.ReleaseDate,
		},
		SysInfo: SysInfo{
			Vendor:  winBios.SystemProduct.Vendor,
			Model:   winBios.SystemProduct.Name,
			Version: winBios.SystemProduct.Version,
			SKU:     winBios.SystemProduct.SKUNumber,
			UUID:    winBios.SystemProduct.UUID,
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       winBios.BaseBoard.Manufacturer,
			Model:        winBios.BaseBoard.Product,
			SerialNumber: winBios.BaseBoard.SerialNumber,
			Version:      winBios.BaseBoard.Version,
		},
		ChassisInfo: ChassisInfo{ // TODO: Might want to make this a slice
			Vendor:       winBios.Chassis[0].Manufacturer,
			Model:        toString(winBios.Chassis[0].Model),
			Version:      winBios.Chassis[0].Version,
			SerialNumber: winBios.Chassis[0].SerialNumber,
			Type:         winBios.Chassis[0].GetChassisTypes().Value()[0],
		},
	}

	return &smInfo, nil
}

func toString(i *string) string {
	if i == nil {
		return ""
	}
	return *i
}

// remote path, and fallback for the local native path
func fetchWindowsSmbiosPowershell(conn shared.Connection) (smbiosWindows, error) {
	var winBios smbiosWindows

	c, err := conn.RunCommand(powershell.Encode(smbiosWindowsScript))
	if err != nil {
		return winBios, err
	}

	if c.ExitStatus != 0 {
		stderr, err := io.ReadAll(c.Stderr)
		if err != nil {
			return winBios, err
		}
		return winBios, errors.New("failed to retrieve smbios info: " + string(stderr))
	}

	return ParseWindowsSmbiosInfo(c.Stdout)
}

func ParseWindowsSmbiosInfo(r io.Reader) (smbiosWindows, error) {
	var smbios smbiosWindows
	data, err := io.ReadAll(r)
	if err != nil {
		return smbios, err
	}

	err = json.Unmarshal(data, &smbios)
	if err != nil {
		return smbios, err
	}

	return smbios, nil
}
