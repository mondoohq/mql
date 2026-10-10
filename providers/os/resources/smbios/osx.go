// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"bytes"
	"io"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	plist "howett.net/plist"
)

// We use the ioreg implementation to get native access. Its preferred
// over system_profiler since its much faster
//
// hardware info
// ioreg -rw0 -d2 -c IOPlatformExpertDevice -a
//
// acpi info:
// ioreg -rw0 -d1 -c AppleACPIPlatformExpert
//
// get the rom version:
// ioreg -r -p IODeviceTree -n rom@0
//
// helpful mac commands:
// https://github.com/erikberglund/Scripts/blob/master/snippets/macos_hardware.md
//
// results can be compared with dmidecode
// https://hotsrc.dev/blog/dmidecode-for-apple-osx.html
type OSXSmbiosManager struct {
	provider shared.Connection
	platform *inventory.Platform
}

func (s *OSXSmbiosManager) Name() string {
	return "macOS Smbios Manager"
}

func (s *OSXSmbiosManager) Info() (*SmBiosInfo, error) {
	smInfo := SmBiosInfo{}

	cmd, err := s.provider.RunCommand("ioreg -rw0 -d2 -c IOPlatformExpertDevice -a")
	if err != nil {
		return nil, err
	}

	hw, err := ParseMacosIOPlatformExpertDevice(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	smInfo.SysInfo.Vendor = plistData(hw.Manufacturer)
	smInfo.SysInfo.Model = plistData(hw.Model)
	smInfo.SysInfo.Version = plistData(hw.Version)
	smInfo.SysInfo.SerialNumber = hw.IOPlatformSerialNumber
	smInfo.SysInfo.UUID = hw.IOPlatformUUID

	smInfo.BaseBoardInfo.Vendor = plistData(hw.Manufacturer)
	smInfo.BaseBoardInfo.Model = plistData(hw.BoardID)
	smInfo.BaseBoardInfo.Version = ""
	smInfo.BaseBoardInfo.SerialNumber = hw.IOPlatformSerialNumber

	smInfo.ChassisInfo.Vendor = plistData(hw.Manufacturer)
	smInfo.ChassisInfo.Version = plistData(hw.BoardID)
	smInfo.ChassisInfo.SerialNumber = hw.IOPlatformSerialNumber
	smInfo.ChassisInfo.Type = "Laptop"

	cmd, err = s.provider.RunCommand("ioreg -r -p IODeviceTree -n rom@0 -a")
	if err != nil {
		return nil, err
	}

	// TODO: this does not work on m1 macs yet, we need to find a way to gather that information
	if s.platform.Arch == "x86_64" {
		bios, err := ParseMacosBios(cmd.Stdout)
		if err != nil {
			return nil, err
		}
		smInfo.BIOS.ReleaseDate = plistData(bios.ReleaseDate)
		smInfo.BIOS.Vendor = plistData(bios.Vendor)
		smInfo.BIOS.Version = plistData(bios.Version)
	}

	return &smInfo, nil
}

func plistData(data []byte) string {
	return string(bytes.Trim(data, "\x00"))
}

type IOPlatformExpertDevice struct {
	IORegistryEntryName    string `plist:"IORegistryEntryName"`
	BoardID                []byte `plist:"board-id"`
	Manufacturer           []byte `plist:"manufacturer"`
	Model                  []byte `plist:"model"`
	SerialNumber           []byte `plist:"serial-number"`
	IOPlatformUUID         string `plist:"IOPlatformUUID"`
	IOPlatformSerialNumber string `plist:"IOPlatformSerialNumber"`
	ProductName            []byte `plist:"product-name"`
	Version                []byte `plist:"version"`
}

func ParseMacosIOPlatformExpertDevice(input io.Reader) (*IOPlatformExpertDevice, error) {
	var r io.ReadSeeker
	r, ok := input.(io.ReadSeeker)

	// if the read seeker is not implemented lets cache stdout in-memory
	if !ok {
		entries, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		r = strings.NewReader(string(entries))
	}

	var data []IOPlatformExpertDevice
	decoder := plist.NewDecoder(r)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data[0], nil
}

type IODeviceTree struct {
	Vendor      []byte `plist:"vendor"`
	ReleaseDate []byte `plist:"release-date"`
	Version     []byte `plist:"version"`
}

func ParseMacosBios(input io.Reader) (*IODeviceTree, error) {
	var r io.ReadSeeker
	r, ok := input.(io.ReadSeeker)

	// if the read seeker is not implemented lets cache stdout in-memory
	if !ok {
		entries, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		r = strings.NewReader(string(entries))
	}

	var data []IODeviceTree
	decoder := plist.NewDecoder(r)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data[0], nil
}
