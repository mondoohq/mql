// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package smbios

import (
	"runtime"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
)

// native WMI on local Windows; PowerShell otherwise or on failure
func fetchWindowsSmbios(conn shared.Connection) (smbiosWindows, error) {
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		winBios, err := nativeWindowsSmbios()
		if err == nil {
			return winBios, nil
		}
		log.Debug().Err(err).Msg("could not query smbios via WMI, falling back to PowerShell")
	}
	return fetchWindowsSmbiosPowershell(conn)
}

func nativeWindowsSmbios() (out smbiosWindows, err error) {
	bios, err := wmiquery.Query("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_Bios",
		"Manufacturer", "SMBIOSBIOSVersion", "ReleaseDate", "SerialNumber")
	if err != nil {
		return out, err
	}
	if len(bios) > 0 {
		out.Bios = smbiosWinBios{
			Manufacturer:      bios[0].String("Manufacturer"),
			SMBIOSBIOSVersion: bios[0].String("SMBIOSBIOSVersion"),
			SerialNumber:      bios[0].String("SerialNumber"),
		}
		if releaseDate, ok := bios[0].Time("ReleaseDate"); ok {
			out.Bios.ReleaseDate = releaseDate.Format(time.RFC3339)
		}
	}

	baseboard, err := wmiquery.Query("SELECT Manufacturer, Product, Version, SerialNumber FROM Win32_BaseBoard",
		"Manufacturer", "Product", "Version", "SerialNumber")
	if err != nil {
		return out, err
	}
	if len(baseboard) > 0 {
		out.BaseBoard = smbiosBaseBoard{
			Manufacturer: baseboard[0].String("Manufacturer"),
			Product:      baseboard[0].String("Product"),
			Version:      baseboard[0].String("Version"),
			SerialNumber: baseboard[0].String("SerialNumber"),
		}
	}

	chassis, err := wmiquery.Query("SELECT Manufacturer, Model, ChassisTypes, Version, SerialNumber, SMBIOSAssetTag FROM Win32_SystemEnclosure",
		"Manufacturer", "Model", "ChassisTypes", "Version", "SerialNumber", "SMBIOSAssetTag")
	if err != nil {
		return out, err
	}
	for _, ch := range chassis {
		// ChassisTypes arrives as an array of VT_I4, whatever its documented
		// uint16 type says; Int64s reads either.
		chassisTypes, _ := ch.Int64s("ChassisTypes")
		types := make([]string, 0, len(chassisTypes))
		for _, t := range chassisTypes {
			types = append(types, strconv.FormatInt(t, 10))
		}
		out.Chassis = append(out.Chassis, smbiosChassis{
			Manufacturer:   ch.String("Manufacturer"),
			Model:          ch.StringPtr("Model"),
			ChassisTypes:   &smbiosChassisTypes{ChassisTypes: types},
			Version:        ch.String("Version"),
			SerialNumber:   ch.String("SerialNumber"),
			SMBIOSAssetTag: ch.String("SMBIOSAssetTag"),
		})
	}

	product, err := wmiquery.Query("SELECT Vendor, Name, Version, SKUNumber, UUID, IdentifyingNumber FROM Win32_ComputerSystemProduct",
		"Vendor", "Name", "Version", "SKUNumber", "UUID", "IdentifyingNumber")
	if err != nil {
		return out, err
	}
	if len(product) > 0 {
		out.SystemProduct = smbiosSystemProduct{
			Vendor:            product[0].String("Vendor"),
			Name:              product[0].String("Name"),
			Version:           product[0].String("Version"),
			SKUNumber:         product[0].String("SKUNumber"),
			UUID:              product[0].String("UUID"),
			IdentifyingNumber: product[0].String("IdentifyingNumber"),
		}
	}

	return out, nil
}
