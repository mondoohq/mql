// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package platformid

import (
	"errors"
	"runtime"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
)

func windowsMachineId(conn shared.Connection) (string, error) {
	// if we are running locally on windows, we want to avoid using powershell to be faster
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		// on an error, or a panic in WMI, fall back to PowerShell instead of
		// failing the platform ID
		entries, err := wmiquery.Query(wmiMachineIDQuery, "UUID")
		if err != nil {
			log.Debug().Err(err).Msg("could not query the machine UUID via WMI, falling back to PowerShell")
			return PowershellWindowsMachineId(conn)
		}

		if len(entries) != 1 || entries[0].StringPtr("UUID") == nil {
			return "", errors.New("could not query machine id on windows")
		}

		return entries[0].String("UUID"), nil
	}

	return PowershellWindowsMachineId(conn)
}
