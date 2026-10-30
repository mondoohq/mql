// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

const wmiMachineIDQuery = "SELECT UUID FROM Win32_ComputerSystemProduct"

func PowershellWindowsMachineId(conn shared.Connection) (string, error) {
	cmd, err := conn.RunCommand("powershell -c \"Get-WmiObject -Query '" + wmiMachineIDQuery + "' | Select-Object -ExpandProperty UUID\"")
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}
	// PowerShell terminates its output with CRLF. Without trimming it the
	// machine id carries the line ending into every comparison, and into the
	// asset identifier built from it in id/platform.go, which then reads
	// "//platformid.api.mondoo.app/machineid/<uuid>\r\n". The linux and darwin
	// providers already trim. Case is deliberately left alone: WMI reports the
	// UUID in upper case, and lowering it here would change the identifier for
	// every Windows asset already scanned.
	return strings.TrimSpace(string(data)), nil
}

type WinIdProvider struct {
	connection shared.Connection
}

func (p *WinIdProvider) Name() string {
	return "Windows Machine ID"
}

func (p *WinIdProvider) ID() (string, error) {
	return windowsMachineId(p.connection)
}
