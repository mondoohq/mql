// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (r *mqlWindowsPrinterDriver) id() (string, error) {
	// The spooler keys drivers by name within an environment, and the same
	// driver can be registered for both x64 and x86, so the pair is the
	// identity rather than the name alone.
	return r.Name.Data + "/" + r.Environment.Data, nil
}

func (r *mqlWindowsPrinterDrivers) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand(powershell.Encode(windows.PrinterDriversScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve printer drivers: " + string(stderr))
	}

	drivers, err := windows.ParsePrinterDrivers(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(drivers))
	for _, d := range drivers {
		res, err := CreateResource(r.MqlRuntime, "windows.printerDriver", map[string]*llx.RawData{
			"name":           llx.StringData(d.Name),
			"purl":           llx.StringData(d.Purl()),
			"hardwareId":     llx.StringData(d.HardwareID),
			"version":        llx.StringData(d.DottedVersion()),
			"modelVersion":   llx.IntData(d.MajorVersion),
			"manufacturer":   llx.StringData(d.Manufacturer),
			"environment":    llx.StringData(d.PrinterEnvironment),
			"infPath":        llx.StringData(d.InfPath),
			"driverPath":     llx.StringData(d.DriverPath),
			"configFile":     llx.StringData(d.ConfigFile),
			"dataFile":       llx.StringData(d.DataFile),
			"printProcessor": llx.StringData(d.PrintProcessor),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
