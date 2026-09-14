// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (r *mqlWindowsDriver) id() (string, error) {
	// The SCM keys a driver by its service name, which is unique per machine.
	return r.Name.Data, nil
}

// file resolves the driver image so that permission and ownership checks reach
// it. The image is deliberately resolved whether or not it exists on disk: a
// driver whose image was deleted still holds its service entry, and callers
// need `exists` to report that rather than the whole field going null.
func (r *mqlWindowsDriver) file(path string) (*mqlFile, error) {
	if path == "" {
		// Nothing to point at. The state has to be set explicitly, or the
		// runtime does not know the field resolved and may re-fetch it.
		r.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	f, err := NewResource(r.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (r *mqlWindowsDrivers) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand(powershell.Encode(windows.DriversScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve drivers: " + string(stderr))
	}

	drivers, err := windows.ParseDrivers(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(drivers))
	for _, d := range drivers {
		res, err := CreateResource(r.MqlRuntime, "windows.driver", map[string]*llx.RawData{
			"name":         llx.StringData(d.Name),
			"displayName":  llx.StringData(d.DisplayName),
			"description":  llx.StringData(d.Description),
			"path":         llx.StringData(d.Path),
			"serviceType":  llx.StringData(d.ServiceType),
			"startMode":    llx.StringData(d.StartMode),
			"running":      llx.BoolData(d.Started),
			"version":      llx.StringData(d.Version),
			"manufacturer": llx.StringData(d.Manufacturer),
			// Signed is deliberately a pointer: a driver whose image could not
			// be read has no verdict, and llx.BoolDataPtr preserves that as
			// null rather than reporting the driver as unsigned.
			"signed": llx.BoolDataPtr(d.Signed),
			"signer": llx.StringData(windows.SignerCommonName(d.Signer)),
			"purl":   llx.StringData(d.Purl()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
