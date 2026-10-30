// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"regexp"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

// validAixDeviceName matches a device name as the ODM holds it (sys0, en0,
// hdisk1, ipsec_v4); anything else is rejected before it reaches a command.
var validAixDeviceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]*$`)

func initAixDevice(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	raw := args["name"]
	if raw == nil {
		return nil, nil, fmt.Errorf("aix.device requires a name")
	}
	name, ok := raw.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("aix.device name must be a string")
	}
	if !validAixDeviceName.MatchString(name) {
		return nil, nil, fmt.Errorf("aix.device name %q is not a device name", name)
	}
	return args, nil, nil
}

func (d *mqlAixDevice) id() (string, error) {
	return "aix.device/" + d.Name.Data, nil
}

func (d *mqlAixDevice) attributes() (map[string]any, error) {
	if err := requireAix(d.MqlRuntime, "aix.device"); err != nil {
		return nil, err
	}
	out, _, err := runAixCommand(d.MqlRuntime, `lsattr -El `+d.Name.Data+` -F "attribute value"`)
	if err != nil {
		return nil, err
	}
	return aix.StringMap(aix.ParseLsattr(out)), nil
}
