// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/google/uuid"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (u *mqlUuid) id() (string, error) {
	return "uuid:" + u.Value.Data, nil
}

func initUuid(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["value"]; ok {
		value, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'value' in uuid initialization, it must be a string")
		}

		// ensure the value is a proper uuid
		u, err := uuid.Parse(value)
		if err != nil {
			return nil, nil, errors.New("invalid uuid: " + value)
		}

		args["value"] = llx.StringData(u.String())
	}

	return args, nil, nil
}

func (u *mqlUuid) parse() error {
	x, err := uuid.Parse(u.Value.Data)
	if err != nil {
		u.Urn = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		u.Version = plugin.TValue[int64]{Error: err, State: plugin.StateIsSet}
		u.Variant = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		return err
	}

	u.Urn = plugin.TValue[string]{Data: x.URN(), State: plugin.StateIsSet}
	u.Version = plugin.TValue[int64]{Data: int64(x.Version()), State: plugin.StateIsSet}
	u.Variant = plugin.TValue[string]{Data: x.Variant().String(), State: plugin.StateIsSet}
	return nil
}

func (u *mqlUuid) urn() (string, error) {
	return "", u.parse()
}

func (u *mqlUuid) version() (int64, error) {
	return 0, u.parse()
}

func (u *mqlUuid) variant() (string, error) {
	return "", u.parse()
}
