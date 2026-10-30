// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ipmi/connection"
)

func (r *mqlIpmi) id() (string, error) {
	return "ipmi", nil
}

func (r *mqlIpmi) guid() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	return conn.Guid()
}

func (r *mqlIpmi) deviceID() (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	client := conn.Client()

	resp, err := client.DeviceID()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(resp)
}

func (r *mqlIpmiChassis) id() (string, error) {
	return "ipmi.chassis", nil
}

func (r *mqlIpmiChassis) status() (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	client := conn.Client()

	resp, err := client.ChassisStatus()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(resp)
}

func (r *mqlIpmiChassis) systemBootOptions() (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	client := conn.Client()

	resp, err := client.ChassisSystemBootOptions()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(resp)
}
