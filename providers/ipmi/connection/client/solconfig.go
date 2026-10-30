// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"encoding/binary"
	"fmt"
)

// Serial-over-LAN configuration parameter selectors (§26.4).
const (
	solParamEnable         uint8 = 1
	solParamAuthentication uint8 = 2
	solParamPayloadPort    uint8 = 8
)

// SOLConfig is the Serial-over-LAN configuration of one channel. As with the
// LAN parameters, each block is nil when its parameter was not answered.
type SOLConfig struct {
	ChannelID int64

	// Enabled is nil when parameter 1 was not answered.
	Enabled *bool
	// Authentication is nil when parameter 2 was not answered.
	Authentication *SOLAuthentication
	// PayloadPort is nil when parameter 8 was not answered.
	PayloadPort *int64
}

// SOLAuthentication holds the protection settings of the Serial-over-LAN
// payload (§26.4, parameter 2).
type SOLAuthentication struct {
	ForceEncryption     bool
	ForceAuthentication bool
	PrivilegeLevel      string
}

// SOLConfig reads the Serial-over-LAN configuration of one channel.
func (c *IpmiClient) SOLConfig(channel uint8) (*SOLConfig, error) {
	info, err := c.ChannelInfo(channel)
	if err != nil {
		return nil, err
	}

	cfg := &SOLConfig{ChannelID: info.ID}
	answered := false

	if data, err := c.solConfigParam(channel, solParamEnable); err == nil {
		if enabled, err := decodeSOLEnable(data); err == nil {
			cfg.Enabled = enabled
			answered = true
		}
	}

	if data, err := c.solConfigParam(channel, solParamAuthentication); err == nil {
		if auth, err := decodeSOLAuthentication(data); err == nil {
			cfg.Authentication = auth
			answered = true
		}
	}

	if data, err := c.solConfigParam(channel, solParamPayloadPort); err == nil {
		if port, err := decodeSOLPayloadPort(data); err == nil {
			cfg.PayloadPort = port
			answered = true
		}
	}

	if !answered {
		return nil, fmt.Errorf("ipmi: controller answered none of the Serial-over-LAN configuration parameters for channel %d", info.ID)
	}
	return cfg, nil
}

// solConfigParam runs Get SOL Configuration Parameters (§26.3) for one
// parameter and returns the parameter data with the revision byte stripped.
func (c *IpmiClient) solConfigParam(channel uint8, param uint8) ([]byte, error) {
	data, err := c.sendRaw(networkFunctionTransport, commandGetSOLConfigParam, []byte{channel & 0x0f, param, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("ipmi: empty Serial-over-LAN configuration parameter %d response", param)
	}
	return data[1:], nil
}

func decodeSOLEnable(data []byte) (*bool, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("ipmi: short Serial-over-LAN enable parameter, expected at least 1 byte, got %d", len(data))
	}
	enabled := data[0]&0x01 != 0
	return &enabled, nil
}

func decodeSOLAuthentication(data []byte) (*SOLAuthentication, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("ipmi: short Serial-over-LAN authentication parameter, expected at least 1 byte, got %d", len(data))
	}
	return &SOLAuthentication{
		ForceEncryption:     data[0]&0x80 != 0,
		ForceAuthentication: data[0]&0x40 != 0,
		PrivilegeLevel:      decodePrivilegeLevel(data[0] & 0x0f),
	}, nil
}

func decodeSOLPayloadPort(data []byte) (*int64, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ipmi: short Serial-over-LAN payload port parameter, expected at least 2 bytes, got %d", len(data))
	}
	port := int64(binary.LittleEndian.Uint16(data[0:2]))
	return &port, nil
}
