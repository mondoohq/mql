// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"errors"

	ipmiTransport "github.com/vmware/goipmi"
)

// Network function codes the vendored transport does not declare (IPMI 2.0
// §5.1). NetworkFunctionApp (0x06) and NetworkFunctionChassis (0x00) come
// from the transport itself.
const (
	networkFunctionStorage   = ipmiTransport.NetworkFunction(0x0a)
	networkFunctionTransport = ipmiTransport.NetworkFunction(0x0c)
)

// Command numbers per IPMI 2.0 table G-1. CommandGetAuthCapabilities (0x38)
// and CommandGetUserName (0x46) come from the transport itself.
const (
	commandGetLanConfigParam   = ipmiTransport.Command(0x02)
	commandGetSOLConfigParam   = ipmiTransport.Command(0x22)
	commandGetWatchdogTimer    = ipmiTransport.Command(0x25)
	commandGetBMCGlobalEnables = ipmiTransport.Command(0x2f)
	commandGetSELInfo          = ipmiTransport.Command(0x40)
	commandGetChannelAccess    = ipmiTransport.Command(0x41)
	commandGetChannelInfo      = ipmiTransport.Command(0x42)
	commandGetUserAccess       = ipmiTransport.Command(0x44)
)

// ChannelSelf addresses the channel the current session is running over
// (IPMI 2.0 §6.3). A controller answers it with the settings of whichever
// channel the request arrived on, so it reaches the LAN channel this
// provider connects through without having to discover its number first.
const ChannelSelf uint8 = 0x0e

// rawResponse accepts any completion-coded response without imposing a
// length on it. Response payload lengths vary between controllers even for
// the same command (a v1.5-only controller returns a shorter Get Channel
// Authentication Capabilities response than a v2.0 one), so every decoder
// checks the length it needs for itself rather than failing the whole
// response here.
type rawResponse struct {
	ipmiTransport.CompletionCode
	Data []byte
}

func (r *rawResponse) UnmarshalBinary(buf []byte) error {
	if len(buf) == 0 {
		return errors.New("ipmi: empty response")
	}
	r.CompletionCode = ipmiTransport.CompletionCode(buf[0])
	r.Data = append([]byte(nil), buf[1:]...)
	return nil
}

// sendRaw issues one IPMI request and returns the response bytes that follow
// the completion code. A non-zero completion code is returned as an error by
// the transport, so a nil error means the controller answered the command.
func (c *IpmiClient) sendRaw(netfn ipmiTransport.NetworkFunction, cmd ipmiTransport.Command, data []byte) ([]byte, error) {
	req := &ipmiTransport.Request{
		NetworkFunction: netfn,
		Command:         cmd,
		Data:            data,
	}
	res := &rawResponse{}
	if err := c.Client.Send(req, res); err != nil {
		return nil, err
	}
	return res.Data, nil
}
