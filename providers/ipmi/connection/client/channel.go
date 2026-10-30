// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"fmt"

	ipmiTransport "github.com/vmware/goipmi"
)

// Channel describes one communication channel of the management controller.
type Channel struct {
	ID                 int64
	MediumType         string
	ProtocolType       string
	SessionSupport     string
	ActiveSessionCount int64

	// Auth is nil when the controller did not answer Get Channel
	// Authentication Capabilities for this channel.
	Auth *ChannelAuthCapabilities
	// Access holds the active (volatile) channel access settings, nil when
	// the controller did not answer Get Channel Access.
	Access *ChannelAccess
	// NonVolatileAccess holds the persisted channel access settings, nil
	// when the controller did not answer Get Channel Access.
	NonVolatileAccess *ChannelAccess
}

// ChannelAuthCapabilities is the pre-authentication capability report of a
// channel, from Get Channel Authentication Capabilities (§22.13).
type ChannelAuthCapabilities struct {
	AuthTypes                       []string
	KgConfigured                    bool
	PerMessageAuthenticationEnabled bool
	UserLevelAuthenticationEnabled  bool
	NonNullUsernamesEnabled         bool
	NullUsernamesEnabled            bool
	AnonymousLoginEnabled           bool
	SupportsIpmi15                  bool
	SupportsIpmi20                  bool
}

// ChannelAccess is one set of channel access settings, from Get Channel
// Access (§22.23). The controller keeps a volatile (active) set and a
// non-volatile (persisted) set, and the same layout describes both.
type ChannelAccess struct {
	AccessMode      string
	PrivilegeLimit  string
	AlertingEnabled bool
}

// enumeratedChannels are the channel numbers worth probing. 0x0c and 0x0d
// are reserved by the specification and 0x0e is the alias for the channel
// the request arrives on, which would report a duplicate of one of the
// others. 0x0f is the fixed system interface channel.
var enumeratedChannels = []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15}

// Channels enumerates the channels the controller implements. Channel
// numbers the controller does not implement answer with an error completion
// code and are skipped, so the returned list holds only real channels.
func (c *IpmiClient) Channels() ([]*Channel, error) {
	channels := make([]*Channel, 0, len(enumeratedChannels))
	for _, num := range enumeratedChannels {
		ch, err := c.ChannelInfo(num)
		if err != nil {
			// An unimplemented channel number is reported with an error
			// completion code. That is the normal answer for most of the
			// range, not a failure of the scan.
			continue
		}

		// A controller may implement the channel but refuse either of the
		// follow-up commands. Leave the corresponding block nil so the
		// resource reports null rather than a fabricated default.
		if auth, err := c.ChannelAuthCapabilities(num); err == nil {
			ch.Auth = auth
		}
		if access, err := c.ChannelAccess(num, true); err == nil {
			ch.Access = access
		}
		if access, err := c.ChannelAccess(num, false); err == nil {
			ch.NonVolatileAccess = access
		}

		channels = append(channels, ch)
	}
	return channels, nil
}

// ChannelInfo runs Get Channel Info (§22.24) for one channel.
func (c *IpmiClient) ChannelInfo(channel uint8) (*Channel, error) {
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, commandGetChannelInfo, []byte{channel & 0x0f})
	if err != nil {
		return nil, err
	}
	return decodeChannelInfo(data)
}

// ChannelAuthCapabilities runs Get Channel Authentication Capabilities
// (§22.13) for one channel. The privilege level in the request selects which
// authentication-type enables come back; administrator is requested because
// the security question is which authentication types can reach the highest
// privilege on the channel.
func (c *IpmiClient) ChannelAuthCapabilities(channel uint8) (*ChannelAuthCapabilities, error) {
	req := []byte{(channel & 0x0f) | 0x80, ipmiTransport.PrivLevelAdmin}
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, ipmiTransport.CommandGetAuthCapabilities, req)
	if err != nil {
		return nil, err
	}
	return decodeChannelAuthCapabilities(data)
}

// ChannelAccess runs Get Channel Access (§22.23) for one channel. When
// volatile is true the active settings are read, otherwise the settings
// persisted across a controller restart.
func (c *IpmiClient) ChannelAccess(channel uint8, volatile bool) (*ChannelAccess, error) {
	// Access set selector: 01b non-volatile, 10b volatile (active).
	selector := byte(0x01 << 6)
	if volatile {
		selector = byte(0x02 << 6)
	}
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, commandGetChannelAccess, []byte{channel & 0x0f, selector})
	if err != nil {
		return nil, err
	}
	return decodeChannelAccess(data)
}

func decodeChannelInfo(data []byte) (*Channel, error) {
	// Channel number, medium type, protocol type and the session byte are
	// the four the controller must return. Vendor ID and auxiliary info
	// follow and are not read here.
	if len(data) < 4 {
		return nil, fmt.Errorf("ipmi: short channel info response, expected at least 4 bytes, got %d", len(data))
	}
	return &Channel{
		ID:                 int64(data[0] & 0x0f),
		MediumType:         decodeChannelMedium(data[1] & 0x7f),
		ProtocolType:       decodeChannelProtocol(data[2] & 0x1f),
		SessionSupport:     decodeSessionSupport(data[3] >> 6),
		ActiveSessionCount: int64(data[3] & 0x3f),
	}, nil
}

func decodeChannelAuthCapabilities(data []byte) (*ChannelAuthCapabilities, error) {
	// Channel number, authentication type support, status and the extended
	// capabilities byte. A v1.5-only controller returns the fourth byte as
	// reserved, which the extended-data flag guards against.
	if len(data) < 4 {
		return nil, fmt.Errorf("ipmi: short channel authentication capabilities response, expected at least 4 bytes, got %d", len(data))
	}

	types := []string{}
	if data[1]&0x01 != 0 {
		types = append(types, "none")
	}
	if data[1]&0x02 != 0 {
		types = append(types, "md2")
	}
	if data[1]&0x04 != 0 {
		types = append(types, "md5")
	}
	if data[1]&0x10 != 0 {
		types = append(types, "password")
	}
	if data[1]&0x20 != 0 {
		types = append(types, "oem")
	}

	caps := &ChannelAuthCapabilities{
		AuthTypes: types,
		// Both flags are stored inverted on the wire: the bit is set when
		// the protection is switched off.
		KgConfigured:                    data[2]&0x20 != 0,
		PerMessageAuthenticationEnabled: data[2]&0x10 == 0,
		UserLevelAuthenticationEnabled:  data[2]&0x08 == 0,
		NonNullUsernamesEnabled:         data[2]&0x04 != 0,
		NullUsernamesEnabled:            data[2]&0x02 != 0,
		AnonymousLoginEnabled:           data[2]&0x01 != 0,
	}

	// The connection-support byte only carries meaning when the controller
	// says it returned IPMI v2.0 extended data; on a v1.5-only controller
	// it is reserved and reads as zero.
	if data[1]&0x80 != 0 {
		caps.SupportsIpmi20 = data[3]&0x02 != 0
		caps.SupportsIpmi15 = data[3]&0x01 != 0
	}

	return caps, nil
}

func decodeChannelAccess(data []byte) (*ChannelAccess, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ipmi: short channel access response, expected at least 2 bytes, got %d", len(data))
	}
	return &ChannelAccess{
		AccessMode: decodeChannelAccessMode(data[0] & 0x07),
		// The alerting bit is set when alerting is switched off.
		AlertingEnabled: data[0]&0x20 == 0,
		PrivilegeLimit:  decodePrivilegeLevel(data[1] & 0x0f),
	}, nil
}

// decodeChannelMedium maps the channel medium type number (§6.5).
func decodeChannelMedium(b uint8) string {
	switch b {
	case 0x01:
		return "ipmb"
	case 0x02:
		return "icmb-v1.0"
	case 0x03:
		return "icmb-v0.9"
	case 0x04:
		return "802.3-lan"
	case 0x05:
		return "serial-modem"
	case 0x06:
		return "other-lan"
	case 0x07:
		return "pci-smbus"
	case 0x08:
		return "smbus-v1.x"
	case 0x09:
		return "smbus-v2.0"
	case 0x0a:
		return "usb-1.x"
	case 0x0b:
		return "usb-2.x"
	case 0x0c:
		return "system-interface"
	}
	if b >= 0x60 && b <= 0x7f {
		return "oem"
	}
	return "reserved"
}

// decodeChannelProtocol maps the channel protocol type number (§6.4).
func decodeChannelProtocol(b uint8) string {
	switch b {
	case 0x01:
		return "ipmb-1.0"
	case 0x02:
		return "icmb-1.0"
	case 0x04:
		return "ipmi-smbus"
	case 0x05:
		return "kcs"
	case 0x06:
		return "smic"
	case 0x07:
		return "bt-10"
	case 0x08:
		return "bt-15"
	case 0x09:
		return "tmode"
	}
	if b >= 0x1c && b <= 0x1f {
		return "oem"
	}
	return "reserved"
}

func decodeSessionSupport(b uint8) string {
	switch b {
	case 0x0:
		return "session-less"
	case 0x1:
		return "single-session"
	case 0x2:
		return "multi-session"
	default:
		return "session-based"
	}
}

// decodeChannelAccessMode maps the channel access mode (§6.6).
func decodeChannelAccessMode(b uint8) string {
	switch b {
	case 0x0:
		return "disabled"
	case 0x1:
		return "pre-boot-only"
	case 0x2:
		return "always-available"
	case 0x3:
		return "shared"
	default:
		return "reserved"
	}
}

// decodePrivilegeLevel maps a channel privilege level (§6.8). 0x0f is the
// documented "no access" value; 0x00 means the controller did not specify a
// level rather than that it granted none.
func decodePrivilegeLevel(b uint8) string {
	switch b {
	case 0x00:
		return "unspecified"
	case 0x01:
		return "callback"
	case 0x02:
		return "user"
	case 0x03:
		return "operator"
	case 0x04:
		return "administrator"
	case 0x05:
		return "oem"
	case 0x0f:
		return "no-access"
	default:
		return "reserved"
	}
}
