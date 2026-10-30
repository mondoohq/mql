// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"bytes"
	"fmt"
	"strings"

	ipmiTransport "github.com/vmware/goipmi"
)

// User is one account slot of the management controller, as it applies to a
// single channel. Privileges and the messaging flags are per channel; the
// name is not.
type User struct {
	ID        int64
	ChannelID int64

	// Name is nil when the controller did not answer Get User Name for this
	// slot. An empty string is a slot whose user name is unset, which is a
	// different state and the one that makes a slot usable anonymously.
	Name *string
	// Enabled is nil when the controller reports the enable status as
	// unspecified, which implementations older than IPMI 2.0 errata 3 do.
	Enabled *bool

	PrivilegeLimit            string
	LinkAuthenticationEnabled bool
	IpmiMessagingEnabled      bool
	CallbackOnly              bool
	FixedName                 bool
}

// userAccess is the decoded Get User Access response for one slot. The first
// three counts are properties of the channel rather than of the slot, and
// come back identically for every slot.
type userAccess struct {
	MaxUserIDs                int64
	EnabledUserCount          int64
	FixedNameUserCount        int64
	EnableStatus              uint8
	CallbackOnly              bool
	LinkAuthenticationEnabled bool
	IpmiMessagingEnabled      bool
	PrivilegeLimit            string
}

// maxUserSlots bounds the slot walk. The user ID field is six bits wide
// (§22.27), so a controller can never report more than 63 slots, and a
// corrupt count must not turn into an unbounded request loop.
const maxUserSlots = 63

// Users lists the account slots of the controller for one channel. Slot 1 is
// the reserved null user and is included, because a null user with a
// privilege limit above callback is exactly what makes anonymous access
// possible.
func (c *IpmiClient) Users(channel uint8) ([]*User, error) {
	// The channel this session arrived on has to be resolved to its real
	// number before it can key a user, because 0x0e is an alias rather than
	// a channel and would make two slots of the same channel look distinct.
	info, err := c.ChannelInfo(channel)
	if err != nil {
		return nil, err
	}
	channelID := info.ID

	first, err := c.userAccess(channel, 1)
	if err != nil {
		return nil, err
	}

	slots := min(first.MaxUserIDs, maxUserSlots)

	users := make([]*User, 0, slots)
	for id := int64(1); id <= slots; id++ {
		access := first
		if id > 1 {
			access, err = c.userAccess(channel, uint8(id))
			if err != nil {
				// Controllers answer an unconfigured slot with an error
				// completion code rather than with an empty record.
				continue
			}
		}

		user := &User{
			ID:                        id,
			ChannelID:                 channelID,
			Enabled:                   decodeUserEnableStatus(access.EnableStatus),
			PrivilegeLimit:            access.PrivilegeLimit,
			LinkAuthenticationEnabled: access.LinkAuthenticationEnabled,
			IpmiMessagingEnabled:      access.IpmiMessagingEnabled,
			CallbackOnly:              access.CallbackOnly,
			FixedName:                 id <= access.FixedNameUserCount,
		}

		if name, err := c.UserName(uint8(id)); err == nil {
			user.Name = &name
		}

		users = append(users, user)
	}

	return users, nil
}

// UserName runs Get User Name (§22.29) for one slot.
func (c *IpmiClient) UserName(userID uint8) (string, error) {
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, ipmiTransport.CommandGetUserName, []byte{userID & 0x3f})
	if err != nil {
		return "", err
	}
	return decodeUserName(data), nil
}

func (c *IpmiClient) userAccess(channel uint8, userID uint8) (*userAccess, error) {
	data, err := c.sendRaw(ipmiTransport.NetworkFunctionApp, commandGetUserAccess, []byte{channel & 0x0f, userID & 0x3f})
	if err != nil {
		return nil, err
	}
	return decodeUserAccess(data)
}

func decodeUserAccess(data []byte) (*userAccess, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ipmi: short user access response, expected at least 4 bytes, got %d", len(data))
	}
	return &userAccess{
		MaxUserIDs:                int64(data[0] & 0x3f),
		EnableStatus:              (data[1] & 0xc0) >> 6,
		EnabledUserCount:          int64(data[1] & 0x3f),
		FixedNameUserCount:        int64(data[2] & 0x3f),
		CallbackOnly:              data[3]&0x40 != 0,
		LinkAuthenticationEnabled: data[3]&0x20 != 0,
		IpmiMessagingEnabled:      data[3]&0x10 != 0,
		PrivilegeLimit:            decodePrivilegeLevel(data[3] & 0x0f),
	}, nil
}

// decodeUserEnableStatus maps the two-bit enable status. 00b means the
// controller does not report the state at all, which is null rather than
// disabled; 11b is reserved and is treated the same way.
func decodeUserEnableStatus(b uint8) *bool {
	enabled := true
	disabled := false
	switch b {
	case 0x1:
		return &enabled
	case 0x2:
		return &disabled
	default:
		return nil
	}
}

// decodeUserName reads the user name out of a Get User Name response. The
// name is a fixed 16-byte field padded with nulls, but controllers have been
// seen returning a shorter payload, so the length is not enforced.
func decodeUserName(data []byte) string {
	if i := bytes.IndexByte(data, 0x00); i >= 0 {
		data = data[:i]
	}
	return strings.TrimSpace(string(data))
}
