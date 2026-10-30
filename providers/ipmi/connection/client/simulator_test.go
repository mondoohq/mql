// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipmiTransport "github.com/vmware/goipmi"
)

// simResponse is a canned response payload, completion code first. It lets a
// test answer a command with exact wire bytes rather than with a Go struct,
// so the request encoding and the response plumbing are exercised end to end
// rather than only the decoders.
type simResponse []byte

func (r simResponse) Code() uint8 {
	if len(r) == 0 {
		return 0
	}
	return r[0]
}

func (r simResponse) MarshalBinary() ([]byte, error) {
	return []byte(r), nil
}

const (
	simCompleted    = 0x00
	simInvalidField = 0xcc
)

// newSimClient starts a simulator with handlers for the commands this
// provider issues over the application network function, and returns a
// client with an open session against it.
func newSimClient(t *testing.T) *IpmiClient {
	t.Helper()

	sim := ipmiTransport.NewSimulator(net.UDPAddr{})
	require.NoError(t, sim.Run())
	t.Cleanup(sim.Stop)

	// Get Channel Authentication Capabilities also carries the session
	// negotiation, so this payload has to keep the MD5 bit set for the
	// session to open at all. Beyond that it reports a channel with every
	// null-login state set and both authentication protections switched off.
	sim.SetHandler(ipmiTransport.NetworkFunctionApp, ipmiTransport.CommandGetAuthCapabilities, func(*ipmiTransport.Message) ipmiTransport.Response {
		return simResponse{simCompleted, 0x01, 0xb5, 0x3f, 0x03, 0x00, 0x00, 0x00, 0x00}
	})

	// Only channels 1 and 15 are implemented. 0x0e is the alias for the
	// channel the request arrived on and resolves to channel 1, which is
	// what the user key depends on.
	sim.SetHandler(ipmiTransport.NetworkFunctionApp, commandGetChannelInfo, func(m *ipmiTransport.Message) ipmiTransport.Response {
		switch m.Data[0] & 0x0f {
		case 0x01, 0x0e:
			return simResponse{simCompleted, 0x01, 0x04, 0x01, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00}
		case 0x0f:
			return simResponse{simCompleted, 0x0f, 0x0c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		default:
			return simResponse{simInvalidField}
		}
	})

	sim.SetHandler(ipmiTransport.NetworkFunctionApp, commandGetChannelAccess, func(m *ipmiTransport.Message) ipmiTransport.Response {
		// Volatile requests carry 10b in the top two bits, non-volatile 01b.
		if m.Data[1]>>6 == 0x02 {
			return simResponse{simCompleted, 0x02, 0x04}
		}
		return simResponse{simCompleted, 0x01, 0x03}
	})

	sim.SetHandler(ipmiTransport.NetworkFunctionApp, commandGetUserAccess, func(m *ipmiTransport.Message) ipmiTransport.Response {
		switch m.Data[1] & 0x3f {
		case 0x01:
			// Five slots, two enabled, one with a fixed name. Slot 1 sits at
			// user privilege with no flags set.
			return simResponse{simCompleted, 0x05, 0x42, 0x01, 0x02}
		case 0x02:
			return simResponse{simCompleted, 0x05, 0x42, 0x01, 0x34}
		default:
			// A controller answers an unconfigured slot with an error.
			return simResponse{simInvalidField}
		}
	})

	sim.SetHandler(ipmiTransport.NetworkFunctionApp, ipmiTransport.CommandGetUserName, func(m *ipmiTransport.Message) ipmiTransport.Response {
		name := make([]byte, 17)
		name[0] = simCompleted
		switch m.Data[0] & 0x3f {
		case 0x01:
			// The null user: a real, empty name.
		case 0x02:
			copy(name[1:], "admin")
		default:
			return simResponse{simInvalidField}
		}
		return simResponse(name)
	})

	sim.SetHandler(ipmiTransport.NetworkFunctionApp, commandGetWatchdogTimer, func(*ipmiTransport.Message) ipmiTransport.Response {
		return simResponse{simCompleted, 0xc4, 0x21, 0x1e, 0x0a, 0x70, 0x17, 0xff, 0x02}
	})

	sim.SetHandler(ipmiTransport.NetworkFunctionApp, commandGetBMCGlobalEnables, func(*ipmiTransport.Message) ipmiTransport.Response {
		return simResponse{simCompleted, 0x0f}
	})

	addr := sim.LocalAddr()
	client, err := NewIpmiClient(&Connection{
		Hostname:  addr.IP.String(),
		Port:      int32(addr.Port),
		Username:  "test",
		Password:  "test",
		Interface: "lan",
	})
	require.NoError(t, err)
	require.NoError(t, client.Open())
	t.Cleanup(func() { _ = client.Close() })

	return client
}

func TestSimulatorChannels(t *testing.T) {
	client := newSimClient(t)

	channels, err := client.Channels()
	require.NoError(t, err)

	// Channel numbers the controller does not implement answer with an error
	// completion code and must be dropped rather than reported as channels
	// that exist with empty settings.
	require.Len(t, channels, 2)

	lan := channels[0]
	assert.Equal(t, int64(1), lan.ID)
	assert.Equal(t, "802.3-lan", lan.MediumType)
	assert.Equal(t, "ipmb-1.0", lan.ProtocolType)
	assert.Equal(t, "multi-session", lan.SessionSupport)
	assert.Equal(t, int64(2), lan.ActiveSessionCount)

	require.NotNil(t, lan.Access)
	assert.Equal(t, "always-available", lan.Access.AccessMode)
	assert.Equal(t, "administrator", lan.Access.PrivilegeLimit)
	assert.True(t, lan.Access.AlertingEnabled)

	// The persisted settings are a separate request and must not be
	// overwritten by the active ones.
	require.NotNil(t, lan.NonVolatileAccess)
	assert.Equal(t, "pre-boot-only", lan.NonVolatileAccess.AccessMode)
	assert.Equal(t, "operator", lan.NonVolatileAccess.PrivilegeLimit)

	require.NotNil(t, lan.Auth)
	assert.True(t, lan.Auth.AnonymousLoginEnabled)
	assert.True(t, lan.Auth.NullUsernamesEnabled)
	assert.False(t, lan.Auth.PerMessageAuthenticationEnabled)
	assert.False(t, lan.Auth.UserLevelAuthenticationEnabled)
	assert.Equal(t, []string{"none", "md5", "password", "oem"}, lan.Auth.AuthTypes)

	assert.Equal(t, int64(15), channels[1].ID)
	assert.Equal(t, "system-interface", channels[1].MediumType)
	assert.Equal(t, "session-less", channels[1].SessionSupport)
}

func TestSimulatorUsers(t *testing.T) {
	client := newSimClient(t)

	users, err := client.Users(ChannelSelf)
	require.NoError(t, err)

	// Five slots are reported but only two answer, so the walk must stop
	// reporting after the ones the controller actually has.
	require.Len(t, users, 2)

	// The channel alias 0x0e has to be resolved to the real channel number
	// before it keys a user, or two channels' slots would collide.
	assert.Equal(t, int64(1), users[0].ChannelID)
	assert.Equal(t, int64(1), users[1].ChannelID)

	assert.Equal(t, int64(1), users[0].ID)
	require.NotNil(t, users[0].Name)
	assert.Equal(t, "", *users[0].Name)
	assert.Equal(t, "user", users[0].PrivilegeLimit)
	assert.True(t, users[0].FixedName)
	assert.False(t, users[0].IpmiMessagingEnabled)
	require.NotNil(t, users[0].Enabled)
	assert.True(t, *users[0].Enabled)

	assert.Equal(t, int64(2), users[1].ID)
	require.NotNil(t, users[1].Name)
	assert.Equal(t, "admin", *users[1].Name)
	assert.Equal(t, "administrator", users[1].PrivilegeLimit)
	assert.True(t, users[1].LinkAuthenticationEnabled)
	assert.True(t, users[1].IpmiMessagingEnabled)
	assert.False(t, users[1].FixedName)
}

func TestSimulatorWatchdog(t *testing.T) {
	client := newSimClient(t)

	wd, err := client.Watchdog()
	require.NoError(t, err)
	assert.True(t, wd.Running)
	assert.True(t, wd.DontLog)
	assert.Equal(t, "sms-os", wd.TimerUse)
	assert.Equal(t, "hard-reset", wd.TimeoutAction)
	assert.Equal(t, []string{"bios-frb2", "os-load"}, wd.ExpiredTimerUses)
}

func TestSimulatorSystemEventLoggingEnabled(t *testing.T) {
	client := newSimClient(t)

	enabled, err := client.SystemEventLoggingEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestSimulatorUnsupportedCommandIsAnError(t *testing.T) {
	client := newSimClient(t)

	// Get SEL Info is a storage command and the simulator has no handler
	// for it. A controller that does not implement a command must surface as
	// an error rather than as a resource full of zero values.
	_, err := client.SELInfo()
	require.Error(t, err)
}
