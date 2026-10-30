// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// LAN configuration parameter selectors (§23.1). Only the parameters that
// carry a security decision are read. Parameter 16, the SNMP community
// string, is deliberately not read: it is credential material.
const (
	lanParamAuthTypeEnables       uint8 = 2
	lanParamVlanID                uint8 = 20
	lanParamCipherSuitesSupport   uint8 = 22
	lanParamCipherSuitesID        uint8 = 23
	lanParamCipherSuitesPrivilege uint8 = 24
	lanParamBadPasswordThreshold  uint8 = 26
)

// maxCipherSuiteEntries is the number of RMCP+ cipher suite entries the
// parameters can carry (§23.1, parameters 23 and 24).
const maxCipherSuiteEntries = 16

// LanConfig is the security-relevant LAN configuration of one channel. Each
// parameter is a separate request and controllers differ in which they
// implement, so a block is nil when its parameter was not answered rather
// than being filled with zero values.
type LanConfig struct {
	ChannelID int64

	// AuthTypeEnables maps a privilege level to the authentication types
	// the controller accepts for it. nil when parameter 2 was not answered.
	AuthTypeEnables map[string][]string
	// CipherSuites lists the RMCP+ cipher suite IDs the channel offers.
	// nil when parameter 23 was not answered.
	CipherSuites []int64
	// CipherSuitePrivilegeLevels maps a cipher suite ID to the highest
	// privilege a session using it may reach. nil when parameter 24 was not
	// answered.
	CipherSuitePrivilegeLevels map[string]string
	// CipherZeroEnabled is nil when the cipher suite parameters were not
	// both answered, because whether cipher suite 0 is usable cannot be
	// decided from either one alone.
	CipherZeroEnabled *bool

	// BadPassword is nil when parameter 26 was not answered.
	BadPassword *LanBadPassword
	// Vlan is nil when parameter 20 was not answered.
	Vlan *LanVlan
}

// LanBadPassword holds the failed-authentication lockout settings of a
// channel (§23.1, parameter 26).
type LanBadPassword struct {
	Threshold                        int64
	AttemptCountResetIntervalSeconds int64
	UserLockoutIntervalSeconds       int64
	InvalidPasswordEventEnabled      bool
}

// LanVlan holds the 802.1q VLAN assignment of a channel (§23.1, parameter 20).
type LanVlan struct {
	Enabled bool
	ID      int64
}

// LanConfig reads the security-relevant LAN configuration parameters of one
// channel. A controller that answers none of them returns an error; one that
// answers some leaves the rest nil.
func (c *IpmiClient) LanConfig(channel uint8) (*LanConfig, error) {
	info, err := c.ChannelInfo(channel)
	if err != nil {
		return nil, err
	}

	cfg := &LanConfig{ChannelID: info.ID}
	answered := false

	if data, err := c.lanConfigParam(channel, lanParamAuthTypeEnables); err == nil {
		if enables, err := decodeLanAuthTypeEnables(data); err == nil {
			cfg.AuthTypeEnables = enables
			answered = true
		}
	}

	if data, err := c.lanConfigParam(channel, lanParamVlanID); err == nil {
		if vlan, err := decodeLanVlan(data); err == nil {
			cfg.Vlan = vlan
			answered = true
		}
	}

	if data, err := c.lanConfigParam(channel, lanParamBadPasswordThreshold); err == nil {
		if bad, err := decodeLanBadPassword(data); err == nil {
			cfg.BadPassword = bad
			answered = true
		}
	}

	if c.readCipherSuites(channel, cfg) {
		answered = true
	}

	if !answered {
		return nil, fmt.Errorf("ipmi: controller answered none of the LAN configuration parameters for channel %d", info.ID)
	}
	return cfg, nil
}

// readCipherSuites fills the three cipher suite fields, which need the ID
// list and the privilege list together to mean anything. It reports whether
// anything was filled in.
func (c *IpmiClient) readCipherSuites(channel uint8, cfg *LanConfig) bool {
	idData, err := c.lanConfigParam(channel, lanParamCipherSuitesID)
	if err != nil {
		return false
	}

	// The supported-count parameter tells how many of the 16 entries are
	// real. Without it a zero entry cannot be told apart from cipher suite
	// 0, so fall back to the convention that only the first entry may be 0.
	count := -1
	if countData, err := c.lanConfigParam(channel, lanParamCipherSuitesSupport); err == nil {
		if n, err := decodeCipherSuiteCount(countData); err == nil {
			count = n
		}
	}

	ids, err := decodeCipherSuiteIDs(idData, count)
	if err != nil {
		return false
	}
	cfg.CipherSuites = ids

	privData, err := c.lanConfigParam(channel, lanParamCipherSuitesPrivilege)
	if err != nil {
		// The suite list alone is still worth reporting, but nothing can be
		// said about cipher suite 0 without the privilege levels.
		return true
	}
	privs, err := decodeCipherSuitePrivileges(privData)
	if err != nil {
		return true
	}

	levels, cipherZero := cipherSuiteLevels(ids, privs)
	cfg.CipherSuitePrivilegeLevels = levels
	cfg.CipherZeroEnabled = &cipherZero
	return true
}

// cipherSuiteLevels pairs each cipher suite entry with the highest privilege
// a session using it may reach, and reports whether cipher suite 0 is one of
// them at a usable privilege. Cipher suite 0 negotiates authentication and
// then performs none, so an entry for it at any privilege above unspecified
// accepts an arbitrary password for a session at that privilege.
func cipherSuiteLevels(ids []int64, privs [maxCipherSuiteEntries]uint8) (map[string]string, bool) {
	levels := make(map[string]string, len(ids))
	cipherZero := false
	for i, id := range ids {
		if i >= maxCipherSuiteEntries {
			break
		}
		levels[strconv.FormatInt(id, 10)] = decodePrivilegeLevel(privs[i])
		if id == 0 && privs[i] != 0x00 {
			cipherZero = true
		}
	}
	return levels, cipherZero
}

// lanConfigParam runs Get LAN Configuration Parameters (§23.2) for one
// parameter and returns the parameter data with the revision byte stripped.
func (c *IpmiClient) lanConfigParam(channel uint8, param uint8) ([]byte, error) {
	data, err := c.sendRaw(networkFunctionTransport, commandGetLanConfigParam, []byte{channel & 0x0f, param, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("ipmi: empty LAN configuration parameter %d response", param)
	}
	return data[1:], nil
}

// decodeLanAuthTypeEnables decodes parameter 2, one byte per privilege level
// holding the authentication types enabled for that level.
func decodeLanAuthTypeEnables(data []byte) (map[string][]string, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("ipmi: short authentication type enables parameter, expected at least 5 bytes, got %d", len(data))
	}
	levels := []string{"callback", "user", "operator", "administrator", "oem"}
	out := make(map[string][]string, len(levels))
	for i, level := range levels {
		out[level] = decodeAuthTypeBits(data[i])
	}
	return out, nil
}

func decodeAuthTypeBits(b uint8) []string {
	types := []string{}
	if b&0x01 != 0 {
		types = append(types, "none")
	}
	if b&0x02 != 0 {
		types = append(types, "md2")
	}
	if b&0x04 != 0 {
		types = append(types, "md5")
	}
	if b&0x10 != 0 {
		types = append(types, "password")
	}
	if b&0x20 != 0 {
		types = append(types, "oem")
	}
	return types
}

// decodeLanVlan decodes parameter 20.
func decodeLanVlan(data []byte) (*LanVlan, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ipmi: short VLAN parameter, expected at least 2 bytes, got %d", len(data))
	}
	return &LanVlan{
		Enabled: data[1]&0x80 != 0,
		ID:      int64(uint16(data[1]&0x0f)<<8 | uint16(data[0])),
	}, nil
}

// decodeLanBadPassword decodes parameter 26. The two intervals are carried in
// tens of seconds.
func decodeLanBadPassword(data []byte) (*LanBadPassword, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("ipmi: short bad password threshold parameter, expected at least 6 bytes, got %d", len(data))
	}
	return &LanBadPassword{
		InvalidPasswordEventEnabled:      data[0]&0x01 != 0,
		Threshold:                        int64(data[1]),
		AttemptCountResetIntervalSeconds: int64(binary.LittleEndian.Uint16(data[2:4])) * 10,
		UserLockoutIntervalSeconds:       int64(binary.LittleEndian.Uint16(data[4:6])) * 10,
	}, nil
}

// decodeCipherSuiteCount decodes parameter 22, the number of cipher suite
// entries parameters 23 and 24 carry.
func decodeCipherSuiteCount(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("ipmi: short cipher suite support parameter, expected at least 1 byte, got %d", len(data))
	}
	n := min(int(data[0]&0x1f), maxCipherSuiteEntries)
	return n, nil
}

// decodeCipherSuiteIDs decodes parameter 23. The first byte is the set
// selector and the entries follow. When count is negative the number of
// entries is not known, and the convention is applied that only the first
// entry may legitimately be cipher suite 0 while a later zero is an unused
// slot.
func decodeCipherSuiteIDs(data []byte, count int) ([]int64, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ipmi: short cipher suite ID parameter, expected at least 2 bytes, got %d", len(data))
	}
	entries := data[1:]
	if len(entries) > maxCipherSuiteEntries {
		entries = entries[:maxCipherSuiteEntries]
	}

	if count >= 0 {
		if count > len(entries) {
			count = len(entries)
		}
		entries = entries[:count]
	}

	ids := make([]int64, 0, len(entries))
	for i, v := range entries {
		if count < 0 && i > 0 && v == 0 {
			break
		}
		ids = append(ids, int64(v))
	}
	return ids, nil
}

// decodeCipherSuitePrivileges decodes parameter 24: a reserved byte followed
// by eight bytes holding two four-bit privilege levels each, in cipher suite
// entry order.
func decodeCipherSuitePrivileges(data []byte) ([maxCipherSuiteEntries]uint8, error) {
	var privs [maxCipherSuiteEntries]uint8
	if len(data) < 9 {
		return privs, fmt.Errorf("ipmi: short cipher suite privilege parameter, expected at least 9 bytes, got %d", len(data))
	}
	for i := range 8 {
		b := data[i+1]
		privs[2*i] = b & 0x0f
		privs[2*i+1] = (b >> 4) & 0x0f
	}
	return privs, nil
}
