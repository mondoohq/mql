// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"testing"

	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDialectString(t *testing.T) {
	tests := []struct {
		dialect uint16
		want    string
	}{
		{gosmb.DialectSmb_3_1_1, "3.1.1"},
		{gosmb.DialectSmb_3_0_2, "3.0.2"},
		{gosmb.DialectSmb_3_0, "3.0"},
		{gosmb.DialectSmb_2_1, "2.1"},
		{gosmb.DialectSmb_2_0_2, "2.0.2"},
		{0x9999, "unknown(0x9999)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, DialectString(tt.dialect))
	}
}

func TestParseSMB2NegotiateResponse(t *testing.T) {
	t.Run("signing required and encryption via CAP flag (pre-3.1.1)", func(t *testing.T) {
		resp := buildMockSMB2NegResponse(
			uint16(gosmb.SecurityModeSigningRequired)|uint16(gosmb.SecurityModeSigningEnabled),
			gosmb.DialectSmb_3_0_2,
			gosmb.GlobalCapEncryption|gosmb.GlobalCapDFS,
		)
		result, err := parseSMB2NegotiateResponse(resp)
		require.NoError(t, err)
		assert.True(t, result.SigningRequired)
		assert.True(t, result.EncryptionSupported)
		assert.Equal(t, gosmb.DialectSmb_3_0_2, result.HighestDialect)
	})

	t.Run("3.1.1 with encryption context", func(t *testing.T) {
		resp := buildMockSMB311NegResponse(
			uint16(gosmb.SecurityModeSigningRequired)|uint16(gosmb.SecurityModeSigningEnabled),
			0,                // no CAP_ENCRYPTION in Capabilities — encryption comes from context
			[]uint16{0x0002}, // AES-128-GCM
		)
		result, err := parseSMB2NegotiateResponse(resp)
		require.NoError(t, err)
		assert.True(t, result.SigningRequired)
		assert.True(t, result.EncryptionSupported, "encryption should be detected from negotiate context")
		assert.Equal(t, gosmb.DialectSmb_3_1_1, result.HighestDialect)
	})

	t.Run("3.1.1 without encryption context", func(t *testing.T) {
		resp := buildMockSMB311NegResponse(
			uint16(gosmb.SecurityModeSigningEnabled),
			0,
			nil, // no encryption ciphers
		)
		result, err := parseSMB2NegotiateResponse(resp)
		require.NoError(t, err)
		assert.False(t, result.SigningRequired)
		assert.False(t, result.EncryptionSupported)
		assert.Equal(t, gosmb.DialectSmb_3_1_1, result.HighestDialect)
	})

	t.Run("signing enabled only, no encryption", func(t *testing.T) {
		resp := buildMockSMB2NegResponse(
			uint16(gosmb.SecurityModeSigningEnabled),
			gosmb.DialectSmb_2_1,
			gosmb.GlobalCapDFS,
		)
		result, err := parseSMB2NegotiateResponse(resp)
		require.NoError(t, err)
		assert.False(t, result.SigningRequired)
		assert.False(t, result.EncryptionSupported)
		assert.Equal(t, gosmb.DialectSmb_2_1, result.HighestDialect)
	})

	t.Run("too short for body", func(t *testing.T) {
		_, err := parseSMB2NegotiateResponse([]byte{0xFE, 'S', 'M', 'B'})
		assert.Error(t, err)
	})

	t.Run("wrong magic", func(t *testing.T) {
		resp := make([]byte, 100)
		copy(resp[0:4], []byte{0xFF, 'S', 'M', 'B'})
		_, err := parseSMB2NegotiateResponse(resp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected SMB2 magic")
	})

	t.Run("empty response", func(t *testing.T) {
		_, err := parseSMB2NegotiateResponse(nil)
		assert.Error(t, err)
	})
}

func TestBuildSMB2NegotiateRequest(t *testing.T) {
	pkt := buildSMB2NegotiateRequest()

	// SMB2 magic.
	assert.Equal(t, []byte{0xFE, 'S', 'M', 'B'}, pkt[0:4])
	// Header StructureSize = 64.
	assert.Equal(t, uint16(64), le16(pkt[4:6]))
	// Body StructureSize = 36.
	assert.Equal(t, uint16(36), le16(pkt[64:66]))
	// 5 dialects offered (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1).
	assert.Equal(t, uint16(5), le16(pkt[66:68]))

	// Negotiate context count = 2 (preauth + encryption).
	assert.Equal(t, uint16(2), le16(pkt[64+32:64+34]))

	// NegotiateContextOffset should be > 0 and 8-byte aligned.
	ctxOff := int(le32(pkt[64+28 : 64+32]))
	assert.Greater(t, ctxOff, 0)
	assert.Equal(t, 0, ctxOff%8, "NegotiateContextOffset must be 8-byte aligned")

	// First context type = 0x0001 (SMB2_PREAUTH_INTEGRITY_CAPABILITIES).
	require.Greater(t, len(pkt), ctxOff+2)
	assert.Equal(t, uint16(0x0001), le16(pkt[ctxOff:ctxOff+2]))
}

func TestBuildSMB1NegotiateRequest(t *testing.T) {
	pkt := buildSMB1NegotiateRequest()

	// SMB1 magic.
	assert.Equal(t, []byte{0xFF, 'S', 'M', 'B'}, pkt[0:4])
	// Command = SMB_COM_NEGOTIATE (0x72).
	assert.Equal(t, byte(0x72), pkt[4])
	// Contains the dialect string.
	assert.Contains(t, string(pkt), "NT LM 0.12")
}

func TestResolveSMBInitiator(t *testing.T) {
	t.Run("kerberos mode returns error", func(t *testing.T) {
		c := &ActiveDirectoryConnection{
			Conf: &inventory.Config{
				Options: map[string]string{
					OptionKerberos: "true",
					OptionUser:     "admin",
					OptionPassword: "pass",
				},
			},
		}
		_, err := c.resolveSMBInitiator()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Kerberos")
	})

	t.Run("simple bind with UPN extracts domain", func(t *testing.T) {
		c := &ActiveDirectoryConnection{
			Conf: &inventory.Config{
				Options: map[string]string{
					OptionUser:     "admin@mini.lab",
					OptionPassword: "pass123",
				},
			},
		}
		initiator, err := c.resolveSMBInitiator()
		require.NoError(t, err)
		assert.Equal(t, "admin", initiator.User)
		assert.Equal(t, "pass123", initiator.Password)
		assert.Equal(t, "mini.lab", initiator.Domain)
	})

	t.Run("explicit domain overrides UPN", func(t *testing.T) {
		c := &ActiveDirectoryConnection{
			Conf: &inventory.Config{
				Options: map[string]string{
					OptionUser:     "admin@mini.lab",
					OptionPassword: "pass123",
					OptionDomain:   "OVERRIDE.COM",
				},
			},
		}
		initiator, err := c.resolveSMBInitiator()
		require.NoError(t, err)
		assert.Equal(t, "admin", initiator.User)
		assert.Equal(t, "OVERRIDE.COM", initiator.Domain)
	})

	t.Run("missing credentials returns error", func(t *testing.T) {
		c := &ActiveDirectoryConnection{
			Conf: &inventory.Config{
				Options: map[string]string{},
			},
		}
		_, err := c.resolveSMBInitiator()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --user")
	})
}

func TestErrRegistryValueNotFound(t *testing.T) {
	// Verify the sentinel wraps correctly through fmt.Errorf %w.
	wrapped := fmt.Errorf("reading registry value %q: %w", "TestValue", ErrRegistryValueNotFound)
	assert.True(t, errors.Is(wrapped, ErrRegistryValueNotFound))
	assert.Contains(t, wrapped.Error(), "TestValue")
	assert.Contains(t, wrapped.Error(), "registry value not found")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildMockSMB2NegResponse creates a minimal pre-3.1.1 negotiate response.
// Encryption is indicated by CAP_ENCRYPTION in Capabilities.
func buildMockSMB2NegResponse(secMode, dialect uint16, caps uint32) []byte {
	// 64-byte SMB2 header + at least 65-byte negotiate response body.
	resp := make([]byte, 64+65)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})

	body := resp[64:]
	le16Put(body[0:2], 65)      // StructureSize
	le16Put(body[2:4], secMode) // SecurityMode
	le16Put(body[4:6], dialect) // DialectRevision
	le32Put(body[24:28], caps)  // Capabilities

	return resp
}

// buildMockSMB311NegResponse creates a 3.1.1 negotiate response with optional
// SMB2_ENCRYPTION_CAPABILITIES negotiate context. Encryption is indicated by
// the presence of ciphers in the context, not by CAP_ENCRYPTION.
func buildMockSMB311NegResponse(secMode uint16, caps uint32, ciphers []uint16) []byte {
	// Base: 64-byte header + 65-byte body = 129 bytes.
	// Contexts start at the next 8-byte boundary: 136.
	const ctxOffset = 136

	var ctxCount uint16
	ctxData := []byte{}

	if len(ciphers) > 0 {
		ctxCount = 1
		// SMB2_ENCRYPTION_CAPABILITIES: header(8) + CipherCount(2) + ciphers(2 each).
		dataLen := 2 + len(ciphers)*2
		ctx := make([]byte, 8+dataLen)
		le16Put(ctx[0:2], 0x0002)          // ContextType
		le16Put(ctx[2:4], uint16(dataLen)) // DataLength
		le16Put(ctx[8:10], uint16(len(ciphers)))
		for i, c := range ciphers {
			le16Put(ctx[10+i*2:12+i*2], c)
		}
		ctxData = ctx
	}

	resp := make([]byte, ctxOffset+len(ctxData))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})

	body := resp[64:]
	le16Put(body[0:2], 65)                     // StructureSize
	le16Put(body[2:4], secMode)                // SecurityMode
	le16Put(body[4:6], gosmb.DialectSmb_3_1_1) // DialectRevision
	le16Put(body[6:8], ctxCount)               // NegotiateContextCount
	le32Put(body[24:28], caps)                 // Capabilities
	le32Put(body[60:64], ctxOffset)            // NegotiateContextOffset

	copy(resp[ctxOffset:], ctxData)
	return resp
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le16Put(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}
func le32Put(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
