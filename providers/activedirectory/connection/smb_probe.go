// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
	"github.com/rs/zerolog/log"
)

// smbProbeTimeout caps how long we wait for SMB probe TCP connections.
const (
	smbProbeTimeout = 10 * time.Second
	msrrpLoggerName = "github.com/jfjallid/go-smb/dcerpc/msrrp"
)

// ErrRegistryValueNotFound indicates the queried registry value does not exist.
// Callers use errors.Is to distinguish "not configured" from transport failures.
var ErrRegistryValueNotFound = errors.New("registry value not found")

func init() {
	// The upstream msrrp package logs expected missing-value errors before returning
	// them. We rely on the returned error path instead of duplicate stderr noise.
	golog.Set(msrrpLoggerName, "msrrp", golog.LevelNone, golog.LstdFlags, io.Discard, io.Discard)
}

// ---------------------------------------------------------------------------
// NegotiateResult — cached pre-auth SMB metadata from raw negotiate probes
// ---------------------------------------------------------------------------

// NegotiateResult holds the pre-auth metadata extracted from raw SMB
// negotiate probes on port 445. Populated once via ProbeSMBNegotiate.
type NegotiateResult struct {
	SigningRequired     bool
	SMBv1Enabled        bool
	EncryptionSupported bool
	HighestDialect      uint16
}

// DialectString returns a human-readable SMB dialect version.
func DialectString(d uint16) string {
	switch d {
	case gosmb.DialectSmb_3_1_1:
		return "3.1.1"
	case gosmb.DialectSmb_3_0_2:
		return "3.0.2"
	case gosmb.DialectSmb_3_0:
		return "3.0"
	case gosmb.DialectSmb_2_1:
		return "2.1"
	case gosmb.DialectSmb_2_0_2:
		return "2.0.2"
	default:
		return fmt.Sprintf("unknown(0x%04x)", d)
	}
}

// ---------------------------------------------------------------------------
// Family A — Raw pre-auth negotiate probes (no authentication)
// ---------------------------------------------------------------------------

// ProbeSMBNegotiate performs two raw TCP probes to extract pre-auth SMB
// metadata. Result is cached via sync.Once on the connection; concurrent
// callers block and share the outcome.
func (c *ActiveDirectoryConnection) ProbeSMBNegotiate() (*NegotiateResult, error) {
	c.smbProbeOnce.Do(func() {
		c.smbNegotiate, c.smbProbeErr = c.probeSMBNegotiateUncached()
	})
	return c.smbNegotiate, c.smbProbeErr
}

func (c *ActiveDirectoryConnection) probeSMBNegotiateUncached() (*NegotiateResult, error) {
	addr := net.JoinHostPort(c.dcHost, "445")

	// Phase 1: SMB2 negotiate — signing, encryption, dialect.
	smb2Result, err := probeSMB2Negotiate(addr)
	if err != nil {
		return nil, fmt.Errorf("SMB2 negotiate probe on %s: %w", c.dcHost, err)
	}

	// Phase 2: SMB1-only negotiate — explicit SMBv1 acceptance test.
	smb1Enabled, err := probeSMB1Negotiate(addr)
	if err != nil {
		// Port 445 is reachable (SMB2 succeeded) but SMB1 probe failed.
		// Treat as SMBv1 disabled with a debug note.
		log.Debug().Err(err).Str("dc", c.dcHost).Msg("SMB1 probe failed after successful SMB2 probe; treating SMBv1 as disabled")
		smb1Enabled = false
	}

	smb2Result.SMBv1Enabled = smb1Enabled
	return smb2Result, nil
}

// probeSMB2Negotiate sends a raw SMB2 negotiate request and parses the
// response for SecurityMode, Capabilities, and DialectRevision.
func probeSMB2Negotiate(addr string) (*NegotiateResult, error) {
	conn, err := net.DialTimeout("tcp", addr, smbProbeTimeout)
	if err != nil {
		return nil, fmt.Errorf("port 445 unreachable: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(smbProbeTimeout)); err != nil {
		return nil, fmt.Errorf("setting connection deadline: %w", err)
	}

	// Build a minimal SMB2 negotiate request.
	negReq := buildSMB2NegotiateRequest()
	if err := sendNetBIOS(conn, negReq); err != nil {
		return nil, fmt.Errorf("sending SMB2 negotiate: %w", err)
	}

	resp, err := recvNetBIOS(conn)
	if err != nil {
		return nil, fmt.Errorf("reading SMB2 negotiate response: %w", err)
	}

	return parseSMB2NegotiateResponse(resp)
}

// probeSMB1Negotiate sends a raw SMB1-only negotiate request offering only
// "NT LM 0.12". Returns true if the server responds with an SMB1 header
// (magic \xFFSMB), false if the probe is rejected.
func probeSMB1Negotiate(addr string) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, smbProbeTimeout)
	if err != nil {
		return false, fmt.Errorf("port 445 unreachable: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(smbProbeTimeout)); err != nil {
		return false, fmt.Errorf("setting connection deadline: %w", err)
	}

	negReq := buildSMB1NegotiateRequest()
	if err := sendNetBIOS(conn, negReq); err != nil {
		return false, fmt.Errorf("sending SMB1 negotiate: %w", err)
	}

	resp, err := recvNetBIOS(conn)
	if err != nil {
		// Connection reset or closed = SMB1 rejected.
		return false, nil
	}

	if len(resp) < 4 {
		return false, nil
	}

	// SMB1 response magic: \xFFSMB
	if resp[0] == 0xFF && resp[1] == 'S' && resp[2] == 'M' && resp[3] == 'B' {
		return true, nil
	}
	// SMB2 response magic: \xFESMB — server rejected SMB1 and responded with SMB2.
	if resp[0] == 0xFE && resp[1] == 'S' && resp[2] == 'M' && resp[3] == 'B' {
		return false, nil
	}
	return false, fmt.Errorf("unexpected response magic: %02x%02x%02x%02x", resp[0], resp[1], resp[2], resp[3])
}

// ---------------------------------------------------------------------------
// Raw SMB packet builders and parsers
// ---------------------------------------------------------------------------

// buildSMB2NegotiateRequest creates an SMB2 negotiate request offering
// dialects 2.0.2 through 3.1.1. For 3.1.1, MS-SMB2 2.2.3 requires negotiate
// contexts; we include SMB2_PREAUTH_INTEGRITY_CAPABILITIES (SHA-512) and
// SMB2_ENCRYPTION_CAPABILITIES (AES-128-CCM/GCM, AES-256-CCM/GCM).
func buildSMB2NegotiateRequest() []byte {
	dialects := []uint16{
		gosmb.DialectSmb_2_0_2,
		gosmb.DialectSmb_2_1,
		gosmb.DialectSmb_3_0,
		gosmb.DialectSmb_3_0_2,
		gosmb.DialectSmb_3_1_1,
	}

	// Layout: 64-byte header + 36-byte body + dialects + padding + negotiate contexts.
	dialectsSize := len(dialects) * 2
	preCtxOffset := 64 + 36 + dialectsSize
	// Pad to 8-byte alignment for negotiate context list.
	padding := (8 - preCtxOffset%8) % 8
	ctxOffset := preCtxOffset + padding

	// Context 1: SMB2_PREAUTH_INTEGRITY_CAPABILITIES (MS-SMB2 2.2.3.1.1).
	// Data: HashAlgorithmCount(2) + SaltLength(2) + SHA-512(2) + 32-byte salt.
	const preauthDataLen = 2 + 2 + 2 + 32 // 38 bytes
	preauthCtxLen := 8 + preauthDataLen   // 46 bytes (header + data)
	preauthPadded := preauthCtxLen + (8-preauthCtxLen%8)%8

	// Context 2: SMB2_ENCRYPTION_CAPABILITIES (MS-SMB2 2.2.3.1.2).
	// Data: CipherCount(2) + 4 ciphers(8).
	const encDataLen = 2 + 4*2  // 10 bytes
	encCtxLen := 8 + encDataLen // 18 bytes (last context, no padding)

	totalLen := ctxOffset + preauthPadded + encCtxLen
	pkt := make([]byte, totalLen)

	// -- SMB2 Header --
	copy(pkt[0:4], []byte{0xFE, 'S', 'M', 'B'})  // ProtocolId
	binary.LittleEndian.PutUint16(pkt[4:6], 64)  // StructureSize (header)
	binary.LittleEndian.PutUint16(pkt[12:14], 0) // Command: NEGOTIATE
	binary.LittleEndian.PutUint16(pkt[14:16], 1) // CreditRequest

	// -- Negotiate Request Body --
	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], uint16(gosmb.SecurityModeSigningEnabled))
	// body[6:8] Reserved = 0
	// body[8:12] Capabilities = 0
	// body[12:28] ClientGuid = 0
	// body[28:32] NegotiateContextOffset (from header start)
	binary.LittleEndian.PutUint32(body[28:32], uint32(ctxOffset))
	// body[32:34] NegotiateContextCount
	binary.LittleEndian.PutUint16(body[32:34], 2)
	// body[34:36] Reserved2 = 0

	// Dialects array at body offset 36.
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:38+i*2], d)
	}

	// -- Negotiate Contexts (at pkt[ctxOffset:]) --
	ctx := pkt[ctxOffset:]

	// Context 1: SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
	binary.LittleEndian.PutUint16(ctx[0:2], 0x0001)         // ContextType
	binary.LittleEndian.PutUint16(ctx[2:4], preauthDataLen) // DataLength
	// ctx[4:8] Reserved = 0
	binary.LittleEndian.PutUint16(ctx[8:10], 1)       // HashAlgorithmCount
	binary.LittleEndian.PutUint16(ctx[10:12], 32)     // SaltLength
	binary.LittleEndian.PutUint16(ctx[12:14], 0x0001) // SHA-512
	// ctx[14:46] Salt = 32 zero bytes (sufficient for a probe)

	// Context 2: SMB2_ENCRYPTION_CAPABILITIES.
	ctx2 := ctx[preauthPadded:]
	binary.LittleEndian.PutUint16(ctx2[0:2], 0x0002)     // ContextType
	binary.LittleEndian.PutUint16(ctx2[2:4], encDataLen) // DataLength
	// ctx2[4:8] Reserved = 0
	binary.LittleEndian.PutUint16(ctx2[8:10], 4)       // CipherCount
	binary.LittleEndian.PutUint16(ctx2[10:12], 0x0001) // AES-128-CCM
	binary.LittleEndian.PutUint16(ctx2[12:14], 0x0002) // AES-128-GCM
	binary.LittleEndian.PutUint16(ctx2[14:16], 0x0003) // AES-256-CCM
	binary.LittleEndian.PutUint16(ctx2[16:18], 0x0004) // AES-256-GCM

	return pkt
}

// buildSMB1NegotiateRequest creates a raw SMB1 negotiate offering only
// "NT LM 0.12" (the SMBv1 dialect).
func buildSMB1NegotiateRequest() []byte {
	// Dialect string: \x02 + "NT LM 0.12" + \x00
	dialect := append([]byte{0x02}, append([]byte("NT LM 0.12"), 0x00)...)

	// SMB1 header = 32 bytes, word count(1)=0, byte count(2)=len(dialect).
	headerSize := 32
	pkt := make([]byte, headerSize+1+2+len(dialect))

	copy(pkt[0:4], []byte{0xFF, 'S', 'M', 'B'}) // ProtocolId
	pkt[4] = 0x72                               // Command: SMB_COM_NEGOTIATE

	// Flags: case-insensitive pathnames.
	pkt[13] = 0x08
	// Flags2: knows long names, knows extended attributes.
	binary.LittleEndian.PutUint16(pkt[14:16], 0xC001)

	// WordCount = 0 (no parameter words for negotiate).
	pkt[headerSize] = 0
	// ByteCount = dialect string length.
	binary.LittleEndian.PutUint16(pkt[headerSize+1:headerSize+3], uint16(len(dialect)))
	copy(pkt[headerSize+3:], dialect)

	return pkt
}

// parseSMB2NegotiateResponse extracts SecurityMode, Capabilities,
// DialectRevision, and (for 3.1.1) encryption support from negotiate contexts.
func parseSMB2NegotiateResponse(resp []byte) (*NegotiateResult, error) {
	if len(resp) < 4 {
		return nil, errors.New("response too short")
	}
	// Validate SMB2 magic.
	if resp[0] != 0xFE || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' {
		return nil, fmt.Errorf("expected SMB2 magic, got %02x%02x%02x%02x", resp[0], resp[1], resp[2], resp[3])
	}
	// Negotiate response body starts after the 64-byte SMB2 header.
	if len(resp) < 64+4 {
		return nil, errors.New("response too short for SMB2 negotiate body")
	}

	body := resp[64:]

	// Negotiate response structure (MS-SMB2 2.2.4):
	// Offset  Field
	// 0       StructureSize (uint16, must be 65)
	// 2       SecurityMode (uint16)
	// 4       DialectRevision (uint16)
	// 6       NegotiateContextCount/Reserved (uint16)
	// 8       ServerGuid (16 bytes)
	// 24      Capabilities (uint32)
	// 56      SecurityBufferOffset (uint16)
	// 58      SecurityBufferLength (uint16)
	// 60      NegotiateContextOffset/Reserved (uint32)
	if len(body) < 28 {
		return nil, errors.New("negotiate response body too short")
	}

	securityMode := binary.LittleEndian.Uint16(body[2:4])
	dialectRevision := binary.LittleEndian.Uint16(body[4:6])
	capabilities := binary.LittleEndian.Uint32(body[24:28])

	result := &NegotiateResult{
		SigningRequired: (securityMode & uint16(gosmb.SecurityModeSigningRequired)) != 0,
		HighestDialect:  dialectRevision,
	}

	// For pre-3.1.1 dialects, encryption is indicated by CAP_ENCRYPTION in Capabilities.
	// For 3.1.1, encryption is negotiated via SMB2_ENCRYPTION_CAPABILITIES context.
	if dialectRevision >= gosmb.DialectSmb_3_1_1 {
		result.EncryptionSupported = parseEncryptionContext(resp, body)
	} else {
		result.EncryptionSupported = (capabilities & gosmb.GlobalCapEncryption) != 0
	}

	return result, nil
}

// parseEncryptionContext walks the negotiate context list in a 3.1.1 response
// and returns true if the server included an SMB2_ENCRYPTION_CAPABILITIES
// context (0x0002) with at least one cipher.
func parseEncryptionContext(resp, body []byte) bool {
	// Need NegotiateContextCount at body[6:8] and NegotiateContextOffset at body[60:64].
	if len(body) < 64 {
		return false
	}
	ctxCount := binary.LittleEndian.Uint16(body[6:8])
	ctxOffset := binary.LittleEndian.Uint32(body[60:64])
	if ctxCount == 0 || ctxOffset == 0 {
		return false
	}

	// Contexts are at resp[ctxOffset:] (offset from header start).
	pos := int(ctxOffset)
	for range ctxCount {
		if pos+8 > len(resp) {
			break
		}
		ctxType := binary.LittleEndian.Uint16(resp[pos : pos+2])
		dataLen := int(binary.LittleEndian.Uint16(resp[pos+2 : pos+4]))
		data := resp[pos+8:]
		if len(data) < dataLen {
			break
		}

		if ctxType == 0x0002 && dataLen >= 4 { // SMB2_ENCRYPTION_CAPABILITIES
			cipherCount := binary.LittleEndian.Uint16(data[0:2])
			if cipherCount > 0 {
				return true
			}
		}

		// Advance to next context (8-byte aligned, except the last).
		entryLen := 8 + dataLen
		entryLen += (8 - entryLen%8) % 8
		pos += entryLen
	}
	return false
}

// ---------------------------------------------------------------------------
// NetBIOS session transport helpers
// ---------------------------------------------------------------------------

// sendNetBIOS wraps an SMB packet in a 4-byte NetBIOS session header
// (message type 0x00 + 3-byte big-endian length) and writes it.
func sendNetBIOS(conn net.Conn, pkt []byte) error {
	hdr := make([]byte, 4)
	// Type 0x00 (session message). Length in 3 bytes big-endian.
	hdr[1] = byte(len(pkt) >> 16)
	hdr[2] = byte(len(pkt) >> 8)
	hdr[3] = byte(len(pkt))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(pkt)
	return err
}

// recvNetBIOS reads a 4-byte NetBIOS session header, then the payload.
// Returns the raw SMB packet (header bytes stripped).
func recvNetBIOS(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 || length > 1<<20 { // sanity: cap at 1 MiB
		return nil, fmt.Errorf("invalid NetBIOS payload length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// Family B — Null session and guest probes (go-smb throwaway connections)
// ---------------------------------------------------------------------------

// ProbeSMBNullSession tests whether the DC accepts an SMB null session
// (empty credentials). Returns true if the session is established and
// flagged as null by the server.
func (c *ActiveDirectoryConnection) ProbeSMBNullSession() (bool, error) {
	smbConn, err := gosmb.NewConnection(gosmb.Options{
		Host:        c.dcHost,
		Port:        445,
		DialTimeout: smbProbeTimeout,
		Initiator:   &spnego.NTLMInitiator{NullSession: true},
	})
	if err != nil {
		// Connection refused or negotiate failure — null session test inconclusive.
		if isConnectionRefused(err) {
			return false, fmt.Errorf("port 445 unreachable on %s: %w", c.dcHost, err)
		}
		// Session setup rejected — null session is blocked.
		return false, nil
	}
	defer smbConn.Close()

	return smbConn.IsNullSession(), nil
}

// ProbeSMBGuestAccess tests whether the DC falls back to a guest session
// when invalid credentials are presented. Uses a non-existent username
// and random password to avoid triggering lockout on real accounts.
func (c *ActiveDirectoryConnection) ProbeSMBGuestAccess() (bool, error) {
	smbConn, err := gosmb.NewConnection(gosmb.Options{
		Host:        c.dcHost,
		Port:        445,
		DialTimeout: smbProbeTimeout,
		Initiator: &spnego.NTLMInitiator{
			User:     "mondoo_guest_probe_nonexistent",
			Password: "ProbePassword!NoLockout42",
			Domain:   "",
		},
	})
	if err != nil {
		if isConnectionRefused(err) {
			return false, fmt.Errorf("port 445 unreachable on %s: %w", c.dcHost, err)
		}
		// Auth rejected outright — guest fallback is blocked.
		return false, nil
	}
	defer smbConn.Close()

	return smbConn.IsGuestSession(), nil
}

func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	return errors.Is(opErr.Err, syscall.ECONNREFUSED)
}

// ---------------------------------------------------------------------------
// Authenticated SMB session (lazy, cached via sync.Once)
// ---------------------------------------------------------------------------

// SMBSession returns a cached authenticated SMB connection for DCERPC use.
// Only available in simple-bind (NTLM) mode. Returns an error in Kerberos
// mode until explicit Kerberos SMB support is wired.
func (c *ActiveDirectoryConnection) SMBSession() (*gosmb.Connection, error) {
	c.smbOnce.Do(func() {
		c.smbConn, c.smbErr = c.dialSMBSession()
	})
	return c.smbConn, c.smbErr
}

func (c *ActiveDirectoryConnection) dialSMBSession() (*gosmb.Connection, error) {
	initiator, err := c.resolveSMBInitiator()
	if err != nil {
		return nil, err
	}

	smbConn, err := gosmb.NewConnection(gosmb.Options{
		Host:        c.dcHost,
		Port:        445,
		DialTimeout: smbProbeTimeout,
		Initiator:   initiator,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticated SMB session to %s: %w", c.dcHost, err)
	}
	return smbConn, nil
}

// resolveSMBInitiator builds an NTLM initiator from the current credential
// context. Kerberos modes are not yet supported for SMB; authenticated
// SMB-backed fields will surface as data unavailable.
func (c *ActiveDirectoryConnection) resolveSMBInitiator() (*spnego.NTLMInitiator, error) {
	useKerberos := strings.EqualFold(c.Conf.Options[OptionKerberos], "true")
	if useKerberos {
		return nil, errors.New("authenticated SMB/DCERPC requires NTLM credentials; " +
			"Kerberos-authenticated SMB is not yet supported — " +
			"use --user/--password without --kerberos for SMB-backed checks " +
			"(ldapChannelBindingRequired)")
	}

	user, password := c.resolveCredentials()
	if user == "" || password == "" {
		return nil, errors.New("authenticated SMB session requires --user and --password")
	}

	// Extract domain from UPN if present (user@DOMAIN → domain, user).
	domain := c.Conf.Options[OptionDomain]
	parts := strings.SplitN(user, "@", 2)
	if len(parts) == 2 {
		user = parts[0]
		if domain == "" {
			domain = parts[1]
		}
	}

	return &spnego.NTLMInitiator{
		User:     user,
		Password: password,
		Domain:   domain,
	}, nil
}

// ---------------------------------------------------------------------------
// Remote Registry — narrow DWORD reader via DCERPC MS-RRP
// ---------------------------------------------------------------------------

// ProbeRegistryDWORD reads a single DWORD value from the remote registry
// via DCERPC over the authenticated SMB session. Returns the value and any
// error. The caller must ensure SMBSession() succeeds before calling this.
//
// Example: ProbeRegistryDWORD(msrrp.HKEYLocalMachine,
//
//	`SYSTEM\CurrentControlSet\Services\NTDS\Parameters`,
//	"LdapEnforceChannelBinding")
func (c *ActiveDirectoryConnection) ProbeRegistryDWORD(hive byte, subkeyPath, valueName string) (uint32, error) {
	session, err := c.SMBSession()
	if err != nil {
		return 0, fmt.Errorf("registry DWORD probe: %w", err)
	}

	// Open the winreg named pipe on IPC$.
	file, err := session.OpenFile("IPC$", "winreg")
	if err != nil {
		return 0, fmt.Errorf("opening winreg pipe: %w", err)
	}
	defer func() { _ = file.CloseFile() }()

	transport, err := smbtransport.NewSMBTransport(file)
	if err != nil {
		return 0, fmt.Errorf("creating SMB transport: %w", err)
	}

	bind, err := dcerpc.Bind(transport, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, msrrp.NDRUuid)
	if err != nil {
		return 0, fmt.Errorf("DCERPC bind to winreg: %w", err)
	}

	rpc := msrrp.NewRPCCon(bind)

	// Open base key (e.g., HKLM).
	hKey, err := rpc.OpenBaseKey(hive)
	if err != nil {
		return 0, fmt.Errorf("opening base key %d: %w", hive, err)
	}
	defer func() { _ = rpc.CloseKeyHandle(hKey) }()

	// Open subkey path.
	hSubKey, err := rpc.OpenSubKey(hKey, subkeyPath)
	if err != nil {
		return 0, fmt.Errorf("opening subkey %q: %w", subkeyPath, err)
	}
	defer func() { _ = rpc.CloseKeyHandle(hSubKey) }()

	// Read value.
	result, dataType, err := rpc.QueryValueExt(hSubKey, valueName)
	if err != nil {
		// msrrp returns a plain string error for missing values. Translate to a
		// typed sentinel so callers can distinguish "not configured" from real failures.
		if strings.Contains(err.Error(), "not found") {
			return 0, fmt.Errorf("reading registry value %q: %w", valueName, ErrRegistryValueNotFound)
		}
		return 0, fmt.Errorf("reading registry value %q: %w", valueName, err)
	}

	if dataType != msrrp.RegDword {
		return 0, fmt.Errorf("expected REG_DWORD for %q, got type %d", valueName, dataType)
	}

	val, ok := result.(uint32)
	if !ok {
		return 0, fmt.Errorf("unexpected Go type for REG_DWORD value %q: %T", valueName, result)
	}

	log.Debug().Str("key", subkeyPath).Str("value", valueName).Uint32("data", val).Msg("remote registry DWORD read")
	return val, nil
}
