// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	krbflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	// Register hash implementations used for channel binding. MD5 is mandated by
	// RFC 4121 §4.1.1 for the authenticator checksum binding field (not used as a
	// cryptographic primitive); SHA-256/384/512 back the RFC 5929 cert hash.
	_ "crypto/md5" //nolint:gosec
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// gssTokIDKRB5APREQ is the GSSAPI KRB5 MechToken ID for an AP-REQ (RFC 4121).
const gssTokIDKRB5APREQ = "0100"

// channelBindingGSSAPIClient is an ldap.GSSAPIClient that mirrors the gokrb5
// bind performed by go-ldap's gssapi.Client but injects an RFC 5929
// "tls-server-end-point" channel binding into the AP-REQ authenticator
// checksum (RFC 4121 §4.1.1).
//
// go-ldap's cross-platform gssapi.Client (unlike its Windows SSPI client, which
// exposes NewSSPIClientWithChannelBinding) always emits an all-zero channel
// binding, so a Kerberos SASL bind against a domain controller that enforces
// LDAP channel binding (LdapEnforceChannelBinding = 2, "Always") is rejected
// with SEC_E_BAD_BINDINGS (0x80090346). This wrapper supplies the binding
// derived from the DC's TLS certificate so those hardened DCs accept the bind
// over LDAPS/StartTLS.
//
// It also sets the mutual-required AP option, which go-ldap leaves to the
// caller (go-ldap issue #536). Active Directory rejects an AP-REQ without it
// with AcceptSecurityContext data 57, whatever its channel binding setting.
//
// When bnd is empty (no TLS transport) the token differs from go-ldap's only
// in that AP option.
type channelBindingGSSAPIClient struct {
	krb5   *krbclient.Client
	closer func() error
	bnd    []byte // 16-byte MD5 channel binding, or nil for none

	ekey   types.EncryptionKey
	subkey types.EncryptionKey
}

// newChannelBindingClient wraps an already-initialized go-ldap gssapi.Client
// (keytab/ccache/password source) and derives the channel binding from the
// server certificate. A nil cert yields no binding (empty behavior parity).
func newChannelBindingClient(base *ldapgssapi.Client, cert *x509.Certificate) *channelBindingGSSAPIClient {
	return &channelBindingGSSAPIClient{
		krb5:   base.Client,
		closer: base.Close,
		bnd:    tlsServerEndPointBinding(cert),
	}
}

// InitSecContext initiates the GSSAPI security context. See RFC 4752 §3.1.
func (c *channelBindingGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, []int{})
}

// InitSecContextWithOptions mirrors go-ldap's gokrb5 bind but sets the channel
// binding in the AP-REQ authenticator checksum and requires mutual
// authentication.
func (c *channelBindingGSSAPIClient) InitSecContextWithOptions(target string, input []byte, apOptions []int) ([]byte, bool, error) {
	gssapiFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	if input == nil {
		tkt, ekey, err := c.krb5.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		c.ekey = ekey

		mechToken, err := c.newAPREQMechToken(tkt, ekey, gssapiFlags, apOptions)
		if err != nil {
			return nil, false, err
		}
		return mechToken, true, nil
	}

	var token spnego.KRB5Token
	if err := token.Unmarshal(input); err != nil {
		return nil, false, err
	}

	completed := false
	if token.IsAPRep() {
		completed = true
		encpart, err := krbcrypto.DecryptEncPart(token.APRep.EncPart, c.ekey, keyusage.AP_REP_ENCPART)
		if err != nil {
			return nil, false, err
		}
		part := &messages.EncAPRepPart{}
		if err := part.Unmarshal(encpart); err != nil {
			return nil, false, err
		}
		c.subkey = part.Subkey
	}
	if token.IsKRBError() {
		return nil, true, token.KRBError
	}
	return make([]byte, 0), !completed, nil
}

// NegotiateSaslAuth performs the final SASL handshake step. See RFC 4752 §3.1.
// We never request a security layer, matching go-ldap's behavior.
func (c *channelBindingGSSAPIClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	inToken := &gssapi.WrapToken{}
	if err := ldapgssapi.UnmarshalWrapToken(inToken, input, true); err != nil {
		return nil, err
	}
	if (inToken.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	key := c.ekey
	if (inToken.Flags & 0b100) != 0 {
		key = c.subkey
	}
	if _, err := inToken.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	if len(inToken.Payload) != 4 {
		return nil, fmt.Errorf("server sent bad final token for SASL GSSAPI handshake")
	}

	// Advertise no security layer (first octet 0x00) and no receive buffer.
	b := [4]byte{0, 0, 0, 0}
	payload := append(b[:], []byte(authzid)...)

	encType, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	outToken := &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}
	if err := outToken.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return outToken.Marshal()
}

// DeleteSecContext destroys any established secure context.
func (c *channelBindingGSSAPIClient) DeleteSecContext() error {
	c.ekey = types.EncryptionKey{}
	c.subkey = types.EncryptionKey{}
	return nil
}

// Close releases the underlying gokrb5 client.
func (c *channelBindingGSSAPIClient) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

var _ ldap.GSSAPIClient = (*channelBindingGSSAPIClient)(nil)

// newAPREQMechToken builds a GSSAPI KRB5 AP-REQ MechToken whose authenticator
// checksum carries the channel binding and whose AP options always include
// mutual-required. It mirrors gokrb5's spnego.NewKRB5TokenAPREQ, which does
// not expose a channel-binding hook.
func (c *channelBindingGSSAPIClient) newAPREQMechToken(tkt messages.Ticket, sessionKey types.EncryptionKey, gssapiFlags, apOptions []int) ([]byte, error) {
	auth, err := types.NewAuthenticator(c.krb5.Credentials.Domain(), c.krb5.Credentials.CName())
	if err != nil {
		return nil, fmt.Errorf("error generating authenticator: %w", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  authenticatorChecksum(gssapiFlags, c.bnd),
	}

	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return nil, err
	}
	// SASL GSSAPI requires mutual authentication (RFC 4752 §3.1) and the
	// checksum already asks for it, but go-ldap's GSSAPIBind passes no AP
	// options. Without mutual-required, AD rejects the AP-REQ (data 57).
	types.SetFlag(&apReq.APOptions, krbflags.APOptionMutualRequired)
	for _, o := range apOptions {
		types.SetFlag(&apReq.APOptions, o)
	}

	oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, fmt.Errorf("error marshalling krb5 OID: %w", err)
	}
	tokID, _ := hex.DecodeString(gssTokIDKRB5APREQ)
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshalling AP_REQ: %w", err)
	}

	b := append(oidBytes, tokID...)
	b = append(b, apReqBytes...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// authenticatorChecksum builds the 24-byte (or 28-byte with DCE-style delegation)
// GSSAPI authenticator checksum of RFC 4121 §4.1.1. Bytes 0-3 hold the length of
// the channel-binding field (16), bytes 4-19 hold the binding (Bnd), and bytes
// 20-23 hold the GSS flags. This mirrors gokrb5's unexported newAuthenticatorChksum
// but fills Bnd instead of leaving it zero.
func authenticatorChecksum(flags []int, bnd []byte) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	if len(bnd) == 16 {
		copy(a[4:20], bnd)
	}
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

// tlsServerEndPointBinding computes the 16-byte MD5 channel binding (the Bnd
// field of the GSSAPI authenticator checksum) for the RFC 5929
// "tls-server-end-point" binding derived from the server certificate.
//
// The application data is "tls-server-end-point:" followed by the certificate
// hash. Per RFC 5929 §4.1 the hash is the certificate signature hash algorithm,
// upgraded to SHA-256 when that algorithm is MD5 or SHA-1. The Bnd value is the
// MD5 of the GSS_C channel-bindings structure (all address fields empty), which
// is how MIT krb5 and Windows compute it.
func tlsServerEndPointBinding(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	appData := append([]byte("tls-server-end-point:"), certificateHash(cert)...)

	// GSS_C channel-bindings structure: initiator addrtype/len, acceptor
	// addrtype/len (all zero), then application-data len + bytes; 20-byte header.
	buf := make([]byte, 20+len(appData))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(appData)))
	copy(buf[20:], appData)

	h := crypto.MD5.New()
	h.Write(buf)
	return h.Sum(nil)
}

// certificateHash returns the tls-server-end-point certificate hash per RFC 5929.
func certificateHash(cert *x509.Certificate) []byte {
	var h crypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = crypto.SHA512
	default:
		// RFC 5929 §4.1: MD5/SHA-1 (and unknown) are upgraded to SHA-256.
		h = crypto.SHA256
	}
	hasher := h.New()
	hasher.Write(cert.Raw)
	return hasher.Sum(nil)
}
