// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// shake that SSL

package tlsshake

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/v13/utils/multierr"
	"golang.org/x/crypto/ocsp"
)

var TLS_VERSIONS = []string{"ssl3", "tls1.0", "tls1.1", "tls1.2", "tls1.3"}

// ScanConfig allows to tune the TLS scanner
type ScanConfig struct {
	Versions                  []string
	SNIsupported              bool
	FakeSNI                   bool
	SecureClientRenegotiation bool
	// ConnectTimeout is used to check if a connection exists in the first place.
	// It is only used for the initial verification OSI Layer 4
	ConnectTimeout time.Duration

	// internal scan fields that users don't configure
	version       string
	ciphersFilter func(string) bool
}

const DefaultTimeout = 2 * time.Second

var ErrFailedToConnect = errors.New("failed to connect")

var ErrFailedToWrite = errors.New("failed to write")

var ErrFailedToTlsResponse = errors.New("failed to get a TLS response")

var ErrTimeout = errors.New("timeout failure")

func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		SNIsupported:              true,
		FakeSNI:                   true,
		SecureClientRenegotiation: true,
		ConnectTimeout:            DefaultTimeout,
	}
}

// Tester is the test runner and results object for any findings done in a
// session of tests. We re-use it to avoid duplicate requests and optimize
// the overall test run.
type Tester struct {
	Findings   Findings
	sync       sync.Mutex
	proto      string
	target     string
	domainName string
}

// Findings tracks the current state of tested components and their findings
type Findings struct {
	Versions           map[string]bool
	Ciphers            map[string]bool
	Extensions         map[string]bool
	Errors             []string
	Certificates       []*x509.Certificate
	NonSNIcertificates []*x509.Certificate
	Revocations        map[string]*Revocation
	NegotiatedGroup    string
}

type Revocation struct {
	At     time.Time
	Via    string
	Reason int
}

// New creates a new tester object for the given target (via proto, host, port)
//   - the proto, host, and port are used to construct the target for net.Dial
//     example: proto="tcp", host="mondoo.io", port=443
func New(proto string, domainName string, host string, port int) *Tester {
	target := host + ":" + strconv.Itoa(port)

	return &Tester{
		Findings: Findings{
			Versions:    map[string]bool{},
			Ciphers:     map[string]bool{},
			Extensions:  map[string]bool{},
			Revocations: map[string]*Revocation{},
		},
		proto:      proto,
		target:     target,
		domainName: domainName,
	}
}

// Test runs the TLS/SSL probes for a given scan configuration
//   - versions may contain any supported pre-defined TLS/SSL versions
//     with a complete list found in TLS_VERSIONS. Leave empty to test all.
func (s *Tester) Test(conf ScanConfig) error {
	// Default minimum timeout if none is set
	if conf.ConnectTimeout == 0 {
		conf.ConnectTimeout = DefaultTimeout
	}

	// Check if we can connect to the endpoint at all.
	conn, err := net.DialTimeout(s.proto, s.target, conf.ConnectTimeout)
	if err != nil {
		return ErrFailedToConnect
	}
	if conn != nil {
		// we ignore the error here for now
		_ = conn.Close()
	}

	if len(conf.Versions) == 0 {
		conf.Versions = TLS_VERSIONS
	}

	var workers sync.WaitGroup
	var errs multierr.Errors

	remainingCiphers := func(cipher string) bool {
		s.sync.Lock()
		defer s.sync.Unlock()
		if v, ok := s.Findings.Ciphers[cipher]; ok && v {
			return false
		}
		return true
	}
	supportedCiphers := func(cipher string) bool {
		s.sync.Lock()
		defer s.sync.Unlock()
		if v, ok := s.Findings.Ciphers[cipher]; ok && v {
			return true
		}
		return false
	}

	for i := range conf.Versions {
		version := conf.Versions[i]

		workers.Add(1)
		go func() {
			defer workers.Done()

			// we don't activate any of the additional tests in the beginning
			// let's find out if we work on this version of TLS/SSL
			curConf := &ScanConfig{
				version:       version,
				ciphersFilter: remainingCiphers,
			}

			for {
				remaining, err := s.testTLS(s.proto, s.target, curConf)
				if err != nil {
					s.sync.Lock()
					errs.Add(err)
					s.sync.Unlock()
					return
				}

				if remaining <= 0 {
					break
				}
			}

			if version == "tls1.2" || version == "tls1.3" {
				if conf.SNIsupported || conf.SecureClientRenegotiation {
					curConf = &ScanConfig{
						version:                   version,
						ciphersFilter:             supportedCiphers,
						SNIsupported:              conf.SNIsupported,
						SecureClientRenegotiation: conf.SecureClientRenegotiation,
					}
					// we don't record separate per-version errors for now
					_, _ = s.testTLS(s.proto, s.target, curConf)
				}

				if conf.FakeSNI {
					curConf = &ScanConfig{
						version:       version,
						ciphersFilter: supportedCiphers,
						FakeSNI:       conf.FakeSNI,
					}
					// we don't record separate per-version errors for now
					_, _ = s.testTLS(s.proto, s.target, curConf)
				}
			}
		}()
	}

	workers.Wait()

	resErr := errs.Deduplicate()

	// After deduplicating all the errors, there is one special case:
	// If we only received one unique error, and it indicates that we cannot
	// get any TLS response, then we can declare this entire scan to be
	// a non-TLS scan and just return that error. If errors are mixed, we have to
	// return them one by one, because valid responses have been reached.
	// But if all we get is this error, there is no TLS at this endpoint.
	mE, ok := resErr.(*multierr.Errors)
	if !ok {
		return resErr // or handle it as per your logic
	}

	if len(mE.Errors) == 1 && errors.Is(mE.Errors[0], ErrFailedToTlsResponse) {
		return ErrFailedToTlsResponse
	}

	return resErr
}

// Attempts to connect to an endpoint with a given version and records
// results in the Tester.
// Returns the number of remaining ciphers to test (if so desired)
// and any potential error
func (s *Tester) testTLS(proto string, target string, conf *ScanConfig) (int, error) {
	conn, err := net.Dial(proto, target)
	if err != nil {
		return 0, multierr.Wrap(err, "failed to connect to target")
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	defer conn.Close()

	return s.testTLSWithConn(conn, conf)
}

func (s *Tester) testTLSWithConn(conn net.Conn, conf *ScanConfig) (int, error) {
	msg, cipherCount, err := s.helloTLSMsg(conf)
	if err != nil {
		return 0, err
	}

	_, err = conn.Write(msg)
	if err != nil {
		return 0, ErrFailedToWrite
	}

	success, err := s.parseHello(conn, conf)
	if err != nil || !success {
		return 0, err
	}

	return cipherCount - 1, nil
}

func (s *Tester) addError(msg string) {
	s.sync.Lock()
	s.Findings.Errors = append(s.Findings.Errors, msg)
	s.sync.Unlock()
}

func (s *Tester) parseAlert(data []byte, conf *ScanConfig) error {
	// An Alert record body is 2 bytes (level + description). A hostile or broken
	// server can send a shorter body; guard before indexing so we don't panic.
	if len(data) < 2 {
		return errors.New("malformed TLS/SSL alert (body too short)")
	}
	var severity string
	switch data[0] {
	case '\x01':
		severity = "Warning"
	case '\x02':
		severity = "Fatal"
	default:
		severity = "Unknown"
	}

	description, ok := ALERT_DESCRIPTIONS[data[1]]
	if !ok {
		description = "cannot find description"
	}

	switch description {
	case "PROTOCOL_VERSION":
		// here we know the TLS version is not supported
		s.sync.Lock()
		s.Findings.Versions[conf.version] = false
		s.sync.Unlock()

	case "HANDSHAKE_FAILURE":
		if conf.version == "ssl3" {
			// Note: it's a little fuzzy here, since we don't know if the protocol
			// version is unsupported or just its ciphers. So we check if we found
			// it previously and if so, don't add it to the list of unsupported
			// versions.
			s.sync.Lock()
			if _, ok := s.Findings.Versions["ssl3"]; !ok {
				s.Findings.Versions["ssl3"] = false
			}
			s.sync.Unlock()
		}

		names := cipherNames(conf.version, conf.ciphersFilter)
		for i := range names {
			name := names[i]
			s.sync.Lock()
			if _, ok := s.Findings.Ciphers[name]; !ok {
				s.Findings.Ciphers[name] = false
			}
			s.sync.Unlock()
		}

	default:
		s.addError("failed to connect via " + conf.version + ": " + severity + " - " + description)
	}

	return nil
}

// helloRetryRequestRandom is the value of the random field in a ServerHello
// message that indicates a HelloRetryRequest. We must check for this value
// in order to handle HelloRetryRequests correctly. Otherwise, we will
// incorrectly interpret the message as a ServerHello. The server will
// wait for us to send a new ClientHello with the correct parameters. And we
// will be stuck waiting for data that will never come.
var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

func hexdump(data []byte) string {
	var res bytes.Buffer
	for i := 0; i < len(data); i++ {
		if i > 0 {
			res.WriteString(" ")
		}
		res.WriteString(hex.EncodeToString(data[i : i+1]))
	}
	return res.String()
}

func (s *Tester) parseServerHello(data []byte, version string, conf *ScanConfig) error {
	idx := 0

	// version(2) + random(32) + session-ID-length(1) are mandatory fixed fields.
	// The whole body length is attacker-controlled, so bounds-check before every
	// read; an unchecked index here panics and takes down the entire scan.
	if len(data) < idx+35 {
		return errors.New("malformed ServerHello (too short for random + session-ID length)")
	}
	idx += 2
	random := data[idx : idx+32]
	isHelloRetryRequest := bytes.Equal(random, helloRetryRequestRandom)

	idx += 32

	// we don't need the session ID
	sessionIDlen := byte1int(data[idx])
	idx += 1
	idx += sessionIDlen

	// cipher(2) + compression(1) follow the (variable-length) session ID.
	if idx+3 > len(data) {
		return errors.New("malformed ServerHello (truncated before cipher suite)")
	}
	cipher, cipherOK := ALL_CIPHERS[string(data[idx:idx+2])]
	idx += 2

	// TLS 1.3 pretends to be TLS 1.2 in the preceding headers for
	// compatibility. To correctly identify it, we have to look at
	// any Supported Versions extensions that the server sent us.

	// compression method (which should be set to null)
	idx += 1

	// no extensions found
	var allExtLen int
	if len(data) >= idx+2 {
		allExtLen = bytes2int(data[idx : idx+2])
		idx += 2
	}

	var serverKeyShareGroup []byte
	for allExtLen > 0 && idx+4 <= len(data) {
		extType := string(data[idx : idx+2])
		extLen := bytes2int(data[idx+2 : idx+4])
		if idx+4+extLen > len(data) {
			// extension length runs past the record; stop rather than panic,
			// but surface the truncation so a malformed/misconfigured
			// ServerHello isn't silently treated as fully parsed.
			s.sync.Lock()
			s.Findings.Errors = append(s.Findings.Errors, "malformed ServerHello: extension length runs past the record")
			s.sync.Unlock()
			break
		}
		extData := data[idx+4 : idx+4+extLen]

		allExtLen -= 4 + extLen
		idx += 4 + extLen

		switch extType {
		case EXTENSION_SupportedVersions:
			if v, ok := VERSIONS_LOOKUP[string(extData)]; ok {
				version = v
			} else {
				s.sync.Lock()
				s.Findings.Errors = append(s.Findings.Errors, "Failed to parse supported_versions extension: '"+string(extData)+"'")
				s.sync.Unlock()
			}
		case EXTENSION_RenegotiationInfo:
			s.sync.Lock()
			s.Findings.Extensions["renegotiation_info"] = true
			s.sync.Unlock()
		case EXTENSION_KeyShare:
			if len(extData) >= 2 {
				serverKeyShareGroup = extData[0:2]
			}
		}
	}

	if isHelloRetryRequest {
		if len(serverKeyShareGroup) > 0 {
			serverKeyShareGroupHex := hexdump(serverKeyShareGroup)
			return errors.New("unexpected HelloRetryRequest. (key_share_selected_group = " + serverKeyShareGroupHex + ")")
		}
		// The server wants us to retry. However, we hardcode a bunch of inputs
		// so we can't really retry.
		return errors.New("unexpected HelloRetryRequest")
	}

	// Store the negotiated key exchange group if we recognized it
	if len(serverKeyShareGroup) > 0 {
		if groupName, ok := NAMED_GROUPS[string(serverKeyShareGroup)]; ok {
			s.sync.Lock()
			s.Findings.NegotiatedGroup = groupName
			s.sync.Unlock()
		}
	}

	// we have to wait for any changes to the detected version (in the extensions)
	// once done, let's lock it once and write all results
	s.sync.Lock()
	if !cipherOK {
		s.Findings.Ciphers["unknown"] = true
	} else {
		s.Findings.Ciphers[cipher] = true
	}
	s.Findings.Versions[version] = true
	s.sync.Unlock()

	return nil
}

func (s *Tester) parseCertificate(data []byte, conf *ScanConfig) error {
	if len(data) < 3 {
		return errors.New("malformed certificate response, too little data read from stream to parse certificate")
	}
	certsLen := bytes3int(data[0:3])
	if len(data) < certsLen+3 {
		return errors.New("malformed certificate response, too little data read from stream to parse certificate")
	}

	certs := []*x509.Certificate{}
	i := 3
	for i < 3+certsLen {
		// each cert is prefixed by a 3-byte length; both the prefix and the cert
		// body it describes are attacker-controlled and must stay within data.
		if i+3 > len(data) {
			return errors.New("malformed certificate response, truncated certificate length prefix")
		}
		certLen := bytes3int(data[i : i+3])
		i += 3

		if i+certLen > len(data) {
			return errors.New("malformed certificate response, certificate length exceeds record")
		}
		rawCert := data[i : i+certLen]
		i += certLen

		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			s.addError(
				multierr.Wrap(err, "failed to parse certificate (x509 parser error)").Error(),
			)
		} else {
			certs = append(certs, cert)
		}
	}

	// TODO: we are currently overwriting any certs that may have been tested already
	// The assumption is that the same endpoint will always return the same
	// certificates no matter what version/configuration is used.
	// This may not be true and in case it isn't improve this code to carefully
	// write new certificates and manage separate certificate chains
	s.sync.Lock()
	if conf.SNIsupported {
		// by default we collect with SNI enabled. If the test is set to test SNI,
		// we actually test the exact opposite, ie what do we get without SNI.
		// Thus, we collect the non-sni certificates here
		s.Findings.NonSNIcertificates = certs

		if len(certs) != 0 && len(s.Findings.Certificates) != 0 {
			if !bytes.Equal(certs[0].Raw, s.Findings.Certificates[0].Raw) {
				s.Findings.Extensions["server_name"] = true
			}
		}
	} else if conf.FakeSNI {
		if len(certs) != 0 && len(s.Findings.NonSNIcertificates) != 0 {
			if bytes.Equal(certs[0].Raw, s.Findings.NonSNIcertificates[0].Raw) {
				s.Findings.Extensions["fake_server_name"] = true
			}
		}
	} else {
		s.Findings.Certificates = certs
	}
	s.sync.Unlock()

	for i := 0; i+1 < len(certs); i++ {
		err := s.checkRevocation(certs[i], certs[i+1])
		if err != nil {
			s.addError(err.Error())
		}
	}

	return nil
}

// returns true if we are done parsing through handshake responses.
//   - If i'ts a ServerHello, it will check if we have certificates.
//     If we don't, we should read more handshake responses...
//     If we do, we might as well be done at this stage, no need to read more
//   - There are a few other responses that also signal that we are done
//     processing handshake responses, like ServerHelloDone or Finished
func (s *Tester) parseHandshake(data []byte, version string, conf *ScanConfig) (bool, int, error) {
	// The 4-byte handshake header (type + 3-byte length) and the body it
	// describes are attacker-controlled; a short record or an oversized length
	// field must not panic the slice operations below.
	if len(data) < 4 {
		return true, 0, errors.New("malformed TLS/SSL handshake (header too short)")
	}
	handshakeType := data[0]
	handshakeLen := bytes3int(data[1:4])
	bodyEnd := 4 + handshakeLen

	switch handshakeType {
	case HANDSHAKE_TYPE_ServerHello:
		if bodyEnd > len(data) {
			return true, 0, errors.New("malformed TLS/SSL handshake (ServerHello body exceeds record)")
		}
		err := s.parseServerHello(data[4:bodyEnd], version, conf)
		return false, handshakeLen, err
	case HANDSHAKE_TYPE_Certificate:
		if bodyEnd > len(data) {
			return true, 0, errors.New("malformed TLS/SSL handshake (Certificate body exceeds record)")
		}
		return true, handshakeLen, s.parseCertificate(data[4:bodyEnd], conf)
	case HANDSHAKE_TYPE_ServerKeyExchange:
		return false, handshakeLen, nil
	case HANDSHAKE_TYPE_ServerHelloDone:
		return true, handshakeLen, nil
	case HANDSHAKE_TYPE_Finished:
		return true, handshakeLen, nil
	default:
		typ := "0x" + hex.EncodeToString([]byte{handshakeType})
		s.addError("Unhandled TLS/SSL handshake: '" + typ + "'")
		return false, handshakeLen, nil
	}
}

// returns:
//
//	true if the handshake was successful, false otherwise
func (s *Tester) parseHello(conn net.Conn, conf *ScanConfig) (bool, error) {
	reader := bufio.NewReader(conn)
	header := make([]byte, 5)
	var success bool
	var done bool
	hasAlert := false

	for !done {
		_, err := io.ReadFull(reader, header)
		if err != nil {
			hasConnectionReset := strings.Contains(err.Error(), "connection reset by peer")
			if err == io.EOF {
				break
			} else if hasConnectionReset {
				// If we get a connection reset, we assume the server doesn't support
				// any of the ciphers we are testing.
				names := cipherNames(conf.version, conf.ciphersFilter)
				for i := range names {
					name := names[i]
					s.sync.Lock()
					if _, ok := s.Findings.Ciphers[name]; !ok {
						s.Findings.Ciphers[name] = false
					}
					s.sync.Unlock()
				}
				return false, nil
			} else if strings.Contains(err.Error(), "i/o timeout") {
				return false, ErrTimeout
			}
			return false, err
		}

		typ := "0x" + hex.EncodeToString(header[0:1])
		headerVersion := VERSIONS_LOOKUP[string(header[1:3])]
		if headerVersion == "" && hasAlert {
			break
		}

		msgLen := bytes2int(header[3:5])
		if msgLen == 0 {
			return false, errors.New("No body in TLS/SSL response (type: '" + typ + "')")
		}
		if msgLen > 1<<20 {
			return false, errors.New("TLS/SSL response body is too large (type: '" + typ + "')")
		}

		msg := make([]byte, msgLen)
		_, err = io.ReadFull(reader, msg)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return false, ErrFailedToTlsResponse
			}
			return false, multierr.Wrap(err, "Failed to read full TLS/SSL response body (type: '"+typ+"')")
		}

		switch header[0] {
		case CONTENT_TYPE_Alert:
			hasAlert = true
			// Do not grab the version here, instead use the pre-provided
			// There is a nice edge-case in TLS1.3 which is handled further down,
			// but not required here since we are dealing with an error
			if err := s.parseAlert(msg, conf); err != nil {
				return false, err
			}

		case CONTENT_TYPE_Handshake:
			var handshakeDone bool
			var handshakeLen int
			for !handshakeDone {
				handshakeDone, handshakeLen, err = s.parseHandshake(msg, headerVersion, conf)
				if err != nil {
					return false, err
				}
				if !handshakeDone {
					// If we are at the end of the msg, then we break out of the loop
					if handshakeLen+4 >= len(msg) {
						break
					}
					// this is the handshake type (1) and the length (3)
					msg = msg[handshakeLen+4:]
				}
			}
			success = true
			done = handshakeDone

		case CONTENT_TYPE_ChangeCipherSpec:
			// This also means we are done with this stream, since it signals that we
			// are no longer looking at a handshake.
			done = true

		case CONTENT_TYPE_Application:
			// Definitely don't care about anything past the handshake.
			done = true

		default:
			if hasAlert {
				done = true
				break
			}
			s.addError("Unhandled TLS/SSL response (received '" + typ + "')")
		}
	}

	return success, nil
}

func filterCipherMsg(org map[string]string, f func(cipher string) bool) ([]byte, int) {
	var res bytes.Buffer
	var n int
	for k, v := range org {
		if f(v) {
			res.WriteString(k)
			n++
		}
	}
	return res.Bytes(), n
}

func filterCipherNames(org map[string]string, f func(cipher string) bool) []string {
	var res []string
	for _, v := range org {
		if f(v) {
			res = append(res, v)
		}
	}
	return res
}

func cipherNames(version string, filter func(cipher string) bool) []string {
	switch version {
	case "ssl3":
		regular := filterCipherNames(SSL3_CIPHERS, filter)
		fips := filterCipherNames(SSL_FIPS_CIPHERS, filter)
		return append(regular, fips...)
	case "tls1.0", "tls1.1", "tls1.2":
		return filterCipherNames(TLS_CIPHERS, filter)
	case "tls1.3":
		return filterCipherNames(TLS13_CIPHERS, filter)
	default:
		return []string{}
	}
}

func writeExtension(buf *bytes.Buffer, typ string, body []byte) {
	buf.WriteString(typ)
	buf.Write(int2bytes(len(body)))
	buf.Write(body)
}

func sniMsg(domainName string) []byte {
	l := len(domainName)
	var res bytes.Buffer

	res.Write(int2bytes(l + 3)) // server name list length
	res.WriteByte('\x00')       // name type: host name
	res.Write(int2bytes(l))     // name length
	res.WriteString(domainName) // name

	return res.Bytes()
}

func (s *Tester) helloTLSMsg(conf *ScanConfig) ([]byte, int, error) {
	var ciphers []byte
	var cipherCount int

	var extensions bytes.Buffer

	if conf.version != "ssl3" {
		domainName := s.domainName
		if conf.SNIsupported {
			// don't write an SNI and see if we get a different certificates
			domainName = ""
		} else if conf.FakeSNI {
			// give it a fake name
			domainName = strconv.FormatUint(rand.Uint64(), 10) + ".com"
		}

		if domainName != "" {
			writeExtension(&extensions, EXTENSION_ServerName, sniMsg(domainName))
		}

		// add signature_algorithms
		extensions.WriteString("\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01")
	}

	if conf.version == "tls1.2" || conf.version == "tls1.3" {
		// Renegotiation info
		// https://datatracker.ietf.org/doc/html/rfc5746
		// - we leave the body empty, we only need a response to the request
		// - the body has 1 byte containing the length of the extension (which is 0)
		if conf.SecureClientRenegotiation {
			writeExtension(&extensions, EXTENSION_RenegotiationInfo, []byte("\x00"))
		}
	}

	switch conf.version {
	case "ssl3":
		regular, n1 := filterCipherMsg(SSL3_CIPHERS, conf.ciphersFilter)
		fips, n2 := filterCipherMsg(SSL_FIPS_CIPHERS, conf.ciphersFilter)
		ciphers = append(regular, fips...)
		cipherCount = n1 + n2

	case "tls1.0", "tls1.1", "tls1.2":
		org, n1 := filterCipherMsg(TLS10_CIPHERS, conf.ciphersFilter)
		tls, n2 := filterCipherMsg(TLS_CIPHERS, conf.ciphersFilter)
		ciphers = append(org, tls...)
		cipherCount = n1 + n2

		// add heartbeat
		extensions.WriteString("\x00\x0f\x00\x01\x01")
		// add ec_points_format
		extensions.WriteString("\x00\x0b\x00\x02\x01\x00")
		// add elliptic_curve
		extensions.WriteString("\x00\x0a\x00\x0a\x00\x08\xfa\xfa\x00\x1d\x00\x17\x00\x18")

	case "tls1.3":
		org, n1 := filterCipherMsg(TLS10_CIPHERS, conf.ciphersFilter)
		tls, n2 := filterCipherMsg(TLS_CIPHERS, conf.ciphersFilter)
		tls13, n3 := filterCipherMsg(TLS13_CIPHERS, conf.ciphersFilter)
		ciphers = append(org, tls...)
		ciphers = append(ciphers, tls13...)
		cipherCount = n1 + n2 + n3

		// TLSv1.3 Supported Versions extension
		extensions.WriteString("\x00\x2b\x00\x03\x02\x03\x04")
		// add supported groups extension
		extensions.WriteString("\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18")

		// This is a pre-generated public/private key pair using the x25519 curve:
		// It was generated from the command line with:
		//
		// > openssl-1.1.1e/apps/openssl genpkey -algorithm x25519 > pkey
		// > openssl-1.1.1e/apps/openssl pkey -noout -text < pkey
		// priv:
		//     30:90:f3:89:f4:9e:52:59:3c:ba:e9:f4:78:84:a0:
		//     23:86:73:5e:f5:c9:46:6c:3a:c3:4e:ec:56:57:81:
		//     5d:62
		// pub:
		//     e7:08:71:36:d0:81:e0:16:19:3a:cb:67:ca:b8:28:
		//     d9:45:92:16:ff:36:63:0d:0d:5a:3d:9d:47:ce:3e:
		//     cd:7e

		// The comment above is not how the stuff below was generated. It was taken
		// from a real-world TLS 1.3 handshake and then converted to a byte array.
		// It contains both x25519 and secp256r1 keys. I'm leaving the comment above
		// for reference, but it's not how the keys were generated.
		keyShareBytes := []byte{
			0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d,
			0x00, 0x20, 0x5b, 0x55, 0x18, 0x62, 0xb8, 0x87,
			0x93, 0xd2, 0xb5, 0xa3, 0xdf, 0x2d, 0xdf, 0x5a,
			0x05, 0x00, 0xaf, 0xa5, 0xde, 0xea, 0xd6, 0x3a,
			0x6e, 0x29, 0x10, 0x8e, 0x5b, 0xcf, 0xde, 0xc6,
			0x57, 0x08, 0x00, 0x17, 0x00, 0x41, 0x04, 0x6b,
			0xf2, 0x37, 0x7d, 0xf2, 0x20, 0xd5, 0x6f, 0xb0,
			0xde, 0xe7, 0x5f, 0x98, 0x79, 0x7a, 0x31, 0x54,
			0x10, 0x44, 0xde, 0xed, 0x4a, 0xfc, 0x59, 0xda,
			0x51, 0x00, 0x8a, 0xfe, 0x0a, 0xc6, 0x14, 0xea,
			0x07, 0xe3, 0x3a, 0xc5, 0x31, 0x55, 0xfb, 0x70,
			0xed, 0x4c, 0xdb, 0x84, 0x66, 0x47, 0xd2, 0x3a,
			0xd7, 0xe3, 0xf6, 0x0d, 0x72, 0x30, 0x6a, 0x73,
			0x54, 0xc1, 0x93, 0x1f, 0x97, 0x75, 0x44,
		}

		extensions.Write(keyShareBytes)

	default:
		return nil, 0, errors.New("unsupported TLS/SSL version: " + conf.version)
	}

	hello, err := constructTLSHello(conf.version, ciphers, extensions.Bytes())
	if err != nil {
		return nil, 0, err
	}
	return hello, cipherCount, nil
}

// OCSP:
// https://datatracker.ietf.org/doc/html/rfc6960
// https://datatracker.ietf.org/doc/html/rfc2560

// checkRevocation determines whether a certificate has been revoked and records
// the outcome in Findings.Revocations.
//
// OCSP is asked first. When the certificate names no responder, or the
// responder cannot be reached, the CRL it points at answers instead - which is
// now the common case, since the CA/Browser Forum made OCSP optional and
// several large issuers have retired their responders entirely.
//
// The map only gains an entry when a determination was actually reached:
// absent means unknown, a nil value means not revoked, and a non-nil value
// means revoked. Callers must keep that three-way distinction, because
// reporting an unchecked certificate as "not revoked" is indistinguishable
// from having checked.
func (s *Tester) checkRevocation(cert *x509.Certificate, issuer *x509.Certificate) error {
	determined, revocation, err := CheckRevocation(cert, issuer)
	if !determined {
		return err
	}

	s.recordRevocation(cert, revocation)
	return nil
}

// CheckRevocation determines whether a certificate has been revoked.
//
// The first return says whether a determination was reached at all. When it is
// false the certificate's status is unknown and the caller must report it as
// such: a certificate that could not be checked is not a certificate that is
// good. A nil Revocation with a true first return means the certificate was
// checked and is not revoked.
//
// Callers outside the handshake tester need this because the tester's findings
// describe the chain its own probes negotiated, which is not always the chain
// the caller is reporting on.
func CheckRevocation(cert *x509.Certificate, issuer *x509.Certificate) (bool, *Revocation, error) {
	var errs multierr.Errors

	determined, revocation, err := ocspRevocation(cert, issuer)
	if determined {
		return true, revocation, nil
	}
	errs.Add(err)

	determined, revocation, err = crlRevocation(cert, issuer)
	if determined {
		return true, revocation, nil
	}
	errs.Add(err)

	return false, nil, errs.Deduplicate()
}

// recordRevocation stores a reached determination. A nil revocation means the
// certificate was checked and is not revoked.
func (s *Tester) recordRevocation(cert *x509.Certificate, revocation *Revocation) {
	s.sync.Lock()
	s.Findings.Revocations[string(cert.Signature)] = revocation
	s.sync.Unlock()
}

// ocspRevocation asks the certificate's OCSP responder for its status.
//
// The first return says whether the responder answered at all. Everything that
// stops it from answering - no responder named, an unreachable one, a response
// that will not parse - leaves the status unknown rather than good.
func ocspRevocation(cert *x509.Certificate, issuer *x509.Certificate) (bool, *Revocation, error) {
	if len(cert.OCSPServer) == 0 {
		return false, nil, errors.New("no OCSP server specified for revocation check, skipping it")
	}

	server := cert.OCSPServer[0]

	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
	if err != nil {
		return false, nil, multierr.Wrap(err, "failed to create OCSP request")
	}

	reqBody := bytes.NewBuffer(req)
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Post(server, "application/ocsp-request", reqBody)
	if err != nil {
		return false, nil, multierr.Wrap(err, "failed to post OCSP request")
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, nil, errors.New("OCSP request returned " + res.Status)
	}
	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return false, nil, multierr.Wrap(err, "failed to read OCSP response")
	}
	ocspRes, err := ocsp.ParseResponseForCert(resp, cert, issuer)
	if err != nil {
		return false, nil, multierr.Wrap(err, "failed to parse OCSP response")
	}

	if ocspRes.RevokedAt.IsZero() {
		return true, nil, nil
	}
	return true, &Revocation{
		At:     ocspRes.RevokedAt,
		Via:    server,
		Reason: ocspRes.RevocationReason,
	}, nil
}

func int1byte(i int) []byte {
	res := make([]byte, 2)
	binary.BigEndian.PutUint16(res, uint16(i))
	return res[1:]
}

func int2bytes(i int) []byte {
	res := make([]byte, 2)
	binary.BigEndian.PutUint16(res, uint16(i))
	return res
}

func int3bytes(i int) []byte {
	res := make([]byte, 4)
	binary.BigEndian.PutUint32(res, uint32(i))
	return res[1:]
}

func byte1int(b byte) int {
	return int(binary.BigEndian.Uint16([]byte{0x00, b}))
}

func bytes2int(b []byte) int {
	return int(binary.BigEndian.Uint16(b))
}

func bytes3int(b []byte) int {
	return int(binary.BigEndian.Uint32(append([]byte{0x00}, b...)))
}

func constructTLSHello(version string, ciphers []byte, extensions []byte) ([]byte, error) {
	sessionID := ""
	compressions := "\x00"

	var content bytes.Buffer
	content.WriteString(VERSIONS[version])

	// The 32-byte ClientHello random must come from a cryptographically secure
	// source per the TLS spec.
	rnd := make([]byte, 32)
	if _, err := crand.Read(rnd); err != nil {
		return nil, err
	}
	content.Write(rnd)

	content.Write(int1byte(len(sessionID)))
	content.WriteString(sessionID)

	content.Write(int2bytes(len(ciphers)))
	content.Write(ciphers)

	content.Write(int1byte(len(compressions)))
	content.WriteString(compressions)

	content.Write(int2bytes(len(extensions)))
	content.Write(extensions)

	c := content.Bytes()

	core := []byte{HANDSHAKE_TYPE_ClientHello}
	core = append(core, int3bytes(len(c))...)
	core = append(core, c...)

	return constructTLSMsg(CONTENT_TYPE_Handshake, core, []byte(VERSIONS[version])), nil
}

func constructTLSMsg(contentType byte, content []byte, version []byte) []byte {
	var res bytes.Buffer
	res.WriteByte(contentType)
	res.Write(version)
	res.Write(int2bytes(len(content)))
	res.Write(content)
	return res.Bytes()
}

var VERSIONS = map[string]string{
	"ssl3":   "\x03\x00",
	"tls1.0": "\x03\x01",
	"tls1.1": "\x03\x02",
	"tls1.2": "\x03\x03",
	// RFC 8446 4.1.2:
	// In TLS 1.3, the client indicates its version preferences in the
	// "supported_versions" extension (Section 4.2.1) and the
	// legacy_version field MUST be set to 0x0303, which is the version
	// number for TLS 1.2.  TLS 1.3 ClientHellos are identified as having
	// a legacy_version of 0x0303 and a supported_versions extension
	// present with 0x0304 as the highest version indicated therein.
	"tls1.3": "\x03\x04",
}

var (
	VERSIONS_LOOKUP map[string]string
	ALL_CIPHERS     map[string]string
)

func init() {
	VERSIONS_LOOKUP = make(map[string]string, len(VERSIONS))
	for k, v := range VERSIONS {
		VERSIONS_LOOKUP[v] = k
	}

	ALL_CIPHERS = make(map[string]string,
		len(SSL2_CIPHERS)+
			len(SSL_FIPS_CIPHERS)+
			len(TLS10_CIPHERS)+
			len(TLS13_CIPHERS)+
			len(TLS_CIPHERS))

	// Note: overlapping names will be overwritten
	maps.Copy(ALL_CIPHERS, SSL2_CIPHERS)
	maps.Copy(ALL_CIPHERS, SSL3_CIPHERS)
	maps.Copy(ALL_CIPHERS, SSL_FIPS_CIPHERS)
	maps.Copy(ALL_CIPHERS, TLS10_CIPHERS)
	maps.Copy(ALL_CIPHERS, TLS13_CIPHERS)
	maps.Copy(ALL_CIPHERS, TLS_CIPHERS)
}

const (
	CONTENT_TYPE_ChangeCipherSpec byte = '\x14'
	CONTENT_TYPE_Alert            byte = '\x15'
	CONTENT_TYPE_Handshake        byte = '\x16'
	CONTENT_TYPE_Application      byte = '\x17'
	CONTENT_TYPE_Heartbeat        byte = '\x18'

	HANDSHAKE_TYPE_HelloRequest       byte = '\x00'
	HANDSHAKE_TYPE_ClientHello        byte = '\x01'
	HANDSHAKE_TYPE_ServerHello        byte = '\x02'
	HANDSHAKE_TYPE_NewSessionTicket   byte = '\x04'
	HANDSHAKE_TYPE_Certificate        byte = '\x0b'
	HANDSHAKE_TYPE_ServerKeyExchange  byte = '\x0c'
	HANDSHAKE_TYPE_CertificateRequest byte = '\x0d'
	HANDSHAKE_TYPE_ServerHelloDone    byte = '\x0e'
	HANDSHAKE_TYPE_CertificateVerify  byte = '\x0f'
	HANDSHAKE_TYPE_ClientKeyExchange  byte = '\x10'
	HANDSHAKE_TYPE_Finished           byte = '\x14'

	EXTENSION_ServerName        string = "\x00\x00"
	EXTENSION_SupportedVersions string = "\x00\x2b"
	EXTENSION_RenegotiationInfo string = "\xff\x01"
	EXTENSION_KeyShare          string = "\x00\x33"
)

// NAMED_GROUPS maps TLS named group IDs to their human-readable names.
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
var NAMED_GROUPS = map[string]string{
	"\x00\x17": "secp256r1",
	"\x00\x18": "secp384r1",
	"\x00\x19": "secp521r1",
	"\x00\x1d": "x25519",
	"\x00\x1e": "x448",
	"\x01\x00": "ffdhe2048",
	"\x01\x01": "ffdhe3072",
	"\x01\x02": "ffdhe4096",
	"\x01\x03": "ffdhe6144",
	"\x01\x04": "ffdhe8192",
	"\x11\xeb": "SecP256r1MLKEM768",
	"\x11\xec": "X25519MLKEM768",
	"\x11\xed": "SecP384r1MLKEM1024",
}

// https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.3
// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2
var ALERT_DESCRIPTIONS = map[byte]string{
	'\x00': "CLOSE_NOTIFY",
	'\x0A': "UNEXPECTED_MESSAGE",
	'\x14': "BAD_RECORD_MAC",
	'\x15': "DECRYPTION_FAILED_RESERVED",
	'\x16': "RECORD_OVERFLOW",
	'\x1E': "DECOMPRESSION_FAILURE",
	'\x28': "HANDSHAKE_FAILURE",
	'\x29': "NO_CERTIFICATE_RESERVED",
	'\x2A': "BAD_CERTIFICATE",
	'\x2B': "UNSUPPORTED_CERTIFICATE",
	'\x2C': "CERTIFICATE_REVOKED",
	'\x2D': "CERTIFICATE_EXPIRED",
	'\x2E': "CERTIFICATE_UNKNOWN",
	'\x2F': "ILLEGAL_PARAMETER",
	'\x30': "UNKNOWN_CA",
	'\x31': "ACCESS_DENIED",
	'\x32': "DECODE_ERROR",
	'\x33': "DECRYPT_ERROR",
	'\x3C': "EXPORT_RESTRICTION_RESERVED",
	'\x46': "PROTOCOL_VERSION",
	'\x47': "INSUFFICIENT_SECURITY",
	'\x50': "INTERNAL_ERROR",
	'\x56': "INAPPROPRIATE_FALLBACK",
	'\x5A': "USER_CANCELED",
	'\x64': "NO_RENEGOTIATION_RESERVED",
	'\x6D': "MISSING_EXTENSION",
	'\x6E': "UNSUPPORTED_EXTENSION",
	'\x6F': "CERTIFICATE_UNOBTAINABLE_RESERVED",
	'\x70': "UNRECOGNIZED_NAME",
	'\x71': "BAD_CERTIFICATE_STATUS_RESPONSE",
	'\x72': "BAD_CERTIFICATE_HASH_VALUE_RESERVED",
	'\x73': "UNKNOWN_PSK_IDENTITY",
	'\x74': "CERTIFICATE_REQUIRED",
	'\x78': "NO_APPLICATION_PROTOCOL",
}
