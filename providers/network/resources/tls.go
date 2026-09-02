// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/tls"
	"crypto/x509"
	"maps"
	"net"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/core/resources/regex"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/resources/certificates"
	"go.mondoo.com/mql/providers/network/resources/tlsshake"
	"go.mondoo.com/mql/types"
)

var reTarget = regexp.MustCompile(`([^/:]+?)(:\d+)?$`)

var rexUrlDomain = regexp.MustCompile(regex.UrlDomain)

var DefaultDialerTimeout = tlsshake.DefaultTimeout

// Returns the connection's port adjusted for TLS.
// If no port is set, we estimate what it might be from the scheme.
// If that doesn't help, we set it to 443.
func connTlsPort(conn *connection.HostConnection) int64 {
	if conn.Conf.Port != 0 {
		return int64(conn.Conf.Port)
	}

	if conn.Conf.Runtime == "" {
		return 443
	}

	port := CommonPorts[conn.Conf.Runtime]
	if port == 0 {
		return 443
	}
	return int64(port)
}

func initTls(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// if the socket is set already, we have nothing else to do
	if _, ok := args["socket"]; ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.HostConnection)
	port := connTlsPort(conn)

	if target, ok := args["target"]; ok {
		m := reTarget.FindStringSubmatch(target.Value.(string))
		if len(m) == 0 {
			return nil, nil, errors.New("target must be provided in the form of: tcp://target:port, udp://target:port, or target:port (defaults to tcp)")
		}

		proto := "tcp"
		// If the port is set as part of the target string, try to parse it
		// from here.
		if len(m[2]) != 0 {
			rawPort, err := strconv.ParseUint(m[2][1:], 10, 64)
			if err != nil {
				return nil, nil, errors.New("failed to parse port: " + m[2])
			}
			port = int64(rawPort)
		}

		address := m[1]
		domainName := ""
		if rexUrlDomain.MatchString(address) {
			domainName = address
		}

		socket, err := CreateResource(runtime, "socket", map[string]*llx.RawData{
			"protocol": llx.StringData(proto),
			"port":     llx.IntData(port),
			"address":  llx.StringData(address),
		})
		if err != nil {
			return nil, nil, err
		}

		args["socket"] = llx.ResourceData(socket, "socket")
		args["domainName"] = llx.StringData(domainName)
		delete(args, "target")

	} else {
		socket, err := CreateResource(runtime, "socket", map[string]*llx.RawData{
			"protocol": llx.StringData("tcp"),
			"port":     llx.IntData(port),
			"address":  llx.StringData(conn.Conf.Host),
		})
		if err != nil {
			return nil, nil, err
		}

		args["socket"] = llx.ResourceData(socket, "socket")
		args["domainName"] = llx.StringData(conn.Conf.Host)
	}

	return args, nil, nil
}

type mqlTlsInternal struct {
	// This mutex is used to protect the tls resource from doing multiple detections at once
	lock sync.Mutex
	// we only detect once if the a socket is running on TLS or not, once the detection runs,
	// this boolean gets set and tells other functions if the socket has tls enabled or not
	tlsEnabled *bool
	// if the socket has TLS enabled, this tester will have findings, ciphers and versions
	tester *tlsshake.Tester
	// during TLS detection, if we find any issue, we record it here
	Error error
	// cached stdlib TLS connection state for negotiated* fields
	connState     *tls.ConnectionState
	connStateErr  error
	connStateDone bool
}

func (s *mqlTls) id() (string, error) {
	return "tls+" + s.Socket.Data.__id, nil
}

// withChainRevocations returns known plus a determination for every certificate
// in chain that it does not already cover.
//
// The result is a copy: known belongs to the handshake tester and is read by
// other fields, so it must not be written through.
//
// Only certificates with an issuer below them in the chain are checked. The last
// one is a trust anchor, and its revocation is not a question its own chain can
// answer.
func withChainRevocations(known map[string]*tlsshake.Revocation, chain []*x509.Certificate) map[string]*tlsshake.Revocation {
	res := make(map[string]*tlsshake.Revocation, len(known)+len(chain))
	maps.Copy(res, known)

	for i := 0; i+1 < len(chain); i++ {
		key := string(chain[i].Signature)
		if _, ok := res[key]; ok {
			continue
		}

		determined, revocation, err := tlsshake.CheckRevocation(chain[i], chain[i+1])
		if !determined {
			log.Debug().
				Str("subject", chain[i].Subject.CommonName).
				Err(err).
				Msg("network.tls> revocation status could not be determined")
			continue
		}
		res[key] = revocation
	}

	return res
}

// revocationFields maps a revocation lookup onto the three fields that report
// it.
//
// There are three states, not two. An entry in the map means the check ran: nil
// says the certificate is good, non-nil says it is revoked. No entry means
// nothing was determined - the certificate names no OCSP responder and no CRL,
// or none of them could be reached - and that must not be reported as "not
// revoked". Leaving isRevoked at its zero value is what made an unchecked
// certificate, and a genuinely revoked one whose issuer has retired OCSP, both
// read as good.
func revocationFields(revocations map[string]*tlsshake.Revocation, cert *x509.Certificate) (
	isRevoked *llx.RawData, revokedAt *llx.RawData, revocationChecked *llx.RawData,
) {
	revocation, ok := revocations[string(cert.Signature)]
	if !ok {
		return llx.NilData, llx.NilData, llx.BoolFalse
	}
	if revocation == nil {
		return llx.BoolFalse, llx.NilData, llx.BoolTrue
	}
	return llx.BoolTrue, llx.TimeData(revocation.At), llx.BoolTrue
}

func parseCertificates(runtime *plugin.Runtime, domainName string, certificateList []*x509.Certificate, revocations map[string]*tlsshake.Revocation) ([]any, []string, error) {
	res := make([]any, len(certificateList))
	errors := []string{}

	verified := false
	if len(certificateList) != 0 {
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certificateList); i++ {
			intermediates.AddCert(certificateList[i])
		}

		verifyCerts, err := certificateList[0].Verify(x509.VerifyOptions{
			DNSName:       domainName,
			Intermediates: intermediates,
		})
		if err != nil {
			errors = append(errors, "Failed to verify certificate chain for "+certificateList[0].Subject.String())
		}

		if len(verifyCerts) != 0 {
			verified = verifyCerts[0][0].Equal(certificateList[0])
		}
	}

	for i := range certificateList {
		cert := certificateList[i]

		isRevoked, revokedAt, revocationChecked := revocationFields(revocations, cert)

		pem, err := certificates.EncodeCertAsPEM(cert)

		if err != nil {
			return nil, nil, err
		}

		raw, err := CreateResource(runtime, "certificate", map[string]*llx.RawData{
			"pem": llx.StringData(string(pem)),
			// NOTE: if we do not set the hash here, it will generate the cache content before we can store it
			// we are using the hashes for the id, therefore it is required during creation
			"fingerprints":      llx.MapData(certificates.Fingerprints(cert), types.String),
			"isRevoked":         isRevoked,
			"revokedAt":         revokedAt,
			"revocationChecked": revocationChecked,
			"isVerified":        llx.BoolData(verified),
		})
		if err != nil {
			return nil, nil, err
		}

		// store parsed object with resource
		mqlCert := raw.(*mqlCertificate)
		mqlCert.cert = plugin.TValue[*x509.Certificate]{Data: cert, State: plugin.StateIsSet}

		res[i] = mqlCert
	}

	return res, errors, nil
}

func (s *mqlTls) params(socket *mqlSocket, domainName string) (map[string]any, error) {
	enabled, err := s.TLSEnabled(socket, domainName)
	if err != nil {
		return nil, err
	}

	if !enabled {
		return nil, nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	res := map[string]any{}
	findings := s.tester.Findings

	lists := map[string][]string{
		"errors": findings.Errors,
	}
	for field, data := range lists {
		v := make([]any, len(data))
		for i := range data {
			v[i] = data[i]
		}
		res[field] = v
	}

	maps := map[string]map[string]bool{
		"versions":   findings.Versions,
		"ciphers":    findings.Ciphers,
		"extensions": findings.Extensions,
	}
	for field, data := range maps {
		v := make(map[string]any, len(data))
		for k, vv := range data {
			v[k] = vv
		}
		res[field] = v
	}

	if findings.NegotiatedGroup != "" {
		res["negotiatedGroup"] = findings.NegotiatedGroup
	}

	return res, nil
}

func (s *mqlTls) versions(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	// only happens in case of unexpected errors or null
	if !ok {
		s.Versions.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	raw, ok := paramsM["versions"]
	if !ok {
		return []any{}, nil
	}

	data := raw.(map[string]any)
	res := []any{}
	for k, v := range data {
		if v.(bool) {
			res = append(res, k)
		}
	}

	return res, nil
}

func (s *mqlTls) ciphers(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	// only happens in case of unexpected errors or null
	if !ok {
		s.Ciphers.State = plugin.StateIsSet | plugin.StateIsNull
		return []any{}, nil
	}

	raw, ok := paramsM["ciphers"]
	if !ok {
		return []any{}, nil
	}

	data := raw.(map[string]any)
	res := []any{}
	for k, v := range data {
		if v.(bool) {
			res = append(res, k)
		}
	}

	return res, nil
}

func (s *mqlTls) cipherSuites(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	if !ok {
		s.CipherSuites.State = plugin.StateIsSet | plugin.StateIsNull
		return []any{}, nil
	}

	raw, ok := paramsM["ciphers"]
	if !ok {
		return []any{}, nil
	}

	data := raw.(map[string]any)
	names := make([]string, 0, len(data))
	for name, supported := range data {
		if b, _ := supported.(bool); b {
			names = append(names, name)
		}
	}
	sort.Strings(names) // map iteration is non-deterministic; keep a stable order

	res := make([]any, 0, len(names))
	for _, name := range names {
		info := classifyCipher(name)
		resource, err := CreateResource(s.MqlRuntime, "tls.cipher", map[string]*llx.RawData{
			"__id":           llx.StringData("tls.cipher/" + name),
			"name":           llx.StringData(name),
			"keyExchange":    llx.StringData(info.keyExchange),
			"authentication": llx.StringData(info.authentication),
			"encryption":     llx.StringData(info.encryption),
			"mac":            llx.StringData(info.mac),
			"forwardSecrecy": llx.BoolData(info.forwardSecrecy),
			"aead":           llx.BoolData(info.aead),
			"export":         llx.BoolData(info.export),
			"nullCipher":     llx.BoolData(info.null),
			"anonymous":      llx.BoolData(info.anonymous),
			"cbc":            llx.BoolData(info.cbc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}

	return res, nil
}

func (s *mqlTls) extensions(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	// only happens in case of unexpected errors or null
	if !ok {
		s.Extensions.State = plugin.StateIsSet | plugin.StateIsNull
		return []any{}, nil
	}

	raw, ok := paramsM["extensions"]
	if !ok {
		return []any{}, nil
	}

	data := raw.(map[string]any)
	res := []any{}
	for k, v := range data {
		if v.(bool) {
			res = append(res, k)
		}
	}

	return res, nil
}

// dialTLSWithoutSNI opens a TLS connection that sends no server_name extension.
//
// tls.DialWithDialer cannot do this: it clones the config and fills ServerName
// in from the dial address whenever it is empty, so a config with no ServerName
// still sends SNI for the host being dialed. Dialing the socket separately and
// handing it to tls.Client is what actually leaves the extension off, which is
// the whole point of the probe.
func dialTLSWithoutSNI(dialer *net.Dialer, proto, addr string) (*tls.Conn, error) {
	raw, err := dialer.Dial(proto, addr)
	if err != nil {
		return nil, err
	}

	if err := raw.SetDeadline(time.Now().Add(DefaultDialerTimeout)); err != nil {
		raw.Close()
		return nil, err
	}

	// Certificate verification is deliberately off, and here it is not even
	// well defined: with no server name there is nothing to verify the
	// certificate against. This resource reports validity rather than requiring
	// it, through isVerified and certificateMatchesDomain, so a chain that does
	// not verify is the finding rather than a reason to refuse the connection.
	// Verifying at the transport would make the resource fail on exactly the
	// endpoints it exists to describe.
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	// The deadline covered the handshake; leaving it in place would expire the
	// connection while the caller is still reading from it.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// gatherTlsCertificates returns the chain the endpoint serves for domainName,
// and the chain it serves to a client that sends no SNI at all.
//
// The second chain is reported in full rather than as the certificates that
// differ from the first. A host that serves the same certificate either way
// genuinely does serve it without SNI, and reporting nothing there says the
// opposite. The interesting case - a default virtual host answering with an
// unrelated certificate - reads the same way in both shapes.
//
// Only a failure of the first connection is an error. A server that requires
// SNI closes the second one, and that is an answer about the endpoint rather
// than a failure of the scan: the non-SNI chain comes back nil and the caller
// reports it as unknown.
func gatherTlsCertificates(proto, host, port, domainName string) ([]*x509.Certificate, []*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: DefaultDialerTimeout}
	addr := net.JoinHostPort(host, port)
	log.Trace().
		Str("address", addr).
		Str("domain_name", domainName).
		Dur("timeout", DefaultDialerTimeout).
		Msg("network.tls> gathering tls certificates")

	conn, err := tls.DialWithDialer(dialer, proto, addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domainName,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	sniCerts := conn.ConnectionState().PeerCertificates

	nonSniConn, err := dialTLSWithoutSNI(dialer, proto, addr)
	if err != nil {
		log.Debug().
			Str("address", addr).
			Err(err).
			Msg("network.tls> endpoint served no certificate without SNI")
		return sniCerts, nil, nil
	}
	defer nonSniConn.Close()

	return sniCerts, nonSniConn.ConnectionState().PeerCertificates, nil
}

// we should only detect once if the socket is running on TLS or not, if we have already detected it and, it
// is NOT a TLS connection, we should exit fast.
//
// NOTE that this method should be called by functions once they have locked the Mutex inside `mqlTlsInternal`
func (s *mqlTls) unsafeTLSTest(socket *mqlSocket, domainName string) error {
	if s.tlsEnabled != nil {
		return s.Error
	}

	host := socket.Address.Data
	port := socket.Port.Data
	proto := socket.Protocol.Data

	s.tester = tlsshake.New(proto, domainName, host, int(port))
	if err := s.tester.Test(tlsshake.DefaultScanConfig()); err != nil {

		log.Debug().
			Str("host", host).
			Str("proto", proto).
			Int64("port", port).
			Interface("findings", s.tester.Findings).
			Bool("tls_enabled", false).
			Msg("network.tls> detection")
		s.tlsEnabled = convert.ToPtr(false)

		if errors.Is(err, tlsshake.ErrFailedToConnect) ||
			errors.Is(err, tlsshake.ErrFailedToWrite) ||
			errors.Is(err, tlsshake.ErrTimeout) ||
			errors.Is(err, tlsshake.ErrFailedToTlsResponse) {

			s.Params.State = plugin.StateIsSet | plugin.StateIsNull
			s.Certificates.State = plugin.StateIsSet | plugin.StateIsNull
			s.NonSniCertificates.State = plugin.StateIsSet | plugin.StateIsNull
			s.NegotiatedGroup.State = plugin.StateIsSet | plugin.StateIsNull
			s.NegotiatedVersion.State = plugin.StateIsSet | plugin.StateIsNull
			s.NegotiatedCipher.State = plugin.StateIsSet | plugin.StateIsNull
			return nil
		}

		s.Error = err
		return s.Error
	}

	s.tlsEnabled = convert.ToPtr(len(s.tester.Findings.Versions) != 0)

	log.Debug().
		Str("host", host).
		Str("proto", proto).
		Int64("port", port).
		Strs("versions", s.tester.Findings.Errors).
		Interface("versions", s.tester.Findings.Versions).
		Bool("tls_enabled", *s.tlsEnabled).
		Msg("network.tls> detection")
	return nil
}

// TLSEnabled checks if the provider socket speaks TLS or plain text (like HTTP)
func (s *mqlTls) TLSEnabled(socket *mqlSocket, domainName string) (enabled bool, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.tlsEnabled == nil {
		// we only detect once
		err = s.unsafeTLSTest(socket, domainName)
	} else {
		err = s.Error
	}

	enabled = *s.tlsEnabled

	return
}
func (s *mqlTls) populateCertificates(socket *mqlSocket, domainName string) error {
	enabled, err := s.TLSEnabled(socket, domainName)
	if err != nil {
		return err
	}

	if !enabled {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	host := socket.Address.Data
	port := socket.Port.Data
	proto := socket.Protocol.Data

	certs, nonSniCerts, err := gatherTlsCertificates(proto, host, strconv.FormatInt(port, 10), domainName)
	if err != nil {
		s.Certificates = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		s.NonSniCertificates = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		return err
	}

	// The handshake tester checks revocation and records the outcome keyed by
	// string(cert.Signature); reuse that so certificate.isRevoked/revokedAt
	// reflect a real check instead of a hardcoded "not revoked".
	//
	// Its findings describe the chain its own probes negotiated, which is not
	// always this one. A host that serves both an RSA and an ECDSA certificate
	// hands the tester's TLS 1.2 probe one leaf and this TLS 1.3 connection
	// another, and the tester's answer is then about a certificate nobody is
	// reporting on. Fill in whatever is missing against the chain actually being
	// reported. Default to an empty (non-nil) map so parseCertificates never
	// receives nil.
	revocations := map[string]*tlsshake.Revocation{}
	if s.tester != nil && s.tester.Findings.Revocations != nil {
		revocations = s.tester.Findings.Revocations
	}
	revocations = withChainRevocations(revocations, certs)

	mqlCerts, _, err := parseCertificates(s.MqlRuntime, domainName, certs, revocations)
	if err != nil {
		s.Certificates = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
	} else {
		s.Certificates = plugin.TValue[[]any]{Data: mqlCerts, State: plugin.StateIsSet}
	}

	// A server that requires SNI closes the connection that omits it, so there
	// is no chain to report. That is unknown rather than empty: an empty list
	// would read as "this endpoint serves nothing without SNI", which is a
	// different statement from "it would not talk to us at all".
	if nonSniCerts == nil {
		s.NonSniCertificates.State = plugin.StateIsSet | plugin.StateIsNull
		return nil
	}

	// The non-SNI chain is matched against the same domain name so that
	// isVerified keeps its meaning: the question there is whether the
	// certificate served without SNI would satisfy a client asking for this
	// host, which is exactly what makes a default virtual host interesting.
	mqlNonSniCerts, _, err := parseCertificates(s.MqlRuntime, domainName, nonSniCerts, revocations)
	if err != nil {
		s.NonSniCertificates = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
	} else {
		s.NonSniCertificates = plugin.TValue[[]any]{Data: mqlNonSniCerts, State: plugin.StateIsSet}
	}
	return nil
}

func (s *mqlTls) certificates(socket *mqlSocket, domainName string) ([]any, error) {
	return nil, s.populateCertificates(socket, domainName)
}

func (s *mqlTls) nonSniCertificates(socket *mqlSocket, domainName string) ([]any, error) {
	return nil, s.populateCertificates(socket, domainName)
}

// certificateMatchesDomain reports whether the served leaf certificate covers
// the connection's domain name, applying RFC 6125 SAN matching (including
// wildcards). It isolates hostname coverage from chain trust and expiry. When
// there is no domain name to match (e.g. connecting directly to an IP), the
// field is null.
func (s *mqlTls) certificateMatchesDomain() (bool, error) {
	domainName := s.GetDomainName()
	if domainName.Error != nil {
		return false, domainName.Error
	}
	if domainName.Data == "" {
		s.CertificateMatchesDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	certs := s.GetCertificates()
	if certs.Error != nil {
		return false, certs.Error
	}
	if len(certs.Data) == 0 {
		s.CertificateMatchesDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	leaf, ok := certs.Data[0].(*mqlCertificate)
	if !ok || leaf.cert.Data == nil {
		s.CertificateMatchesDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return certMatchesDomain(leaf.cert.Data, domainName.Data), nil
}

// certMatchesDomain reports whether the certificate is valid for the given
// domain name. It applies RFC 6125 matching against the certificate's Subject
// Alternative Name DNS entries, including wildcards (`*.example.com` covers
// `api.example.com`). Following modern client behavior, the Subject Common
// Name is not consulted.
func certMatchesDomain(cert *x509.Certificate, domainName string) bool {
	return cert.VerifyHostname(domainName) == nil
}

// getConnectionState performs a single Go stdlib TLS connection and caches the result.
// All three negotiated* fields share this connection — only one dial is made.
func (s *mqlTls) getConnectionState(socket *mqlSocket, domainName string) (*tls.ConnectionState, error) {
	s.lock.Lock()
	if s.connStateDone {
		cs, err := s.connState, s.connStateErr
		s.lock.Unlock()
		return cs, err
	}
	s.lock.Unlock()

	host := socket.Address.Data
	port := socket.Port.Data
	proto := socket.Protocol.Data
	addr := net.JoinHostPort(host, strconv.FormatInt(port, 10))

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: DefaultDialerTimeout},
		proto, addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: domainName},
	)

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.connStateDone {
		// Another goroutine won the race — close our redundant connection
		if conn != nil {
			conn.Close()
		}
		return s.connState, s.connStateErr
	}
	s.connStateDone = true
	if err != nil {
		s.connStateErr = err
		return nil, err
	}
	cs := conn.ConnectionState()
	conn.Close()
	s.connState = &cs
	return s.connState, nil
}

func (s *mqlTls) negotiatedGroup(socket *mqlSocket, domainName string) (string, error) {
	enabled, err := s.TLSEnabled(socket, domainName)
	if err != nil {
		return "", err
	}
	if !enabled {
		s.NegotiatedGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	cs, err := s.getConnectionState(socket, domainName)
	if err != nil {
		return "", err
	}
	if cs.CurveID == 0 {
		s.NegotiatedGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return cs.CurveID.String(), nil
}

func (s *mqlTls) negotiatedVersion(socket *mqlSocket, domainName string) (string, error) {
	enabled, err := s.TLSEnabled(socket, domainName)
	if err != nil {
		return "", err
	}
	if !enabled {
		s.NegotiatedVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	cs, err := s.getConnectionState(socket, domainName)
	if err != nil {
		return "", err
	}
	return tls.VersionName(cs.Version), nil
}

func (s *mqlTls) negotiatedCipher(socket *mqlSocket, domainName string) (string, error) {
	enabled, err := s.TLSEnabled(socket, domainName)
	if err != nil {
		return "", err
	}
	if !enabled {
		s.NegotiatedCipher.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	cs, err := s.getConnectionState(socket, domainName)
	if err != nil {
		return "", err
	}
	return tls.CipherSuiteName(cs.CipherSuite), nil
}
