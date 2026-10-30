// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stmcginnis/gofish/schemas"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redfish/connection"
	"go.mondoo.com/mql/types"
)

// odataRef is a Redfish link to another resource.
type odataRef struct {
	ODataID string `json:"@odata.id"`
}

// protocolSettingJSON is one protocol block of a ManagerNetworkProtocol
// document. ProtocolEnabled and Port are pointers so an absent property stays
// distinguishable from a property the controller reports as false or zero.
type protocolSettingJSON struct {
	ProtocolEnabled *bool     `json:"ProtocolEnabled"`
	Port            *int64    `json:"Port"`
	Certificates    *odataRef `json:"Certificates"`
}

// networkProtocolJSON is the subset of a ManagerNetworkProtocol document the
// provider surfaces. Each protocol is a pointer so an absent block stays
// distinguishable from a block that reports the protocol as disabled.
type networkProtocolJSON struct {
	ODataID      string               `json:"@odata.id"`
	HostName     string               `json:"HostName"`
	FQDN         string               `json:"FQDN"`
	HTTP         *protocolSettingJSON `json:"HTTP"`
	HTTPS        *protocolSettingJSON `json:"HTTPS"`
	SSH          *protocolSettingJSON `json:"SSH"`
	Telnet       *protocolSettingJSON `json:"Telnet"`
	IPMI         *protocolSettingJSON `json:"IPMI"`
	SNMP         *protocolSettingJSON `json:"SNMP"`
	VirtualMedia *protocolSettingJSON `json:"VirtualMedia"`
	KVMIP        *protocolSettingJSON `json:"KVMIP"`
}

// parseNetworkProtocol decodes a ManagerNetworkProtocol document.
func parseNetworkProtocol(raw []byte) (*networkProtocolJSON, error) {
	var np networkProtocolJSON
	if err := json.Unmarshal(raw, &np); err != nil {
		return nil, err
	}
	return &np, nil
}

// protocolEnabled returns the enabled state of a protocol block, or nil when
// the controller does not report the protocol.
func protocolEnabled(p *protocolSettingJSON) *bool {
	if p == nil {
		return nil
	}
	return p.ProtocolEnabled
}

// protocolPort returns the port of a protocol block, or nil when the controller
// does not report the protocol or leaves the port out.
func protocolPort(p *protocolSettingJSON) *int64 {
	if p == nil {
		return nil
	}
	return p.Port
}

// parseManagerNetworkProtocolLink returns the NetworkProtocol URI of a manager
// document, or an empty string when the manager carries no such link.
func parseManagerNetworkProtocolLink(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var mgr struct {
		NetworkProtocol *odataRef `json:"NetworkProtocol"`
	}
	if err := json.Unmarshal(raw, &mgr); err != nil {
		log.Debug().Err(err).Msg("redfish: could not parse manager document")
		return ""
	}
	if mgr.NetworkProtocol == nil {
		return ""
	}
	return mgr.NetworkProtocol.ODataID
}

// parseCollectionMembers returns the member URIs of a Redfish collection.
func parseCollectionMembers(raw []byte) ([]string, error) {
	var collection struct {
		Members []odataRef `json:"Members"`
	}
	if err := json.Unmarshal(raw, &collection); err != nil {
		return nil, err
	}
	members := make([]string, 0, len(collection.Members))
	for _, m := range collection.Members {
		if m.ODataID != "" {
			members = append(members, m.ODataID)
		}
	}
	return members, nil
}

// consoleServiceJSON is one console service block of a Manager document.
// ServiceEnabled and MaxConcurrentSessions are pointers so a property the
// controller leaves out stays distinguishable from a console it reports as
// disabled or as allowing no session.
type consoleServiceJSON struct {
	ServiceEnabled        *bool    `json:"ServiceEnabled"`
	MaxConcurrentSessions *int64   `json:"MaxConcurrentSessions"`
	ConnectTypesSupported []string `json:"ConnectTypesSupported"`
}

// managerConsolesJSON is the console services of a Manager document. Each
// service is a pointer so a controller that does not describe a console stays
// distinguishable from one that reports the console as disabled.
type managerConsolesJSON struct {
	CommandShell     *consoleServiceJSON `json:"CommandShell"`
	GraphicalConsole *consoleServiceJSON `json:"GraphicalConsole"`
	SerialConsole    *consoleServiceJSON `json:"SerialConsole"`
}

// parseManagerConsoles decodes the console services of a Manager document. It
// returns an empty result when the document does not decode, so every console
// field resolves to null rather than to a console that is switched off.
func parseManagerConsoles(raw []byte) managerConsolesJSON {
	var consoles managerConsolesJSON
	if len(raw) == 0 {
		return consoles
	}
	if err := json.Unmarshal(raw, &consoles); err != nil {
		log.Debug().Err(err).Msg("redfish: could not decode the console services of a manager")
		return managerConsolesJSON{}
	}
	return consoles
}

// consoleEnabled returns the enabled state of a console service, or nil when
// the controller does not describe the service.
func consoleEnabled(c *consoleServiceJSON) *bool {
	if c == nil {
		return nil
	}
	return c.ServiceEnabled
}

// consoleMaxSessions returns the concurrent session limit of a console
// service, or nil when the controller does not describe the service or leaves
// the limit out.
func consoleMaxSessions(c *consoleServiceJSON) *int64 {
	if c == nil {
		return nil
	}
	return c.MaxConcurrentSessions
}

// consoleConnectTypes returns the transports a console service accepts. It
// returns nil when the controller does not describe the service, so an audit
// does not read an undescribed console as one that accepts nothing.
func consoleConnectTypes(c *consoleServiceJSON) *llx.RawData {
	if c == nil {
		return llx.NilData
	}
	connectTypes := make([]any, 0, len(c.ConnectTypesSupported))
	for _, t := range c.ConnectTypesSupported {
		connectTypes = append(connectTypes, t)
	}
	return llx.ArrayData(connectTypes, types.String)
}

// accountFlagsJSON is the subset of a ManagerAccount document that gofish
// decodes into plain values. The booleans are pointers here so an account on a
// controller that does not report them resolves to null rather than to false,
// which would state as fact that no password change is pending.
type accountFlagsJSON struct {
	PasswordChangeRequired *bool  `json:"PasswordChangeRequired"`
	StrictAccountTypes     *bool  `json:"StrictAccountTypes"`
	PasswordExpiration     string `json:"PasswordExpiration"`
	AccountExpiration      string `json:"AccountExpiration"`
}

// parseAccountFlags decodes the optional properties of a ManagerAccount
// document. It returns an empty result when the document does not decode, so
// every field resolves to null.
func parseAccountFlags(raw []byte) accountFlagsJSON {
	var flags accountFlagsJSON
	if len(raw) == 0 {
		return flags
	}
	if err := json.Unmarshal(raw, &flags); err != nil {
		log.Debug().Err(err).Msg("redfish: could not decode the optional properties of an account")
		return accountFlagsJSON{}
	}
	return flags
}

// externalAccountProviderJSON is the subset of an external account provider
// block the provider surfaces. Only the authentication method is read: the
// same block also carries the password, the token, and the encryption key that
// the controller uses to bind to the directory, and those never leave it.
type externalAccountProviderJSON struct {
	ServiceEnabled   *bool    `json:"ServiceEnabled"`
	ServiceAddresses []string `json:"ServiceAddresses"`
	Authentication   *struct {
		AuthenticationType string `json:"AuthenticationType"`
	} `json:"Authentication"`
}

// accountServiceJSON is the subset of a Redfish AccountService document the
// provider surfaces. Every scalar is a pointer because zero is a meaningful
// value for most of them: a lockout threshold of 0 means the controller never
// locks an account out, which is a finding, while an absent threshold means
// the controller did not say, which is not.
type accountServiceJSON struct {
	ServiceEnabled                    *bool  `json:"ServiceEnabled"`
	MinPasswordLength                 *int64 `json:"MinPasswordLength"`
	MaxPasswordLength                 *int64 `json:"MaxPasswordLength"`
	AccountLockoutThreshold           *int64 `json:"AccountLockoutThreshold"`
	AccountLockoutDuration            *int64 `json:"AccountLockoutDuration"`
	AccountLockoutCounterResetAfter   *int64 `json:"AccountLockoutCounterResetAfter"`
	AccountLockoutCounterResetEnabled *bool  `json:"AccountLockoutCounterResetEnabled"`
	AuthFailureLoggingThreshold       *int64 `json:"AuthFailureLoggingThreshold"`
	EnforcePasswordHistoryCount       *int64 `json:"EnforcePasswordHistoryCount"`
	PasswordExpirationDays            *int64 `json:"PasswordExpirationDays"`
	RequireChangePasswordAction       *bool  `json:"RequireChangePasswordAction"`
	HTTPBasicAuth                     string `json:"HTTPBasicAuth"`
	LocalAccountAuth                  string `json:"LocalAccountAuth"`

	LDAP            *externalAccountProviderJSON `json:"LDAP"`
	ActiveDirectory *externalAccountProviderJSON `json:"ActiveDirectory"`
	TACACSplus      *externalAccountProviderJSON `json:"TACACSplus"`
}

// parseAccountService decodes a Redfish AccountService document.
func parseAccountService(raw []byte) (*accountServiceJSON, error) {
	var svc accountServiceJSON
	if err := json.Unmarshal(raw, &svc); err != nil {
		return nil, err
	}
	return &svc, nil
}

// certIdentifierJSON is the issuer or subject of a Redfish certificate.
type certIdentifierJSON struct {
	CommonName   string `json:"CommonName"`
	Organization string `json:"Organization"`
}

// certificateJSON is the subset of a Redfish Certificate document the provider
// surfaces.
type certificateJSON struct {
	ODataID                  string             `json:"@odata.id"`
	CertificateString        string             `json:"CertificateString"`
	CertificateType          string             `json:"CertificateType"`
	CertificateUsageTypes    []string           `json:"CertificateUsageTypes"`
	Fingerprint              string             `json:"Fingerprint"`
	FingerprintHashAlgorithm string             `json:"FingerprintHashAlgorithm"`
	Issuer                   certIdentifierJSON `json:"Issuer"`
	SerialNumber             string             `json:"SerialNumber"`
	SignatureAlgorithm       string             `json:"SignatureAlgorithm"`
	Subject                  certIdentifierJSON `json:"Subject"`
	ValidNotAfter            string             `json:"ValidNotAfter"`
	ValidNotBefore           string             `json:"ValidNotBefore"`
}

// parseCertificate decodes a Redfish Certificate document.
func parseCertificate(raw []byte) (*certificateJSON, error) {
	var cert certificateJSON
	if err := json.Unmarshal(raw, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// parsePEMCertificate decodes the PEM body of a Redfish certificate. It returns
// nil when the controller withholds the encoded certificate or the body does
// not decode, because several controllers return an empty CertificateString.
func parsePEMCertificate(certificateString string) *x509.Certificate {
	if certificateString == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(certificateString))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Debug().Err(err).Msg("redfish: could not parse certificate body")
		return nil
	}
	return cert
}

// certificateKeyInfo returns the public key size in bits and the key algorithm
// of a certificate. Both are nil and empty when the certificate is missing or
// the key type is unknown, so an audit does not read a missing value as a weak
// key.
func certificateKeyInfo(cert *x509.Certificate) (*int64, string) {
	if cert == nil {
		return nil, ""
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := int64(key.N.BitLen())
		return &bits, "RSA"
	case *ecdsa.PublicKey:
		bits := int64(key.Curve.Params().BitSize)
		return &bits, "ECDSA"
	case ed25519.PublicKey:
		bits := int64(len(key) * 8)
		return &bits, "Ed25519"
	case *mldsa.PublicKey:
		bits := int64(key.Parameters().PublicKeySize() * 8)
		return &bits, "ML-DSA"
	default:
		return nil, ""
	}
}

// certificateSelfSigned reports whether the issuer and the subject of a
// certificate are the same entity. It prefers the encoded certificate and falls
// back to the issuer and subject that Redfish reports. The result is nil when
// neither source carries an identity, so an audit does not read missing data as
// a certificate signed by a certificate authority.
func certificateSelfSigned(cert *certificateJSON, parsed *x509.Certificate) *bool {
	if parsed != nil {
		selfSigned := bytes.Equal(parsed.RawIssuer, parsed.RawSubject)
		return &selfSigned
	}
	if cert == nil || cert.Issuer.CommonName == "" || cert.Subject.CommonName == "" {
		return nil
	}
	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName &&
		cert.Issuer.Organization == cert.Subject.Organization
	return &selfSigned
}

// redfishTimeLayouts lists the timestamp formats controllers return. The
// Redfish specification mandates ISO 8601, but several controllers drop the
// time zone or return a date alone.
var redfishTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// parseRedfishTime parses a Redfish timestamp. It returns nil when the
// controller reports no timestamp or a format the provider cannot read, so a
// date comparison resolves to null rather than to the zero time.
func parseRedfishTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range redfishTimeLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return &parsed
		}
	}
	log.Debug().Str("value", value).Msg("redfish: could not parse timestamp")
	return nil
}

// defaultVendorAccountNames holds the login names that management controllers
// ship with from the factory. Names are compared without case, because vendors
// differ in how they capitalize them.
var defaultVendorAccountNames = map[string]struct{}{
	"root":          {}, // Dell iDRAC, HPE iLO on some generations
	"administrator": {}, // HPE iLO
	"admin":         {}, // Cisco CIMC, Supermicro on newer firmware
	"userid":        {}, // Lenovo XClarity, IBM IMM
	"sysadmin":      {}, // Quanta and several OpenBMC builds
	"anonymous":     {}, // Fujitsu iRMC
}

// isDefaultVendorAccountName reports whether a login name is a known vendor
// default.
func isDefaultVendorAccountName(userName string) bool {
	_, ok := defaultVendorAccountNames[strings.ToLower(strings.TrimSpace(userName))]
	return ok
}

// isPersistentBootOverride reports whether a boot source override stays active
// across resets. It requires the Continuous state and a target other than None,
// because a Continuous state with no target changes nothing.
func isPersistentBootOverride(overrideEnabled, overrideTarget string) bool {
	if !strings.EqualFold(overrideEnabled, "Continuous") {
		return false
	}
	target := strings.TrimSpace(overrideTarget)
	return target != "" && !strings.EqualFold(target, "None")
}

// mqlRedfishInternal caches the raw ManagerNetworkProtocol documents. Both the
// network protocol settings and the HTTPS certificates come from the same
// document, so it is fetched once per scan.
type mqlRedfishInternal struct {
	networkProtocolOnce sync.Once
	networkProtocolData []*networkProtocolJSON
	networkProtocolErr  error
}

// loadNetworkProtocols fetches and parses the ManagerNetworkProtocol document
// of every controller that links one.
func (r *mqlRedfish) loadNetworkProtocols() ([]*networkProtocolJSON, error) {
	r.networkProtocolOnce.Do(func() {
		conn := redfishConn(r.MqlRuntime)
		managers, err := conn.Managers()
		if err != nil {
			r.networkProtocolErr = err
			return
		}

		res := make([]*networkProtocolJSON, 0, len(managers))
		for _, m := range managers {
			link := parseManagerNetworkProtocolLink(m.RawData)
			if link == "" {
				continue
			}
			raw, err := conn.GetRaw(link)
			if errors.Is(err, connection.ErrNotFound) {
				// The manager advertises the resource but does not serve it.
				log.Debug().Err(err).Msg("redfish: manager serves no network protocol resource")
				continue
			}
			if err != nil {
				r.networkProtocolErr = err
				return
			}
			np, err := parseNetworkProtocol(raw)
			if err != nil {
				r.networkProtocolErr = err
				return
			}
			if np.ODataID == "" {
				np.ODataID = link
			}
			res = append(res, np)
		}
		r.networkProtocolData = res
	})
	return r.networkProtocolData, r.networkProtocolErr
}

// networkProtocols returns the management network protocol settings of every
// controller. The provider parses the Redfish document itself so an absent
// protocol block resolves to null rather than to a disabled protocol.
func (r *mqlRedfish) networkProtocols() ([]any, error) {
	protocols, err := r.loadNetworkProtocols()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(protocols))
	for _, np := range protocols {
		o, err := CreateResource(r.MqlRuntime, "redfish.networkProtocol", map[string]*llx.RawData{
			"__id":                llx.StringData(np.ODataID),
			"hostName":            llx.StringData(np.HostName),
			"fqdn":                llx.StringData(np.FQDN),
			"httpEnabled":         llx.BoolDataPtr(protocolEnabled(np.HTTP)),
			"httpPort":            llx.IntDataPtr(protocolPort(np.HTTP)),
			"httpsEnabled":        llx.BoolDataPtr(protocolEnabled(np.HTTPS)),
			"httpsPort":           llx.IntDataPtr(protocolPort(np.HTTPS)),
			"sshEnabled":          llx.BoolDataPtr(protocolEnabled(np.SSH)),
			"sshPort":             llx.IntDataPtr(protocolPort(np.SSH)),
			"telnetEnabled":       llx.BoolDataPtr(protocolEnabled(np.Telnet)),
			"telnetPort":          llx.IntDataPtr(protocolPort(np.Telnet)),
			"ipmiEnabled":         llx.BoolDataPtr(protocolEnabled(np.IPMI)),
			"ipmiPort":            llx.IntDataPtr(protocolPort(np.IPMI)),
			"snmpEnabled":         llx.BoolDataPtr(protocolEnabled(np.SNMP)),
			"snmpPort":            llx.IntDataPtr(protocolPort(np.SNMP)),
			"virtualMediaEnabled": llx.BoolDataPtr(protocolEnabled(np.VirtualMedia)),
			"virtualMediaPort":    llx.IntDataPtr(protocolPort(np.VirtualMedia)),
			"kvmipEnabled":        llx.BoolDataPtr(protocolEnabled(np.KVMIP)),
			"kvmipPort":           llx.IntDataPtr(protocolPort(np.KVMIP)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// certificates returns the TLS certificates that the controllers present on
// their HTTPS endpoint.
func (r *mqlRedfish) certificates() ([]any, error) {
	conn := redfishConn(r.MqlRuntime)
	protocols, err := r.loadNetworkProtocols()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(protocols))
	seen := map[string]struct{}{}
	for _, np := range protocols {
		if np.HTTPS == nil || np.HTTPS.Certificates == nil || np.HTTPS.Certificates.ODataID == "" {
			continue
		}

		collectionRaw, err := conn.GetRaw(np.HTTPS.Certificates.ODataID)
		if errors.Is(err, connection.ErrNotFound) {
			// The controller links a certificate collection it does not serve.
			log.Debug().Err(err).Msg("redfish: controller serves no certificate collection")
			continue
		}
		if err != nil {
			return nil, err
		}
		members, err := parseCollectionMembers(collectionRaw)
		if err != nil {
			return nil, err
		}

		for _, member := range members {
			if _, dup := seen[member]; dup {
				continue
			}
			seen[member] = struct{}{}

			certRaw, err := conn.GetRaw(member)
			if errors.Is(err, connection.ErrNotFound) {
				// The collection lists a certificate the controller removed.
				log.Debug().Err(err).Msg("redfish: certificate member is gone")
				continue
			}
			if err != nil {
				return nil, err
			}
			cert, err := parseCertificate(certRaw)
			if err != nil {
				return nil, err
			}

			parsed := parsePEMCertificate(cert.CertificateString)
			keySize, keyAlgorithm := certificateKeyInfo(parsed)

			usageTypes := make([]any, 0, len(cert.CertificateUsageTypes))
			for _, t := range cert.CertificateUsageTypes {
				usageTypes = append(usageTypes, t)
			}

			id := cert.ODataID
			if id == "" {
				id = member
			}
			o, err := CreateResource(r.MqlRuntime, "redfish.certificate", map[string]*llx.RawData{
				"__id":                     llx.StringData(id),
				"issuerCommonName":         llx.StringData(cert.Issuer.CommonName),
				"issuerOrganization":       llx.StringData(cert.Issuer.Organization),
				"subjectCommonName":        llx.StringData(cert.Subject.CommonName),
				"subjectOrganization":      llx.StringData(cert.Subject.Organization),
				"validNotBefore":           llx.TimeDataPtr(parseRedfishTime(cert.ValidNotBefore)),
				"validNotAfter":            llx.TimeDataPtr(parseRedfishTime(cert.ValidNotAfter)),
				"serialNumber":             llx.StringData(cert.SerialNumber),
				"signatureAlgorithm":       llx.StringData(cert.SignatureAlgorithm),
				"fingerprint":              llx.StringData(cert.Fingerprint),
				"fingerprintHashAlgorithm": llx.StringData(cert.FingerprintHashAlgorithm),
				"certificateType":          llx.StringData(cert.CertificateType),
				"certificateUsageTypes":    llx.ArrayData(usageTypes, types.String),
				"keySizeBits":              llx.IntDataPtr(keySize),
				"keyAlgorithm":             llx.StringData(keyAlgorithm),
				"selfSigned":               llx.BoolDataPtr(certificateSelfSigned(cert, parsed)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, o)
		}
	}
	return res, nil
}

// mqlRedfishSessionServiceInternal holds the session service document, which
// every field of the resource reads. The document itself is cached on the
// connection, because redfish.sessions reads it too.
type mqlRedfishSessionServiceInternal struct {
	once   sync.Once
	loaded bool
	svc    *schemas.SessionService
}

func (r *mqlRedfishSessionService) id() (string, error) {
	return "redfish.sessionService", nil
}

// load fetches the session service once. loaded stays false when the controller
// exposes no session service or the fetch fails, so every field resolves to
// null instead of to a disabled service.
func (r *mqlRedfishSessionService) load() {
	r.once.Do(func() {
		sessionService, err := redfishConn(r.MqlRuntime).SessionService()
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not read the session service")
			return
		}
		if sessionService == nil {
			return
		}
		r.svc = sessionService
		r.loaded = true
	})
}

func (r *mqlRedfishSessionService) serviceEnabled() (bool, error) {
	r.load()
	if !r.loaded {
		r.ServiceEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return r.svc.ServiceEnabled, nil
}

func (r *mqlRedfishSessionService) sessionTimeout() (int64, error) {
	r.load()
	if !r.loaded {
		r.SessionTimeout.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return int64(r.svc.SessionTimeout), nil
}

func (r *mqlRedfishSessionService) absoluteSessionTimeout() (int64, error) {
	r.load()
	if !r.loaded {
		r.AbsoluteSessionTimeout.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return int64(r.svc.AbsoluteSessionTimeout), nil
}

func (r *mqlRedfishSessionService) absoluteSessionTimeoutEnabled() (bool, error) {
	r.load()
	if !r.loaded {
		r.AbsoluteSessionTimeoutEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return r.svc.AbsoluteSessionTimeoutEnabled, nil
}

// sessions returns the sessions that are currently open on the management
// service.
func (r *mqlRedfish) sessions() ([]any, error) {
	sessionService, err := redfishConn(r.MqlRuntime).SessionService()
	if err != nil {
		return nil, err
	}
	if sessionService == nil {
		return []any{}, nil
	}
	sessions, err := sessionService.Sessions()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(sessions))
	for _, s := range sessions {
		roles := make([]any, 0, len(s.Roles))
		for _, role := range s.Roles {
			roles = append(roles, role)
		}

		o, err := CreateResource(r.MqlRuntime, "redfish.session", map[string]*llx.RawData{
			"__id":                  llx.StringData(s.ODataID),
			"userName":              llx.StringData(s.UserName),
			"clientOriginIPAddress": llx.StringData(s.ClientOriginIPAddress),
			"sessionType":           llx.StringData(string(s.SessionType)),
			"createdTime":           llx.TimeDataPtr(parseRedfishTime(s.CreatedTime)),
			"expirationTime":        llx.TimeDataPtr(parseRedfishTime(s.ExpirationTime)),
			"roles":                 llx.ArrayData(roles, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// serviceRootUnauthenticated reports whether the controller returns its service
// root without credentials. It resolves to null when the probe cannot reach the
// controller, so an audit does not read a network failure as a closed service
// root.
func (r *mqlRedfish) serviceRootUnauthenticated() (bool, error) {
	answers, err := redfishConn(r.MqlRuntime).ServiceRootUnauthenticated()
	if err != nil {
		log.Debug().Err(err).Msg("redfish: unauthenticated service root probe failed")
		r.ServiceRootUnauthenticated.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return answers, nil
}

// mqlRedfishAccountServiceInternal holds the account service document, which
// every field of the resource reads. The provider decodes the document itself
// rather than reading the values gofish already decoded, because gofish types
// most of them as plain integers and booleans: that collapses a property the
// controller never reported into the same zero a controller reports when it
// disables a control.
type mqlRedfishAccountServiceInternal struct {
	once   sync.Once
	loaded bool
	svc    *accountServiceJSON
}

func (r *mqlRedfishAccountService) id() (string, error) {
	return "redfish.accountService", nil
}

// load fetches and decodes the account service once. loaded stays false when
// the controller exposes no account service or the fetch fails, so every field
// resolves to null instead of to an unrestricted policy.
func (r *mqlRedfishAccountService) load() {
	r.once.Do(func() {
		accountService, err := redfishConn(r.MqlRuntime).AccountService()
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not read the account service")
			return
		}
		if accountService == nil {
			return
		}
		svc, err := parseAccountService(accountService.RawData)
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not decode the account service")
			return
		}
		r.svc = svc
		r.loaded = true
	})
}

// value returns the decoded account service, or an empty document when the
// controller exposes none, so an accessor can read a property without a nil
// check of its own. It loads the document, because an accessor reads the
// property as an argument and Go evaluates that before calling the helper that
// would otherwise have loaded it.
func (r *mqlRedfishAccountService) value() *accountServiceJSON {
	r.load()
	if r.svc == nil {
		return &accountServiceJSON{}
	}
	return r.svc
}

// boolField resolves an optional boolean, marking the field null when the
// controller exposes no account service or omits the property.
func (r *mqlRedfishAccountService) boolField(field *plugin.TValue[bool], value *bool) (bool, error) {
	r.load()
	if !r.loaded || value == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return *value, nil
}

func (r *mqlRedfishAccountService) intField(field *plugin.TValue[int64], value *int64) (int64, error) {
	r.load()
	if !r.loaded || value == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return *value, nil
}

func (r *mqlRedfishAccountService) stringField(field *plugin.TValue[string], value string) (string, error) {
	r.load()
	if !r.loaded || value == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return value, nil
}

func (r *mqlRedfishAccountService) serviceEnabled() (bool, error) {
	return r.boolField(&r.ServiceEnabled, r.value().ServiceEnabled)
}

func (r *mqlRedfishAccountService) minPasswordLength() (int64, error) {
	return r.intField(&r.MinPasswordLength, r.value().MinPasswordLength)
}

func (r *mqlRedfishAccountService) maxPasswordLength() (int64, error) {
	return r.intField(&r.MaxPasswordLength, r.value().MaxPasswordLength)
}

func (r *mqlRedfishAccountService) accountLockoutThreshold() (int64, error) {
	return r.intField(&r.AccountLockoutThreshold, r.value().AccountLockoutThreshold)
}

func (r *mqlRedfishAccountService) accountLockoutDuration() (int64, error) {
	return r.intField(&r.AccountLockoutDuration, r.value().AccountLockoutDuration)
}

func (r *mqlRedfishAccountService) accountLockoutCounterResetAfter() (int64, error) {
	return r.intField(&r.AccountLockoutCounterResetAfter, r.value().AccountLockoutCounterResetAfter)
}

func (r *mqlRedfishAccountService) accountLockoutCounterResetEnabled() (bool, error) {
	return r.boolField(&r.AccountLockoutCounterResetEnabled, r.value().AccountLockoutCounterResetEnabled)
}

func (r *mqlRedfishAccountService) authFailureLoggingThreshold() (int64, error) {
	return r.intField(&r.AuthFailureLoggingThreshold, r.value().AuthFailureLoggingThreshold)
}

func (r *mqlRedfishAccountService) enforcePasswordHistoryCount() (int64, error) {
	return r.intField(&r.EnforcePasswordHistoryCount, r.value().EnforcePasswordHistoryCount)
}

func (r *mqlRedfishAccountService) passwordExpirationDays() (int64, error) {
	return r.intField(&r.PasswordExpirationDays, r.value().PasswordExpirationDays)
}

func (r *mqlRedfishAccountService) requireChangePasswordAction() (bool, error) {
	return r.boolField(&r.RequireChangePasswordAction, r.value().RequireChangePasswordAction)
}

func (r *mqlRedfishAccountService) httpBasicAuth() (string, error) {
	return r.stringField(&r.HttpBasicAuth, r.value().HTTPBasicAuth)
}

func (r *mqlRedfishAccountService) localAccountAuth() (string, error) {
	return r.stringField(&r.LocalAccountAuth, r.value().LocalAccountAuth)
}

// providerEnabled reports whether an external account provider is enabled.
func (r *mqlRedfishAccountService) providerEnabled(field *plugin.TValue[bool], p *externalAccountProviderJSON) (bool, error) {
	if p == nil {
		return r.boolField(field, nil)
	}
	return r.boolField(field, p.ServiceEnabled)
}

// providerAddresses returns the servers an external account provider points
// at. It resolves to null when the controller describes no such provider, so
// an audit does not read an undescribed provider as one with no server.
func (r *mqlRedfishAccountService) providerAddresses(field *plugin.TValue[[]any], p *externalAccountProviderJSON) ([]any, error) {
	r.load()
	if !r.loaded || p == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	addresses := make([]any, 0, len(p.ServiceAddresses))
	for _, a := range p.ServiceAddresses {
		addresses = append(addresses, a)
	}
	return addresses, nil
}

// providerAuthType returns the method an external account provider uses to
// authenticate the controller itself. The credential is never read.
func (r *mqlRedfishAccountService) providerAuthType(field *plugin.TValue[string], p *externalAccountProviderJSON) (string, error) {
	if p == nil || p.Authentication == nil {
		return r.stringField(field, "")
	}
	return r.stringField(field, p.Authentication.AuthenticationType)
}

func (r *mqlRedfishAccountService) ldapEnabled() (bool, error) {
	return r.providerEnabled(&r.LdapEnabled, r.value().LDAP)
}

func (r *mqlRedfishAccountService) ldapServiceAddresses() ([]any, error) {
	return r.providerAddresses(&r.LdapServiceAddresses, r.value().LDAP)
}

func (r *mqlRedfishAccountService) ldapAuthenticationType() (string, error) {
	return r.providerAuthType(&r.LdapAuthenticationType, r.value().LDAP)
}

func (r *mqlRedfishAccountService) activeDirectoryEnabled() (bool, error) {
	return r.providerEnabled(&r.ActiveDirectoryEnabled, r.value().ActiveDirectory)
}

func (r *mqlRedfishAccountService) activeDirectoryServiceAddresses() ([]any, error) {
	return r.providerAddresses(&r.ActiveDirectoryServiceAddresses, r.value().ActiveDirectory)
}

func (r *mqlRedfishAccountService) activeDirectoryAuthenticationType() (string, error) {
	return r.providerAuthType(&r.ActiveDirectoryAuthenticationType, r.value().ActiveDirectory)
}

func (r *mqlRedfishAccountService) tacacsPlusEnabled() (bool, error) {
	return r.providerEnabled(&r.TacacsPlusEnabled, r.value().TACACSplus)
}

func (r *mqlRedfishAccountService) tacacsPlusServiceAddresses() ([]any, error) {
	return r.providerAddresses(&r.TacacsPlusServiceAddresses, r.value().TACACSplus)
}

func (r *mqlRedfishAccountService) tacacsPlusAuthenticationType() (string, error) {
	return r.providerAuthType(&r.TacacsPlusAuthenticationType, r.value().TACACSplus)
}
