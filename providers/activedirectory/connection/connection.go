// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// Option keys for inventory.Config.Options
	OptionDC        = "dc"
	OptionUser      = "user"
	OptionPassword  = "password"
	OptionDomain    = "domain"
	OptionBaseDN    = "base-dn"
	OptionLDAPS     = "ldaps"
	OptionPlainLDAP = "plain-ldap"
	OptionPort      = "port"
	OptionInsecure  = "insecure"
	OptionBackend   = "backend"
	OptionStartTLS  = "starttls"
	OptionKerberos  = "kerberos"
	OptionKeytab    = "keytab"
	OptionKrb5Conf  = "krb5conf"
	OptionCCache    = "ccache"
	// defaultKrb5ConfPath is the conventional krb5.conf location on Unix-like
	// systems. It does not exist on Windows, where we synthesize a config
	// instead (see loadOrGenerateKrb5Config).
	defaultKrb5ConfPath = "/etc/krb5.conf"
	// dialTimeout caps how long we wait for TCP connection to the DC.
	dialTimeout = 30 * time.Second
	// Probe with non-sensitive invalid credentials so we never expose real
	// secrets on plaintext LDAP while checking signing enforcement.
	ldapSigningProbeUser     = "invalid-probe-user"
	ldapSigningProbePassword = "invalid-probe-password"
	// Global Catalog defaults track the chosen LDAP transport: LDAPS uses 3269,
	// while LDAP and StartTLS use 3268.
	globalCatalogLDAPS = 3269
	globalCatalogLDAP  = 3268
)

type ldapTransport string

const (
	ldapTransportLDAPS    ldapTransport = "ldaps"
	ldapTransportStartTLS ldapTransport = "starttls"
	ldapTransportPlain    ldapTransport = "ldap"
)

type kerberosAuthSource string

const (
	kerberosAuthSourceKeytab         kerberosAuthSource = "keytab"
	kerberosAuthSourceCCache         kerberosAuthSource = "ccache"
	kerberosAuthSourcePassword       kerberosAuthSource = "password"
	kerberosAuthSourceCurrentSession kerberosAuthSource = "current-session"
)

func isTrueOption(value string) bool {
	return strings.EqualFold(value, "true")
}

func resolveLDAPTransport(opts map[string]string) (ldapTransport, error) {
	useLDAPS := isTrueOption(opts[OptionLDAPS])
	usePlainLDAP := isTrueOption(opts[OptionPlainLDAP])
	useStartTLS := isTrueOption(opts[OptionStartTLS])

	enabled := 0
	if useLDAPS {
		enabled++
	}
	if usePlainLDAP {
		enabled++
	}
	if useStartTLS {
		enabled++
	}
	if enabled > 1 {
		return "", errors.New("LDAP transport options are mutually exclusive: choose one of ldaps, plain-ldap, or starttls")
	}

	switch {
	case usePlainLDAP:
		return ldapTransportPlain, nil
	case useStartTLS:
		return ldapTransportStartTLS, nil
	default:
		return ldapTransportLDAPS, nil
	}
}

func (t ldapTransport) defaultPort() int {
	if t == ldapTransportLDAPS {
		return 636
	}
	return 389
}

func (t ldapTransport) dialScheme() string {
	if t == ldapTransportLDAPS {
		return "ldaps"
	}
	return "ldap"
}

func (t ldapTransport) usesTLS() bool {
	return t != ldapTransportPlain
}

func (t ldapTransport) usesStartTLS() bool {
	return t == ldapTransportStartTLS
}

func (t ldapTransport) globalCatalogPort() int {
	if t == ldapTransportLDAPS {
		return globalCatalogLDAPS
	}
	return globalCatalogLDAP
}

func selectKerberosAuthSource(user, password string, opts map[string]string) (kerberosAuthSource, error) {
	switch {
	case opts[OptionKeytab] != "":
		if user == "" {
			return "", errors.New("--user is required with --keytab to identify the principal")
		}
		return kerberosAuthSourceKeytab, nil
	case opts[OptionCCache] != "":
		return kerberosAuthSourceCCache, nil
	case password != "":
		if user == "" {
			return "", errors.New("--user is required with --password for Kerberos authentication")
		}
		return kerberosAuthSourcePassword, nil
	default:
		if user != "" {
			return "", errors.New("--kerberos with --user also requires --password, --keytab, or --ccache; omit --user to use the current Windows session")
		}
		return kerberosAuthSourceCurrentSession, nil
	}
}

func dialLDAPHost(host string, port int, transport ldapTransport, insecure bool, timeout time.Duration) (*ldap.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if transport == ldapTransportLDAPS {
		opts = append(opts, ldap.DialWithTLSConfig(newLDAPTLSConfig(host, insecure)))
	}

	ldapConn, err := ldap.DialURL(transport.dialScheme()+"://"+addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial LDAP at %s: %w", addr, err)
	}
	if transport.usesStartTLS() {
		if err := ldapConn.StartTLS(newLDAPTLSConfig(host, insecure)); err != nil {
			ldapConn.Close()
			return nil, fmt.Errorf("StartTLS upgrade failed for %s: %w", addr, err)
		}
	}
	return ldapConn, nil
}

// ActiveDirectoryConnection manages a single LDAP connection to an
// Active Directory Domain Services domain controller.
type ActiveDirectoryConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	ldapConn  *ldap.Conn
	dcHost    string
	transport ldapTransport

	baseDN string
	// domainDN is always the domain root DN from RootDSE, used for SID/metadata.
	// Separate from baseDN which may be overridden by --base-dn.
	domainDN             string
	configDN             string
	schemaDN             string
	rootDomainDN         string
	domainSID            string
	rootDomainSID        string
	domainDnsZonesDN     string
	forestDnsZonesDN     string
	domainNamingContexts []string

	domainFunctionalLevel string
	forestFunctionalLevel string
	cacheMu               sync.RWMutex
	cache                 map[string]any

	// SMB probe state. Lazy-initialized on first SMB-backed field access.
	// sync.Once (not CachedFetch) because failed probes must not retry.
	smbProbeOnce sync.Once
	smbNegotiate *NegotiateResult
	smbProbeErr  error

	smbOnce sync.Once
	smbConn *gosmb.Connection
	smbErr  error
}

// NewActiveDirectoryConnection dials the domain controller, binds, queries
// RootDSE for naming contexts and functional levels, and retrieves the domain
// and forest root SIDs.
func NewActiveDirectoryConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ActiveDirectoryConnection, error) {
	if conf.Options == nil {
		return nil, errors.New("active directory provider requires connection options")
	}

	dcHost := conf.Options[OptionDC]
	if dcHost == "" {
		return nil, errors.New("active directory provider requires option 'dc' (domain controller hostname)")
	}

	user, password := resolveCredentials(conf)

	backend := conf.Options[OptionBackend]
	if backend == "rsat" {
		return nil, errors.New("backend 'rsat' is not yet implemented; use --backend=ldap (the default)")
	}

	transport, err := resolveLDAPTransport(conf.Options)
	if err != nil {
		return nil, err
	}
	useKerberos := isTrueOption(conf.Options[OptionKerberos])
	insecure := isTrueOption(conf.Options[OptionInsecure])

	// Kerberos auth doesn't require a password (keytab or ccache can substitute),
	// but simple bind always does.
	if !useKerberos {
		if user == "" {
			return nil, errors.New("active directory provider requires option 'user'")
		}
		if password == "" {
			return nil, errors.New("active directory provider requires option 'password'")
		}
	}

	port := defaultPort(transport)
	if p := conf.Options[OptionPort]; p != "" {
		parsed, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		port = parsed
	}

	ldapConn, err := dialLDAPHost(dcHost, port, transport, insecure, dialTimeout)
	if err != nil {
		return nil, err
	}

	if err := bindLDAPConn(ldapConn, dcHost, user, password, conf.Options, transport, true); err != nil {
		ldapConn.Close()
		return nil, err
	}

	c := &ActiveDirectoryConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		ldapConn:   ldapConn,
		dcHost:     dcHost,
		transport:  transport,
		cache:      make(map[string]any),
	}

	// Override baseDN: --base-dn takes precedence, then --domain, then RootDSE auto-detection.
	if explicitBase := conf.Options[OptionBaseDN]; explicitBase != "" {
		c.baseDN = explicitBase
	} else if domain := conf.Options[OptionDomain]; domain != "" {
		c.baseDN = domainToDN(domain)
	}

	if err := c.discoverRootDSE(); err != nil {
		ldapConn.Close()
		return nil, fmt.Errorf("RootDSE discovery failed: %w", err)
	}

	if err := c.discoverDomainSID(); err != nil {
		ldapConn.Close()
		return nil, fmt.Errorf("domain SID discovery failed: %w", err)
	}

	if err := c.discoverRootDomainSID(); err != nil {
		ldapConn.Close()
		return nil, fmt.Errorf("forest root domain SID discovery failed: %w", err)
	}

	authMethod := "simple-bind"
	if useKerberos {
		authMethod = "kerberos/gssapi"
	}
	log.Info().
		Str("dc", dcHost).
		Str("transport", string(transport)).
		Str("baseDN", c.baseDN).
		Str("domainSID", c.domainSID).
		Str("forestRootSID", c.rootDomainSID).
		Str("domainLevel", c.domainFunctionalLevel).
		Str("forestLevel", c.forestFunctionalLevel).
		Str("auth", authMethod).
		Msg("Active Directory connection established")

	return c, nil
}

// domainToDN converts a DNS domain name to an LDAP distinguished name.
// Example: "mini.lab" → "DC=mini,DC=lab"
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

func newLDAPTLSConfig(serverName string, insecure bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: insecure, //nolint:gosec // user-controlled flag for lab/test environments
	}
}

// bindLDAPConn authenticates an already-established LDAP transport using either
// Kerberos/GSSAPI or simple bind.
func bindLDAPConn(conn *ldap.Conn, dcHost, user, password string, opts map[string]string, transport ldapTransport, warnOnPlaintext bool) error {
	if isTrueOption(opts[OptionKerberos]) {
		return kerberosGSSAPIBind(conn, dcHost, user, password, opts, serverCertFromConn(conn))
	}
	if warnOnPlaintext && !transport.usesTLS() {
		log.Warn().Str("dc", dcHost).Msg("LDAP simple bind over plaintext connection — credentials are transmitted in the clear; use LDAPS (the default transport) or --starttls unless you explicitly opt into --plain-ldap for a lab")
	}
	if err := conn.Bind(user, password); err != nil {
		return fmt.Errorf("LDAP bind failed for %s: %w", user, err)
	}
	return nil
}

// serverCertFromConn returns the DC's leaf TLS certificate for the connection,
// or nil when the transport is plaintext LDAP. It is used to derive the RFC 5929
// tls-server-end-point channel binding for Kerberos SASL binds.
func serverCertFromConn(conn *ldap.Conn) *x509.Certificate {
	state, ok := conn.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

func newKerberosClient(user, password, dcHost string, opts map[string]string, serverCert *x509.Certificate) (ldap.GSSAPIClient, func() error, kerberosAuthSource, string, error) {
	source, err := selectKerberosAuthSource(user, password, opts)
	if err != nil {
		return nil, nil, "", "", err
	}

	// The current Windows logon session is sourced via SSPI and needs no
	// krb5 config of its own.
	if source == kerberosAuthSourceCurrentSession {
		gssClient, cleanup, err := newImplicitKerberosClient(serverCert)
		if err != nil {
			return nil, nil, "", "", err
		}
		return gssClient, cleanup, source, "", nil
	}

	// Kerberos identifies a principal as user@REALM. The NetBIOS DOMAIN\user
	// form works for simple bind but not here — it would be parsed as a
	// realm-less principal and fail obscurely against the KDC. Catch it early
	// with a clear message. Only keytab and password derive a principal from
	// --user; ccache carries its own principal, so DOMAIN\user is harmless there.
	if (source == kerberosAuthSourceKeytab || source == kerberosAuthSourcePassword) && strings.Contains(user, `\`) {
		return nil, nil, "", "", fmt.Errorf("--kerberos requires the user as user@REALM (for example admin@CORP.LOCAL), "+
			"not the NetBIOS DOMAIN\\user form %q; drop --kerberos to use simple bind with DOMAIN\\user", user)
	}

	// Keytab, ccache, and password auth all need a krb5 config. When no
	// krb5.conf file is available — the default on Windows, where
	// /etc/krb5.conf does not exist — synthesize one from the connection
	// parameters so users don't have to hand-author a krb5.conf just to scan.
	// We build the gokrb5 client from the in-memory *config.Config directly
	// (rather than the file-path gssapi.NewClientWith* helpers) precisely so
	// no file on disk is required.
	krb5conf, krb5confDesc, err := loadOrGenerateKrb5Config(opts, user, dcHost)
	if err != nil {
		return nil, nil, "", "", err
	}

	switch source {
	case kerberosAuthSourceKeytab:
		principal, realm := splitPrincipal(user)
		kt, err := keytab.Load(opts[OptionKeytab])
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("kerberos keytab %q: %w", opts[OptionKeytab], err)
		}
		krbClient := client.NewWithKeytab(principal, realm, kt, krb5conf, client.DisablePAFXFAST(true))
		cb := newChannelBindingClient(&gssapi.Client{Client: krbClient}, serverCert)
		return cb, cb.Close, source, krb5confDesc, nil
	case kerberosAuthSourceCCache:
		ccache, err := credentials.LoadCCache(opts[OptionCCache])
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("kerberos ccache %q: %w", opts[OptionCCache], err)
		}
		krbClient, err := client.NewFromCCache(ccache, krb5conf, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("kerberos ccache client: %w", err)
		}
		cb := newChannelBindingClient(&gssapi.Client{Client: krbClient}, serverCert)
		return cb, cb.Close, source, krb5confDesc, nil
	case kerberosAuthSourcePassword:
		principal, realm := splitPrincipal(user)
		krbClient := client.NewWithPassword(principal, realm, password, krb5conf, client.DisablePAFXFAST(true))
		cb := newChannelBindingClient(&gssapi.Client{Client: krbClient}, serverCert)
		return cb, cb.Close, source, krb5confDesc, nil
	default:
		return nil, nil, "", "", fmt.Errorf("unsupported Kerberos auth source %q", source)
	}
}

// kerberosGSSAPIBind performs a Kerberos/GSSAPI SASL bind on the connection.
// It supports four credential sources, tried in order:
//  1. --keytab: service keytab file
//  2. --ccache: existing Kerberos credential cache (e.g. from kinit)
//  3. --user + --password: password-based Kerberos AS exchange
//  4. On Windows only, the current logon session when no explicit credential
//     material is supplied.
func kerberosGSSAPIBind(conn *ldap.Conn, dcHost, user, password string, opts map[string]string, serverCert *x509.Certificate) error {
	// LDAP service principal: ldap/<dc_hostname>
	servicePrincipal := "ldap/" + dcHost

	gssClient, cleanup, source, krb5confDesc, err := newKerberosClient(user, password, dcHost, opts, serverCert)
	if err != nil {
		return err
	}
	defer cleanup()

	authLogger := log.Debug().
		Str("servicePrincipal", servicePrincipal).
		Str("credentialSource", string(source)).
		Bool("channelBinding", serverCert != nil)
	if krb5confDesc != "" {
		authLogger = authLogger.Str("krb5conf", krb5confDesc)
	}
	authLogger.Msg("performing GSSAPI/Kerberos bind")

	if err := conn.GSSAPIBind(gssClient, servicePrincipal, ""); err != nil {
		return enrichKerberosBindError(err, servicePrincipal, krb5confDesc, serverCert != nil)
	}

	return nil
}

// enrichKerberosBindError turns a raw GSSAPI/Kerberos bind failure into an
// actionable message. The underlying gokrb5 errors (KDC unreachable, no SRV
// records, invalid token) are terse and offer no remediation, which is
// especially unhelpful for the multi-forest case where the right fix is a
// hand-authored krb5.conf.
func enrichKerberosBindError(err error, servicePrincipal, krb5confDesc string, overTLS bool) error {
	msg := err.Error()
	autoGenerated := strings.HasPrefix(krb5confDesc, "auto-generated")

	switch {
	// AD error 80090346 (SEC_E_BAD_BINDINGS): the DC enforces LDAP channel
	// binding and rejected the token. Over plaintext LDAP no binding can be
	// sent at all; over TLS we send a tls-server-end-point binding, so a
	// remaining failure points at the DC certificate or a terminating proxy.
	case strings.Contains(msg, "80090346"):
		if !overTLS {
			return fmt.Errorf("GSSAPI bind to %s failed: the domain controller requires LDAP "+
				"channel binding, which is only possible over TLS — use LDAPS (the default transport) "+
				"or --starttls: %w", servicePrincipal, err)
		}
		return fmt.Errorf("GSSAPI bind to %s failed: the domain controller rejected the channel "+
			"binding token (ensure --dc is the DC's certificate hostname and the TLS connection "+
			"terminates at the DC, not a proxy/load balancer): %w", servicePrincipal, err)

	// AD error 80090308 (SEC_E_INVALID_TOKEN) with data 57 means the DC rejected
	// the AP-REQ itself. A missing mutual-required AP option causes it (set
	// since go-ldap issue #536 surfaced it; see newAPREQMechToken), and it has
	// been attributed to LDAP signing enforcement on a non-TLS transport. A
	// missing or wrong channel binding is 80090346 instead, handled above.
	case strings.Contains(msg, "80090308"):
		if !overTLS {
			return fmt.Errorf("GSSAPI bind to %s failed: the domain controller requires LDAP signing "+
				"and/or channel binding for SASL binds; use LDAPS (the default transport) or --starttls, or "+
				"fall back to simple bind with --user/--password without --kerberos: %w", servicePrincipal, err)
		}
		return fmt.Errorf("GSSAPI bind to %s failed (the domain controller rejected the SASL bind; "+
			"try simple bind with --user/--password without --kerberos over LDAPS): %w", servicePrincipal, err)

	// KDC could not be located or reached. With an auto-generated config this
	// is the expected failure mode for a multi-forest topology whose foreign
	// realm KDC is not discoverable via DNS SRV records. The substrings below
	// are the Kerberos-specific tokens gokrb5 emits for KDC discovery/reach
	// and the AS/TGS exchanges — "KDC" alone covers "no KDC SRV records found",
	// "no KDCs defined", "error sending to a KDC", "error resolving KDC
	// address", and "no KDCs resolved", and won't match unrelated LDAP errors.
	case strings.Contains(msg, "KDC") ||
		strings.Contains(msg, "AS Exchange") ||
		strings.Contains(msg, "TGS Exchange") ||
		strings.Contains(msg, "valid TGT"):
		hint := "ensure the realm's KDC is reachable from this host"
		if autoGenerated {
			hint = "the Kerberos config was auto-generated from --dc/--domain/--user; ensure DNS can " +
				"resolve the realm's _kerberos._tcp SRV records (and the KDCs are reachable), or supply a " +
				"krb5.conf via --krb5conf that lists the KDCs for every realm involved — recommended for " +
				"multi-forest setups where the user and the domain controller live in different forests"
		}
		return fmt.Errorf("GSSAPI bind to %s failed: could not obtain a Kerberos ticket (%s): %w", servicePrincipal, hint, err)

	default:
		return fmt.Errorf("GSSAPI bind to %s failed: %w", servicePrincipal, err)
	}
}

// loadOrGenerateKrb5Config returns a Kerberos configuration for keytab,
// ccache, or password authentication. It honors an explicit --krb5conf, the
// KRB5_CONFIG environment variable, or an existing default /etc/krb5.conf. When
// none of those is present it synthesizes a config from the connection
// parameters (see generateKrb5Config) — which is what lets
// `--kerberos --user --password` work on Windows, where /etc/krb5.conf does
// not exist. The second return value is a short description for logs: either
// the file path used or "auto-generated (...)".
func loadOrGenerateKrb5Config(opts map[string]string, user, dcHost string) (*config.Config, string, error) {
	if path := existingKrb5ConfPath(opts); path != "" {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, "", fmt.Errorf("loading krb5.conf %q: %w", path, err)
		}
		return cfg, path, nil
	}

	confText, desc, err := generateKrb5Config(dcHost, opts[OptionDomain], user)
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.NewFromString(confText)
	if err != nil {
		return nil, "", fmt.Errorf("parsing auto-generated krb5 config: %w", err)
	}
	return cfg, desc, nil
}

// existingKrb5ConfPath resolves the krb5.conf path to use, or "" when no file
// is configured or present. An explicit --krb5conf or KRB5_CONFIG is returned
// as-is (so a wrong path surfaces a clear load error rather than being silently
// replaced by a generated config); the platform default is returned only when
// the file actually exists.
func existingKrb5ConfPath(opts map[string]string) string {
	if p := opts[OptionKrb5Conf]; p != "" {
		return p
	}
	if p := os.Getenv("KRB5_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat(defaultKrb5ConfPath); err == nil {
		return defaultKrb5ConfPath
	}
	return ""
}

// generateKrb5Config builds an in-memory krb5.conf for Kerberos password,
// keytab, or ccache authentication when no krb5.conf file is present (the
// common case on Windows). The config is derived from the connection
// parameters:
//
//   - The service (DC) realm comes from --domain, or from the DC hostname's
//     DNS domain ("dc01.corp.local" -> "CORP.LOCAL"). Its KDC is pinned to the
//     DC host so the common single-realm case works without DNS.
//   - The user realm comes from the user@REALM principal and becomes the
//     default realm, so the initial AS exchange targets the right realm even
//     when the user lives in a different forest than the DC.
//   - dns_lookup_kdc lets gokrb5 discover KDCs for any realm via DNS SRV
//     records (_kerberos._tcp.<REALM>), which Active Directory publishes by
//     default. This is what makes cross-realm / multi-forest authentication
//     work without hand-listing every forest's KDC.
//
// It returns the config text and a short human-readable description for logs.
func generateKrb5Config(dcHost, domain, user string) (string, string, error) {
	dcRealm := strings.ToUpper(strings.TrimSpace(domain))
	if dcRealm == "" {
		dcRealm = strings.ToUpper(domainFromHost(dcHost))
	}

	_, userRealm := splitPrincipal(user)
	userRealm = strings.ToUpper(userRealm)

	// The user authenticates against their own realm when given as
	// user@REALM, otherwise against the DC's realm.
	defaultRealm := userRealm
	if defaultRealm == "" {
		defaultRealm = dcRealm
	}
	if defaultRealm == "" {
		return "", "", errors.New("cannot determine a Kerberos realm for auto-configuration: " +
			"pass a realm via --user <user@REALM>, set --domain, or provide a krb5.conf with --krb5conf")
	}

	var b strings.Builder
	b.WriteString("[libdefaults]\n")
	fmt.Fprintf(&b, "  default_realm = %s\n", defaultRealm)
	// AD issues large PAC-bearing tickets; prefer TCP to avoid UDP truncation.
	b.WriteString("  udp_preference_limit = 1\n")
	// Discover KDCs for any realm (the user's and the DC's, which may live in
	// different forests) from DNS SRV records.
	b.WriteString("  dns_lookup_kdc = true\n")
	b.WriteString("  dns_lookup_realm = false\n")

	// Pin the DC's realm to the DC host so the common single-realm case works
	// even without DNS, and map the DC's domain to that realm so the
	// ldap/<dc> service principal resolves.
	if dcRealm != "" && dcHost != "" {
		b.WriteString("\n[realms]\n")
		fmt.Fprintf(&b, "  %s = {\n", dcRealm)
		fmt.Fprintf(&b, "    kdc = %s\n", dcHost)
		b.WriteString("  }\n")

		dcDomain := domainFromHost(dcHost)
		if dcDomain == "" {
			dcDomain = strings.TrimSpace(domain)
		}
		if dcDomain != "" {
			dcDomain = strings.ToLower(dcDomain)
			b.WriteString("\n[domain_realm]\n")
			fmt.Fprintf(&b, "  .%s = %s\n", dcDomain, dcRealm)
			fmt.Fprintf(&b, "  %s = %s\n", dcDomain, dcRealm)
		}
	}

	desc := fmt.Sprintf("auto-generated (default_realm=%s", defaultRealm)
	if dcRealm != "" && dcRealm != defaultRealm {
		desc += fmt.Sprintf(", dc_realm=%s", dcRealm)
	}
	if dcHost != "" {
		desc += fmt.Sprintf(", kdc=%s", dcHost)
	}
	desc += ")"
	return b.String(), desc, nil
}

// domainFromHost strips the leftmost label from a hostname to get its DNS
// domain: "dc01.corp.local" -> "corp.local". It returns "" when host is empty,
// an IP address, or has no domain part (a single label), since none of those
// yield a Kerberos realm.
func domainFromHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if idx := strings.Index(host, "."); idx >= 0 && idx+1 < len(host) {
		return host[idx+1:]
	}
	return ""
}

// splitPrincipal splits a Kerberos principal like "user@REALM" into
// ("user", "REALM"). If no '@' is present, realm is empty and the
// gokrb5 client uses the default realm from krb5.conf.
func splitPrincipal(upn string) (string, string) {
	if before, after, ok := strings.CutLast(upn, "@"); ok {
		return before, after
	}
	return upn, ""
}

// discoverRootDSE queries the RootDSE (base scope, empty baseDN) to populate
// naming contexts, functional levels, and DNS zone partitions.
func (c *ActiveDirectoryConnection) discoverRootDSE() error {
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{
			"defaultNamingContext",
			"configurationNamingContext",
			"schemaNamingContext",
			"rootDomainNamingContext",
			"namingContexts",
			"domainFunctionality",
			"forestFunctionality",
		},
		nil,
	)

	resp, err := c.ldapConn.Search(req)
	if err != nil {
		return fmt.Errorf("RootDSE search: %w", err)
	}
	if len(resp.Entries) == 0 {
		return errors.New("RootDSE returned no entries")
	}

	entry := resp.Entries[0]

	c.domainDN = GetStringAttr(entry, "defaultNamingContext")
	// Only set baseDN from RootDSE if not explicitly overridden via options.
	if c.baseDN == "" {
		c.baseDN = c.domainDN
	}
	c.configDN = GetStringAttr(entry, "configurationNamingContext")
	c.schemaDN = GetStringAttr(entry, "schemaNamingContext")
	c.rootDomainDN = GetStringAttr(entry, "rootDomainNamingContext")

	domainLevel := GetStringAttr(entry, "domainFunctionality")
	forestLevel := GetStringAttr(entry, "forestFunctionality")
	c.domainFunctionalLevel = FunctionalLevelName(domainLevel)
	c.forestFunctionalLevel = FunctionalLevelName(forestLevel)

	// Detect domain naming contexts and DNS application partitions from RootDSE.

	namingContexts := GetStringSliceAttr(entry, "namingContexts")
	c.domainDnsZonesDN, c.forestDnsZonesDN, c.domainNamingContexts = classifyNamingContexts(namingContexts)

	return nil
}

// discoverDomainSID retrieves the objectSid of the current domain by
// searching the domainDN at base scope.
func (c *ActiveDirectoryConnection) discoverDomainSID() error {
	sid, err := c.fetchObjectSID(c.domainDN)
	if err != nil {
		return fmt.Errorf("reading domain objectSid from %s: %w", c.domainDN, err)
	}
	c.domainSID = sid
	return nil
}

// discoverRootDomainSID retrieves the objectSid of the forest root domain.
// In a single-domain forest, rootDomainDN == domainDN, so this may be identical
// to domainSID. In a child domain, the child DC does not hold the parent partition
// so a direct base-scope read would yield a referral. Fallback order:
//  1. Direct base-scope read (works when connected to the forest root DC).
//  2. Global Catalog query on port 3268 (works when the DC is a GC — typical).
//  3. crossRef objectSid from CN=Partitions,CN=Configuration,... (rarely populated).
//  4. Current domainSID with warning (last resort; Enterprise/Schema Admin detection will be wrong).
func (c *ActiveDirectoryConnection) discoverRootDomainSID() error {
	if c.rootDomainDN == "" || c.rootDomainDN == c.domainDN {
		c.rootDomainSID = c.domainSID
		return nil
	}

	// 1. Direct base-scope read.
	sid, err := c.fetchObjectSID(c.rootDomainDN)
	if err == nil {
		c.rootDomainSID = sid
		return nil
	}
	log.Debug().Err(err).Msg("direct root domain SID lookup failed")

	// 2. Global Catalog (port 3268). Any GC holds a partial replica of every
	//    domain in the forest, including the root domain's objectSid.
	gcSID, gcErr := c.fetchRootDomainSIDViaGC()
	if gcErr == nil {
		c.rootDomainSID = gcSID
		return nil
	}
	log.Debug().Err(gcErr).Msg("GC root domain SID lookup failed")

	// 3. crossRef objectSid from the Partitions container.
	partitionsDN := "CN=Partitions," + c.configDN
	req := ldap.NewSearchRequest(
		partitionsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=crossRef)(nCName=%s))", ldap.EscapeFilter(c.rootDomainDN)),
		[]string{"objectSid"},
		nil,
	)
	resp, searchErr := c.ldapConn.Search(req)
	if searchErr != nil {
		return fmt.Errorf("crossRef lookup in %s failed: %w (direct: %v, GC: %v)", partitionsDN, searchErr, err, gcErr)
	}
	if len(resp.Entries) > 0 {
		raw := GetBinaryAttr(resp.Entries[0], "objectSid")
		if len(raw) > 0 {
			rootSID, decodeErr := DecodeSID(raw)
			if decodeErr != nil {
				return fmt.Errorf("decoding forest root SID from crossRef: %w", decodeErr)
			}
			c.rootDomainSID = rootSID
			return nil
		}
	}

	// 4. Last resort: use current domain SID.
	log.Warn().Str("rootDomainDN", c.rootDomainDN).Msg("could not resolve forest root SID via direct read, GC, or crossRef; Enterprise/Schema Admin detection may be incomplete")
	c.rootDomainSID = c.domainSID
	return nil
}

// fetchRootDomainSIDViaGC connects to the Global Catalog on the current DC
// and reads the forest root domain's objectSid using the same effective LDAP
// transport as the primary connection: LDAPS uses 3269, while LDAP and
// StartTLS use 3268.
func (c *ActiveDirectoryConnection) fetchRootDomainSIDViaGC() (string, error) {
	transport := c.effectiveLDAPTransport()
	gcPort := transport.globalCatalogPort()
	gcConn, err := dialLDAPHost(c.dcHost, gcPort, transport, isTrueOption(c.Conf.Options[OptionInsecure]), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("GC port %d unreachable on %s: %w", gcPort, c.dcHost, err)
	}
	defer gcConn.Close()

	// Re-bind with the same credentials on the GC connection.
	user, password := c.resolveCredentials()
	if err := bindLDAPConn(gcConn, c.dcHost, user, password, c.Conf.Options, transport, false); err != nil {
		return "", fmt.Errorf("GC bind failed: %w", err)
	}

	req := ldap.NewSearchRequest(
		c.rootDomainDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)
	resp, err := gcConn.Search(req)
	if err != nil {
		return "", fmt.Errorf("GC search for %s: %w", c.rootDomainDN, err)
	}
	if len(resp.Entries) == 0 {
		return "", fmt.Errorf("GC returned no entry for %s", c.rootDomainDN)
	}
	raw := GetBinaryAttr(resp.Entries[0], "objectSid")
	if len(raw) == 0 {
		return "", fmt.Errorf("GC objectSid empty for %s", c.rootDomainDN)
	}
	return DecodeSID(raw)
}

// fetchObjectSID performs a base-scope search for objectSid on the given DN
// and returns the decoded string SID.
func (c *ActiveDirectoryConnection) fetchObjectSID(dn string) (string, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)
	resp, err := c.ldapConn.Search(req)
	if err != nil {
		return "", err
	}
	if len(resp.Entries) == 0 {
		return "", fmt.Errorf("no entry returned for DN %s", dn)
	}
	raw := GetBinaryAttr(resp.Entries[0], "objectSid")
	if len(raw) == 0 {
		return "", fmt.Errorf("objectSid attribute empty for DN %s", dn)
	}
	return DecodeSID(raw)
}

func defaultPort(transport ldapTransport) int {
	return transport.defaultPort()
}

func (c *ActiveDirectoryConnection) effectiveLDAPTransport() ldapTransport {
	if c != nil && c.transport != "" {
		return c.transport
	}
	if c == nil || c.Conf == nil {
		return ldapTransportLDAPS
	}
	transport, err := resolveLDAPTransport(c.Conf.Options)
	if err != nil {
		return ldapTransportLDAPS
	}
	return transport
}

func (c *ActiveDirectoryConnection) LDAPPort() int {
	if c != nil && c.Conf != nil {
		if p := c.Conf.Options[OptionPort]; p != "" {
			if parsed, err := strconv.Atoi(p); err == nil {
				return parsed
			}
		}
	}
	return c.effectiveLDAPTransport().defaultPort()
}

func (c *ActiveDirectoryConnection) LDAPUsesTLS() bool {
	return c.effectiveLDAPTransport().usesTLS()
}

func (c *ActiveDirectoryConnection) LDAPUsesStartTLS() bool {
	return c.effectiveLDAPTransport().usesStartTLS()
}

func (c *ActiveDirectoryConnection) DialLDAPHost(host string, port int, timeout time.Duration) (*ldap.Conn, error) {
	var insecure bool
	if c != nil && c.Conf != nil {
		insecure = isTrueOption(c.Conf.Options[OptionInsecure])
	}
	return dialLDAPHost(host, port, c.effectiveLDAPTransport(), insecure, timeout)
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

func (c *ActiveDirectoryConnection) Name() string             { return "activedirectory" }
func (c *ActiveDirectoryConnection) Asset() *inventory.Asset  { return c.asset }
func (c *ActiveDirectoryConnection) FQDN() string             { return c.dcHost }
func (c *ActiveDirectoryConnection) LDAPConn() *ldap.Conn     { return c.ldapConn }
func (c *ActiveDirectoryConnection) BaseDN() string           { return c.baseDN }
func (c *ActiveDirectoryConnection) ConfigDN() string         { return c.configDN }
func (c *ActiveDirectoryConnection) SchemaDN() string         { return c.schemaDN }
func (c *ActiveDirectoryConnection) RootDomainDN() string     { return c.rootDomainDN }
func (c *ActiveDirectoryConnection) DomainSID() string        { return c.domainSID }
func (c *ActiveDirectoryConnection) RootDomainSID() string    { return c.rootDomainSID }
func (c *ActiveDirectoryConnection) DomainDnsZonesDN() string { return c.domainDnsZonesDN }
func (c *ActiveDirectoryConnection) ForestDnsZonesDN() string { return c.forestDnsZonesDN }
func (c *ActiveDirectoryConnection) DomainNamingContexts() []string {
	res := make([]string, len(c.domainNamingContexts))
	copy(res, c.domainNamingContexts)
	return res
}
func (c *ActiveDirectoryConnection) DomainDN() string              { return c.domainDN }
func (c *ActiveDirectoryConnection) DomainFunctionalLevel() string { return c.domainFunctionalLevel }
func (c *ActiveDirectoryConnection) ForestFunctionalLevel() string { return c.forestFunctionalLevel }

// PlatformId returns a deterministic platform identifier for the connected domain.
func (c *ActiveDirectoryConnection) PlatformId() string {
	return "//platformid.api.mondoo.app/runtime/activedirectory/domain/" + c.domainDN
}

// Close terminates the LDAP connection and any lazy-created SMB connection.
func (c *ActiveDirectoryConnection) Close() {
	if c.ldapConn != nil {
		c.ldapConn.Close()
	}
	if c.smbConn != nil {
		c.smbConn.Close()
	}
}

// resolveCredentials extracts user/password from Config using the standard
// precedence: Credentials[0] (set by ParseCLI) > Options map.
// This is the free-function form used during construction before c exists.
func resolveCredentials(conf *inventory.Config) (user, password string) {
	if len(conf.Credentials) > 0 && conf.Credentials[0].Type == vault.CredentialType_password {
		return conf.Credentials[0].User, string(conf.Credentials[0].Secret)
	}
	return conf.Options[OptionUser], conf.Options[OptionPassword]
}

// resolveCredentials is the method form for use after construction.
func (c *ActiveDirectoryConnection) resolveCredentials() (user, password string) {
	return resolveCredentials(c.Conf)
}

// ProbeLDAPSigning detects whether the DC rejects unsigned simple binds by
// attempting one with invalid credentials on port 389. If the DC rejects with
// LDAPResultStrongAuthRequired, signing is enforced. If the DC instead rejects
// the bogus credentials as invalid, unsigned simple binds are still accepted.
// Uses a throwaway connection and never transmits real scan credentials.
func (c *ActiveDirectoryConnection) ProbeLDAPSigning() (bool, error) {
	addr := net.JoinHostPort(c.dcHost, "389")
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	probeConn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
	if err != nil {
		return false, fmt.Errorf("LDAP signing probe: port 389 unreachable on %s: %w", c.dcHost, err)
	}
	defer probeConn.Close()

	err = probeConn.Bind(ldapSigningProbeUser, ldapSigningProbePassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultStrongAuthRequired) {
			return true, nil
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("LDAP signing probe bind failed: %w", err)
	}

	return false, nil
}

// ---------------------------------------------------------------------------
// Thread-safe cache
// ---------------------------------------------------------------------------

// CachedFetch returns a cached value for the given key, computing it via fn
// on first access. Concurrent callers block on the write if the key is absent.
func (c *ActiveDirectoryConnection) CachedFetch(key string, fn func() (any, error)) (any, error) {
	c.cacheMu.RLock()
	if v, ok := c.cache[key]; ok {
		c.cacheMu.RUnlock()
		return v, nil
	}
	c.cacheMu.RUnlock()

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Double-check after acquiring write lock.
	if v, ok := c.cache[key]; ok {
		return v, nil
	}

	v, err := fn()
	if err != nil {
		return nil, err
	}
	c.cache[key] = v
	return v, nil
}
