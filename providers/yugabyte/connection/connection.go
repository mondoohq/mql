// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

const (
	// OptionHost is the hostname or IP address of the node to connect to.
	OptionHost = "host"
	// OptionMasterHTTPPort is the HTTP port of the master on the host.
	OptionMasterHTTPPort = "master-http-port"
	// OptionTserverHTTPPort is the HTTP port of the tablet server on the host.
	OptionTserverHTTPPort = "tserver-http-port"
	// OptionYSQLPort is the YSQL (PostgreSQL protocol) port.
	OptionYSQLPort = "ysql-port"
	// OptionYCQLPort is the YCQL (CQL protocol) port.
	OptionYCQLPort = "ycql-port"
	// OptionDatabase is the YSQL database the connection opens.
	OptionDatabase = "database"
	// OptionSSLMode selects the YSQL TLS mode (disable/allow/prefer/require/verify-ca/verify-full).
	OptionSSLMode = "sslmode"
	// OptionSSLRootCert is the path to the CA certificate that signed the
	// server certificates; it is trusted for YSQL, YCQL, and HTTPS.
	OptionSSLRootCert = "sslrootcert"
	// OptionSSLCert is the path to a client certificate for YSQL and YCQL.
	OptionSSLCert = "sslcert"
	// OptionSSLKey is the path to the client certificate's private key.
	OptionSSLKey = "sslkey"
	// OptionYCQLTLS makes the YCQL connection use TLS when "true"; it is
	// implied by OptionSSLRootCert.
	OptionYCQLTLS = "ycql-tls"
	// OptionHTTPS makes the master and tablet server HTTP requests use HTTPS when "true".
	OptionHTTPS = "https"
	// OptionTLSInsecure skips server certificate verification for YCQL and HTTPS when "true".
	OptionTLSInsecure = "tls-insecure"

	// EnvPassword is read for the password when no password is given.
	EnvPassword = "YUGABYTE_PASSWORD"
	// EnvYCQLPassword is read for the YCQL password when no YCQL password is
	// given; without either, YCQL uses the password.
	EnvYCQLPassword = "YUGABYTE_YCQL_PASSWORD"
)

const (
	defaultMasterHTTPPort  = 7000
	defaultTserverHTTPPort = 9000
	defaultYSQLPort        = 5433
	defaultYCQLPort        = 9042
	defaultDatabase        = "yugabyte"
	defaultYSQLUser        = "yugabyte"
	defaultYCQLUser        = "cassandra"
)

// YugabyteConnection holds what is needed to reach a YugabyteDB cluster
// through one of its nodes: the master and tablet server HTTP APIs on the
// host, and YSQL and YCQL connections, each opened on first use.
type YugabyteConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host            string
	masterHTTPPort  int
	tserverHTTPPort int
	ysqlPort        int
	ycqlPort        int
	database        string
	// user is the user given on the command line; empty selects each
	// API's default user.
	user     string
	password string
	// ycqlUser and ycqlPassword override user and password for YCQL.
	ycqlUser     string
	ycqlPassword string
	sslmode      string
	sslrootcert  string
	sslcert      string
	sslkey       string
	ycqlTLS      bool
	https        bool
	tlsInsecure  bool

	httpOnce   sync.Once
	httpClient *http.Client
	httpErr    error

	poolOnce sync.Once
	pool     *pgxpool.Pool
	poolErr  error

	sessionOnce sync.Once
	session     *gocql.Session
	sessionErr  error

	memoMu sync.Mutex
	memo   map[string]*memoEntry
}

type memoEntry struct {
	once  sync.Once
	value any
	err   error
}

// Memo runs fn once per key for the lifetime of the connection and returns
// its result to every caller, so a list several resources read is fetched
// once per scan.
func (c *YugabyteConnection) Memo(key string, fn func() (any, error)) (any, error) {
	c.memoMu.Lock()
	if c.memo == nil {
		c.memo = map[string]*memoEntry{}
	}
	e, ok := c.memo[key]
	if !ok {
		e = &memoEntry{}
		c.memo[key] = e
	}
	c.memoMu.Unlock()

	e.once.Do(func() {
		e.value, e.err = fn()
	})
	return e.value, e.err
}

func NewYugabyteConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*YugabyteConnection, error) {
	conn := &YugabyteConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}
	opts := conf.Options

	conn.host = opts[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for yugabyte connection")
	}

	var err error
	ports := []struct {
		option string
		def    int
		dst    *int
	}{
		{OptionMasterHTTPPort, defaultMasterHTTPPort, &conn.masterHTTPPort},
		{OptionTserverHTTPPort, defaultTserverHTTPPort, &conn.tserverHTTPPort},
		{OptionYSQLPort, defaultYSQLPort, &conn.ysqlPort},
		{OptionYCQLPort, defaultYCQLPort, &conn.ycqlPort},
	}
	for _, p := range ports {
		if *p.dst, err = parsePort(opts[p.option], p.def); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid %s: %v", p.option, err)
		}
	}

	conn.database = opts[OptionDatabase]
	if conn.database == "" {
		conn.database = defaultDatabase
	}

	// The first password credential is for YSQL and, unless a second one
	// is given, for YCQL too.
	passwords := 0
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			continue
		}
		switch passwords {
		case 0:
			conn.user = cred.User
			conn.password = string(cred.Secret)
		case 1:
			conn.ycqlUser = cred.User
			conn.ycqlPassword = string(cred.Secret)
		}
		passwords++
	}
	if conn.password == "" {
		conn.password = os.Getenv(EnvPassword)
	}
	if conn.ycqlPassword == "" {
		conn.ycqlPassword = os.Getenv(EnvYCQLPassword)
	}

	conn.sslmode = opts[OptionSSLMode]
	conn.sslrootcert = opts[OptionSSLRootCert]
	conn.sslcert = opts[OptionSSLCert]
	conn.sslkey = opts[OptionSSLKey]
	// A CA means the cluster encrypts client connections, which covers YCQL.
	conn.ycqlTLS = opts[OptionYCQLTLS] == "true" || conn.sslrootcert != ""
	conn.https = opts[OptionHTTPS] == "true"
	conn.tlsInsecure = opts[OptionTLSInsecure] == "true"
	if conn.sslmode == "" {
		conn.sslmode = "prefer"
		if conn.sslrootcert != "" {
			conn.sslmode = "verify-full"
		}
	}

	return conn, nil
}

func parsePort(value string, def int) (int, error) {
	if value == "" {
		return def, nil
	}
	p, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range", p)
	}
	return p, nil
}

func (c *YugabyteConnection) Name() string {
	return "yugabyte"
}

func (c *YugabyteConnection) Asset() *inventory.Asset {
	return c.asset
}

// Host returns the host the provider connects to.
func (c *YugabyteConnection) Host() string {
	return c.host
}

// MasterEndpoint returns the HTTP address of the master on the host.
func (c *YugabyteConnection) MasterEndpoint() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.masterHTTPPort))
}

// TserverEndpoint returns the HTTP address of the tablet server on the host.
func (c *YugabyteConnection) TserverEndpoint() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.tserverHTTPPort))
}

// ysqlUser returns the user YSQL authenticates as.
func (c *YugabyteConnection) ysqlUser() string {
	if c.user != "" {
		return c.user
	}
	return defaultYSQLUser
}

// ycqlCredentials returns the user and password YCQL authenticates with.
func (c *YugabyteConnection) ycqlCredentials() (string, string) {
	user := c.ycqlUser
	if user == "" {
		user = c.user
	}
	if user == "" {
		user = defaultYCQLUser
	}
	password := c.ycqlPassword
	if password == "" {
		password = c.password
	}
	return user, password
}

// tlsConfig returns the client TLS configuration for YCQL and HTTPS: the CA
// from sslrootcert (else the system pool) and the client certificate when
// one is given. The sslmode that governs YSQL governs them too: verify-full
// (the default with a CA) checks the chain and the host name, verify-ca only
// the chain, which suits a node reached at an address its certificate does
// not name, and require or tls-insecure checks nothing.
func (c *YugabyteConnection) tlsConfig(serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if c.sslrootcert != "" {
		pem, err := os.ReadFile(c.sslrootcert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in %s", c.sslrootcert)
		}
		cfg.RootCAs = pool
	}
	if c.sslcert != "" || c.sslkey != "" {
		cert, err := tls.LoadX509KeyPair(c.sslcert, c.sslkey)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	switch {
	case c.tlsInsecure || c.sslmode == "require":
		cfg.InsecureSkipVerify = true //nolint:gosec // asked for with --tls-insecure or --sslmode require
	case c.sslmode == "verify-ca":
		// Go verifies the host name with the chain; check the chain alone.
		cfg.InsecureSkipVerify = true //nolint:gosec // the chain is verified below
		cfg.VerifyPeerCertificate = verifyChain(cfg.RootCAs)
	}
	return cfg, nil
}

// verifyChain returns a check that the server certificate chains to roots
// (the system pool when nil), without checking the host name.
func verifyChain(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server presented no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
}

// HTTPClient returns the client for the master and tablet server HTTP APIs.
func (c *YugabyteConnection) HTTPClient() (*http.Client, error) {
	c.httpOnce.Do(func() {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if c.https {
			cfg, err := c.tlsConfig("")
			if err != nil {
				c.httpErr = err
				return
			}
			transport.TLSClientConfig = cfg
		}
		c.httpClient = &http.Client{Timeout: 15 * time.Second, Transport: transport}
	})
	return c.httpClient, c.httpErr
}

// URL returns the URL of path on the server at the HTTP address addr.
func (c *YugabyteConnection) URL(addr, path string) string {
	scheme := "http"
	if c.https {
		scheme = "https"
	}
	return scheme + "://" + addr + path
}

// ysqlConnString builds the postgresql:// URL for the YSQL connection.
func (c *YugabyteConnection) ysqlConnString() string {
	query := url.Values{}
	query.Set("sslmode", c.sslmode)
	if c.sslrootcert != "" {
		query.Set("sslrootcert", c.sslrootcert)
	}
	if c.sslcert != "" {
		query.Set("sslcert", c.sslcert)
	}
	if c.sslkey != "" {
		query.Set("sslkey", c.sslkey)
	}
	query.Set("application_name", "mondoo")
	query.Set("connect_timeout", "15")
	user := url.User(c.ysqlUser())
	if c.password != "" {
		user = url.UserPassword(c.ysqlUser(), c.password)
	}
	u := &url.URL{
		Scheme:   "postgresql",
		User:     user,
		Host:     net.JoinHostPort(c.host, strconv.Itoa(c.ysqlPort)),
		Path:     "/" + c.database,
		RawQuery: query.Encode(),
	}
	return u.String()
}

// YSQL returns the YSQL connection pool, opening it on first use.
func (c *YugabyteConnection) YSQL() (*pgxpool.Pool, error) {
	c.poolOnce.Do(func() {
		cfg, err := pgxpool.ParseConfig(c.ysqlConnString())
		if err != nil {
			c.poolErr = err
			return
		}
		cfg.MaxConns = 4
		c.pool, c.poolErr = pgxpool.NewWithConfig(context.Background(), cfg)
	})
	return c.pool, c.poolErr
}

// YCQL returns the YCQL session, opening it on first use. It talks to the
// configured node only.
func (c *YugabyteConnection) YCQL() (*gocql.Session, error) {
	c.sessionOnce.Do(func() {
		cluster := gocql.NewCluster(c.host)
		cluster.Port = c.ycqlPort
		cluster.Consistency = gocql.One
		cluster.ConnectTimeout = 10 * time.Second
		cluster.Timeout = 15 * time.Second
		// The nodes the cluster reports may not be reachable from the
		// scanner (published container ports); stay on the configured node.
		cluster.DisableInitialHostLookup = true
		cluster.Events.DisableNodeStatusEvents = true
		cluster.Events.DisableTopologyEvents = true
		cluster.Events.DisableSchemaEvents = true
		user, password := c.ycqlCredentials()
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: password,
		}
		if c.ycqlTLS {
			cfg, err := c.tlsConfig(c.host)
			if err != nil {
				c.sessionErr = err
				return
			}
			cluster.SslOpts = &gocql.SslOptions{
				Config: cfg,
				// With a configuration given, false leaves its checks as
				// they are; true would force the host name check.
				EnableHostVerification: false,
			}
		}
		c.session, c.sessionErr = cluster.CreateSession()
	})
	return c.session, c.sessionErr
}

// Close releases the YSQL pool and the YCQL session.
func (c *YugabyteConnection) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
	if c.session != nil {
		c.session.Close()
	}
}

// ErrNoCluster is returned when the master does not report a cluster UUID.
var ErrNoCluster = errors.New("yugabyte master did not report a cluster UUID")
