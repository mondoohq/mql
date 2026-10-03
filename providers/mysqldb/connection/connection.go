// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// MysqldbConnection holds the settings to reach a MySQL/MariaDB server. Unlike
// PostgreSQL, a single connection can query every schema, so there is one
// shared handle rather than a pool per database.
type MysqldbConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host     string
	port     int
	user     string
	password string
	database string
	tlsMode  string
	tlsCA    string
	tlsCert  string
	tlsKey   string
	// tlsServerName is the name verified in the server certificate, when it
	// differs from host (for example when connecting by IP address).
	tlsServerName string

	// scopedDatabase is set when the asset is a single discovered schema.
	scopedDatabase string

	clientOnce sync.Once
	client     *sql.DB
	clientErr  error

	metaOnce sync.Once
	serverID string
	flavor   string
	version  string
	metaErr  error

	accessOnce sync.Once
	access     *CallerAccess
	accessErr  error
}

func NewMysqldbConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MysqldbConnection, error) {
	conn := &MysqldbConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}

	conn.host = conf.Options[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	conn.database = conf.Options[OptionDatabase]
	conn.scopedDatabase = conf.Options[OptionScopedDatabase]
	if conn.scopedDatabase != "" && conn.database == "" {
		conn.database = conn.scopedDatabase
	}
	conn.tlsMode = conf.Options[OptionTLSMode]
	if conn.tlsMode == "" {
		conn.tlsMode = "preferred"
	}
	conn.tlsCA = conf.Options[OptionTLSCA]
	conn.tlsCert = conf.Options[OptionTLSCert]
	conn.tlsKey = conf.Options[OptionTLSKey]
	conn.tlsServerName = conf.Options[OptionTLSServerName]

	conn.port = 3306
	if p := conf.Options[OptionPort]; p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid port %q: %v", p, err)
		}
		conn.port = v
	} else if conf.Port > 0 {
		conn.port = int(conf.Port)
	}

	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		if cred.Type == vault.CredentialType_password {
			conn.user = cred.User
			conn.password = string(cred.Secret)
		}
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for mysqldb connection")
	}
	if conn.user == "" {
		return nil, status.Error(codes.InvalidArgument, "missing user for mysqldb connection")
	}

	return conn, nil
}

func (c *MysqldbConnection) Name() string {
	return "mysqldb"
}

// classifyFlavor determines the server flavor from its version metadata.
func classifyFlavor(versionComment, version string) string {
	hay := strings.ToLower(versionComment + " " + version)
	switch {
	case strings.Contains(hay, "mariadb"):
		return "mariadb"
	case strings.Contains(hay, "percona"):
		return "percona"
	default:
		return "mysql"
	}
}

func (c *MysqldbConnection) Asset() *inventory.Asset {
	return c.asset
}

// ScopedDatabase returns the single schema this asset is scoped to, or an empty
// string when the asset is the whole server.
func (c *MysqldbConnection) ScopedDatabase() string {
	return c.scopedDatabase
}

// Close releases the shared database handle.
func (c *MysqldbConnection) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

// Connection timeouts. dialTimeout bounds the TCP connect, so an unreachable
// host fails in seconds rather than after the operating system's SYN retries
// (over two minutes on Linux). ioTimeout bounds each read and write, so a
// server that stops answering mid-query cannot hang the scan.
const (
	dialTimeout = 15 * time.Second
	ioTimeout   = 5 * time.Minute
)

// tlsConfig resolves the TLS settings for a connection. It returns a nil
// config for plaintext, and whether the driver may fall back to plaintext when
// the server does not offer TLS.
//
//   - false: plaintext, whatever certificate flags are given.
//   - preferred: TLS when the server offers it, plaintext otherwise. The
//     server is verified against --tls-ca when one is given, and not
//     verified otherwise. The fallback covers a server that does not offer
//     TLS; a server that offers TLS but fails verification or the handshake
//     is an error, not a plaintext connection.
//   - skip-verify: TLS required, server not verified.
//   - true: TLS required, server verified against --tls-ca or the system
//     roots, by --tls-server-name or the host name.
//
// Client certificate material is presented in every TLS mode.
func (c *MysqldbConnection) tlsConfig() (*tls.Config, bool, error) {
	mode := strings.ToLower(c.tlsMode)
	// the driver's boolean spellings
	switch mode {
	case "0":
		mode = "false"
	case "1":
		mode = "true"
	}
	switch mode {
	case "false":
		return nil, false, nil
	case "preferred", "skip-verify", "true":
	default:
		return nil, false, fmt.Errorf("invalid tls-mode %q: use false, preferred, skip-verify, or true", c.tlsMode)
	}
	fallback := mode == "preferred"
	// skip-verify, and preferred without a CA to verify against, encrypt
	// without authenticating the server, as their names say
	skipVerify := mode == "skip-verify" || (mode == "preferred" && c.tlsCA == "")
	cfg := &tls.Config{ServerName: c.tlsServerName, InsecureSkipVerify: skipVerify}

	if c.tlsCA != "" && !skipVerify {
		pem, err := os.ReadFile(c.tlsCA)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, false, fmt.Errorf("failed to parse tls-ca %q", c.tlsCA)
		}
		cfg.RootCAs = pool
	}
	if (c.tlsCert == "") != (c.tlsKey == "") {
		return nil, false, errors.New("tls-cert and tls-key must be given together")
	}
	if c.tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(c.tlsCert, c.tlsKey)
		if err != nil {
			return nil, false, fmt.Errorf("failed to load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, fallback, nil
}

// Client returns the shared database handle, dialing on first use.
func (c *MysqldbConnection) Client() (*sql.DB, error) {
	c.clientOnce.Do(func() {
		c.client, c.clientErr = c.dial()
	})
	return c.client, c.clientErr
}

// driverConfig builds the driver configuration for the connection.
func (c *MysqldbConnection) driverConfig() (*mysqldriver.Config, error) {
	tlsCfg, fallback, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}

	cfg := mysqldriver.NewConfig()
	cfg.User = c.user
	cfg.Passwd = c.password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(c.host, strconv.Itoa(c.port))
	cfg.DBName = c.database
	cfg.TLS = tlsCfg
	cfg.AllowFallbackToPlaintext = fallback
	cfg.ParseTime = true
	cfg.Timeout = dialTimeout
	cfg.ReadTimeout = ioTimeout
	cfg.WriteTimeout = ioTimeout
	return cfg, nil
}

func (c *MysqldbConnection) dial() (*sql.DB, error) {
	cfg, err := c.driverConfig()
	if err != nil {
		return nil, err
	}
	connector, err := mysqldriver.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	return db, nil
}

// classifyConnectError gives a failure to reach or log in to the server its
// ADR 046 kind. Anything else is returned as is.
func classifyConnectError(err error) error {
	if err == nil {
		return nil
	}
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case 1045: // access denied: unknown user or wrong password
			return llx.Unauthenticated(err)
		case 1044, // access denied to the --database schema
			1130, // host is not allowed to connect
			3118, // account is locked
			1862, // password expired, client cannot change it
			3159: // insecure transport prohibited (require_secure_transport)
			return llx.Forbidden(err)
		}
		return err
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return llx.Unavailable(err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return llx.Unavailable(err)
	}
	return err
}

// ServerID returns a stable identifier for the server: @@server_uuid, or on a
// server without one (MariaDB) an id derived from the server's own identity.
func (c *MysqldbConnection) ServerID() (string, error) {
	if err := c.resolveMeta(); err != nil {
		return "", err
	}
	return c.serverID, nil
}

// IsMariaDB reports whether the server is MariaDB. It is false when the
// flavor cannot be read.
func (c *MysqldbConnection) IsMariaDB() bool {
	flavor, err := c.Flavor()
	return err == nil && flavor == "mariadb"
}

// Version returns the server version (@@version).
func (c *MysqldbConnection) Version() (string, error) {
	if err := c.resolveMeta(); err != nil {
		return "", err
	}
	return c.version, nil
}

// derivedServerID identifies a server that has no @@server_uuid from what the
// server reports about itself, so the same server reached under two names
// gets one id and two servers both reached as 127.0.0.1:3306 get two. The
// datadir separates instances that share a hostname; it is hashed because it
// is a path and the id is used as a platform id segment.
func derivedServerID(hostname, port, serverID, datadir string) string {
	sum := sha256.Sum256([]byte(hostname + "\x00" + port + "\x00" + serverID + "\x00" + datadir))
	return hex.EncodeToString(sum[:16])
}

// Flavor returns the detected server flavor: mysql, mariadb, or percona.
func (c *MysqldbConnection) Flavor() (string, error) {
	if err := c.resolveMeta(); err != nil {
		return "", err
	}
	return c.flavor, nil
}

func (c *MysqldbConnection) resolveMeta() error {
	c.metaOnce.Do(func() {
		db, err := c.Client()
		if err != nil {
			c.metaErr = classifyConnectError(err)
			return
		}

		var versionComment, version string
		if err := db.QueryRowContext(context.Background(),
			"SELECT @@version_comment, @@version").Scan(&versionComment, &version); err != nil {
			c.metaErr = classifyConnectError(err)
			return
		}
		c.flavor = classifyFlavor(versionComment, version)
		c.version = version

		var uuid string
		// @@server_uuid is MySQL/Percona; MariaDB has none.
		if err := db.QueryRowContext(context.Background(), "SELECT @@server_uuid").Scan(&uuid); err == nil && uuid != "" {
			c.serverID = uuid
			return
		}
		var hostname, port, serverID, datadir sql.NullString
		if err := db.QueryRowContext(context.Background(),
			"SELECT @@hostname, @@port, @@server_id, @@datadir").Scan(&hostname, &port, &serverID, &datadir); err == nil && hostname.String != "" {
			c.serverID = derivedServerID(hostname.String, port.String, serverID.String, datadir.String)
		} else {
			c.serverID = net.JoinHostPort(c.host, strconv.Itoa(c.port))
		}
	})
	return c.metaErr
}
