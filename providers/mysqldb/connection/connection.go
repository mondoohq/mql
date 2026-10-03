// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	mysqldriver "github.com/go-sql-driver/mysql"
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

	// scopedDatabase is set when the asset is a single discovered schema.
	scopedDatabase string

	clientOnce sync.Once
	client     *sql.DB
	clientErr  error

	metaOnce sync.Once
	serverID string
	flavor   string
	metaErr  error

	accessOnce sync.Once
	access     *CallerAccess
	accessErr  error

	versionOnce sync.Once
	version     string
	versionErr  error
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

// tlsParam resolves the go-sql-driver `tls` DSN parameter, registering a custom
// TLS config when CA or client-certificate material is supplied.
func (c *MysqldbConnection) tlsParam() (string, error) {
	if c.tlsCA == "" && c.tlsCert == "" && c.tlsKey == "" {
		// keyword modes handled by the driver directly
		return c.tlsMode, nil
	}

	cfg := &tls.Config{InsecureSkipVerify: c.tlsMode == "skip-verify"}
	if c.tlsCA != "" {
		pem, err := os.ReadFile(c.tlsCA)
		if err != nil {
			return "", fmt.Errorf("failed to read tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return "", fmt.Errorf("failed to parse tls-ca %q", c.tlsCA)
		}
		cfg.RootCAs = pool
	}
	if c.tlsCert != "" && c.tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(c.tlsCert, c.tlsKey)
		if err != nil {
			return "", fmt.Errorf("failed to load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	name := fmt.Sprintf("mysqldb-%d", c.ID())
	if err := mysqldriver.RegisterTLSConfig(name, cfg); err != nil {
		return "", err
	}
	return name, nil
}

// Client returns the shared database handle, dialing on first use.
func (c *MysqldbConnection) Client() (*sql.DB, error) {
	c.clientOnce.Do(func() {
		c.client, c.clientErr = c.dial()
	})
	return c.client, c.clientErr
}

func (c *MysqldbConnection) dial() (*sql.DB, error) {
	tlsName, err := c.tlsParam()
	if err != nil {
		return nil, err
	}

	cfg := mysqldriver.NewConfig()
	cfg.User = c.user
	cfg.Passwd = c.password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(c.host, strconv.Itoa(c.port))
	cfg.DBName = c.database
	cfg.TLSConfig = tlsName
	cfg.ParseTime = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	return db, nil
}

// ServerID returns a stable identifier for the server (@@server_uuid, falling
// back to host:port when the variable is unavailable, e.g. older MariaDB).
func (c *MysqldbConnection) ServerID() (string, error) {
	if err := c.resolveMeta(); err != nil {
		return "", err
	}
	return c.serverID, nil
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
			c.metaErr = err
			return
		}

		var versionComment, version string
		if err := db.QueryRowContext(context.Background(),
			"SELECT @@version_comment, @@version").Scan(&versionComment, &version); err != nil {
			c.metaErr = err
			return
		}
		c.flavor = classifyFlavor(versionComment, version)

		var uuid string
		// @@server_uuid is MySQL/Percona; some MariaDB versions lack it.
		if err := db.QueryRowContext(context.Background(), "SELECT @@server_uuid").Scan(&uuid); err == nil && uuid != "" {
			c.serverID = uuid
		} else {
			c.serverID = net.JoinHostPort(c.host, strconv.Itoa(c.port))
		}
	})
	return c.metaErr
}
