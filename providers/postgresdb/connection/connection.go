// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// PostgresdbConnection holds the settings needed to reach a PostgreSQL server.
// Because PostgreSQL cannot query across databases, it keeps one connection
// pool per database, opened lazily and shared across resources.
type PostgresdbConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	user        string
	password    string
	database    string // database used for the server-level connection
	sslmode     string
	sslrootcert string
	sslcert     string
	sslkey      string

	// scopedDatabase is set when the asset is a single discovered database.
	scopedDatabase string

	poolsMu sync.Mutex
	pools   map[string]*pgxpool.Pool

	systemIDOnce sync.Once
	systemID     string
	systemIDErr  error

	versionOnce sync.Once
	versionNum  int
	versionErr  error
}

func NewPostgresdbConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*PostgresdbConnection, error) {
	conn := &PostgresdbConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		pools:      map[string]*pgxpool.Pool{},
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}

	conn.host = conf.Options[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	conn.database = conf.Options[OptionDatabase]
	if conn.database == "" {
		conn.database = "postgres"
	}
	conn.scopedDatabase = conf.Options[OptionScopedDatabase]
	conn.sslmode = conf.Options[OptionSSLMode]
	if conn.sslmode == "" {
		conn.sslmode = "prefer"
	}
	conn.sslrootcert = conf.Options[OptionSSLRootCert]
	conn.sslcert = conf.Options[OptionSSLCert]
	conn.sslkey = conf.Options[OptionSSLKey]

	conn.port = 5432
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
		return nil, status.Error(codes.InvalidArgument, "missing host for postgres connection")
	}
	if conn.user == "" {
		return nil, status.Error(codes.InvalidArgument, "missing user for postgres connection")
	}

	return conn, nil
}

func (c *PostgresdbConnection) Name() string {
	return "postgresdb"
}

func (c *PostgresdbConnection) Asset() *inventory.Asset {
	return c.asset
}

// ScopedDatabase returns the single database this asset is scoped to, or an
// empty string when the asset is the whole server.
func (c *PostgresdbConnection) ScopedDatabase() string {
	return c.scopedDatabase
}

// connString builds a postgres:// URL for a specific database.
func (c *PostgresdbConnection) connString(database string) string {
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
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.user, c.password),
		Host:     net.JoinHostPort(c.host, strconv.Itoa(c.port)),
		Path:     "/" + database,
		RawQuery: query.Encode(),
	}
	return u.String()
}

// Client returns a connection pool for the given database, opening it on first
// use. An empty database name resolves to the server-level database.
func (c *PostgresdbConnection) Client(database string) (*pgxpool.Pool, error) {
	if database == "" {
		database = c.database
	}

	c.poolsMu.Lock()
	defer c.poolsMu.Unlock()
	if pool, ok := c.pools[database]; ok {
		return pool, nil
	}

	pool, err := pgxpool.New(context.Background(), c.connString(database))
	if err != nil {
		return nil, err
	}
	c.pools[database] = pool
	return pool, nil
}

// Close releases every open pool.
func (c *PostgresdbConnection) Close() {
	c.poolsMu.Lock()
	defer c.poolsMu.Unlock()
	for _, pool := range c.pools {
		pool.Close()
	}
	c.pools = map[string]*pgxpool.Pool{}
}

// ServerVersionNum returns the server's server_version_num (for example
// 90224 for 9.2.24, 170004 for 17.4). It is resolved once and shared, so
// queries can select only the catalog columns the server has.
func (c *PostgresdbConnection) ServerVersionNum() (int, error) {
	c.versionOnce.Do(func() {
		pool, err := c.Client("")
		if err != nil {
			c.versionErr = err
			return
		}
		c.versionErr = pool.QueryRow(context.Background(),
			"SELECT current_setting('server_version_num')::int").Scan(&c.versionNum)
	})
	return c.versionNum, c.versionErr
}

// minVersionControlSystem is the first release with pg_control_system().
const minVersionControlSystem = 90600

// usesLegacySystemID reports whether the server is too old to report its
// system identifier through SQL.
func usesLegacySystemID(serverVersionNum int) bool {
	return serverVersionNum < minVersionControlSystem
}

// legacySystemID derives a stable identifier for a server that cannot report
// its system identifier (before 9.6, pg_control_system() does not exist and
// pg_control is only readable from the file system). It hashes the host the
// server was reached at and the port the server itself listens on: both
// survive a restart, and two clusters on one host always differ in port.
// The value is the same for every role that connects, since neither input
// needs a privilege to read.
func legacySystemID(host string, serverPort string) string {
	sum := sha256.Sum256([]byte(host + "\x00" + serverPort))
	return "legacy-" + hex.EncodeToString(sum[:16])
}

// SystemID returns the cluster system identifier, used to build stable asset
// platform ids. It is resolved once and shared.
func (c *PostgresdbConnection) SystemID() (string, error) {
	c.systemIDOnce.Do(func() {
		version, err := c.ServerVersionNum()
		if err != nil {
			c.systemIDErr = err
			return
		}
		pool, err := c.Client("")
		if err != nil {
			c.systemIDErr = err
			return
		}
		if usesLegacySystemID(version) {
			var port string
			if err := pool.QueryRow(context.Background(), "SELECT current_setting('port')").Scan(&port); err != nil {
				c.systemIDErr = err
				return
			}
			c.systemID = legacySystemID(c.host, port)
			return
		}
		c.systemIDErr = pool.QueryRow(context.Background(),
			"SELECT system_identifier::text FROM pg_control_system()").Scan(&c.systemID)
	})
	return c.systemID, c.systemIDErr
}
