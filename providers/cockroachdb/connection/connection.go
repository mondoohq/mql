// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

const (
	// OptionHost is the CockroachDB hostname or IP address.
	OptionHost = "host"
	// OptionPort is the CockroachDB SQL port.
	OptionPort = "port"
	// OptionDatabase is the database the connection opens.
	OptionDatabase = "database"
	// OptionSSLMode selects the TLS mode (disable/allow/prefer/require/verify-ca/verify-full).
	OptionSSLMode = "sslmode"
	// OptionSSLRootCert is the path to the trusted CA certificate.
	OptionSSLRootCert = "sslrootcert"
	// OptionSSLCert is the path to the client certificate.
	OptionSSLCert = "sslcert"
	// OptionSSLKey is the path to the client private key.
	OptionSSLKey = "sslkey"
	// OptionCertsDir is a CockroachDB certificate directory, as cockroach
	// cert create-* writes it: ca.crt, client.<user>.crt and client.<user>.key.
	OptionCertsDir = "certs-dir"
)

const (
	defaultPort     = 26257
	defaultDatabase = "defaultdb"
	defaultUser     = "root"
)

// CockroachdbConnection holds the settings needed to reach a CockroachDB
// cluster and one connection pool, opened on first use. CockroachDB reads
// across databases from any connection, so one pool serves every resource.
type CockroachdbConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	user        string
	password    string
	database    string
	sslmode     string
	sslrootcert string
	sslcert     string
	sslkey      string

	poolOnce sync.Once
	pool     *pgxpool.Pool
	poolErr  error

	clusterOnce sync.Once
	cluster     ClusterInfo
	clusterErr  error

	memoMu sync.Mutex
	memo   map[string]*memoEntry
}

type memoEntry struct {
	once  sync.Once
	value any
	err   error
}

// Memo runs fn once per key for the lifetime of the connection and returns
// its result to every caller, so a list several resources read is queried
// once per scan.
func (c *CockroachdbConnection) Memo(key string, fn func() (any, error)) (any, error) {
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

func NewCockroachdbConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CockroachdbConnection, error) {
	conn := &CockroachdbConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	conn.host = conf.Options[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for cockroachdb connection")
	}

	conn.port = defaultPort
	if p := conf.Options[OptionPort]; p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid port %q: %v", p, err)
		}
		conn.port = v
	} else if conf.Port > 0 {
		conn.port = int(conf.Port)
	}

	conn.database = conf.Options[OptionDatabase]
	if conn.database == "" {
		conn.database = defaultDatabase
	}

	conn.user = defaultUser
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			if cred.User != "" {
				conn.user = cred.User
			}
			conn.password = string(cred.Secret)
		}
	}

	conn.sslmode = conf.Options[OptionSSLMode]
	conn.sslrootcert = conf.Options[OptionSSLRootCert]
	conn.sslcert = conf.Options[OptionSSLCert]
	conn.sslkey = conf.Options[OptionSSLKey]
	if dir := conf.Options[OptionCertsDir]; dir != "" {
		applyCertsDir(conn, dir)
	}
	if conn.sslmode == "" {
		conn.sslmode = "prefer"
	}

	return conn, nil
}

// applyCertsDir fills the TLS paths a CockroachDB certificate directory
// provides, without overriding paths given explicitly. A certificate directory
// means a secure cluster, so the server certificate is verified unless a mode
// was chosen.
func applyCertsDir(conn *CockroachdbConnection, dir string) {
	if conn.sslrootcert == "" {
		conn.sslrootcert = filepath.Join(dir, "ca.crt")
	}
	if conn.sslcert == "" {
		conn.sslcert = filepath.Join(dir, "client."+conn.user+".crt")
	}
	if conn.sslkey == "" {
		conn.sslkey = filepath.Join(dir, "client."+conn.user+".key")
	}
	if conn.sslmode == "" {
		conn.sslmode = "verify-full"
	}
}

func (c *CockroachdbConnection) Name() string {
	return "cockroachdb"
}

func (c *CockroachdbConnection) Asset() *inventory.Asset {
	return c.asset
}

// Host returns the host and port the provider connects to.
func (c *CockroachdbConnection) Host() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// connString builds the postgresql:// URL for the connection.
func (c *CockroachdbConnection) connString() string {
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
	user := url.User(c.user)
	if c.password != "" {
		user = url.UserPassword(c.user, c.password)
	}
	u := &url.URL{
		Scheme:   "postgresql",
		User:     user,
		Host:     c.Host(),
		Path:     "/" + c.database,
		RawQuery: query.Encode(),
	}
	return u.String()
}

// Client returns the connection pool, opening it on first use.
func (c *CockroachdbConnection) Client() (*pgxpool.Pool, error) {
	c.poolOnce.Do(func() {
		c.pool, c.poolErr = pgxpool.New(context.Background(), c.connString())
	})
	return c.pool, c.poolErr
}

// Close releases the connection pool.
func (c *CockroachdbConnection) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
}

// ClusterInfo identifies the connected cluster.
type ClusterInfo struct {
	// ID is the cluster ID, a UUID.
	ID string
	// Version is the release the connected node runs, without the leading "v".
	Version string
	// BuildInfo is the full build description from version().
	BuildInfo string
	// Organization is the cluster.organization setting.
	Organization string
}

// Cluster reads the cluster identity once and shares it, from
// crdb_internal.node_build_info, which every user can read.
func (c *CockroachdbConnection) Cluster() (ClusterInfo, error) {
	c.clusterOnce.Do(func() {
		pool, err := c.Client()
		if err != nil {
			c.clusterErr = err
			return
		}
		rows, err := pool.Query(context.Background(), `SELECT field, value FROM crdb_internal.node_build_info`)
		if err != nil {
			c.clusterErr = err
			return
		}
		defer rows.Close()
		for rows.Next() {
			var field, value string
			if err := rows.Scan(&field, &value); err != nil {
				c.clusterErr = err
				return
			}
			switch field {
			case "ClusterID":
				c.cluster.ID = value
			case "Organization":
				c.cluster.Organization = value
			case "Build":
				c.cluster.BuildInfo = value
			case "Version":
				c.cluster.Version = strings.TrimPrefix(value, "v")
			}
		}
		if err := rows.Err(); err != nil {
			c.clusterErr = err
			return
		}
		if c.cluster.ID == "" {
			c.clusterErr = errors.New("cockroachdb did not report a cluster ID")
		}
	})
	return c.cluster, c.clusterErr
}
