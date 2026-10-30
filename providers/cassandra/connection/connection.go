// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// CassandraConnection holds the settings to reach a Cassandra cluster and, once
// dialed, the shared CQL session.
type CassandraConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	user        string
	password    string
	tls         bool
	tlsCA       string
	tlsInsecure bool

	sessionOnce sync.Once
	session     *gocql.Session
	sessionErr  error
}

func NewCassandraConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CassandraConnection, error) {
	conn := &CassandraConnection{
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
	conn.tls = conf.Options[OptionTLS] == "true"
	conn.tlsCA = conf.Options[OptionTLSCA]
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"
	if conn.tlsCA != "" || conn.tlsInsecure {
		conn.tls = true
	}

	conn.port = 9042
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
		return nil, status.Error(codes.InvalidArgument, "missing host for cassandra connection")
	}

	return conn, nil
}

func (c *CassandraConnection) Name() string {
	return "cassandra"
}

func (c *CassandraConnection) Asset() *inventory.Asset {
	return c.asset
}

// ServerID returns a stable identifier for the target (host:port).
func (c *CassandraConnection) ServerID() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// Session returns the shared CQL session, dialing on first use.
func (c *CassandraConnection) Session() (*gocql.Session, error) {
	c.sessionOnce.Do(func() {
		cluster := gocql.NewCluster(c.host)
		cluster.Port = c.port
		cluster.Consistency = gocql.LocalOne
		cluster.ConnectTimeout = 10 * time.Second
		cluster.Timeout = 15 * time.Second
		// Audit a single reachable node; do not fan out to the whole ring.
		cluster.DisableInitialHostLookup = true

		if c.user != "" {
			cluster.Authenticator = gocql.PasswordAuthenticator{
				Username: c.user,
				Password: c.password,
			}
		}
		if c.tls {
			ssl := &gocql.SslOptions{
				Config:                 &tls.Config{InsecureSkipVerify: c.tlsInsecure},
				EnableHostVerification: !c.tlsInsecure,
			}
			if c.tlsCA != "" {
				ssl.CaPath = c.tlsCA
			}
			cluster.SslOpts = ssl
		}

		session, err := cluster.CreateSession()
		if err != nil {
			c.sessionErr = err
			return
		}
		c.session = session
	})
	return c.session, c.sessionErr
}

// Close releases the shared session.
func (c *CassandraConnection) Close() {
	if c.session != nil {
		c.session.Close()
	}
}

// cqlErrCodeUnauthorized is the CQL error code returned when a role lacks the
// permission to read a table (server error code 0x2100).
const cqlErrCodeUnauthorized = 0x2100

// IsUnauthorized reports whether an error is a Cassandra authorization failure,
// so privilege-gated reads can degrade gracefully instead of failing the asset.
func IsUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	if re, ok := err.(gocql.RequestError); ok {
		return re.Code() == cqlErrCodeUnauthorized
	}
	return false
}
