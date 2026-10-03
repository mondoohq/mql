// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"database/sql"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// ClickhousedbConnection holds the settings to reach a ClickHouse server and,
// once dialed, the shared database handle.
type ClickhousedbConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	database    string
	user        string
	password    string
	tls         bool
	tlsInsecure bool

	clientOnce sync.Once
	client     *sql.DB
	clientErr  error
}

func NewClickhousedbConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ClickhousedbConnection, error) {
	conn := &ClickhousedbConnection{
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
	if conn.database == "" {
		conn.database = "default"
	}
	conn.tls = conf.Options[OptionTLS] == "true"
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"
	if conn.tlsInsecure {
		conn.tls = true
	}

	conn.port = 9000
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
	if conn.user == "" {
		conn.user = "default"
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for clickhouse connection")
	}

	return conn, nil
}

func (c *ClickhousedbConnection) Name() string {
	return "clickhousedb"
}

func (c *ClickhousedbConnection) Asset() *inventory.Asset {
	return c.asset
}

// ServerID returns a stable identifier for the target.
func (c *ClickhousedbConnection) ServerID() string {
	return c.host + ":" + strconv.Itoa(c.port)
}

// DatabaseName returns the connected database name.
func (c *ClickhousedbConnection) DatabaseName() string {
	return c.database
}

// Client returns the shared database handle, opening it on first use.
func (c *ClickhousedbConnection) Client() (*sql.DB, error) {
	c.clientOnce.Do(func() {
		opts := &clickhouse.Options{
			Addr: []string{c.host + ":" + strconv.Itoa(c.port)},
			Auth: clickhouse.Auth{
				Database: c.database,
				Username: c.user,
				Password: c.password,
			},
			// Bound slow connects and hung queries at the driver level so a scan
			// never blocks indefinitely.
			DialTimeout: 30 * time.Second,
			ReadTimeout: 60 * time.Second,
		}
		if c.tls {
			opts.TLS = &tls.Config{InsecureSkipVerify: c.tlsInsecure}
		}
		db := clickhouse.OpenDB(opts)
		db.SetMaxOpenConns(2)
		c.client = db
	})
	return c.client, c.clientErr
}

// Close releases the shared database handle.
func (c *ClickhousedbConnection) Close() {
	if c.client != nil {
		_ = c.client.Close()
	}
}

// Context returns a background context for queries. Query and connect deadlines
// are enforced at the driver level (see DialTimeout/ReadTimeout in Client), so a
// per-call context deadline is not needed here.
func (c *ClickhousedbConnection) Context() context.Context {
	return context.Background()
}

// IsPermissionError reports whether an error is a ClickHouse access-denied
// failure, so privilege-gated reads can degrade gracefully. ClickHouse returns
// code 497 (ACCESS_DENIED) and 492 (UNKNOWN_ACCESS_ENTITY), surfaced in the
// message as "ACCESS_DENIED" / "Not enough privileges".
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ACCESS_DENIED") ||
		strings.Contains(msg, "Not enough privileges") ||
		strings.Contains(msg, "code: 497") ||
		strings.Contains(msg, "code: 492")
}

// IsAccessDenied reports whether an error is the server refusing a query for
// lack of a grant: code 497 (ACCESS_DENIED), whose message reads "Not enough
// privileges. To execute this query, it's necessary to have the grant ...".
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ACCESS_DENIED") ||
		strings.Contains(msg, "Not enough privileges") ||
		strings.Contains(msg, "code: 497")
}

// IsUnknownPortError reports whether an error is getServerPort() refusing a
// listener the server has not configured.
//
// ClickHouse raises this rather than returning zero, and it reuses code 701
// (CLUSTER_DOESNT_EXIST) for it, so the message is what distinguishes a port
// that is switched off from a genuine cluster lookup failure. A server with TLS
// disabled produces it on every call for tcp_port_secure, which is an answer
// rather than a fault.
func IsUnknownPortError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "There is no port named")
}
