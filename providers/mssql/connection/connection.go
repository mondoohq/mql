// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/azuread"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// supportedAuthModes lists the authentication modes the provider can dial with.
// Kerberos/AD auth is a planned follow-up and is intentionally not accepted here
// so a request fails fast rather than dialing with an unsupported mode.
var supportedAuthModes = map[string]struct{}{
	"sql":     {},
	"windows": {},
	"azure":   {},
}

// MssqlConnection holds the settings required to reach a SQL Server instance
// and, once dialed, the shared read-only database handle.
type MssqlConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// resolved connection settings
	host      string
	port      int
	instance  string
	user      string
	password  string
	token     string
	auth      string
	encrypt   string
	trustCert bool

	// database is set when the connection is scoped to a single database,
	// making the asset a mssql-database rather than the whole instance.
	database string

	// dialed TDS handle, opened lazily by Client() the first time a resource
	// needs to run a query and shared across every resource on the asset.
	clientOnce sync.Once
	client     *sql.DB
	clientErr  error

	// what the scanning login may see in the catalog views, read once
	accessOnce sync.Once
	access     *ServerAccess
	accessErr  error
	dbAccessMu sync.Mutex
	dbAccess   map[string]DatabaseAccess
}

func NewMssqlConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MssqlConnection, error) {
	conn := &MssqlConnection{
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
	conn.instance = conf.Options[OptionInstance]
	conn.database = conf.Options[OptionDatabase]
	conn.auth = strings.ToLower(conf.Options[OptionAuth])
	if conn.auth == "" {
		conn.auth = "sql"
	}
	conn.encrypt = conf.Options[OptionEncrypt]
	if conn.encrypt == "" {
		conn.encrypt = "mandatory"
	}
	conn.trustCert = conf.Options[OptionTrustServerCertificate] == "true"

	conn.port = 1433
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
		switch cred.Type {
		case vault.CredentialType_password:
			conn.user = cred.User
			conn.password = string(cred.Secret)
		case vault.CredentialType_bearer:
			// Microsoft Entra ID (Azure AD) access token.
			conn.user = cred.User
			conn.token = string(cred.Secret)
		}
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for mssql connection")
	}

	// A2: reject unknown auth modes up front instead of dialing blindly.
	if _, ok := supportedAuthModes[conn.auth]; !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"unsupported auth mode %q for mssql connection (use sql, windows, or azure)", conn.auth)
	}

	// A1: enforce the credential each mode actually needs.
	switch conn.auth {
	case "sql", "windows":
		if conn.user == "" {
			return nil, status.Error(codes.InvalidArgument, "missing user for mssql connection")
		}
	case "azure":
		if conn.token == "" {
			return nil, status.Error(codes.InvalidArgument, "missing access token for azure auth (set --token)")
		}
	}

	return conn, nil
}

func (c *MssqlConnection) Name() string {
	return "mssql"
}

func (c *MssqlConnection) Asset() *inventory.Asset {
	return c.asset
}

// Database returns the single database this connection is scoped to, or an
// empty string when the connection targets the whole instance.
func (c *MssqlConnection) Database() string {
	return c.database
}

// Port returns the resolved TCP port of the instance.
func (c *MssqlConnection) Port() int {
	return c.port
}

// InstanceID returns a stable identifier for the SQL Server instance, used to
// build asset platform ids. It prefers the named instance over the port so
// multiple instances on one host stay distinct.
func (c *MssqlConnection) InstanceID() string {
	if c.instance != "" {
		return c.host + ":" + c.instance
	}
	return c.host + ":" + strconv.Itoa(c.port)
}

// Client returns the shared database handle, dialing the instance on first use.
// The handle is opened once and reused by every resource on the asset.
func (c *MssqlConnection) Client() (*sql.DB, error) {
	c.clientOnce.Do(func() {
		c.client, c.clientErr = c.dial()
	})
	return c.client, c.clientErr
}

func (c *MssqlConnection) dial() (*sql.DB, error) {
	dsn := c.dsn()

	var connector driver.Connector
	var err error
	if c.auth == "azure" {
		connector, err = azuread.NewConnector(dsn)
	} else {
		connector, err = mssql.NewConnector(dsn)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to build mssql connector: %w", err)
	}

	db := sql.OpenDB(connector)
	// The provider only issues read-only catalog queries; a small pool is plenty.
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	return db, nil
}

// dsn builds a sqlserver:// DSN from the resolved connection settings.
func (c *MssqlConnection) dsn() string {
	query := url.Values{}
	if c.database != "" {
		query.Set("database", c.database)
	}
	query.Set("encrypt", mapEncrypt(c.encrypt))
	if c.trustCert {
		query.Set("TrustServerCertificate", "true")
	}
	query.Set("app name", "mondoo")
	if c.auth == "azure" {
		// The access token is carried in the password; fedauth selects the flow.
		query.Set("fedauth", "ActiveDirectoryAccessToken")
	}

	u := &url.URL{
		Scheme:   "sqlserver",
		RawQuery: query.Encode(),
	}

	// A named instance is resolved by the SQL Browser service, so the port is
	// omitted and the instance name is carried in the path.
	if c.instance != "" {
		u.Host = c.host
		u.Path = c.instance
	} else {
		u.Host = net.JoinHostPort(c.host, strconv.Itoa(c.port))
	}

	switch c.auth {
	case "azure":
		u.User = url.UserPassword(c.user, c.token)
	default:
		u.User = url.UserPassword(c.user, c.password)
	}

	return u.String()
}

// mapEncrypt translates the user-facing encryption mode to the driver's token.
func mapEncrypt(mode string) string {
	switch strings.ToLower(mode) {
	case "strict":
		return "strict"
	case "optional", "false":
		return "false"
	case "disable", "disabled":
		return "disable"
	default: // mandatory, true, or unset
		return "true"
	}
}
