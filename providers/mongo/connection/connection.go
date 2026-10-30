// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoConnection holds the settings to reach a self-hosted MongoDB server and,
// once dialed, the shared client. A single client can query every database, so
// there is one shared handle rather than a pool per database.
type MongoConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string // hostname, or a full mongodb:// connection string
	port        int
	user        string
	password    string
	authDB      string
	tls         bool
	tlsCAFile   string
	tlsInsecure bool

	// scopedDatabase is set when the asset is a single discovered database.
	scopedDatabase string

	clientOnce sync.Once
	client     *mongo.Client
	clientErr  error
}

func NewMongoConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MongoConnection, error) {
	conn := &MongoConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}
	// A password in a mongodb:// host must not travel with the asset.
	MoveURICredentials(conf)

	conn.host = conf.Options[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	conn.authDB = conf.Options[OptionAuthDB]
	if conn.authDB == "" {
		conn.authDB = "admin"
	}
	conn.scopedDatabase = conf.Options[OptionScopedDatabase]
	conn.tls = conf.Options[OptionTLS] == "true"
	conn.tlsCAFile = conf.Options[OptionTLSCA]
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"
	// A CA path or insecure flag implies TLS even without an explicit --tls.
	if conn.tlsCAFile != "" || conn.tlsInsecure {
		conn.tls = true
	}

	conn.port = 27017
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
		return nil, status.Error(codes.InvalidArgument, "missing host for mongo connection")
	}

	return conn, nil
}

func (c *MongoConnection) Name() string {
	return "mongo"
}

func (c *MongoConnection) Asset() *inventory.Asset {
	return c.asset
}

// ScopedDatabase returns the single database this asset is scoped to, or an
// empty string when the asset is the whole server.
func (c *MongoConnection) ScopedDatabase() string {
	return c.scopedDatabase
}

// ServerID returns a stable identifier for the server, used to build asset
// platform ids: host:port, or for a full connection string its host list. It
// never carries the user info or options of a connection string.
func (c *MongoConnection) ServerID() string {
	if p, ok := splitConnString(c.host); ok {
		return p.serverID()
	}
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// DisplayName is the asset name for the server: the host as given, or for a
// full connection string its host list.
func (c *MongoConnection) DisplayName() string {
	if p, ok := splitConnString(c.host); ok {
		return p.serverID()
	}
	return c.host
}

// Host returns the configured host (a hostname or a full mongodb:// string).
func (c *MongoConnection) Host() string {
	return c.host
}

// Port returns the resolved TCP port.
func (c *MongoConnection) Port() int {
	return c.port
}

// uri builds a mongodb:// connection string from the resolved settings. A host
// that is already a full connection string is used as given, with the
// credentials added as its user info. TLS is configured separately via
// tlsConfig/SetTLSConfig, not through query parameters.
func (c *MongoConnection) uri() string {
	if p, ok := splitConnString(c.host); ok {
		if c.user == "" && c.password == "" {
			return c.host
		}
		return p.withCredentials(c.user, c.password)
	}
	q := url.Values{}
	q.Set("authSource", c.authDB)
	u := &url.URL{
		Scheme:   "mongodb",
		Host:     net.JoinHostPort(c.host, strconv.Itoa(c.port)),
		Path:     "/",
		RawQuery: q.Encode(),
	}
	if c.user != "" {
		u.User = url.UserPassword(c.user, c.password)
	}
	return u.String()
}

// tlsConfig builds the TLS configuration from the connection settings, or
// returns nil when TLS is disabled. A configured CA file is loaded into the
// root pool so servers with a private CA verify correctly.
func (c *MongoConnection) tlsConfig() (*tls.Config, error) {
	if !c.tls {
		return nil, nil
	}
	cfg := &tls.Config{InsecureSkipVerify: c.tlsInsecure}
	if c.tlsCAFile != "" {
		pem, err := os.ReadFile(c.tlsCAFile)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to read tls-ca %q: %v", c.tlsCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, status.Errorf(codes.InvalidArgument, "no certificates found in tls-ca %q", c.tlsCAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// clientOptions builds the driver options from the connection settings.
func (c *MongoConnection) clientOptions() (*options.ClientOptions, error) {
	opts := options.Client().ApplyURI(c.uri())
	// A bare host names one server, and that server is the asset. Without a
	// direct connection the driver discovers the replica set and routes
	// commands to the primary, so auditing a secondary reported the primary's
	// configuration, and a member whose set is not initiated yet could not be
	// reached at all. A full connection string keeps its own topology settings
	// (directConnection, replicaSet).
	if c.namesSingleServer() {
		opts.SetDirect(true)
	}
	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts.SetTLSConfig(tlsCfg)
	}
	return opts, nil
}

// Client returns the shared MongoDB client, dialing on first use.
func (c *MongoConnection) Client() (*mongo.Client, error) {
	c.clientOnce.Do(func() {
		opts, err := c.clientOptions()
		if err != nil {
			c.clientErr = err
			return
		}
		client, err := mongo.Connect(opts)
		if err != nil {
			c.clientErr = err
			return
		}
		c.client = client
	})
	return c.client, c.clientErr
}

// Close disconnects the shared client.
func (c *MongoConnection) Close() {
	if c.client != nil {
		_ = c.client.Disconnect(context.Background())
	}
}

// RunAdminCommand runs a command against the admin database and decodes the
// result into out.
func (c *MongoConnection) RunAdminCommand(cmd any, out any) error {
	return c.RunCommand("admin", cmd, out)
}

// RunCommand runs a command against the named database and decodes the result
// into out.
func (c *MongoConnection) RunCommand(db string, cmd any, out any) error {
	client, err := c.Client()
	if err != nil {
		return err
	}
	return client.Database(db).RunCommand(context.Background(), cmd).Decode(out)
}
