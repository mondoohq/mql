// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// RedisdbConnection holds the settings to reach a Redis or Valkey server and,
// once dialed, the shared client.
type RedisdbConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	user        string
	password    string
	database    int
	tls         bool
	tlsCA       string
	tlsCert     string
	tlsKey      string
	tlsInsecure bool

	mu        sync.Mutex
	dialed    bool
	client    *redis.Client
	clientErr error
}

func NewRedisdbConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*RedisdbConnection, error) {
	conn := &RedisdbConnection{
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
	conn.tlsCert = conf.Options[OptionTLSCert]
	conn.tlsKey = conf.Options[OptionTLSKey]
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"
	if conn.tlsCA != "" || conn.tlsCert != "" || conn.tlsKey != "" || conn.tlsInsecure {
		conn.tls = true
	}

	conn.port = 6379
	if p := conf.Options[OptionPort]; p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid port %q: %v", p, err)
		}
		conn.port = v
	} else if conf.Port > 0 {
		conn.port = int(conf.Port)
	}
	if d := conf.Options[OptionDatabase]; d != "" {
		v, err := strconv.Atoi(d)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid database %q: %v", d, err)
		}
		conn.database = v
	}

	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		if cred.Type == vault.CredentialType_password {
			conn.user = cred.User
			conn.password = string(cred.Secret)
		}
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for redisdb connection")
	}

	return conn, nil
}

func (c *RedisdbConnection) Name() string {
	return "redisdb"
}

func (c *RedisdbConnection) Asset() *inventory.Asset {
	return c.asset
}

// ServerID returns a stable identifier for the server (its target address).
func (c *RedisdbConnection) ServerID() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// tlsConfig builds the TLS configuration, or returns nil when TLS is disabled.
func (c *RedisdbConnection) tlsConfig() (*tls.Config, error) {
	if !c.tls {
		return nil, nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: c.tlsInsecure,
		ServerName:         c.host,
	}
	if c.tlsCA != "" {
		pem, err := os.ReadFile(c.tlsCA)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to read tls-ca %q: %v", c.tlsCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, status.Errorf(codes.InvalidArgument, "no certificates found in tls-ca %q", c.tlsCA)
		}
		cfg.RootCAs = pool
	}
	// A server with tls-auth-clients yes refuses the handshake without a
	// client certificate ("tls: certificate required").
	if c.tlsCert != "" || c.tlsKey != "" {
		if c.tlsCert == "" || c.tlsKey == "" {
			return nil, status.Error(codes.InvalidArgument, "tls-cert and tls-key must be set together")
		}
		pair, err := tls.LoadX509KeyPair(c.tlsCert, c.tlsKey)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to load the client certificate %q and key %q: %v", c.tlsCert, c.tlsKey, err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// Client returns the shared Redis/Valkey client, dialing on first use. It is
// safe to call concurrently and alongside Close.
func (c *RedisdbConnection) Client() (*redis.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dialed {
		c.dialed = true
		tlsCfg, err := c.tlsConfig()
		if err != nil {
			c.clientErr = err
		} else {
			c.client = redis.NewClient(&redis.Options{
				Addr:      c.ServerID(),
				Username:  c.user,
				Password:  c.password,
				DB:        c.database,
				TLSConfig: tlsCfg,
			})
		}
	}
	return c.client, c.clientErr
}

// Close releases the shared client. It shares the mutex with Client so the two
// never race on the client handle.
func (c *RedisdbConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		_ = c.client.Close()
		c.client = nil
	}
}

// Context returns a background context for commands.
func (c *RedisdbConnection) Context() context.Context {
	return context.Background()
}

// ParseInfo parses a Redis INFO reply into a flat key/value map, skipping
// section headers and blank lines.
func ParseInfo(info string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = v
		}
	}
	return out
}
