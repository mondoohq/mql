// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Connection option keys. They are the single source of truth shared by the
// provider's ParseCLI and this package: a key spelled differently on either
// side is dropped without an error and the flag becomes a no-op.
const (
	OptionEndpoint       = "endpoint"
	OptionSecurityPolicy = "security-policy"
	OptionSecurityMode   = "security-mode"
	OptionCertFile       = "cert-file"
	OptionKeyFile        = "key-file"
)

type OpcuaConnection struct {
	plugin.Connection
	Conf     *inventory.Config
	asset    *inventory.Asset
	client   *opcua.Client
	endpoint string
}

// clientOptions holds everything needed to open a session, gathered from the
// asset configuration.
type clientOptions struct {
	endpoint       string
	securityPolicy string
	securityMode   string
	certFile       string
	keyFile        string
	username       string
	password       string
}

// tokenType returns the user identity token the configured credentials imply.
func (o *clientOptions) tokenType() ua.UserTokenType {
	if o.username != "" {
		return ua.UserTokenTypeUserName
	}
	return ua.UserTokenTypeAnonymous
}

func newClientOptions(conf *inventory.Config) (*clientOptions, error) {
	if conf.Options == nil || conf.Options[OptionEndpoint] == "" {
		return nil, errors.New("opcua provider requires an endpoint. please set option `endpoint`")
	}

	opts := &clientOptions{
		endpoint:       conf.Options[OptionEndpoint],
		securityPolicy: conf.Options[OptionSecurityPolicy],
		securityMode:   conf.Options[OptionSecurityMode],
		certFile:       conf.Options[OptionCertFile],
		keyFile:        conf.Options[OptionKeyFile],
	}

	if (opts.certFile == "") != (opts.keyFile == "") {
		return nil, errors.New("opcua provider requires both `cert-file` and `key-file` when using a client certificate")
	}

	for _, cred := range conf.Credentials {
		if cred == nil || cred.Type != vault.CredentialType_password {
			continue
		}
		opts.username = cred.User
		opts.password = string(cred.Secret)
		break
	}

	// validate the security settings before we reach out to the server so a
	// typo surfaces as a clear message instead of an endpoint mismatch
	if _, err := parseSecurityPolicy(opts.securityPolicy); err != nil {
		return nil, err
	}
	if _, err := parseSecurityMode(opts.securityMode); err != nil {
		return nil, err
	}

	return opts, nil
}

func NewOpcuaConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OpcuaConnection, error) {
	conn := &OpcuaConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize connection
	if conf.Type != "opcua" {
		return nil, plugin.ErrProviderTypeDoesNotMatch
	}

	opts, err := newClientOptions(conf)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := connectClient(ctx, opts)
	if err != nil {
		return nil, err
	}

	conn.client = client
	conn.endpoint = opts.endpoint

	return conn, nil
}

// connectClient walks the endpoints the server advertises, strongest security
// first, and returns the first session it can establish.
//
// Preferring the strongest endpoint is what makes a properly secured server
// scannable: it typically offers no None/None endpoint at all, and asking for
// one leaves the asset unreachable. Walking down the list keeps a server that
// only speaks None/None working exactly as before.
func connectClient(ctx context.Context, opts *clientOptions) (*opcua.Client, error) {
	endpoints, err := opcua.GetEndpoints(ctx, opts.endpoint)
	if err != nil {
		return nil, err
	}

	tokenType := opts.tokenType()
	candidates, err := selectEndpoints(endpoints, opts.securityPolicy, opts.securityMode, tokenType)
	if err != nil {
		return nil, err
	}

	attemptErrors := []error{}
	for _, ep := range candidates {
		client, err := dialEndpoint(ctx, opts, ep, tokenType)
		if err == nil {
			log.Debug().
				Str("endpoint", opts.endpoint).
				Str("security", describeEndpoint(ep)).
				Msg("opcua> connected")
			return client, nil
		}

		log.Debug().
			Err(err).
			Str("endpoint", opts.endpoint).
			Str("security", describeEndpoint(ep)).
			Msg("opcua> could not establish session, trying next endpoint")
		attemptErrors = append(attemptErrors, fmt.Errorf("%s: %w", describeEndpoint(ep), err))
	}

	return nil, fmt.Errorf("could not connect to OPC UA server %s: %w", opts.endpoint, errors.Join(attemptErrors...))
}

// dialEndpoint opens a session against a single advertised endpoint.
func dialEndpoint(ctx context.Context, opts *clientOptions, ep *ua.EndpointDescription, tokenType ua.UserTokenType) (*opcua.Client, error) {
	clientOpts := []opcua.Option{
		opcua.ApplicationName(applicationName),
		opcua.ApplicationURI(applicationURI),
	}

	if tokenType == ua.UserTokenTypeUserName {
		clientOpts = append(clientOpts, opcua.AuthUsername(opts.username, opts.password))
	} else {
		clientOpts = append(clientOpts, opcua.AuthAnonymous())
	}

	switch {
	case opts.certFile != "":
		clientOpts = append(clientOpts,
			opcua.CertificateFile(opts.certFile),
			opcua.PrivateKeyFile(opts.keyFile),
		)
	case ep.SecurityMode != ua.MessageSecurityModeNone || ep.SecurityPolicyURI != ua.SecurityPolicyURINone:
		// a secured channel is only possible with a client certificate
		certDER, key, err := ephemeralCertificate()
		if err != nil {
			return nil, err
		}
		clientOpts = append(clientOpts, opcua.Certificate(certDER), opcua.PrivateKey(key))
	}

	clientOpts = append(clientOpts, opcua.SecurityFromEndpoint(ep, tokenType))

	// connect to the endpoint URL the user supplied rather than the one the
	// server advertises: servers behind NAT or inside a container routinely
	// advertise a hostname that is not resolvable by the client
	client, err := opcua.NewClient(opts.endpoint, clientOpts...)
	if err != nil {
		return nil, err
	}
	if err := client.Connect(ctx); err != nil {
		// the client holds an open socket even when the session handshake
		// failed, so release it before moving on to the next endpoint
		_ = client.Close(ctx)
		return nil, err
	}
	return client, nil
}

func (c *OpcuaConnection) Name() string {
	return "opcua"
}

func (c *OpcuaConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *OpcuaConnection) Client() *opcua.Client {
	return c.client
}

func (c *OpcuaConnection) Endpoint() string {
	return c.endpoint
}
