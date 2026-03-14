// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13"
	"go.mondoo.com/mql/v13/utils/multierr"
	rangerUtils "go.mondoo.com/mql/v13/utils/ranger"
	"go.mondoo.com/ranger-rpc"
	guard_cert_auth "go.mondoo.com/ranger-rpc/plugins/authentication/cert"
	"go.mondoo.com/ranger-rpc/plugins/authentication/statictoken"
	"go.mondoo.com/ranger-rpc/plugins/rangerguard/crypto"
)

//go:generate protoc --plugin=protoc-gen-go=../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../../../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=../../:. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size+clone upstream.proto

const agents_issuer = "mondoo/ams"

// SysInfoProvider can be set by callers to provide system information for upstream request headers.
// When set, InitClient will call this function and include the platform ID, hostname, IP, etc.
// in the HTTP headers sent to the platform. This is used by the server to track agent check-ins.
// This is a function variable to avoid import cycles (sysinfo -> inventory -> upstream).
// Must be set before any call to InitClient (typically in an init function).
var SysInfoProvider func() *rangerUtils.ClientSysInfo

func NewServiceAccountRangerPlugin(credentials *ServiceAccountCredentials) (ranger.ClientPlugin, error) {
	if credentials == nil {
		return nil, errors.New("agent credentials must be set")
	}
	if credentials.Token != "" {
		return statictoken.NewRangerPlugin(credentials.Token), nil
	}

	// verify that we can read the private key
	privateKey, err := crypto.PrivateKeyFromBytes([]byte(credentials.PrivateKey))
	if err != nil {
		return nil, errors.New("cannot load retrieved key: " + err.Error())
	}

	log.Debug().Str("kid", credentials.Mrn).Str("issuer", agents_issuer).Msg("initialize client authentication")

	// configure authentication plugin, since the server only accepts authenticated calls
	return guard_cert_auth.NewRangerPlugin(guard_cert_auth.ClientConfig{
		PrivateKey: privateKey,
		Issuer:     agents_issuer,
		Kid:        credentials.Mrn,
		Subject:    credentials.Mrn,
	})
}

// mondoo platform config so that resource scan talk upstream
// TODO: this configuration struct does not belong into the MQL package
// nevertheless the MQL runtime needs to have something that allows users
// to store additional credentials so that resource can use those for
// their resources.
type UpstreamClient struct {
	UpstreamConfig
	Plugins    []ranger.ClientPlugin
	HttpClient *http.Client
}

// Hash generates a hash of the upstream config used to avoid creating multiple clients
func (c *UpstreamConfig) Hash() uint64 {
	hash, err := hashstructure.Hash(c.Creds, hashstructure.FormatV2, nil)
	if err != nil {
		log.Error().Err(err).Msg("unable to hash upstream config")
	}
	return hash
}

func (c *UpstreamConfig) InitClient(ctx context.Context) (*UpstreamClient, error) {
	certAuth, err := NewServiceAccountRangerPlugin(c.Creds)
	if err != nil {
		return nil, multierr.Wrap(err, "could not initialize client authentication")
	}

	var si *rangerUtils.ClientSysInfo
	if SysInfoProvider != nil {
		si = SysInfoProvider()
	}

	plugins := []ranger.ClientPlugin{certAuth}
	plugins = append(plugins, rangerUtils.DefaultRangerPlugins(mql.GetFeatures(ctx), si)...)

	res := UpstreamClient{
		UpstreamConfig: *c,
		Plugins:        plugins,
		HttpClient:     c.httpClient(),
	}

	return &res, nil
}

func (c *UpstreamConfig) httpClient() *http.Client {
	if c.ApiProxy == "" {
		return ranger.DefaultHttpClient()
	}
	proxy, err := url.Parse(c.ApiProxy)
	if err != nil {
		log.Fatal().Err(err).Msg("could not parse proxy URL")
	}
	return ranger.NewHttpClient(ranger.WithProxy(proxy))
}
