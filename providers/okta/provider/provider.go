// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/providers/okta/resources"
)

const ConnectionType = "okta"

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: make(map[string]string),
	}

	// flag parsing
	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
	}
	if token == "" {
		// aligns the handling with https://github.com/okta/terraform-provider-okta/blob/03be7cc28de0a9259a48f424c9411cc1c2708c2e/website/docs/index.html.markdown?plain=1#L64-L68
		token = os.Getenv("OKTA_API_TOKEN")
	}
	if token == "" {
		token = os.Getenv("OKTA_TOKEN")
	}

	// Service app credentials are the alternative to an API token. An SSWS
	// token carries the full privileges of the admin who minted it, so orgs
	// that require least privilege authenticate a scoped service app with a
	// private key JWT instead. The environment variable names match the ones
	// the Okta Terraform provider reads, so an org that already configures one
	// does not need a second set.
	clientID := flagOrEnv(flags, "client-id", "OKTA_API_CLIENT_ID")
	privateKeyID := flagOrEnv(flags, "private-key-id", "OKTA_API_PRIVATE_KEY_ID")
	scopes := flagOrEnv(flags, "scopes", "OKTA_API_SCOPES")
	privateKey := flagOrEnv(flags, "private-key", "OKTA_API_PRIVATE_KEY")

	switch {
	case privateKey != "":
		// The value is either the PEM itself or a path to it, matching how the
		// Okta Terraform provider accepts the same argument.
		cred, err := privateKeyCredential(privateKey)
		if err != nil {
			return nil, err
		}
		conf.Credentials = append(conf.Credentials, cred)
		conf.Options["client-id"] = clientID
		conf.Options["private-key-id"] = privateKeyID
		conf.Options["scopes"] = scopes

	case token != "":
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))

	default:
		return nil, errors.New("no okta credentials provided, use --token (or OKTA_API_TOKEN) for an API token, or --client-id, --private-key, --private-key-id and --scopes (or OKTA_API_CLIENT_ID, OKTA_API_PRIVATE_KEY, OKTA_API_PRIVATE_KEY_ID and OKTA_API_SCOPES) for a service app")
	}

	organization := ""
	if x, ok := flags["organization"]; ok && len(x.Value) != 0 {
		organization = string(x.Value)
	}
	if organization == "" {
		// aligns the handling with https://github.com/okta/terraform-provider-okta/blob/03be7cc28de0a9259a48f424c9411cc1c2708c2e/website/docs/index.html.markdown?plain=1#L64-L68
		orgName := os.Getenv("OKTA_ORG_NAME")
		baseUrl := os.Getenv("OKTA_BASE_URL")
		organization = strings.TrimSpace(orgName) + "." + strings.TrimSpace(baseUrl)
	}
	if organization == "" {
		return nil, errors.New("okta provider requires an organization. please set option `organization` like `dev-123456.okta.com`")
	}
	if organization != "" {
		conf.Options["organization"] = organization
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// flagOrEnv reads a CLI flag, falling back to an environment variable when the
// flag was not given.
func flagOrEnv(flags map[string]*llx.Primitive, flag, env string) string {
	if x, ok := flags[flag]; ok && len(x.Value) != 0 {
		return string(x.Value)
	}
	return os.Getenv(env)
}

// privateKeyCredential accepts the service app's key either as the PEM itself
// or as a path to a file holding it, matching how the Okta Terraform provider
// reads the same argument. A value that starts a PEM block is taken literally;
// anything else is read from disk.
func privateKeyCredential(value string) (*vault.Credential, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "-----BEGIN") {
		return vault.NewPrivateKeyCredential("", []byte(value), ""), nil
	}

	cred, err := vault.NewPrivateKeyCredentialFromPath("", value, "")
	if err != nil {
		return nil, errors.Join(errors.New("failed to read okta private key from "+value), err)
	}
	return cred, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset information yet.
	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.OktaConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewOktaConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = connId
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.OktaConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.OktaConnection) error {
	asset.Name = "Okta Organization " + conn.OrganizationID()
	asset.Platform = &inventory.Platform{
		Name:                  "okta-org",
		Family:                []string{"okta"},
		Kind:                  "api",
		Title:                 "Okta Organization",
		Runtime:               "okta",
		TechnologyUrlSegments: []string{"saas", "okta", "org"},
	}

	id, err := conn.Identifier()
	if err != nil {
		return err
	}
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/okta/organization/" + id}
	return nil
}
