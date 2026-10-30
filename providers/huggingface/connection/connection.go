// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	huggingface "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go"
)

const (
	TokenOption     = "token"
	NamespaceOption = "namespace"
	NamespaceType   = "namespace-type"

	NamespaceTypeUser = "user"
	NamespaceTypeOrg  = "org"

	DiscoveryAll  = "all"
	DiscoveryAuto = "auto"
)

type HuggingfaceConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *huggingface.Client
}

func NewHuggingfaceConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*HuggingfaceConnection, error) {
	token := conf.Options[TokenOption]
	if token == "" {
		token = os.Getenv("HF_TOKEN")
	}

	var opts []huggingface.ClientOption
	if token != "" {
		opts = append(opts, huggingface.WithToken(token))
	}

	client := huggingface.NewClient(opts...)

	conn := &HuggingfaceConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
	}

	return conn, nil
}

func (c *HuggingfaceConnection) Name() string {
	return "huggingface"
}

func (c *HuggingfaceConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *HuggingfaceConnection) Client() *huggingface.Client {
	return c.client
}

func (c *HuggingfaceConnection) Namespace() string {
	return c.Conf.Options[NamespaceOption]
}

func (c *HuggingfaceConnection) NsType() string {
	return c.Conf.Options[NamespaceType]
}

var (
	PlatformIdHuggingfaceUser = "//platformid.api.mondoo.app/runtime/huggingface/user/"
	PlatformIdHuggingfaceOrg  = "//platformid.api.mondoo.app/runtime/huggingface/org/"
)

func NewHuggingfaceUserPlatform(name string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "huggingface", "user", name},
	}
	PlatformByName("huggingface-user").Apply(p)
	return p
}

func NewHuggingfaceOrgPlatform(name string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "huggingface", "org", name},
	}
	PlatformByName("huggingface-org").Apply(p)
	return p
}
