// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/n8n.json so the CLI and generated docs can list what
// the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "n8n", Title: "n8n Instance", Family: []string{"n8n"}, Kind: []string{"api"}, Runtime: []string{"n8n"}},
}

const platformIdN8nInstance = "//platformid.api.mondoo.app/runtime/n8n/instance/"

// NewN8nInstancePlatform returns the platform for an n8n instance asset.
func NewN8nInstancePlatform(host string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "n8n",
		Title:                 "n8n Instance",
		Family:                []string{"n8n"},
		Kind:                  "api",
		Runtime:               "n8n",
		TechnologyUrlSegments: []string{"saas", "n8n", host},
	}
}

// InstanceHost is the host (with port, when one is set) that identifies the
// instance. The public API exposes no instance ID, so the address is the
// stable key.
func InstanceHost(instanceURL string) string {
	u, err := url.Parse(instanceURL)
	if err != nil || u.Host == "" {
		return instanceURL
	}
	if u.Path != "" && u.Path != "/" {
		return u.Host + u.Path
	}
	return u.Host
}

// NewN8nInstanceIdentifier returns the stable platform id for an instance.
func NewN8nInstanceIdentifier(host string) string {
	return platformIdN8nInstance + host
}
