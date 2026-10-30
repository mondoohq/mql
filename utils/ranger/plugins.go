// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ranger

import (
	"net/http"
	"runtime"

	"go.mondoo.com/mql"
	"go.mondoo.com/ranger-rpc"
	"go.mondoo.com/ranger-rpc/plugins/scope"
)

type Product struct {
	Name    string
	Version string
	Build   string
}

// ClientSysInfo holds system information for upstream request headers.
// This is a lightweight struct to avoid import cycles with the sysinfo package.
type ClientSysInfo struct {
	PlatformName    string
	PlatformVersion string
	PlatformArch    string
	IP              string
	Hostname        string
	PlatformID      string

	// Product information to include in the header. If not set, defaults to mql product name and mql version/build
	Product Product
}

func DefaultRangerPlugins(features mql.Features, si *ClientSysInfo) []ranger.ClientPlugin {
	plugins := []ranger.ClientPlugin{}
	plugins = append(plugins, scope.NewRequestIDRangerPlugin())
	plugins = append(plugins, sysInfoHeader(features, si))
	return plugins
}

func sysInfoHeader(features mql.Features, si *ClientSysInfo) ranger.ClientPlugin {
	const (
		HttpHeaderUserAgent      = "User-Agent"
		HttpHeaderClientFeatures = "Mondoo-Features"
		HttpHeaderPlatformID     = "Mondoo-PlatformID"
	)

	h := http.Header{}
	info := map[string]string{}

	if si != nil {
		info["PN"] = si.PlatformName
		info["PR"] = si.PlatformVersion
		info["PA"] = si.PlatformArch
		info["IP"] = si.IP
		info["HN"] = si.Hostname
		h.Set(HttpHeaderPlatformID, si.PlatformID)
	}

	// If product information is provided, use it. Otherwise, default to mql product + version
	if si != nil && si.Product.Name != "" && si.Product.Version != "" {
		info[si.Product.Name] = si.Product.Version
	} else {
		info["mql"] = mql.Version
	}

	// If product build information is provided, use it. Otherwise, default to mql build
	if si != nil && si.Product.Build != "" {
		info["build"] = si.Product.Build
	} else {
		info["build"] = mql.Build
	}

	if info["PN"] == "" {
		info["PN"] = runtime.GOOS
	}

	h.Set(HttpHeaderUserAgent, scope.XInfoHeader(info))
	h.Set(HttpHeaderClientFeatures, features.Encode())
	return scope.NewCustomHeaderRangerPlugin(h)
}
