// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
)

// attachContextConfig puts the mondoo.yml at the scanned root on the asset.
// The root is the clone for a git connection, the scanned directory for HCL,
// and the directory holding the file for a single file, a plan or a state.
// Only that root is read: there is no lookup through parent directories.
//
// An asset that already carries a context config keeps it. That is the case
// when the provider that discovered the asset read the config itself, e.g.
// from a repository root, and recorded where.
func attachContextConfig(asset *inventory.Asset, conn *connection.Connection) {
	if asset.ContextConfig != nil || len(asset.Connections) == 0 {
		return
	}

	if root := conn.CloneRoot(); root != "" {
		origin := &inventory.ConfigOrigin{
			Provider:   "terraform",
			Repository: repositoryFromURL(asset.Connections[0].Options["http-url"]),
			Ref:        plugin.GitHeadRef(root),
			Path:       inventory.ContextConfigFilename,
		}
		asset.ContextConfig = plugin.ReadContextConfig(root, origin, ".")
		return
	}

	path := asset.Connections[0].Options["path"]
	if path == "" {
		return
	}
	dir := path
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		dir = filepath.Dir(path)
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	asset.ContextConfig = plugin.ReadContextConfig(dir, &inventory.ConfigOrigin{Provider: "terraform"}, ".")
}

// repositoryFromURL names a repository by host and path, e.g.
// "github.com/org/repo", without scheme, credentials or ".git" suffix.
func repositoryFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host + strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
}
