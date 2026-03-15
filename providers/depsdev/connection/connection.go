// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/mod/modfile"

	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

const OPTION_PATH = "path"

// Dep represents a direct dependency from go.mod.
type Dep struct {
	Path    string
	Version string
}

// DepsDevConnection holds the HTTP client and parsed go.mod dependencies.
type DepsDevConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	HttpClient *http.Client
	Deps       []Dep
}

func NewDepsDevConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DepsDevConnection, error) {
	conn := &DepsDevConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		HttpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Parse go.mod if a path was provided
	goModPath := ""
	if conf.Options != nil {
		goModPath = conf.Options[OPTION_PATH]
	}

	if goModPath != "" {
		deps, err := parseGoMod(goModPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse go.mod")
		}
		conn.Deps = deps
		log.Info().Int("dependencies", len(deps)).Str("path", goModPath).Msg("depsdev> parsed go.mod")
	}

	return conn, nil
}

func (c *DepsDevConnection) Name() string {
	return "depsdev"
}

func (c *DepsDevConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *DepsDevConnection) PlatformInfo() (*inventory.Platform, error) {
	return &inventory.Platform{
		Name:                  "depsdev",
		Title:                 "deps.dev",
		Family:                []string{"depsdev"},
		Kind:                  "api",
		Runtime:               "depsdev",
		TechnologyUrlSegments: []string{"oss", "depsdev"},
	}, nil
}

func (c *DepsDevConnection) Identifier() string {
	if c.Conf.Options != nil && c.Conf.Options[OPTION_PATH] != "" {
		return "//platformid.api.mondoo.app/runtime/depsdev/gomod/" + c.Conf.Options[OPTION_PATH]
	}
	return "//platformid.api.mondoo.app/runtime/depsdev"
}

// parseGoMod reads and parses a go.mod file, returning direct dependencies.
func parseGoMod(path string) ([]Dep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, err
	}

	var deps []Dep
	for _, req := range f.Require {
		if req.Indirect {
			continue
		}
		deps = append(deps, Dep{
			Path:    req.Mod.Path,
			Version: req.Mod.Version,
		})
	}

	return deps, nil
}
