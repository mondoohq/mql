// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/multierr"
	"go.mondoo.com/mql/utils/urlx"
)

var (
	_ shared.Connection = &DockerfileConnection{}
	_ plugin.Closer     = &DockerfileConnection{}
)

type DockerfileConnection struct {
	*local.LocalConnection
	// FileAbsSrc must be the absolute path of the Dockerfile so
	// that we find the file downstream
	FileAbsSrc string
	osFamily   shared.OSFamily
	closer     func()
}

func NewDockerfileConnection(_ uint32,
	conf *inventory.Config, asset *inventory.Asset,
	localConn *local.LocalConnection, localFamily []string,
) (*DockerfileConnection, error) {
	if conf == nil {
		return nil, errors.New("missing configuration to create dockerfile connection")
	}

	// When discovered from a git repository (e.g. by the GitHub provider) the
	// asset carries the repo URL plus a repo-relative path to the Dockerfile.
	// Clone the repo and resolve the Dockerfile within the checkout. The
	// deferred cleanup removes the temporary clone directory on any error path;
	// it is disarmed once ownership of the closer transfers to the connection.
	var closer func()
	cleanup := true
	defer func() {
		if cleanup && closer != nil {
			closer()
		}
	}()
	if conf.Path == "" {
		if _, ok := conf.Options["http-url"]; ok {
			clonePath, c, err := plugin.NewGitClone(asset)
			if err != nil {
				return nil, err
			}
			closer = c
			conf.Path = filepath.Join(clonePath, conf.Options["path"])
		}
	}

	src := conf.Path
	if src == "" {
		return nil, errors.New("please specify a target path for the dockerfile connection")
	}

	absSrc, err := filepath.Abs(src)
	if err != nil {
		return nil, multierr.Wrap(err, "can't get absolute path for dockerfile")
	}

	stat, err := os.Stat(absSrc)
	if err != nil {
		return nil, err
	}

	// A directory is not a Dockerfile. Handed one, this used to build an asset
	// literally named "Dockerfile " whose platform ID hashed the directory
	// path: a plausible-looking asset describing nothing, and the only one of
	// these that failed silently. Discovery always hands over a single file, so
	// nothing that works today stops working.
	if stat.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a Dockerfile: %w", absSrc, plugin.ErrNoMatch)
	}

	filename := filepath.Base(absSrc)
	conf.Path = absSrc

	asset.Platform = &inventory.Platform{
		Name:                  "dockerfile",
		Title:                 "Dockerfile",
		Family:                []string{"docker"},
		Kind:                  "code",
		Runtime:               "docker",
		TechnologyUrlSegments: []string{"iac", "dockerfile"},
	}

	if url, ok := conf.Options["ssh-url"]; ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err != nil {
			return nil, err
		}
		platformID := "//platformid.api.mondoo.app/runtime/dockerfile/domain/" + domain + "/org/" + org + "/repo/" + repo
		name := org + "/" + repo
		// A repository can contain multiple Dockerfiles; qualify the platform ID
		// and name with the repo-relative path so each one is a distinct asset.
		if relPath := conf.Options["path"]; relPath != "" {
			platformID += "/path/" + relPath
			name += "/" + relPath
		}
		conf.PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		asset.Name = "Dockerfile " + name

	} else {
		h := sha256.New()
		h.Write([]byte(absSrc))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/dockerfile/hash/" + hash

		conf.PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		asset.Name = "Dockerfile " + filename
	}

	conn := &DockerfileConnection{
		LocalConnection: localConn,
		// here we must use the absolute path of the Dockerfile so
		// that we find the file downstream
		FileAbsSrc: absSrc,
		closer:     closer,
	}
	// the connection now owns the clone directory and cleans it up via Close()
	cleanup = false

	if slices.Contains(localFamily, "darwin") {
		conn.osFamily = shared.OSFamily_Darwin
	} else if slices.Contains(localFamily, "unix") {
		conn.osFamily = shared.OSFamily_Unix
	} else if slices.Contains(localFamily, "windows") {
		conn.osFamily = shared.OSFamily_Windows
	} else {
		conn.osFamily = shared.OSFamily_None
	}

	return conn, nil
}

func (p *DockerfileConnection) OSFamily() shared.OSFamily {
	return p.osFamily
}

// Close cleans up any temporary directory created by a git clone.
func (p *DockerfileConnection) Close() {
	if p.closer != nil {
		p.closer()
	}
}
