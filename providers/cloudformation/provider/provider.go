// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/cloudformation/connection"
	"go.mondoo.com/mql/providers/cloudformation/resources"
	"go.mondoo.com/mql/utils/urlx"
)

const (
	DefaultConnectionType = "cloudformation"
)

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
		Options: map[string]string{},
	}

	// Do custom flag parsing here
	if len(req.Args) == 0 {
		return nil, errors.New("no cloudformation template path provided")
	}
	conf.Options["path"] = req.Args[0]

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
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
		// One template is one asset, and a repository holds many, so taking
		// this file says nothing about the rest of the tree (ADR 045).
		ContinueExploration: true,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.CloudformationConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.CloudformationConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewCloudformationConnection(connId, asset, conf)
		}
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

		asset.Connections[0].Id = conn.ID()
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

	return runtime.Connection.(*connection.CloudformationConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.CloudformationConnection) error {
	asset.Id = conn.Conf.Type

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"iac", "cloudformation", "template"},
	}
	PlatformByName("cloudformation").Apply(asset.Platform)

	// When discovered from a git repository (e.g. by the GitHub provider) prefer
	// the repo (org/repo) plus the repo-relative template path for the name and
	// platform ID. The local path is a temporary clone directory whose hash
	// would change on every scan.
	if url, ok := asset.Connections[0].Options["ssh-url"]; ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err == nil {
			name := org + "/" + repo
			platformID := "//platformid.api.mondoo.app/runtime/cloudformation/domain/" + domain + "/org/" + org + "/repo/" + repo
			// A repository can hold multiple templates; qualify by the
			// repo-relative path so each one is a distinct asset.
			if relPath := asset.Connections[0].Options["path"]; relPath != "" {
				platformID += "/path/" + relPath
				name += "/" + relPath
			}
			asset.Id = platformID
			asset.Connections[0].PlatformId = platformID
			asset.PlatformIds = []string{platformID}
			// Only name an asset that has no name. A caller who passed --asset-name
			// has already named this asset, and detection running afterwards must not
			// take that back; identity still comes from the platform ID above.
			if asset.Name == "" {
				asset.Name = "CloudFormation template " + name
			}
			return nil
		}
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if ok {
		absPath, _ := filepath.Abs(projectPath)
		h := sha256.New()
		h.Write([]byte(absPath))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/cloudformation/hash/" + hash
		asset.Connections[0].PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		if asset.Name == "" {
			asset.Name = "CloudFormation template " + parseNameFromPath(projectPath)
		}
		return nil
	}

	// Neither branch applied, so the connection host is all there is to go on.
	if asset.Name == "" {
		asset.Name = conn.Conf.Host
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

// TODO: harmonize with tf provider codebase
func parseNameFromPath(file string) string {
	// if it is a local file (which may not be true)
	name := ""
	fi, err := os.Stat(file)
	if err == nil {
		if fi.IsDir() && fi.Name() != "." {
			name = "directory " + fi.Name()
		} else if fi.IsDir() {
			name = fi.Name()
		} else {
			name = filepath.Base(fi.Name())
			extension := filepath.Ext(name)
			name = strings.TrimSuffix(name, extension)
		}
	} else {
		// it is not a local file, so we try to be a bit smart
		name = path.Base(file)
		extension := path.Ext(name)
		name = strings.TrimSuffix(name, extension)
	}

	// if the path is . we read the current directory
	if name == "." {
		abspath, err := filepath.Abs(name)
		if err == nil {
			name = parseNameFromPath(abspath)
		}
	}

	return name
}
