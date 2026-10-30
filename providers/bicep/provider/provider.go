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
	"go.mondoo.com/mql/providers/bicep/connection"
	"go.mondoo.com/mql/providers/bicep/resources"
	"go.mondoo.com/mql/utils/urlx"
)

const (
	DefaultConnectionType = "bicep"
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

	if len(req.Args) == 0 {
		return nil, errors.New("path argument is required")
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: map[string]string{},
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.BicepConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.BicepConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewBicepConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.BicepConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.BicepConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Conf.Host

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"iac", "bicep", "template"},
	}
	PlatformByName("bicep").Apply(asset.Platform)

	// When discovered from a git repository (e.g. by the GitHub provider) prefer
	// the repo (org/repo) for the name and platform ID. The local path is a
	// temporary clone directory whose hash would change on every scan.
	if url, ok := asset.Connections[0].Options["ssh-url"]; ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err == nil {
			platformID := "//platformid.api.mondoo.app/runtime/bicep/domain/" + domain + "/org/" + org + "/repo/" + repo
			asset.Id = platformID
			asset.Connections[0].PlatformId = platformID
			asset.PlatformIds = []string{platformID}
			asset.Name = "Bicep file " + org + "/" + repo
			return nil
		}
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if ok {
		absPath, _ := filepath.Abs(projectPath)
		h := sha256.New()
		h.Write([]byte(absPath))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/bicep/hash/" + hash
		asset.Connections[0].PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		asset.Name = "Bicep file " + parseNameFromPath(projectPath)
		return nil
	}

	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func parseNameFromPath(file string) string {
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
		name = path.Base(file)
		extension := path.Ext(name)
		name = strings.TrimSuffix(name, extension)
	}

	// When the user passed a bare "." (current directory) the loop above
	// hands back "." via path.Base, which makes the asset name read
	// "Bicep file .". Resolve to the absolute path so the
	// recursion picks up the actual directory basename instead.
	if name == "." {
		abspath, err := filepath.Abs(file)
		if err == nil {
			name = parseNameFromPath(abspath)
		}
	}

	return name
}
