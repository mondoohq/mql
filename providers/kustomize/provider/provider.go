// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/kustomize/connection"
	"go.mondoo.com/mql/providers/kustomize/resources"
	"go.mondoo.com/mql/utils/urlx"
)

const (
	DefaultConnectionType = "kustomize"
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

	if len(req.Args) == 0 {
		return nil, errors.New("kustomize provider requires a path argument")
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.KustomizeConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.KustomizeConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewKustomizeConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.KustomizeConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.KustomizeConnection) error {
	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"iac", "kustomize", "overlay"},
	}
	PlatformByName("kustomize").Apply(asset.Platform)

	// When discovered from a git repository (e.g. by the GitHub provider) prefer
	// the repo (org/repo) for the name and platform ID. The local path is a
	// temporary clone directory whose hash would change on every scan.
	if url, ok := asset.Connections[0].Options["ssh-url"]; ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err == nil {
			name := org + "/" + repo
			platformID := "//platformid.api.mondoo.app/runtime/kustomize/domain/" + domain + "/org/" + org + "/repo/" + repo
			// A repository can hold multiple kustomizations (e.g. base + overlays);
			// qualify by the repo-relative directory so each is a distinct asset.
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
				asset.Name = "Kustomize file " + name
			}
			return nil
		}
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if ok {
		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return err
		}
		h := sha256.New()
		h.Write([]byte(absPath))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/kustomize/hash/" + hash
		asset.Id = platformID
		asset.Connections[0].PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		if asset.Name == "" {
			asset.Name = "Kustomize file " + parseNameFromPath(projectPath)
		}
		return nil
	}

	asset.Id = conn.Conf.Type
	if asset.Name == "" {
		asset.Name = conn.Conf.Host
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func parseNameFromPath(file string) string {
	absPath, err := filepath.Abs(file)
	if err != nil {
		return file
	}

	fi, err := os.Stat(absPath)
	if err != nil {
		name := filepath.Base(absPath)
		extension := filepath.Ext(name)
		return strings.TrimSuffix(name, extension)
	}

	if fi.IsDir() {
		return "directory " + filepath.Base(absPath)
	}

	name := filepath.Base(fi.Name())
	extension := filepath.Ext(name)
	return strings.TrimSuffix(name, extension)
}
