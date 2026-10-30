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
	"go.mondoo.com/mql/providers/helm/connection"
	"go.mondoo.com/mql/providers/helm/resources"
	"go.mondoo.com/mql/utils/urlx"
)

const (
	DefaultConnectionType = "helm"
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
		return nil, errors.New("helm provider requires a path argument")
	}
	conf.Options[connection.OptionPath] = req.Args[0]

	// Scalar string/bool flags map straight to Options.
	for flagName, optKey := range map[string]string{
		"release-name":      connection.OptionReleaseName,
		"namespace":         connection.OptionNamespace,
		"kube-version":      connection.OptionKubeVersion,
		"repo":              connection.OptionRepo,
		"version":           connection.OptionVersion,
		"username":          connection.OptionUsername,
		"password":          connection.OptionPassword,
		"repository-config": connection.OptionRepositoryConfig,
		"repository-cache":  connection.OptionRepositoryCache,
	} {
		if f, ok := flags[flagName]; ok {
			if v := string(f.Value); v != "" {
				conf.Options[optKey] = v
			}
		}
	}
	if f, ok := flags["is-upgrade"]; ok {
		if b, isBool := f.RawData().Value.(bool); isBool && b {
			conf.Options[connection.OptionIsUpgrade] = "true"
		}
	}

	// List flags are JSON-encoded into Options (which is map[string]string).
	for flagName, optKey := range map[string]string{
		"values":       connection.OptionValues,
		"set":          connection.OptionSet,
		"set-string":   connection.OptionSetString,
		"set-json":     connection.OptionSetJSON,
		"set-file":     connection.OptionSetFile,
		"api-versions": connection.OptionAPIVersions,
	} {
		if f, ok := flags[flagName]; ok && len(f.Array) > 0 {
			vals := make([]string, 0, len(f.Array))
			for i := range f.Array {
				vals = append(vals, string(f.Array[i].Value))
			}
			if enc := connection.EncodeStringList(vals); enc != "" {
				conf.Options[optKey] = enc
			}
		}
	}

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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.HelmConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.HelmConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewHelmConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.HelmConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.HelmConnection) error {
	asset.Id = conn.Conf.Type
	asset.Name = conn.Conf.Host

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"iac", "helm", "chart"},
	}
	PlatformByName("helm").Apply(asset.Platform)

	// When discovered from a git repository (e.g. by the GitHub provider) prefer
	// the repo (org/repo) for the name and platform ID. The local path is a
	// temporary clone directory whose hash would change on every scan.
	if url, ok := asset.Connections[0].Options["ssh-url"]; ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err == nil {
			name := org + "/" + repo
			platformID := "//platformid.api.mondoo.app/runtime/helm/domain/" + domain + "/org/" + org + "/repo/" + repo
			// A repository can hold multiple charts; qualify by the repo-relative
			// chart directory so each one is a distinct asset.
			if relPath := asset.Connections[0].Options["path"]; relPath != "" {
				platformID += "/path/" + relPath
				name += "/" + relPath
			}
			asset.Id = platformID
			asset.Connections[0].PlatformId = platformID
			asset.PlatformIds = []string{platformID}
			asset.Name = "Helm Chart " + name
			return nil
		}
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if ok {
		absPath, _ := filepath.Abs(projectPath)
		h := sha256.New()
		h.Write([]byte(absPath))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/helm/hash/" + hash
		asset.Connections[0].PlatformId = platformID
		asset.PlatformIds = []string{platformID}
		asset.Name = "Helm Chart " + parseNameFromPath(projectPath)
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

	if name == "." {
		abspath, err := filepath.Abs(name)
		if err == nil {
			name = parseNameFromPath(abspath)
		}
	}

	return name
}
