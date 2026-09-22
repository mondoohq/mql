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
	"go.mondoo.com/mql/providers/ansible/connection"
	"go.mondoo.com/mql/providers/ansible/resources"
)

const (
	DefaultConnectionType = "ansible"
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
		return nil, errors.New("no ansible project path provided")
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
		// A project reads the playbooks in its own directory and in
		// playbooks/, and nothing deeper, so a playbook further down belongs to
		// no project here and is still worth looking for (ADR 045).
		ContinueExploration: true,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.AnsibleConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewAnsibleConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.AnsibleConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.AnsibleConnection) error {
	asset.Id = conn.Conf.Type

	nameKind := "Ansible Playbook Static Analysis "
	if conn.IsProject() {
		asset.Platform = &inventory.Platform{
			TechnologyUrlSegments: []string{"iac", "ansible", "project"},
		}
		PlatformByName("ansible-project").Apply(asset.Platform)
		nameKind = "Ansible Project Static Analysis "
	} else {
		asset.Platform = &inventory.Platform{
			TechnologyUrlSegments: []string{"iac", "ansible", "playbook"},
		}
		PlatformByName("ansible-playbook").Apply(asset.Platform)
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if !ok || projectPath == "" {
		if asset.Name == "" {
			asset.Name = conn.Conf.Host
		}
		return nil
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		absPath = projectPath
	}
	h := sha256.New()
	h.Write([]byte(absPath))
	platformID := "//platformid.api.mondoo.app/runtime/ansible/hash/" + hex.EncodeToString(h.Sum(nil))
	asset.Connections[0].PlatformId = platformID
	asset.PlatformIds = []string{platformID}
	// Only name an asset that has no name. A caller who passed --asset-name has
	// already named this asset, and detection running afterwards must not take
	// that back; identity still comes from the platform ID above.
	if asset.Name == "" {
		asset.Name = nameKind + parseNameFromPath(projectPath)
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
