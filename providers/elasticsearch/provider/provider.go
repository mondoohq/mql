// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
	"go.mondoo.com/mql/providers/elasticsearch/resources"
)

const (
	DefaultConnectionType = "elasticsearch"
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

	flagString := func(name string) string {
		if x, ok := flags[name]; ok && len(x.Value) != 0 {
			return string(x.Value)
		}
		return ""
	}

	if len(req.Args) > 0 {
		conf.Host = req.Args[0]
	}
	if h := flagString("host"); h != "" {
		conf.Host = h
	}

	for _, name := range []string{"scheme", "tls-ca"} {
		if v := flagString(name); v != "" {
			conf.Options[name] = v
		}
	}
	if v := flagString("api-key"); v != "" {
		conf.Options[connection.OptionAPIKey] = v
	}
	if x, ok := flags["tls-insecure"]; ok && x.RawData().Value == true {
		conf.Options["tls-insecure"] = "true"
	}
	if x, ok := flags["port"]; ok {
		if p, ok := x.RawData().Value.(int64); ok && p != 0 {
			conf.Options["port"] = strconv.FormatInt(p, 10)
		}
	}

	if user := flagString("user"); user != "" || flagString("password") != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, flagString("password")))
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
		Id:    conn.ID(),
		Name:  conn.Name(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ElasticsearchConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.ElasticsearchConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewElasticsearchConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.ElasticsearchConnection), nil
}

// rootInfo is the subset of GET / used for asset detection.
type rootInfo struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number       string `json:"number"`
		Distribution string `json:"distribution"`
	} `json:"version"`
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ElasticsearchConnection) error {
	var root rootInfo
	if err := conn.Get("/", &root); err != nil {
		return err
	}
	// OpenSearch reports version.distribution == "opensearch"; this provider
	// models the Elasticsearch security APIs, which OpenSearch does not serve.
	if root.Version.Distribution == "opensearch" {
		return errors.New("connected server is OpenSearch, not Elasticsearch; use the opensearch provider")
	}

	clusterID := root.ClusterUUID
	if clusterID == "" {
		clusterID = conn.Conf.Host
	}
	id := connection.NewElasticsearchClusterIdentifier(clusterID)
	asset.Id = id
	asset.Name = fmt.Sprintf("Elasticsearch %s", root.ClusterName)
	asset.Platform = connection.NewElasticsearchClusterPlatform(clusterID)
	asset.Platform.Version = root.Version.Number
	asset.PlatformIds = []string{id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
