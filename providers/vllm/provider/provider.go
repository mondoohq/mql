// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/vllm/connection"
	"go.mondoo.com/mql/providers/vllm/resources"
)

const (
	DefaultConnectionType = "vllm"
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
	if len(req.Args) != 1 {
		return nil, errors.New("vllm endpoint URL is required")
	}

	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	baseURL, host, scheme, path, port, err := parseEndpoint(req.Args[0])
	if err != nil {
		return nil, err
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Host:    host,
		Runtime: scheme,
		Path:    path,
		Port:    port,
		Options: map[string]string{},
	}
	conf.Options[connection.OptionBaseURL] = baseURL

	if apiKey := stringFlag(flags, connection.OptionAPIKey); apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	} else if apiKey := strings.TrimSpace(os.Getenv("VLLM_API_KEY")); apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	}

	conf.Insecure = boolFlag(flags, "insecure")
	if timeout := intFlag(flags, connection.OptionTimeout); timeout > 0 {
		conf.Options[connection.OptionTimeout] = strconv.Itoa(timeout)
	}

	asset := inventory.Asset{
		Name:        "vLLM " + baseURL,
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
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.VllmConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.VllmConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewVllmConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.VllmConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.VllmConnection) error {
	asset.Id = conn.BaseURL()
	asset.Name = "vLLM " + conn.BaseURL()

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"ai", "vllm", "server"},
	}
	PlatformByName("vllm-server").Apply(asset.Platform)

	// `asset.version` is the canonical, cross-provider way to ask what version
	// something is, and every root carries `asset` (ADR 031). A server that
	// does not answer leaves it empty rather than failing the connect: not
	// knowing the version is not a reason to be unable to scan.
	if version, err := conn.Version(context.Background()); err == nil {
		asset.Platform.Version = version
	}

	asset.Fqdn = conn.Conf.Host
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/vllm/server/" + conn.BaseURL()}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func parseEndpoint(raw string) (baseURL string, host string, scheme string, path string, port int32, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		err = errors.New("vllm endpoint URL is required")
		return
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", "", 0, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", "", "", 0, fmt.Errorf("vllm endpoint must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", "", "", "", 0, errors.New("vllm endpoint URL must include a host")
	}

	host = u.Hostname()
	scheme = u.Scheme
	path = u.EscapedPath()
	if rawPort := u.Port(); rawPort != "" {
		parsed, err := strconv.Atoi(rawPort)
		if err != nil || parsed <= 0 || parsed > 65535 {
			return "", "", "", "", 0, fmt.Errorf("invalid vllm endpoint port %q", rawPort)
		}
		port = int32(parsed)
	}

	u.RawQuery = ""
	u.Fragment = ""
	baseURL = strings.TrimRight(u.String(), "/")

	return baseURL, host, scheme, path, port, nil
}

func stringFlag(flags map[string]*llx.Primitive, name string) string {
	if found, ok := flags[name]; ok && found != nil {
		return strings.TrimSpace(string(found.Value))
	}
	return ""
}

func boolFlag(flags map[string]*llx.Primitive, name string) bool {
	if found, ok := flags[name]; ok && found != nil {
		if raw := found.RawData(); raw != nil && raw.Error == nil {
			if v, ok := raw.Value.(bool); ok {
				return v
			}
		}
	}
	return false
}

func intFlag(flags map[string]*llx.Primitive, name string) int {
	if found, ok := flags[name]; ok && found != nil {
		if raw := found.RawData(); raw != nil && raw.Error == nil {
			switch v := raw.Value.(type) {
			case int:
				return v
			case int64:
				return int(v)
			}
		}
	}
	return 0
}
