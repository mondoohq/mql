// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/resources"
	"go.mondoo.com/mql/providers/network/resources/domain"
)

const (
	HostConnectionType = "host"
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
	target := req.Args[0]

	host, port, scheme, path, err := parseTarget(target)
	if err != nil {
		return nil, err
	}

	insecure := false
	if found, ok := req.Flags["insecure"]; ok {
		insecure, _ = found.RawData().Value.(bool)
	}

	options := map[string]string{}
	if found, ok := req.Flags[connection.OPTION_FOLLOW_REDIRECTS]; ok {
		options[connection.OPTION_FOLLOW_REDIRECTS] = strconv.FormatBool(found.RawData().Value.(bool))
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{{
			Type:     "host",
			Port:     int32(port),
			Host:     host,
			Path:     path,
			Runtime:  scheme,
			Insecure: insecure,
			Options:  options,
		}},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func parseTarget(target string) (string, int, string, string, error) {
	// Note on noSchema handling:
	// A user may type in a target like: `google.com`. Technically, this is not
	// a valid scheme. We need to make it into a valid url scheme for parsing
	// and further processing, but we also want to be mindful of what users intend.
	//
	// If we set this to e.g. an HTTP scheme with port 80, then we break
	// the assumptions that users have when they use other resources (like TLS).
	// For example: `host google.com` and command `tls.versions` is a user
	// indicating that they want the TLS config of https://google.com of course.
	// The same holds for `http.get`, which defaults an unschemed target to
	// HTTPS (see initHttpGet) so a bare `host google.com` inspects the HTTPS
	// endpoint rather than plain :80.
	//
	// Thus: the scheme becomes empty "" and the port is set to 0. Every resource
	// needs to figure out what that means to it.
	noScheme := false
	if i := strings.Index(target, "://"); i == -1 {
		noScheme = true
		target = "http://" + target
	}

	url, err := url.Parse(target)
	if err != nil {
		return "", 0, "", "", err
	}

	host, port := domain.SplitHostPort(url.Host)
	if port == 0 && !noScheme {
		port = resources.CommonPorts[url.Scheme]
	}

	scheme := url.Scheme
	if noScheme {
		scheme = ""
	}

	path := url.Path

	return host, port, scheme, path, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
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

	// TODO: discovery of related assets and use them in the inventory below

	return &plugin.ConnectRes{
		Id:        uint32(conn.ID()),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.HostConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.HostConnection

		switch conf.Type {
		case HostConnectionType:
			conn = connection.NewHostConnection(connId, asset, conf)

		default:
			// generic host connection, without anything else
			conn = connection.NewHostConnection(connId, asset, conf)
		}

		if conn.Conf.Options != nil && conn.Conf.Options["host"] != "" {
			target := conn.Conf.Options["host"]
			host, port, scheme, path, err := parseTarget(target)
			if err != nil {
				return nil, err
			}
			conn.Conf.Host = host
			conn.Conf.Path = path
			conn.Conf.Port = int32(port)
			conn.Conf.Runtime = scheme
		}

		var upstream *upstream.UpstreamClient
		var err error
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = connId
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

	return runtime.Connection.(*connection.HostConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.HostConnection) error {
	if conn.Conf.Runtime != "" {
		hostWithScheme := conn.Conf.Runtime + "://" + conn.Conf.Host
		asset.Name = hostWithScheme
	} else {
		asset.Name = conn.Conf.Host
	}
	platform := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "host"},
	}
	if pi, ok := PlatformByName("host"); ok {
		pi.Apply(platform)
	}
	asset.Platform = platform

	asset.Fqdn = conn.FQDN()
	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/network/host/" + conn.Conf.Runtime + conn.Conf.Host}

	return nil
}
