// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/id/ids"
	"go.mondoo.com/mql/providers/os/resources"
)

func TestLocalConnectionIdDetectors(t *testing.T) {
	srv := &Service{
		Service: plugin.NewService(),
	}

	connectResp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "local",
				},
			},
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, connectResp)

	require.Len(t, connectResp.Asset.IdDetector, 2)
	require.Contains(t, connectResp.Asset.IdDetector, ids.IdDetector_Hostname)
	require.Contains(t, connectResp.Asset.IdDetector, ids.IdDetector_CloudDetect)

	require.Len(t, connectResp.Asset.PlatformIds, 1)

	shutdownconnectResp, err := srv.Shutdown(&plugin.ShutdownReq{})
	require.NoError(t, err)
	require.NotNil(t, shutdownconnectResp)

	srv = &Service{
		Service: plugin.NewService(),
	}
	connectResp, err = srv.Connect(&plugin.ConnectReq{
		Asset: connectResp.Asset,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, connectResp)

	require.Len(t, connectResp.Asset.IdDetector, 2)
	require.Contains(t, connectResp.Asset.IdDetector, ids.IdDetector_Hostname)
	require.Contains(t, connectResp.Asset.IdDetector, ids.IdDetector_CloudDetect)
	// Now the platformIDs are cleaned up
	require.Len(t, connectResp.Asset.PlatformIds, 1)

	shutdownconnectResp, err = srv.Shutdown(&plugin.ShutdownReq{})
	require.NoError(t, err)
	require.NotNil(t, shutdownconnectResp)
}

func TestLocalConnectionIdDetectors_DelayedDiscovery(t *testing.T) {
	srv := &Service{
		Service: plugin.NewService(),
	}

	connectResp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:           "docker-image",
					Host:           "alpine:3.19",
					DelayDiscovery: true,
				},
			},
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, connectResp)

	require.Len(t, connectResp.Asset.IdDetector, 0)
	require.Len(t, connectResp.Asset.PlatformIds, 2)
	require.Nil(t, connectResp.Asset.Platform)

	// Disable delayed discovery and reconnect
	connectResp.Asset.Connections[0].DelayDiscovery = false
	connectResp, err = srv.Connect(&plugin.ConnectReq{
		Asset: connectResp.Asset,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, connectResp)

	require.Len(t, connectResp.Asset.PlatformIds, 2)
	// Verify the platform is set
	require.NotNil(t, connectResp.Asset.Platform)

	shutdownconnectResp, err := srv.Shutdown(&plugin.ShutdownReq{})
	require.NoError(t, err)
	require.NotNil(t, shutdownconnectResp)
}

func TestService_ParseCLI(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "cnquery_tests")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	s := &Service{
		Service: plugin.NewService(),
	}

	req := &plugin.ParseCLIReq{
		Connector: "ssh",
		Args:      []string{"pi@localhost"},
		Flags: map[string]*llx.Primitive{
			"password": {Value: []byte("password123")},
		},
	}
	res, err := s.ParseCLI(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Len(t, res.Asset.Connections[0].Credentials, 2)
	require.Equal(t, vault.CredentialType_password, res.Asset.Connections[0].Credentials[0].Type)
	require.Equal(t, vault.CredentialType_ssh_agent, res.Asset.Connections[0].Credentials[1].Type)

	req = &plugin.ParseCLIReq{
		Connector: "ssh",
		Args:      []string{"pi@localhost"},
	}
	res, err = s.ParseCLI(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Len(t, res.Asset.Connections[0].Credentials, 1)
	require.Equal(t, vault.CredentialType_ssh_agent, res.Asset.Connections[0].Credentials[0].Type)

	req = &plugin.ParseCLIReq{
		Connector: "ssh",
		Args:      []string{"pi@localhost"},
		Flags: map[string]*llx.Primitive{
			"identity-file": {Value: []byte(file.Name())},
		},
	}
	res, err = s.ParseCLI(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Len(t, res.Asset.Connections[0].Credentials, 1)
	require.Equal(t, vault.CredentialType_private_key, res.Asset.Connections[0].Credentials[0].Type)
}

func TestConnect_ContainerImage(t *testing.T) {
	srv := &Service{
		Service: plugin.NewService(),
	}

	connectResp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "docker-image",
					Host: "alpine:3.19.1",
				},
			},
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, connectResp)

	assert.Equal(t, "alpine", connectResp.Asset.Platform.Name)
	assert.Equal(t, "3.19.1", connectResp.Asset.Platform.Version)
	assert.Equal(t, "Alpine Linux v3.19", connectResp.Asset.Platform.Title)
	assert.Equal(t, "container-image", connectResp.Asset.Platform.Kind)
	assert.Equal(t, "docker-image", connectResp.Asset.Platform.Runtime)
}

// TestEnsurePlatformDetected covers the connection Connect left without a
// platform.
//
// A connection that delays discovery -- every container image, because the
// image connection constructor sets the flag during Connect so the layers are
// not downloaded just to answer "what is this" -- skips detection there, and
// detection otherwise happens only in the second, post-discovery connect.
// Between those two points the connection is live and answers queries. Until
// this guard existed it answered them with no platform at all, and any resource
// reading conn.Asset().Platform dereferenced nil.
func TestEnsurePlatformDetected(t *testing.T) {
	newConn := func(t *testing.T, asset *inventory.Asset) (*Service, uint32) {
		t.Helper()
		path, err := filepath.Abs("../detector/testdata/detect-rhel-6.toml")
		require.NoError(t, err)

		conn, err := mock.New(1, asset, mock.WithPath(path))
		require.NoError(t, err)

		s := Init()
		_, err = s.AddRuntime(asset.Connections[0], func(connId uint32) (*plugin.Runtime, error) {
			return plugin.NewRuntime(conn, nil, false, nil, nil, nil, nil, nil), nil
		})
		require.NoError(t, err)
		return s, asset.Connections[0].Id
	}

	delayed := func() *inventory.Asset {
		return &inventory.Asset{
			Connections: []*inventory.Config{{Id: 1, Type: "mock", DelayDiscovery: true}},
		}
	}

	t.Run("detects on first access", func(t *testing.T) {
		asset := delayed()
		require.Nil(t, asset.Platform, "the fixture has to start without a platform")

		s, id := newConn(t, asset)
		require.NoError(t, s.ensurePlatformDetected(id))
		require.NotNil(t, asset.Platform, "platform was not detected")
		assert.NotEmpty(t, asset.Platform.Name)
	})

	t.Run("is idempotent", func(t *testing.T) {
		asset := delayed()
		s, id := newConn(t, asset)

		require.NoError(t, s.ensurePlatformDetected(id))
		first := asset.Platform.Name

		// The second call takes the already-detected path and must not run
		// detection again or disturb what the first one found.
		require.NoError(t, s.ensurePlatformDetected(id))
		assert.Equal(t, first, asset.Platform.Name)
	})

	t.Run("storing detects too", func(t *testing.T) {
		// StoreData creates any resource the connection has not seen, so it
		// carries the same invariant as GetData even though no constructor
		// consults the platform today.
		asset := delayed()
		s, id := newConn(t, asset)
		require.Nil(t, asset.Platform)

		_, err := s.StoreData(&plugin.StoreReq{Connection: id})
		require.NoError(t, err)
		require.NotNil(t, asset.Platform, "StoreData served a connection with no platform")
		assert.NotEmpty(t, asset.Platform.Name)
	})

	t.Run("refuses through GetData when it cannot detect", func(t *testing.T) {
		// An asset with no connection config and no platform, served through
		// GetData with the provider's real resource functions, for a resource
		// whose init reads the platform. Waving this through to the resource is
		// what kept a nil platform reachable: initKernel dereferences it on the
		// last term of its IsFamily chain.
		asset := &inventory.Asset{}
		conn, err := mock.New(7, asset)
		require.NoError(t, err)

		s := Init()
		_, err = s.AddRuntime(&inventory.Config{Id: 7}, func(connId uint32) (*plugin.Runtime, error) {
			return plugin.NewRuntime(conn, nil, false,
				resources.CreateResource, resources.NewResource,
				resources.GetData, resources.SetData, nil), nil
		})
		require.NoError(t, err)

		require.NotPanics(t, func() {
			_, err := s.GetData(&plugin.DataReq{Connection: 7, Resource: "kernel"})
			assert.Error(t, err, "a connection with no platform must not serve a resource")
		})
	})

	t.Run("leaves what it cannot answer for alone", func(t *testing.T) {
		s := Init()
		// A connection this service does not own. GetData reports that, with a
		// better message than this guard could give.
		assert.NoError(t, s.ensurePlatformDetected(999))
	})

	t.Run("forgets the connection on disconnect", func(t *testing.T) {
		asset := delayed()
		s, id := newConn(t, asset)
		require.NoError(t, s.ensurePlatformDetected(id))

		_, ok := s.deferredDetects.Load(id)
		require.True(t, ok, "detection state should be recorded while connected")

		_, err := s.Disconnect(&plugin.DisconnectReq{Connection: id})
		require.NoError(t, err)

		_, ok = s.deferredDetects.Load(id)
		assert.False(t, ok, "detection state outlived the connection")
	})
}
