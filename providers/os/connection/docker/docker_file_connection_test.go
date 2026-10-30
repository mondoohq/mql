// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestNewDockerfileConnection(t *testing.T) {
	t.Run("without path", func(t *testing.T) {
		conf := &inventory.Config{}
		asset := &inventory.Asset{}
		local := local.NewConnection(0, conf, asset)
		subject, err := NewDockerfileConnection(0,
			conf,
			asset,
			local,
			[]string{})
		require.Nil(t, subject)
		require.NotNil(t, err)
		require.Equal(t, "please specify a target path for the dockerfile connection", err.Error())
	})

	t.Run("valid path not exist", func(t *testing.T) {
		conf := &inventory.Config{
			Path: "Dockerfile",
		}
		asset := &inventory.Asset{}
		local := local.NewConnection(0, conf, asset)
		subject, err := NewDockerfileConnection(0,
			conf,
			asset,
			local,
			[]string{})
		require.Nil(t, subject)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})
	t.Run("valid path that exist", func(t *testing.T) {
		dockerfile, err := os.CreateTemp("", "Dockerfile")
		require.Nil(t, err)
		defer os.Remove(dockerfile.Name())
		_, err = dockerfile.WriteString("FROM debian:stable")
		require.Nil(t, err)
		conf := &inventory.Config{
			Path: dockerfile.Name(),
		}
		asset := &inventory.Asset{Connections: []*inventory.Config{{}}}
		local := local.NewConnection(0, conf, asset)
		subject, err := NewDockerfileConnection(0,
			conf,
			asset,
			local,
			[]string{})
		require.Nil(t, err)
		require.NotNil(t, subject)
		require.Equal(t, dockerfile.Name(), subject.FileAbsSrc)
	})
}
