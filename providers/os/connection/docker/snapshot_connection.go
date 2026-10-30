// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"context"
	"os"

	"github.com/moby/moby/client"
	"go.mondoo.com/mql/cli/tmp"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

var _ shared.Connection = &SnapshotConnection{}

type SnapshotConnection struct {
	*tar.Connection
}

// NewSnapshotConnection creates a snapshot for a docker engine container and opens it
func NewSnapshotConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*SnapshotConnection, error) {
	// cache container on local disk
	f, err := tmp.File()
	if err != nil {
		return nil, err
	}

	if conf.Options == nil {
		conf.Options = map[string]string{}
	}
	conf.Options[tar.OPTION_FILE] = f.Name()

	tarConnection, err := tar.NewConnection(
		id,
		conf,
		asset,
		tar.WithFetchFn(func() (string, error) {
			err := exportSnapshot(conf.Host, f)
			if err != nil {
				return "", err
			}

			return f.Name(), nil
		}),
		tar.WithCloseFn(func() {
			// remove temporary file on stream close
			_ = os.Remove(f.Name())
		}))
	if err != nil {
		return nil, err
	}

	return &SnapshotConnection{tarConnection}, nil
}

// ExportSnapshot exports a given container from docker engine to a tar file
func exportSnapshot(containerid string, f *os.File) error {
	dc, err := GetDockerClient()
	if err != nil {
		return err
	}

	rc, err := dc.ContainerExport(context.Background(), containerid, client.ContainerExportOptions{})
	if err != nil {
		return err
	}

	return tar.StreamToTmpFile(rc, f)
}

func (p *SnapshotConnection) Name() string {
	return string(shared.Type_DockerSnapshot)
}

func (p *SnapshotConnection) Type() shared.ConnectionType {
	return shared.Type_DockerSnapshot
}
