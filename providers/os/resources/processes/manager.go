// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh"
)

type OSProcess struct {
	Pid               int64
	Command           string
	Executable        string
	State             string
	Uid               int64
	SocketInodes      []int64
	SocketInodesError error
}

type OSProcessManager interface {
	Name() string
	Exists(pid int64) (bool, error)
	Process(pid int64) (*OSProcess, error)
	List() ([]*OSProcess, error)
	ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error)
}

func ResolveManager(conn shared.Connection) (OSProcessManager, error) {
	var pm OSProcessManager

	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("cannot find OS information for package detection")
	}

	// procfs over ssh is super slow, lets deactivate until we have a faster approach
	disableProcFs := false
	switch conn.(type) {
	case *ssh.Connection:
		disableProcFs = true
	case *mock.Connection:
		disableProcFs = true
	}

	pf := asset.Platform
	switch {
	case pf.Runtime == "docker container":
		pm = &DockerTopManager{conn: conn}
	case pf.IsFamily("linux") && !disableProcFs:
		pm = &LinuxProcManager{conn: conn}
	case pf.IsFamily("unix"):
		pm = &UnixProcessManager{conn: conn, platform: pf}
	case pf.IsFamily("windows"):
		pm = &WindowsProcessManager{conn: conn}
	default:
		return nil, errors.New("could not detect suitable process manager for platform: " + pf.Name)
	}

	return pm, nil
}
