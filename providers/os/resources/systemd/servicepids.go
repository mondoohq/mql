// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"path"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// serviceCgroupRoots are the cgroup hierarchies systemd places a system
// service's processes in: the unified hierarchy (cgroup v2), and the
// name=systemd hierarchy of cgroup v1 and the unified one of hybrid mode.
var serviceCgroupRoots = []string{
	"/sys/fs/cgroup/system.slice",
	"/sys/fs/cgroup/systemd/system.slice",
	"/sys/fs/cgroup/unified/system.slice",
}

// ServicePids returns the pids of the processes a running system service
// (e.g. "mongod.service") has, read from its cgroup without running
// systemctl. It is empty when the service is not running or its cgroup cannot
// be read.
func ServicePids(afs *afero.Afero, unitName string) []string {
	for _, root := range serviceCgroupRoots {
		data, err := afs.ReadFile(path.Join(root, unitName, "cgroup.procs"))
		if err != nil {
			continue
		}
		var pids []string
		for _, pid := range strings.Fields(string(data)) {
			if _, err := strconv.Atoi(pid); err == nil {
				pids = append(pids, pid)
			}
		}
		if len(pids) > 0 {
			return pids
		}
	}
	return nil
}
