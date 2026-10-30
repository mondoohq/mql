// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snapshot

import (
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type LocalCommandRunner struct {
	Shell []string
}

func (r *LocalCommandRunner) RunCommand(command string) (*shared.Command, error) {
	c := local.CommandRunner{Shell: r.Shell}
	args := []string{}

	res, err := c.Exec(command, args)
	return res, err
}
