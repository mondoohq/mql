// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"encoding/json"
	"io"
	"os"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	// ostreeBootedPath exists on a host booted from an ostree deployment:
	// bootc image mode, Fedora CoreOS, Silverblue and the other Atomic
	// desktops.
	ostreeBootedPath = "/run/ostree-booted"
	// ostreeStagedDeploymentPath exists while a deployment is staged to be
	// finalized at shutdown and booted next. `bootc upgrade`, `bootc switch`
	// and rpm-ostree's upgrade, install and kargs stage one.
	ostreeStagedDeploymentPath = "/run/ostree/staged-deployment"

	rpmOstreeStatusCmd = "rpm-ostree status --json"
)

type rpmOstreeStatus struct {
	Deployments []struct {
		ID     string `json:"id"`
		Booted bool   `json:"booted"`
		Staged bool   `json:"staged"`
	} `json:"deployments"`
}

// parseRpmOstreeStatus reports whether the deployment that boots next is not
// the booted one. rpm-ostree lists deployments in boot order, so the first
// one boots next: a staged deployment, or one written directly to the
// bootloader entries, or the rollback target after `rpm-ostree rollback`.
func parseRpmOstreeStatus(r io.Reader) (bool, error) {
	var status rpmOstreeStatus
	if err := json.NewDecoder(r).Decode(&status); err != nil {
		return false, err
	}
	if len(status.Deployments) == 0 {
		return false, errors.New("rpm-ostree status lists no deployments")
	}
	first := status.Deployments[0]
	return first.Staged || !first.Booted, nil
}

// ostreeRebootPending reports whether a host booted from an ostree deployment
// boots into another deployment next. ok is false when the host is not
// booted from ostree.
//
// The rpm database of an ostree host is that of the booted deployment, so a
// new image never shows up as a newer kernel package, and needs-restarting
// is not installed.
func ostreeRebootPending(conn shared.Connection) (pending bool, ok bool, err error) {
	fs := conn.FileSystem()
	if _, err := fs.Stat(ostreeBootedPath); err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}

	if _, err := fs.Stat(ostreeStagedDeploymentPath); err == nil {
		return true, true, nil
	} else if !os.IsNotExist(err) {
		return false, true, err
	}

	// A deployment that was not staged is already in the bootloader entries.
	cmd, err := conn.RunCommand(rpmOstreeStatusCmd)
	if err != nil || cmd.ExitStatus != 0 {
		// bootc-only images may not ship rpm-ostree; the staged deployment
		// is how bootc updates.
		return false, true, nil
	}
	pending, err = parseRpmOstreeStatus(cmd.Stdout)
	if err != nil {
		return false, true, errors.Wrap(err, "could not parse rpm-ostree status")
	}
	return pending, true, nil
}
