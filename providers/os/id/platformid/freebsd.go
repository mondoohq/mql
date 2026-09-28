// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// FreeBSDIdProvider reads the host UUID from the kern.hostuuid sysctl. At boot
// rc.d/hostid sets it from /etc/hostid, which rc.d/hostid_save creates from the
// SMBIOS system UUID (or a random one) when it is missing, so a scan that
// cannot run commands reads /etc/hostid instead.
type FreeBSDIdProvider struct {
	connection shared.Connection
}

func (p *FreeBSDIdProvider) Name() string {
	return "FreeBSD Host UUID"
}

func (p *FreeBSDIdProvider) ID() (string, error) {
	if p.connection.Capabilities().Has(shared.Capability_RunCommand) {
		c, err := p.connection.RunCommand("sysctl -n kern.hostuuid")
		if err == nil && c.ExitStatus == 0 {
			out, err := io.ReadAll(c.Stdout)
			if err != nil {
				return "", err
			}
			return parseFreebsdHostUUID(string(out))
		}
	}

	f, err := p.connection.FileSystem().Open("/etc/hostid")
	if err != nil {
		return "", err
	}
	defer f.Close()
	out, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return parseFreebsdHostUUID(string(out))
}

// nullHostUUID is what kern.hostuuid holds before rc.d/hostid sets it.
const nullHostUUID = "00000000-0000-0000-0000-000000000000"

func parseFreebsdHostUUID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if id == "" || id == nullHostUUID {
		return "", errors.New("could not detect the host uuid")
	}
	return id, nil
}
