// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// AixIdProvider reads the os_uuid attribute of sys0, which AIX generates
// when it is installed and keeps across reboots.
type AixIdProvider struct {
	connection shared.Connection
}

func (p *AixIdProvider) Name() string {
	return "AIX OS UUID"
}

func (p *AixIdProvider) ID() (string, error) {
	c, err := p.connection.RunCommand("lsattr -El sys0 -a os_uuid -F value")
	if err != nil {
		return "", err
	}
	if c.ExitStatus != 0 {
		return "", fmt.Errorf("lsattr exited with %d", c.ExitStatus)
	}
	out, err := io.ReadAll(c.Stdout)
	if err != nil {
		return "", err
	}
	return parseAixOsUUID(string(out))
}

func parseAixOsUUID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if id == "" || id == nullHostUUID {
		return "", errors.New("could not detect the os uuid")
	}
	return id, nil
}
