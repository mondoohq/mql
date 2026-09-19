// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"errors"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// MacOSIdProvider read the operating system id by calling
// "ioreg -rd1 -c IOPlatformExpertDevice" and extracting
// the IOPlatformUUID
type MacOSIdProvider struct {
	connection shared.Connection
}

func (p *MacOSIdProvider) Name() string {
	return "MacOS Platform ID"
}

var MACOS_ID_REGEX = regexp.MustCompile(`\"IOPlatformUUID\"\s*=\s*\"(.*)\"`)

func (p *MacOSIdProvider) ID() (string, error) {
	c, err := p.connection.RunCommand("ioreg -rd1 -c IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	if c.ExitStatus != 0 {
		return "", errors.New("could not detect the machine id: ioreg exited with a non-zero status")
	}

	// parse string with regex with \"IOPlatformUUID\"\s*=\s*\"(.*)\"
	content, err := io.ReadAll(c.Stdout)
	if err != nil {
		return "", err
	}

	m := MACOS_ID_REGEX.FindStringSubmatch(string(content))
	if m == nil {
		return "", errors.New("could not detect the machine id")
	}

	return strings.TrimSpace(strings.ToLower(m[1])), nil
}
