// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"fmt"
	"regexp"
	"strings"
)

type SolarisRelease struct {
	ID      string
	Title   string
	Release string
}

// (?m) so the release line is found even when /etc/release carries preceding
// content, such as a site banner prepended ahead of the vendor line.
var solarisVersionRegex = regexp.MustCompile(`(?m)^\s+((?:[\w]\s*)*Solaris)\s([\w\d.]+)`)

func ParseSolarisRelease(content string) (*SolarisRelease, error) {
	m := solarisVersionRegex.FindStringSubmatch(content)
	if len(m) < 2 {
		return nil, fmt.Errorf("could not parse solaris version: %s", content)
	}

	id := strings.ToLower(m[1])
	id = strings.Replace(id, "oracle", "", 1)
	id = strings.ReplaceAll(id, " ", "")

	return &SolarisRelease{
		ID:      id,
		Title:   m[1],
		Release: m[2],
	}, nil
}
