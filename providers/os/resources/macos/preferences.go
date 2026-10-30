// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package macos

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"howett.net/plist"
)

const (
	currentHostDomains           = "defaults -currentHost domains"
	currentHostDomainPreferences = "defaults -currentHost export %s -"
	userDomains                  = "defaults domains"
	userDomainPreferences        = "defaults export %s -"
)

func NewPreferences(c shared.Connection) *Preferences {
	return &Preferences{
		connection: c,
	}
}

type Preferences struct {
	connection shared.Connection
}

func (p *Preferences) UserPreferences() (map[string]map[string]any, error) {
	return p.preferences(userDomains, userDomainPreferences)
}

func (p *Preferences) UserHostPreferences() (map[string]map[string]any, error) {
	return p.preferences(currentHostDomains, currentHostDomainPreferences)
}

func (p *Preferences) preferences(domainCmd string, preferencesCmd string) (map[string]map[string]any, error) {
	c, err := p.connection.RunCommand(domainCmd)
	if err != nil {
		return nil, err
	}

	domains, err := ParseDomains(c.Stdout)
	if err != nil {
		return nil, err
	}

	res := map[string]map[string]any{}

	for i := range domains {
		domain := domains[i]

		c, err := p.connection.RunCommand(fmt.Sprintf(preferencesCmd, domain))
		if err != nil {
			return nil, err
		}

		data, err := ParsePreferences(c.Stdout)
		if err != nil {
			return nil, err
		}

		res[domain] = data
	}

	return res, nil
}

func ParseDomains(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	res := strings.Split(string(data), ",")

	for i := range res {
		res[i] = strings.TrimSpace(res[i])
	}
	return res, nil
}

func ParsePreferences(input io.Reader) (map[string]any, error) {
	var r io.ReadSeeker
	r, ok := input.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(data)
	}

	var data map[string]any
	decoder := plist.NewDecoder(r)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
