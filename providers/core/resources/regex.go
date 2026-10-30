// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers/core/resources/regex"

func (p *mqlRegex) id() (string, error) {
	return "time", nil
}

func (p *mqlRegex) ipv4() (string, error) {
	return regex.IPv4, nil
}

func (p *mqlRegex) ipv6() (string, error) {
	// This needs a better approach, possibly using advanced regex features if we can...
	return regex.IPv6, nil
}

// TODO: needs to be much more precise
func (p *mqlRegex) url() (string, error) {
	return regex.Url, nil
}

func (p *mqlRegex) domain() (string, error) { //nolint:unused
	return regex.UrlDomain, nil
}

// TODO: this needs serious work! re-use aspects from the domain recognition
func (p *mqlRegex) email() (string, error) {
	return regex.Email, nil
}

func (p *mqlRegex) mac() (string, error) {
	return regex.MAC, nil
}

func (p *mqlRegex) uuid() (string, error) {
	return regex.UUID, nil
}

func (p *mqlRegex) emoji() (string, error) {
	return regex.Emoji, nil
}

func (p *mqlRegex) semver() (string, error) {
	return regex.Semver, nil
}

func (p *mqlRegex) creditCard() (string, error) {
	return regex.CreditCard, nil
}
