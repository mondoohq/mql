// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"errors"
	"regexp"
	"strings"
)

var (
	OS_RELEASE_REGEX    = regexp.MustCompile(`(?m)^\s*(.+?)\s*=\s*['"]?([^'"\n]*)['"]?\s*$`)
	LSB_RELEASE_REGEX   = regexp.MustCompile(`(?m)^\s*(.+?)\s*=["']?(.+?)["']?$`)
	RHEL_PLATFORM_REGEX = regexp.MustCompile(`^(.+)\srelease`)
	RHEL_RELEASE_REGEX  = regexp.MustCompile(`release ([\d\.]+)`)

	// Some redhat-family release files name the product and version without the
	// "release" keyword at all. Fedora ELN writes "Fedora ELN 11".
	RHEL_NO_KEYWORD_REGEX = regexp.MustCompile(`^(.+?)\s+(\d+(?:\.\d+)*)\s*(?:\(.*\))?$`)
)

func ParseImageRelease(content string) (map[string]string, error) {
	return parseKeyValue(content, OS_RELEASE_REGEX), nil
}

func ParseOsRelease(content string) (map[string]string, error) {
	return parseKeyValue(content, OS_RELEASE_REGEX), nil
}

func ParseLsbRelease(content string) (map[string]string, error) {
	return parseKeyValue(content, LSB_RELEASE_REGEX), nil
}

func parseKeyValue(content string, regex *regexp.Regexp) map[string]string {
	res := regex.FindAllStringSubmatch(content, -1)
	m := make(map[string]string)
	for _, value := range res {
		m[value[1]] = value[2]
	}
	return m
}

func ParseRhelVersion(releaseDescription string) (string, string, error) {
	releaseDescription = strings.TrimSpace(releaseDescription)

	// The conventional form carries the keyword:
	//   Red Hat Enterprise Linux release 9.2 (Plow)
	//   CentOS Stream release 9
	m := RHEL_PLATFORM_REGEX.FindStringSubmatch(releaseDescription)
	n := RHEL_RELEASE_REGEX.FindStringSubmatch(releaseDescription)
	if len(m) > 1 && len(n) > 1 {
		return m[1], n[1], nil
	}

	// Fedora ELN omits it: "Fedora ELN 11". Failing here is not cosmetic. The
	// redhat family resolver treats an error from this function as "not a
	// redhat host", which skips the entire subtree (rhel, centos, fedora,
	// oracle, ...) and drops the asset into defaultLinux without the redhat
	// family. Every resource gated on IsFamily("redhat") then goes dead:
	// packages, yum, kernel.installed and os.rebootpending among them.
	if k := RHEL_NO_KEYWORD_REGEX.FindStringSubmatch(releaseDescription); len(k) > 2 {
		return k[1], k[2], nil
	}

	return "", "", errors.New("could not parse rhel version")
}
