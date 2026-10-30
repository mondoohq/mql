// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// MinDowngradeMajor is the oldest major a downgrade can ever target.
//
// The mechanism that consumes translations - the $translate chunk and the
// patcher - ships in v14. A v13 reader receives a bundle carrying translations,
// ignores the field it does not understand, and runs the primary code, so
// nothing below 14 can be served no matter what we emit for it.
const MinDowngradeMajor = 14

// DowngradeMajorSpan is how many majors back the default floor reaches.
const DowngradeMajorSpan = 2

// DefaultDowngradeFloor returns the oldest version of each provider that content
// compiled here should still run on.
//
// The window is the current major minus two, clamped at MinDowngradeMajor, and
// always the .0.0 of that major - a floor is a support boundary, not a specific
// release, so it takes in every patch of the oldest major it serves:
//
//	provider 15.1.2  ->  14.0.0   (15-2 is 13, clamped to 14)
//	provider 17.1.2  ->  15.0.0
//	provider 16.4.0  ->  14.0.0
//
// A provider still on a major below MinDowngradeMajor gets no floor at all
// rather than a floor above its own version. The distinction matters for more
// than tidiness: an unset floor means the compiler never asks that provider for
// a catalog, and asking means starting the provider. Emitting a floor nothing
// could consume would pay that cost for nothing.
//
// An unparseable version is skipped for the same reason. Guessing a floor from a
// version we cannot read risks either withholding fallbacks that would have
// worked or emitting ones that cannot.
func DefaultDowngradeFloor(providerVersions map[string]string) map[string]string {
	if len(providerVersions) == 0 {
		return nil
	}

	res := map[string]string{}
	for provider, version := range providerVersions {
		major, ok := majorOf(version)
		if !ok || major < MinDowngradeMajor {
			continue
		}

		floor := max(major-DowngradeMajorSpan, MinDowngradeMajor)
		res[resources.ProviderKey(provider)] = strconv.Itoa(floor) + ".0.0"
	}

	if len(res) == 0 {
		return nil
	}
	return res
}

// majorOf reads the major out of a version string, tolerating a leading "v" and
// anything trailing the major that is not a digit.
func majorOf(version string) (int, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" {
		return 0, false
	}

	end := strings.IndexByte(version, '.')
	if end < 0 {
		end = len(version)
	}
	major, err := strconv.Atoi(version[:end])
	if err != nil || major < 0 {
		return 0, false
	}
	return major, true
}
