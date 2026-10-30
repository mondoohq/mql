// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generic

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/providers/core/resources/versions/apk"
	"go.mondoo.com/mql/providers/core/resources/versions/deb"
	"go.mondoo.com/mql/providers/core/resources/versions/rpm"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

func Compare(format, a, b string) (int, error) {
	var cmp int
	var err error
	switch format {
	case "rpm":
		var parser rpm.Parser
		cmp, err = parser.Compare(a, b)
	case "pacman":
		var parser deb.Parser
		cmp, err = parser.Compare(a, b)
	case "deb":
		var parser deb.Parser
		cmp, err = parser.Compare(a, b)
	case "apk":
		var parser apk.Parser
		// for apk versions, we need to remove the epoch, since it is the build version for alpine
		cmp, err = parser.Compare(VersionWithoutEpoch(a), VersionWithoutEpoch(b))
	case "npm":
		var parser semver.Parser
		cmp, err = parser.Compare(a, b)
	default:
		err = errors.New("unsupported pkg comparison for " + format)
	}
	return cmp, err
}

func VersionWithoutEpoch(version string) string {
	splitted := strings.SplitN(version, ":", 2)
	if len(splitted) == 1 {
		return splitted[0]
	} else {
		return splitted[1]
	}
}
