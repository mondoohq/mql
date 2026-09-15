// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package semver

import (
	"errors"

	"go.mondoo.com/mql/utils/versionx"
)

// Parser compares semantic versions — provider releases, engine versions, the
// min-version requirements mqlc resolves. It is the strict half of
// [versionx]: the ordering comes from there, so a version sorts the same way here as it
// does in MQL and in package inventories, but a string that is not a semantic version
// is still an error, because every caller of this parser is comparing things that are
// supposed to be semver and wants to hear about it when one is not.
type Parser struct{}

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b. It errors when
// either side is not a semantic version.
func (p Parser) Compare(a, b string) (int, error) {
	va := versionx.Parse(a)
	if va.Kind() != versionx.KindSemver {
		return 0, errors.New("'" + a + "' is not a semantic version")
	}
	vb := versionx.Parse(b)
	if vb.Kind() != versionx.KindSemver {
		return 0, errors.New("'" + b + "' is not a semantic version")
	}

	return va.Compare(vb), nil
}
