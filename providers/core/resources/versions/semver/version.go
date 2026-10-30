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
//
// One ordering difference against the Masterminds parser this used to wrap: that one
// read every "-suffix" as a semver prerelease, so "1.0.0-1" sorted BEFORE "1.0.0".
// [versionx] only reverses the order for recognized prerelease words (alpha, beta, rc,
// …) and reads anything else as a later build, so that pair now sorts the other way.
// Every caller here compares provider and engine versions, which use the standard tags,
// so the difference does not reach them — but this is the note for whoever git-blames
// their way to it.
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
