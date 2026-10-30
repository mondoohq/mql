// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

// The minimum-engine-version axis (ADR 040 part 1) is distinct from the schema
// axis: an old VM can fail on new bytecode no matter which schema it holds. It
// used to live in the per-field `min_mondoo_version`, which was deprecated when
// we moved to provider versions, and nothing replaced it - so the axis was lost
// rather than migrated.
//
// It is recovered here as a static table of language feature -> the engine
// version that introduced it. A table, not a build stamp: the version that
// matters is the one where the feature landed, which no amount of introspection
// at compile time can tell you. `CodeBundle.version` already records which
// engine did the compiling, and that is exactly what makes it useless as a
// minimum.
//
// A feature whose introducing version is not filled in yet contributes no
// requirement. That is deliberate: claiming a wrong minimum is worse than
// claiming none, because content gets withheld from clients that could have run
// it. The detector for such a feature is still live and still tested, so
// recording the version later is a one-line change.
//
// Everything already in main is v14, so a feature landing now is "14.0.0". The
// table only needs an entry per feature that changes what an engine must
// understand, not per release.
type langFeature struct {
	// name is for diagnostics only, never serialized.
	name string
	// since is the engine version that introduced the feature, or "" when we
	// have not established it.
	since string
	// used reports whether a bundle depends on the feature.
	used func(*llx.CodeBundle) bool
}

var langFeatures = []langFeature{
	{
		// ADR 043 strict mode stamps every dereference in an access chain with
		// a nullability marker. An engine that predates the marker parses the
		// bundle fine and ignores the field - proto3 reads an unknown enum
		// value as zero, which here means "unspecified", which means
		// non-strict. So a strict bundle does not fail on an old engine, it
		// silently runs with its strictness stripped: the exact
		// passes-while-verifying-nothing outcome ADR 040 part 4 exists to
		// prevent. It has to be gated on the engine version, not degraded.
		name:  "strict-mode nullability markers (ADR 043)",
		since: "14.0.0",
		used:  usesNullabilityMarkers,
	},
}

// minMqlVersion returns the lowest MQL engine version that can execute this
// bundle, or "" when nothing in it requires more than the baseline.
func minMqlVersion(res *llx.CodeBundle) string {
	if res == nil {
		return ""
	}

	parser := semver.Parser{}
	var min string
	for i := range langFeatures {
		f := &langFeatures[i]
		if f.since == "" || f.used == nil || !f.used(res) {
			continue
		}
		if min == "" {
			min = f.since
			continue
		}
		diff, err := parser.Compare(f.since, min)
		if err != nil {
			continue
		}
		if diff > 0 {
			min = f.since
		}
	}
	return min
}

func usesNullabilityMarkers(res *llx.CodeBundle) bool {
	if res.CodeV2 == nil {
		return false
	}
	for _, block := range res.CodeV2.Blocks {
		if block == nil {
			continue
		}
		for _, chunk := range block.Chunks {
			if chunk == nil || chunk.Function == nil {
				continue
			}
			if chunk.Function.Nullability != llx.Function_NULLABILITY_UNSPECIFIED {
				return true
			}
		}
	}
	return false
}
