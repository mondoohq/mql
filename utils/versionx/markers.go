// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import "strings"

// This file owns the vocabulary of release-stage words — the words that say a version
// is not its release yet ("beta") or is a rebuild of it ("post").
//
// A word is load-bearing: it REVERSES the order of a version against its own release,
// so the list stays conservative and is matched as a WHOLE word. Bare single letters
// are deliberately absent: "1.1.1k" is openssl's patch release and must keep sorting
// ABOVE 1.1.1, and "a"/"b"/"m" cannot be told apart from it. That is also why the list
// is a lookup rather than a prefix regex — "devuan1" opens with "dev" and is a Devuan
// revision, which belongs AFTER its release, and "precise1" is not a "pre" build.
const (
	// rankRelease is where a version with no stage word sits: the release itself.
	rankRelease = 0

	rankDev       = -60 // not even a candidate yet
	rankMilestone = -50
	rankAlpha     = -40
	rankBeta      = -30
	rankPre       = -20
	rankRC        = -10
	rankPost      = 10 // a rebuild of the release, so it follows it
)

// markerRanks orders the stage words. The scale follows PEP 440's own ordering
// (dev < alpha < beta < rc < release < post) with the industry synonyms folded onto
// the tier they mean.
var markerRanks = map[string]int{
	"dev":      rankDev,
	"devel":    rankDev,
	"nightly":  rankDev,
	"snapshot": rankDev,
	"canary":   rankDev,

	"milestone": rankMilestone,

	"alpha": rankAlpha,
	"beta":  rankBeta,

	"pre":        rankPre,
	"prerelease": rankPre,
	"preview":    rankPre,

	"rc": rankRC,

	"post": rankPost,
}

// leadingWord returns the run of ASCII letters a string opens with, lower-cased, or ""
// when it does not open with one.
//
// It stops at the first non-letter, which is what makes the whole-word rule hold in
// both directions: "beta2" yields "beta" (a real marker attached to its number, the
// spelling PostGIS and PEP 440 use), while "devuan1" yields "devuan" and matches
// nothing. It also strips the punctuation a run can carry — splitRuns cuts only at
// digit boundaries, so a non-digit run can arrive as "DEV." or "alpha-".
func leadingWord(s string) string {
	i := 0
	for i < len(s) && isASCIILetter(s[i]) {
		i++
	}
	if i == 0 {
		return ""
	}
	return strings.ToLower(s[:i])
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// markerRank reports where a string's leading word sits on the stage scale.
// rankRelease is returned for anything that is not a stage word, which is the common
// case and the one that must not change behavior.
func markerRank(s string) int {
	w := leadingWord(s)
	if w == "" {
		return rankRelease
	}
	return markerRanks[w]
}

// isPostComponent reports whether a dot-separated component is a PEP 440 post-release
// marker ("post1", "post").
//
// A post-release is NOT a release component, and treating it as one cannot be made to
// work: missing trailing components count as zeros, so "1.0" and "1.0.0" are the same
// version, and any rule that puts "1.0.post1" above "1.0" while the digit-beats-letter
// rule keeps it below "1.0.0" breaks transitivity outright. So Parse splits it off and
// [Version.Compare] weighs it after the release instead.
func isPostComponent(component string) bool {
	return leadingWord(component) == "post"
}
