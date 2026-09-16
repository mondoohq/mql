// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package versionx parses and compares software version strings.
//
// It is meant to be the ONE comparator for versions across Mondoo: MQL's `version`
// type, package inventories, fleet-wide software listings. A version string must order
// the same way no matter which of those asked, which is only true if they all call the
// same code.
//
// # What it has to handle
//
// Real inventories are not semver. A fleet reports, in the same list:
//
//	1:2.4.52-1ubuntu4.6        deb, with an epoch and a distro revision
//	4.18.0-425.13.1.el8_7      rpm, with an underscore in the dist tag
//	1.1.1k-12.el8              upstream letter release (openssl)
//	1.2.3-r4                   apk build revision
//	126.0.6478.126             four components (Chrome, BIG-IP, Windows drivers)
//	1.0.0-rc1                  an actual semver prerelease
//	1!2.0                      PEP 440 epoch
//
// A strict semver parser rejects most of those, and every such rejection has to fall
// back to *something*. When that something is a lexical string compare — which is what
// the previous llx implementation did — the result is silently wrong in the direction
// users notice: 9.x sorts above 16.x, 425.13 below 425.3, and nothing errors. So this
// package does not reject: [Parse] always returns a comparable value, and [Kind]
// reports how much structure was actually recognized.
//
// # The ordering, in one place
//
//  1. Epoch. A higher epoch wins outright, whatever follows it. This is the whole point
//     of an epoch: it exists because upstream versioning was reset or renumbered.
//
//  2. Release — the part before the first '-'. Compared component-wise on '.', each
//     component compared as alternating digit / non-digit runs so that 425.13 > 425.3
//     and 1.1.1k > 1.1.1f. Missing trailing components count as 0, so 1.2 and 1.2.0 are
//     the same version.
//
//  3. Suffix — the part after the first '-'. This is where semver and packaging
//     disagree, and the disagreement is the single most important rule here:
//
//     Under semver, 1.0.0-alpha is BEFORE 1.0.0 (a prerelease leads its release).
//     Under packaging, 1.2.3-1ubuntu1 is AFTER 1.2.3 (a revision is a later build of
//     it), and so is 1.2.3-r4.
//
//     Both are "X-suffix vs X". Nothing in the string says which convention applies, so
//     the suffix decides: a recognized prerelease word (alpha, beta, rc, …) sorts
//     BEFORE the bare release; anything else — a revision, a dist tag, a build id —
//     sorts AFTER it. Treating every dash-suffix as a semver prerelease is what made
//     apk's -r4/-r10 and Debian's -1ubuntu1 compare backwards.
//
//     The words are recognized wherever they appear, not only after a '-', because
//     PEP 440 and several upstreams attach them straight to the number: 3.7.0beta2 is
//     a candidate for 3.7.0, and 1.0.post1 is a rebuild of 1.0 and so follows it.
//
// Two smaller rules ride along: a '~' segment sorts before everything including the
// empty string (Debian's pre-release marker, 1.0~rc1 < 1.0), and '+build' metadata is
// ignored entirely (semver says it carries no precedence).
//
// One shape is disambiguated by magnitude rather than grammar: apk writes a unix
// build stamp where deb writes an epoch, with the same punctuation. See
// [maxPlausibleEpoch].
//
// # Cross-format comparisons
//
// Comparing a deb revision against an rpm release is not meaningful in either scheme,
// and no comparator can make it so. This one is total, transitive and stable for such
// pairs — good enough to sort a mixed list deterministically — and correct within a
// format, which is every list that has a defined answer. Do NOT reuse it to decide
// whether a host is vulnerable: that question needs the per-format parsers the
// advisory data was written against.
package versionx

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is how much structure Parse recognized in a version string. It exists for
// callers that must reject input they cannot interpret (MQL's `version(x, type: ...)`);
// ordering works for every kind, including KindUnknown.
type Kind uint8

const (
	// KindUnknown has nothing numeric to anchor on ("", "latest", "stable"). Such
	// values still compare — deterministically, by their runs — but a caller asking
	// for a specific format should refuse them.
	KindUnknown Kind = iota
	// KindSemver is a semantic version: MAJOR[.MINOR[.PATCH]] with optional
	// -prerelease and +build, and an optional leading "v".
	KindSemver
	// KindDebian is an epoch written with a colon, the deb/rpm form: "1:2.4.52-1ubuntu4.6".
	KindDebian
	// KindPython is an epoch written with an exclamation mark, the PEP 440 form: "1!2.0".
	KindPython
	// KindGeneric is comparable but not one of the above: four components
	// ("126.0.6478.126"), a letter patch ("1.1.1k"), a dist tag ("4.18.0-425.el8_7").
	// Most of a real package inventory lands here, which is why it is a first-class
	// kind rather than a failure.
	KindGeneric
)

// String renders the kind for error messages and tests.
func (k Kind) String() string {
	switch k {
	case KindSemver:
		return "semver"
	case KindDebian:
		return "debian"
	case KindPython:
		return "python"
	case KindGeneric:
		return "generic"
	default:
		return "unknown"
	}
}

// Version is a parsed version string. The zero value is an empty, comparable version
// (it sorts below everything). Values are immutable and safe to share.
type Version struct {
	src     string
	kind    Kind
	epoch   int
	release string // before the first '-', epoch/'v' prefix and +build stripped
	post    string // a trailing PEP 440 ".postN" component, split out of release
	suffix  string // after the first '-', +build stripped
	hasPre  bool   // suffix opens with a recognized prerelease word
}

// reEpoch matches the leading epoch of a deb/rpm ("1:") or PEP 440 ("1!") version.
var reEpoch = regexp.MustCompile(`^([0-9]+)([:!])`)

// maxPlausibleEpoch separates a real epoch from an apk build stamp, which is written in
// the same position with the same punctuation and means the opposite thing.
//
//	1:2.4.52-1ubuntu4.6     deb epoch 1
//	1632431095:1.2.2-r7     apk, and that is a unix timestamp, not an epoch
//
// Nothing in the grammar tells them apart, so magnitude does. An epoch is a hand-bumped
// counter — Debian's are single digits in practice, and the policy that governs them
// exists precisely so they stay rare — while an apk build stamp has been a ten-digit
// unix time since 2001. Anything at or above this threshold is a build stamp; anything
// below it is an epoch, and the gap between the two populations is six orders of
// magnitude wide.
//
// A build stamp is then DROPPED rather than compared, which is what both other Mondoo
// implementations do (mvd/versions/apk and the core provider's generic.Compare both
// call VersionWithoutEpoch first). Two apk versions differing only in their stamp
// therefore compare equal, the same bargain [Parse] already makes for "+build".
const maxPlausibleEpoch = 10000

// reSemver is the shape MQL has always accepted as "semver": a 1-3 component numeric
// core with optional prerelease and build, optionally v-prefixed. Deliberately the
// lenient form (1.2 is semver here) because that is what callers already depend on.
var reSemver = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)?(\.[0-9]+)?(-[0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*)?(\+[0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*)?$`)

// Parse reads a version string. It never fails: an unrecognizable string still yields a
// Version that compares deterministically against every other one (see [Kind]).
func Parse(s string) Version {
	v := Version{src: s}

	rest := strings.TrimSpace(s)
	if rest == "" {
		return v
	}

	// 1. Epoch. It binds tighter than anything that follows, so it comes off first and
	// is compared first.
	if m := reEpoch.FindStringSubmatch(rest); m != nil {
		// The regex guarantees digits; an overflowing epoch keeps 0 rather than
		// erroring, which orders it as "no epoch" instead of losing the version.
		if n, err := strconv.Atoi(m[1]); err == nil {
			switch {
			case m[2] == "!":
				v.epoch, v.kind = n, KindPython
			case n < maxPlausibleEpoch:
				v.epoch, v.kind = n, KindDebian
			default:
				// An apk build stamp. It is not an epoch and must not outrank
				// every other version in the list; drop it and read what
				// follows as an ordinary version. See maxPlausibleEpoch.
			}
			rest = rest[len(m[0]):]
		}
	}

	// 2. Classify what is left. An epoch already fixed the kind; without one, the
	// semver shape is what distinguishes a semantic version from everything else.
	if v.kind == KindUnknown {
		switch {
		case reSemver.MatchString(rest):
			v.kind = KindSemver
		case strings.ContainsAny(rest, "0123456789"):
			v.kind = KindGeneric
		}
	}

	// 3. Build metadata carries no precedence (semver §10), so it is dropped before
	// any comparison rather than being allowed to break ties.
	//
	// Deliberately unconditional, not semver-only: a '+' in a generic or unrecognized
	// string is a build identifier often enough that treating it as one everywhere
	// beats guessing per kind, and the classification above cannot tell the two apart
	// anyway ("1.0+dfsg1-1", a deb, matches the semver shape). The cost is that two
	// versions differing only after the '+' compare equal. Don't "fix" this by
	// restricting it to KindSemver: that changes ordering for the strings it still
	// cannot classify, without making any of them more correct.
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		rest = rest[:i]
	}

	// A leading "v" is decoration; "v1.2.3" and "1.2.3" are the same version.
	if len(rest) > 1 && (rest[0] == 'v' || rest[0] == 'V') && rest[1] >= '0' && rest[1] <= '9' {
		rest = rest[1:]
	}

	// 4. Release / suffix. The first '-' is the boundary in both conventions: semver's
	// prerelease separator and packaging's revision separator.
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		v.release, v.suffix = rest[:i], rest[i+1:]
		v.hasPre = markerRank(v.suffix) < rankRelease
	} else {
		v.release = rest
	}

	// 5. A trailing ".postN" is PEP 440's post-release marker, not a release
	// component, and it has to come out of the release before anything is compared.
	// See isPostComponent for why leaving it in place cannot be made consistent.
	if i := strings.LastIndexByte(v.release, '.'); i >= 0 && isPostComponent(v.release[i+1:]) {
		v.release, v.post = v.release[:i], v.release[i+1:]
	}

	return v
}

// String returns the original, untouched version string.
func (v Version) String() string { return v.src }

// Kind reports how much structure Parse recognized.
func (v Version) Kind() Kind { return v.kind }

// Epoch is the deb/rpm (`1:`) or PEP 440 (`1!`) epoch, 0 when there is none.
func (v Version) Epoch() int { return v.epoch }

// IsZero reports whether this is an empty version (no string at all).
func (v Version) IsZero() bool { return strings.TrimSpace(v.src) == "" }

// Compare returns -1, 0 or +1 as v sorts before, equal to, or after o. It is a total
// order: transitive, antisymmetric, and defined for every pair of strings.
//
// Equality here is SEMANTIC, not textual — "1.2" and "1.2.0" compare equal, as do
// "1.2.3" and "1.2.3+build.5". Callers that need string identity should compare the
// strings.
func (v Version) Compare(o Version) int {
	if v.epoch != o.epoch {
		if v.epoch < o.epoch {
			return -1
		}
		return 1
	}

	if c := compareRelease(v.release, o.release); c != 0 {
		return c
	}

	if c := comparePost(v.post, o.post); c != 0 {
		return c
	}

	return compareSuffix(v, o)
}

// comparePost orders the PEP 440 post-release marker, which sits between the release
// and the suffix: a post-release follows its own release ("1.0.post1" > "1.0", and >
// "1.0.0", which is the same version) and precedes the next one ("1.0.post1" < "1.0.1",
// because that comparison was already settled by the release).
func comparePost(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	return compareRuns(a, b)
}

// compareSuffix orders the part after the first '-', where semver's prerelease rule and
// packaging's revision rule point in opposite directions (see the package doc).
func compareSuffix(a, b Version) int {
	as, bs := a.suffix, b.suffix
	if as == "" && bs == "" {
		return 0
	}

	// Bare release vs suffixed release: the suffix decides which side is newer. A
	// prerelease word leads its release; a revision follows it.
	if as == "" {
		if b.hasPre {
			return 1
		}
		return -1
	}
	if bs == "" {
		if a.hasPre {
			return -1
		}
		return 1
	}

	// Both suffixed. Prerelease-ness still dominates — "1.0.0-rc1" precedes
	// "1.0.0-1ubuntu1" because one is a candidate for the release and the other is a
	// build of it — and only then do the suffixes compare run by run.
	if a.hasPre != b.hasPre {
		if a.hasPre {
			return -1
		}
		return 1
	}
	return compareRuns(as, bs)
}

// Compare parses both strings and orders them. Use it for one-off comparisons; parse
// once with [Parse] when the same version is compared repeatedly (sorting a list).
func Compare(a, b string) int { return Parse(a).Compare(Parse(b)) }

// Less reports whether a sorts before b. It is the comparator to hand to sort.Slice.
func Less(a, b string) bool { return Compare(a, b) < 0 }

// Max returns the newer of two version strings. An empty string loses against any
// version, which makes this the reducer for folding a set of observed versions into the
// highest one — including the common case where some of the inputs are missing.
func Max(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if Compare(b, a) > 0 {
		return b
	}
	return a
}

// SortStrings sorts versions in place, oldest first. It parses each string once rather
// than once per comparison, which is what [Less] would do — use this for lists.
func SortStrings(versions []string) {
	parsed := make([]Version, len(versions))
	for i, v := range versions {
		parsed[i] = Parse(v)
	}

	sort.SliceStable(parsed, func(i, j int) bool { return parsed[i].Compare(parsed[j]) < 0 })

	for i, v := range parsed {
		versions[i] = v.src
	}
}
